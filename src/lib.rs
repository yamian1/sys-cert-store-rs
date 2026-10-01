#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod cert;
mod crypto;
mod error;
pub mod ffi;
pub mod key;
mod native;
mod store;

use crate::cert::{Context, supported_property};
use crate::error::{ApiError, boundary, last_error, message_ptr, require, set_error};
use crate::ffi::*;
use crate::key::PrivateKey;
use crate::native::{native_layout, remove_trusted_certificate, update_anchor};
use crate::store::*;
use cms::content_info::ContentInfo;
use der::{Decode, Encode};
use libc::{c_char, c_void};
use openssl::pkcs12::Pkcs12;
use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};
use rusqlite::OptionalExtension;
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::fs;
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;
use x509_parser::prelude::{FromDer, X509Name as NativeX509Name};
use zeroize::Zeroize;

fn encoding_check(encoding: DWORD) -> Result<(), ApiError> {
    require(
        encoding & X509_ASN_ENCODING != 0
            && encoding & !(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING) == 0,
        ERROR_NOT_SUPPORTED,
        "Only X.509 certificate encoding is supported",
    )
}

unsafe fn bytes(pointer: *const BYTE, size: usize) -> Result<Vec<u8>, ApiError> {
    require(
        !pointer.is_null() || size == 0,
        E_INVALIDARG,
        "Null buffer with nonzero size",
    )?;
    Ok(if size == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(pointer, size) }.to_vec()
    })
}

unsafe fn wide_string(pointer: LPCWSTR) -> Result<String, ApiError> {
    require(!pointer.is_null(), E_INVALIDARG, "Null wide string")?;
    let mut result = String::new();
    let mut cursor = pointer;
    loop {
        let value = unsafe { *cursor };
        if value == 0 {
            break;
        }
        let scalar = value as u32;
        let character = char::from_u32(scalar)
            .ok_or_else(|| ApiError::new(E_INVALIDARG, "Invalid Unicode scalar"))?;
        result.push(character);
        cursor = unsafe { cursor.add(1) };
    }
    Ok(result)
}

fn copy_out(value: &[u8], data: *mut c_void, size: *mut DWORD) -> Result<(), ApiError> {
    require(!size.is_null(), E_INVALIDARG, "Null output size")?;
    let capacity = unsafe { *size } as usize;
    unsafe { *size = dword(value.len())? };
    if data.is_null() {
        return Ok(());
    }
    require(
        capacity >= value.len(),
        ERROR_MORE_DATA,
        "Output buffer is too small",
    )?;
    if !value.is_empty() {
        unsafe { ptr::copy_nonoverlapping(value.as_ptr(), data.cast(), value.len()) };
    }
    Ok(())
}

fn refresh_context(state: &mut State, pointer: *const CERT_CONTEXT) -> Result<(), ApiError> {
    let (store_id, row) = {
        let context = state.context(pointer)?;
        (context.store_id, context.row)
    };
    let Some(store_id) = store_id else {
        return Ok(());
    };
    let open = state
        .stores
        .get(&store_id)
        .is_some_and(|store| store.references > 0);
    if !open {
        return Ok(());
    }
    let properties = {
        let store = state.stores.get(&store_id).unwrap();
        if !row_exists(store, row)? {
            return Ok(());
        }
        read_properties(store, row)?
    };
    state.context_mut(pointer)?.properties = properties;
    Ok(())
}

fn parse_provider(provider: LPCSTR) -> Result<Provider, ApiError> {
    let id = provider as usize;
    match id {
        PROVIDER_MEMORY => Ok(Provider::Memory),
        PROVIDER_SYSTEM_A => Ok(Provider::SystemA),
        PROVIDER_SYSTEM_W => Ok(Provider::SystemW),
        value if value > 0xffff => {
            let name = unsafe { CStr::from_ptr(provider) }.to_string_lossy();
            match name.as_ref() {
                "Memory" => Ok(Provider::Memory),
                "System" => Ok(Provider::SystemW),
                "SysCertSQLite" => Ok(Provider::Sqlite),
                "SysCertNative" => Ok(Provider::Native),
                _ => Err(ApiError::new(
                    ERROR_NOT_SUPPORTED,
                    "Store provider is not supported",
                )),
            }
        }
        _ => Err(ApiError::new(
            ERROR_NOT_SUPPORTED,
            "Store provider is not supported",
        )),
    }
}

unsafe fn open_store_api(
    provider_pointer: LPCSTR,
    encoding: DWORD,
    legacy: HCRYPTPROV_LEGACY,
    flags: DWORD,
    parameter: *const c_void,
) -> Result<HCERTSTORE, ApiError> {
    require(
        legacy == 0,
        ERROR_NOT_SUPPORTED,
        "Legacy cryptographic providers are unsupported",
    )?;
    require(
        encoding == 0
            || encoding == X509_ASN_ENCODING
            || encoding == X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        ERROR_NOT_SUPPORTED,
        "Unsupported store encoding",
    )?;
    let provider = parse_provider(provider_pointer)?;
    let (parameter_utf8, native_root) = match provider {
        Provider::SystemW => (Some(unsafe { wide_string(parameter.cast()) }?), None),
        Provider::SystemA | Provider::Sqlite => {
            require(
                !parameter.is_null(),
                E_INVALIDARG,
                "Missing store parameter",
            )?;
            (
                Some(
                    unsafe { CStr::from_ptr(parameter.cast()) }
                        .to_string_lossy()
                        .into_owned(),
                ),
                None,
            )
        }
        Provider::Native => {
            if parameter.is_null() {
                (None, None)
            } else {
                let options = unsafe { &*(parameter.cast::<SYS_CERT_NATIVE_OPTIONS>()) };
                require(
                    options.cbSize as usize == std::mem::size_of::<SYS_CERT_NATIVE_OPTIONS>(),
                    E_INVALIDARG,
                    "Invalid native options size",
                )?;
                let root = if options.rootPath.is_null() {
                    None
                } else {
                    Some(PathBuf::from(
                        unsafe { CStr::from_ptr(options.rootPath) }
                            .to_string_lossy()
                            .into_owned(),
                    ))
                };
                (None, root)
            }
        }
        Provider::Memory => (None, None),
    };
    open_store(
        &mut STATE.lock(),
        provider,
        flags,
        parameter_utf8,
        native_root,
    )
}

fn release_previous(state: &mut State, previous: *const CERT_CONTEXT) {
    if !previous.is_null() {
        let _ = state.release_context(previous);
    }
}

fn blob_slice(blob: &CRYPT_DATA_BLOB) -> Result<&[u8], ApiError> {
    require(
        !blob.pbData.is_null() || blob.cbData == 0,
        E_INVALIDARG,
        "Invalid blob",
    )?;
    Ok(if blob.cbData == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }
    })
}

fn encoded_name(blob: &CRYPT_DATA_BLOB) -> Result<Vec<u8>, ApiError> {
    let data = blob_slice(blob)?;
    let parsed = NativeX509Name::from_der(data);
    require(
        parsed
            .as_ref()
            .is_ok_and(|(remaining, _)| remaining.is_empty()),
        ERROR_INVALID_DATA,
        "Invalid encoded distinguished name",
    )?;
    Ok(data.to_vec())
}

fn context_matches(
    state: &State,
    candidate: &Context,
    kind: DWORD,
    parameter: *const c_void,
) -> Result<bool, ApiError> {
    if kind == CERT_FIND_ANY {
        return Ok(true);
    }
    require(!parameter.is_null(), E_INVALIDARG, "Null search parameter")?;
    match kind {
        CERT_FIND_EXISTING => Ok(candidate.same_identity(state.context(parameter.cast())?)),
        CERT_FIND_SUBJECT_CERT => {
            let information = unsafe { &*(parameter.cast::<CERT_INFO>()) };
            Ok(
                blob_slice(&candidate.info.SerialNumber)? == blob_slice(&information.SerialNumber)?
                    && candidate.certificate.issuer_raw()? == encoded_name(&information.Issuer)?,
            )
        }
        CERT_FIND_ISSUER_OF => {
            let subject = state.context(parameter.cast())?;
            Ok(candidate.certificate.subject_raw()? == subject.certificate.issuer_raw()?)
        }
        CERT_FIND_SUBJECT_NAME | CERT_FIND_ISSUER_NAME => {
            let name = encoded_name(unsafe { &*(parameter.cast::<CRYPT_DATA_BLOB>()) })?;
            let candidate_name = if kind == CERT_FIND_SUBJECT_NAME {
                candidate.certificate.subject_raw()?
            } else {
                candidate.certificate.issuer_raw()?
            };
            Ok(candidate_name == name)
        }
        CERT_FIND_SUBJECT_STR_A
        | CERT_FIND_SUBJECT_STR_W
        | CERT_FIND_ISSUER_STR_A
        | CERT_FIND_ISSUER_STR_W => {
            let wide = kind == CERT_FIND_SUBJECT_STR_W || kind == CERT_FIND_ISSUER_STR_W;
            let subject = kind == CERT_FIND_SUBJECT_STR_A || kind == CERT_FIND_SUBJECT_STR_W;
            let needle = if wide {
                unsafe { wide_string(parameter.cast()) }?
            } else {
                unsafe { CStr::from_ptr(parameter.cast()) }
                    .to_string_lossy()
                    .into_owned()
            };
            let haystack = Context::simple_name(&candidate.certificate, subject)?;
            Ok(haystack
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase()))
        }
        CERT_FIND_SHA1_HASH
        | CERT_FIND_SHA256_HASH
        | CERT_FIND_MD5_HASH
        | CERT_FIND_KEY_IDENTIFIER => {
            let property = match kind {
                CERT_FIND_SHA1_HASH => CERT_SHA1_HASH_PROP_ID,
                CERT_FIND_SHA256_HASH => CERT_SHA256_HASH_PROP_ID,
                CERT_FIND_MD5_HASH => CERT_MD5_HASH_PROP_ID,
                _ => CERT_KEY_IDENTIFIER_PROP_ID,
            };
            Ok(candidate.property_value(property)?
                == blob_slice(unsafe { &*(parameter.cast::<CRYPT_DATA_BLOB>()) })?)
        }
        CERT_FIND_PROPERTY => {
            let property = unsafe { *parameter.cast::<DWORD>() };
            require(
                supported_property(property),
                ERROR_NOT_SUPPORTED,
                "Search property is not supported",
            )?;
            Ok(candidate.properties.contains_key(&property))
        }
        _ => Err(ApiError::new(
            ERROR_NOT_SUPPORTED,
            "Certificate search type is not supported",
        )),
    }
}

fn find_certificate(
    state: &mut State,
    handle: HCERTSTORE,
    kind: DWORD,
    parameter: *const c_void,
    previous: *const CERT_CONTEXT,
) -> Result<*const CERT_CONTEXT, ApiError> {
    let validation = require(
        matches!(
            kind,
            CERT_FIND_ANY
                | CERT_FIND_EXISTING
                | CERT_FIND_SUBJECT_CERT
                | CERT_FIND_ISSUER_OF
                | CERT_FIND_SUBJECT_NAME
                | CERT_FIND_ISSUER_NAME
                | CERT_FIND_SUBJECT_STR_A
                | CERT_FIND_SUBJECT_STR_W
                | CERT_FIND_ISSUER_STR_A
                | CERT_FIND_ISSUER_STR_W
                | CERT_FIND_SHA1_HASH
                | CERT_FIND_SHA256_HASH
                | CERT_FIND_MD5_HASH
                | CERT_FIND_KEY_IDENTIFIER
                | CERT_FIND_PROPERTY
        ),
        ERROR_NOT_SUPPORTED,
        "Certificate search type is not supported",
    )
    .and_then(|_| {
        require(
            kind == CERT_FIND_ANY || !parameter.is_null(),
            E_INVALIDARG,
            "Null search parameter",
        )
    });
    if let Err(error) = validation {
        release_previous(state, previous);
        return Err(error);
    }
    let view_id = store_key(handle);
    let (sources, archived) = match state.store(handle) {
        Ok(store) => {
            let mut sources = vec![view_id];
            sources.extend_from_slice(&store.inherited);
            (sources, store.archived)
        }
        Err(error) => {
            release_previous(state, previous);
            return Err(error);
        }
    };
    let mut first = 0usize;
    let mut after = 0i64;
    if !previous.is_null() {
        let previous_state = (|| {
            let old = state.context(previous)?;
            require(
                old.view_id.or(old.store_id) == Some(view_id),
                E_INVALIDARG,
                "Previous context belongs to a different store",
            )?;
            let old_store = old.store_id.unwrap();
            let first = sources
                .iter()
                .position(|value| *value == old_store)
                .ok_or_else(|| {
                    ApiError::new(
                        E_INVALIDARG,
                        "Previous context belongs to a removed physical store",
                    )
                })?;
            Ok::<_, ApiError>((first, old.row))
        })();
        match previous_state {
            Ok((source, row)) => {
                first = source;
                after = row;
            }
            Err(error) => {
                release_previous(state, previous);
                return Err(error);
            }
        }
    }
    let outcome = (|| {
        for (index, source_id) in sources.iter().enumerate().skip(first) {
            let rows = {
                let store = state.stores.get_mut(source_id).unwrap();
                materialize(store, false)?;
                let mut statement = store
                    .db
                    .prepare("SELECT id FROM certificates WHERE id>? ORDER BY id")?;
                statement
                    .query_map([if index == first { after } else { 0 }], |record| {
                        record.get::<_, i64>(0)
                    })?
                    .collect::<Result<Vec<_>, _>>()?
            };
            for row in rows {
                let candidate = {
                    let store = state.stores.get(source_id).unwrap();
                    let mut value = load_context(store, row)?;
                    value.properties = read_properties(store, row)?;
                    value
                };
                if kind == CERT_FIND_ANY
                    && !archived
                    && candidate.properties.contains_key(&CERT_ARCHIVED_PROP_ID)
                {
                    continue;
                }
                if !context_matches(state, &candidate, kind, parameter)? {
                    continue;
                }
                let inherited = if *source_id == view_id {
                    None
                } else {
                    Some(view_id)
                };
                return Ok(state.publish_context(candidate, Some(*source_id), row, inherited));
            }
        }
        Err(ApiError::new(CRYPT_E_NOT_FOUND, "No matching certificate"))
    })();
    release_previous(state, previous);
    outcome
}

fn source_copy(state: &mut State, pointer: *const CERT_CONTEXT) -> Result<Box<Context>, ApiError> {
    refresh_context(state, pointer)?;
    let (der, properties, private_key, key_path, inherited) = {
        let source = state.context(pointer)?;
        (
            source.der.clone(),
            source.properties.clone(),
            source.private_key.clone(),
            source.key_path.clone(),
            source.view_id.is_some(),
        )
    };
    let mut result = Context::new(der)?;
    result.properties = properties;
    result.private_key = private_key;
    result.key_path = key_path;
    if result.private_key.is_none() && result.key_path.is_some() {
        require(
            !inherited,
            ERROR_ACCESS_DENIED,
            "Inherited certificate views do not grant access to machine private keys",
        )?;
        load_private_key(&mut result)?;
    }
    Ok(result)
}

fn add_context(
    state: &mut State,
    handle: HCERTSTORE,
    source: &Context,
    disposition: DWORD,
    output: bool,
) -> Result<*const CERT_CONTEXT, ApiError> {
    require(
        (1..=7).contains(&disposition),
        E_INVALIDARG,
        "Invalid certificate add disposition",
    )?;
    let id = store_key(handle);
    let mut store = state.stores.remove(&id).ok_or_else(|| {
        ApiError::new(
            ERROR_INVALID_HANDLE,
            "Invalid or closed certificate store handle",
        )
    })?;
    let operation = (|| {
        writable(&mut store)?;
        let mut existing = None;
        if disposition != CERT_STORE_ADD_ALWAYS {
            let rows = {
                let mut statement = store
                    .db
                    .prepare("SELECT id FROM certificates ORDER BY id")?;
                statement
                    .query_map([], |record| record.get::<_, i64>(0))?
                    .collect::<Result<Vec<_>, _>>()?
            };
            for row in rows {
                let mut candidate = load_context(&store, row)?;
                if candidate.same_identity(source) {
                    candidate.properties = read_properties(&store, row)?;
                    existing = Some((row, candidate));
                    break;
                }
            }
        }
        if existing.is_some() {
            require(
                disposition != CERT_STORE_ADD_NEW,
                CRYPT_E_EXISTS,
                "Certificate already exists",
            )?;
        }
        if let Some((_, old)) = &existing
            && (disposition == CERT_STORE_ADD_NEWER
                || disposition == CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES)
        {
            require(
                source.certificate.not_before_timestamp()?
                    > old.certificate.not_before_timestamp()?,
                CRYPT_E_EXISTS,
                "Existing certificate is not older",
            )?;
        }
        if store.native {
            require(
                source.private_key.is_none(),
                ERROR_NOT_SUPPORTED,
                "Private keys cannot be installed into the system ROOT store",
            )?;
            require(
                source.properties.is_empty(),
                ERROR_NOT_SUPPORTED,
                "Native ROOT certificate properties are not persisted in this release",
            )?;
            require(
                disposition != CERT_STORE_ADD_ALWAYS,
                ERROR_NOT_SUPPORTED,
                "Native trust anchors are unique; use ADD_NEW or ADD_REPLACE_EXISTING",
            )?;
            require(
                existing
                    .as_ref()
                    .is_none_or(|(_, old)| old.der == source.der),
                ERROR_NOT_SUPPORTED,
                "Replacing a native root with different certificate bytes requires explicit deletion first",
            )?;
            if existing.is_none() {
                update_anchor(&source.certificate, true, store.layout.as_ref().unwrap())?;
            }
        }
        let mut properties = source.properties.clone();
        let use_existing = existing.is_some()
            && (disposition == CERT_STORE_ADD_USE_EXISTING
                || disposition == CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES);
        if let Some((_, old)) = &existing
            && matches!(
                disposition,
                CERT_STORE_ADD_USE_EXISTING
                    | CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES
                    | CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES
            )
        {
            let mut merged = old.properties.clone();
            merged.extend(properties);
            properties = merged;
        }
        store.db.execute_batch("BEGIN IMMEDIATE")?;
        let transaction_result = (|| {
            let mut row = existing.as_ref().map(|value| value.0).unwrap_or(0);
            if !use_existing || (source.private_key.is_some() && store.objects.is_some()) {
                if let Some((old_row, _)) = &existing {
                    retire_row(&mut store, *old_row)?;
                }
                let mut material = Context::new(if use_existing {
                    existing.as_ref().unwrap().1.der.clone()
                } else {
                    source.der.clone()
                })?;
                material.private_key = source.private_key.clone().or_else(|| {
                    existing
                        .as_ref()
                        .and_then(|value| value.1.private_key.clone())
                });
                row = insert_material(&mut store, &material)?;
            } else if source.private_key.is_some() && store.objects.is_none() {
                store.memory.get_mut(&row).unwrap().key = source.private_key.clone();
            }
            write_properties(&store, row, &properties)?;
            Ok::<i64, ApiError>(row)
        })();
        let row = match transaction_result {
            Ok(row) => {
                store.db.execute_batch("COMMIT")?;
                row
            }
            Err(error) => {
                let _ = store.db.execute_batch("ROLLBACK");
                return Err(error);
            }
        };
        collect_garbage(&mut store)?;
        let result = if output {
            let mut context = load_context(&store, row)?;
            context.properties = properties;
            Some((context, row))
        } else {
            None
        };
        Ok(result)
    })();
    state.stores.insert(id, store);
    match operation? {
        Some((context, row)) => Ok(state.publish_context(context, Some(id), row, None)),
        None => Ok(ptr::null()),
    }
}

fn delete_context(state: &mut State, pointer: *const CERT_CONTEXT) -> Result<(), ApiError> {
    let result = (|| {
        let (store_id, view_id, row, certificate) = {
            let context = state.context(pointer)?;
            require(
                context.store_id.is_some(),
                E_INVALIDARG,
                "Certificate does not belong to a store",
            )?;
            require(
                context.view_id.is_none(),
                ERROR_ACCESS_DENIED,
                "Inherited computer certificates must be modified through the computer store",
            )?;
            (
                context.store_id.unwrap(),
                context.view_id,
                context.row,
                context.certificate.clone(),
            )
        };
        let mut store = state
            .stores
            .remove(&store_id)
            .ok_or_else(|| ApiError::new(ERROR_INVALID_HANDLE, "Certificate store is closed"))?;
        let operation = (|| {
            writable(&mut store)?;
            if store.native {
                remove_trusted_certificate(&certificate, store.layout.as_ref().unwrap())?;
            }
            store.db.execute_batch("BEGIN IMMEDIATE")?;
            if let Err(error) = retire_row(&mut store, row) {
                let _ = store.db.execute_batch("ROLLBACK");
                return Err(error);
            }
            store.db.execute_batch("COMMIT")?;
            collect_garbage(&mut store)
        })();
        state.stores.insert(store_id, store);
        let _ = view_id;
        operation
    })();
    let release = state.release_context(pointer);
    result.and(release)
}

#[allow(clippy::vec_box)]
fn parse_pfx_openssl(data: &[u8], secret: &str) -> Result<Vec<Box<Context>>, ApiError> {
    let pfx = Pkcs12::from_der(data).map_err(|_| {
        ApiError::new(
            ERROR_INVALID_DATA,
            "Invalid PKCS#12 encoding or trailing bytes",
        )
    })?;
    let parsed = pfx.parse2(secret).map_err(|_| {
        ApiError::new(
            ERROR_INVALID_DATA,
            "PKCS#12 password or integrity check failed",
        )
    })?;
    let mut result = Vec::new();
    if let Some(certificate) = parsed.cert {
        let mut context = Context::new(certificate.to_der()?)?;
        if let Some(key) = parsed.pkey {
            let key = PrivateKey::from_der(key.private_key_to_pkcs8()?)?;
            require(
                key.matches(&context.certificate)?,
                ERROR_INVALID_DATA,
                "PKCS#12 key has no matching certificate",
            )?;
            context.private_key = Some(Arc::new(key));
        }
        result.push(context);
    }
    if let Some(chain) = parsed.ca {
        for certificate in chain {
            result.push(Context::new(certificate.to_der()?)?);
        }
    }
    Ok(result)
}

#[allow(clippy::vec_box)]
fn parse_pfx(
    blob: &CRYPT_DATA_BLOB,
    password: LPCWSTR,
    flags: DWORD,
) -> Result<Vec<Box<Context>>, ApiError> {
    require(
        flags & !(CRYPT_EXPORTABLE | CRYPT_USER_KEYSET | CRYPT_MACHINE_KEYSET) == 0,
        ERROR_NOT_SUPPORTED,
        "Only user/computer-keyset, filesystem-protected PKCS#12 imports are supported",
    )?;
    require(
        !(flags & CRYPT_USER_KEYSET != 0 && flags & CRYPT_MACHINE_KEYSET != 0),
        E_INVALIDARG,
        "Conflicting PKCS#12 keyset flags",
    )?;
    let data = blob_slice(blob)?;
    require(!data.is_empty(), E_INVALIDARG, "Empty PKCS#12 input")?;
    let mut secret = if password.is_null() {
        String::new()
    } else {
        unsafe { wide_string(password) }?
    };
    let keystore = KeyStore::from_pkcs12(data, &secret, Pkcs12ImportPolicy::Raw).map_err(|_| {
        ApiError::new(
            ERROR_INVALID_DATA,
            "PKCS#12 password or integrity check failed",
        )
    })?;
    let keys = KeyStore::from_pkcs12(data, &secret, Pkcs12ImportPolicy::Relaxed).map_err(|_| {
        ApiError::new(
            ERROR_INVALID_DATA,
            "PKCS#12 password or integrity check failed",
        )
    })?;
    let mut result = Vec::new();
    let mut private_key = None;
    let mut requires_openssl = false;
    for (_, entry) in keys.entries() {
        if let KeyStoreEntry::PrivateKeyChain(chain) = entry {
            let key = PrivateKey::from_der(chain.key().as_der().to_vec())?;
            requires_openssl |= key.is_pqc();
            require(
                private_key.is_none(),
                ERROR_NOT_SUPPORTED,
                "PKCS#12 files with multiple private keys are unsupported",
            )?;
            private_key = Some(key);
        }
    }
    for (_, entry) in keystore.entries() {
        match entry {
            KeyStoreEntry::PrivateKeyChain(_) => {}
            KeyStoreEntry::Certificate(certificate) => {
                let context = Context::new(certificate.as_der().to_vec())?;
                requires_openssl |=
                    crate::crypto::is_pqc_oid(&context.certificate.public_key_oid()?)
                        || crate::crypto::is_pqc_oid(&context.certificate.signature_oid()?);
                result.push(context);
            }
            KeyStoreEntry::Secret(_) => {
                return Err(ApiError::new(
                    ERROR_NOT_SUPPORTED,
                    "PKCS#12 secret bags are unsupported",
                ));
            }
        }
    }
    if requires_openssl {
        result = parse_pfx_openssl(data, &secret)?;
    } else if let Some(key) = private_key {
        let matches = result
            .iter()
            .enumerate()
            .filter_map(|(index, context)| {
                key.matches(&context.certificate)
                    .ok()
                    .filter(|matched| *matched)
                    .map(|_| index)
            })
            .collect::<Vec<_>>();
        require(
            matches.len() == 1,
            ERROR_INVALID_DATA,
            "PKCS#12 key has no unique matching certificate",
        )?;
        let mut leaf = result.remove(matches[0]);
        leaf.private_key = Some(Arc::new(key));
        result.insert(0, leaf);
    }
    secret.zeroize();
    require(
        !result.is_empty(),
        ERROR_NOT_SUPPORTED,
        "PKCS#12 contains material that cannot be preserved by this importer",
    )?;
    Ok(result)
}

fn import_pfx(store: &mut Store, certificates: &[Box<Context>]) -> Result<(), ApiError> {
    writable(store)?;
    require(
        store.objects.is_some() && !store.native,
        ERROR_NOT_SUPPORTED,
        "PKCS#12 imports require a file-backed logical store",
    )?;
    store.db.execute_batch("BEGIN IMMEDIATE")?;
    for context in certificates {
        if let Err(error) = insert_material(store, context) {
            let _ = store.db.execute_batch("ROLLBACK");
            return Err(error);
        }
    }
    store.db.execute_batch("COMMIT")?;
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn GetLastError() -> DWORD {
    last_error()
}

#[unsafe(no_mangle)]
pub extern "C" fn SetLastError(error: DWORD) {
    set_error(error, "");
}

#[unsafe(no_mangle)]
pub extern "C" fn SysCertGetLastErrorMessage() -> *const c_char {
    message_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn SysCertConfigureSystemStores(
    configuration: *const SYS_CERT_STORE_CONFIGURATION,
) -> BOOL {
    boundary(FALSE, || {
        let mut state = STATE.lock();
        require(
            state.stores.is_empty() && state.contexts.is_empty(),
            ERROR_BUSY,
            "Close all stores and contexts before changing system-store paths",
        )?;
        let mut paths = SystemPaths::default();
        if !configuration.is_null() {
            let config = unsafe { &*configuration };
            require(
                config.cbSize as usize == std::mem::size_of::<SYS_CERT_STORE_CONFIGURATION>(),
                E_INVALIDARG,
                "Invalid system-store configuration size",
            )?;
            let path = |value: *const c_char, fallback: PathBuf| -> Result<PathBuf, ApiError> {
                if value.is_null() {
                    return Ok(fallback);
                }
                let path = PathBuf::from(
                    unsafe { CStr::from_ptr(value) }
                        .to_string_lossy()
                        .into_owned(),
                );
                require(
                    path.is_absolute(),
                    E_INVALIDARG,
                    "System-store paths must be absolute",
                )?;
                Ok(path)
            };
            paths.user = if config.userStoreDirectory.is_null() {
                None
            } else {
                Some(path(config.userStoreDirectory, PathBuf::new())?)
            };
            paths.machine = path(config.machineStoreDirectory, paths.machine)?;
            paths.root = path(config.systemRoot, paths.root)?;
            require(
                paths.user.as_ref() != Some(&paths.machine),
                E_INVALIDARG,
                "User and computer store directories must differ",
            )?;
        }
        state.paths = paths;
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn SysCertGetCertificateStoreLocation(
    certificate: *const CERT_CONTEXT,
    location: *mut DWORD,
) -> BOOL {
    boundary(FALSE, || {
        require(
            !location.is_null(),
            E_INVALIDARG,
            "Missing store-location output",
        )?;
        let state = STATE.lock();
        let context = state.context(certificate)?;
        let store = context
            .store_id
            .and_then(|id| state.stores.get(&id))
            .ok_or_else(|| {
                ApiError::new(
                    ERROR_NOT_SUPPORTED,
                    "Context does not belong to a scoped system store",
                )
            })?;
        require(
            store.location != 0,
            ERROR_NOT_SUPPORTED,
            "Context does not belong to a scoped system store",
        )?;
        unsafe { *location = store.location };
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertOpenStore(
    provider: LPCSTR,
    encoding: DWORD,
    legacy: HCRYPTPROV_LEGACY,
    flags: DWORD,
    parameter: *const c_void,
) -> HCERTSTORE {
    boundary(ptr::null_mut(), || unsafe {
        open_store_api(provider, encoding, legacy, flags, parameter)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertOpenSystemStoreW(legacy: HCRYPTPROV_LEGACY, name: LPCWSTR) -> HCERTSTORE {
    boundary(ptr::null_mut(), || unsafe {
        open_store_api(
            PROVIDER_SYSTEM_W as LPCSTR,
            0,
            legacy,
            CERT_SYSTEM_STORE_CURRENT_USER,
            name.cast(),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertOpenSystemStoreA(legacy: HCRYPTPROV_LEGACY, name: LPCSTR) -> HCERTSTORE {
    boundary(ptr::null_mut(), || unsafe {
        open_store_api(
            PROVIDER_SYSTEM_A as LPCSTR,
            0,
            legacy,
            CERT_SYSTEM_STORE_CURRENT_USER,
            name.cast(),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertDuplicateStore(handle: HCERTSTORE) -> HCERTSTORE {
    boundary(ptr::null_mut(), || {
        STATE.lock().store_mut(handle)?.references += 1;
        Ok(handle)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertCloseStore(handle: HCERTSTORE, flags: DWORD) -> BOOL {
    boundary(FALSE, || {
        require(
            flags & !CERT_CLOSE_STORE_CHECK_FLAG == 0,
            ERROR_NOT_SUPPORTED,
            "Forced close is not supported",
        )?;
        let mut state = STATE.lock();
        let id = store_key(handle);
        let store = state.stores.get_mut(&id).ok_or_else(|| {
            ApiError::new(
                ERROR_INVALID_HANDLE,
                "Invalid or closed certificate store handle",
            )
        })?;
        let pending = store.contexts != 0;
        store.references -= 1;
        if store.references == 0 {
            let removed = state.stores.remove(&id).unwrap();
            for inherited in removed.inherited {
                state.stores.remove(&inherited);
            }
        }
        require(
            !(pending && flags & CERT_CLOSE_STORE_CHECK_FLAG != 0),
            CRYPT_E_PENDING_CLOSE,
            "Store closed with outstanding contexts",
        )?;
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertCreateCertificateContext(
    encoding: DWORD,
    encoded: *const BYTE,
    size: DWORD,
) -> *const CERT_CONTEXT {
    boundary(ptr::null(), || {
        encoding_check(encoding)?;
        let context = Context::new(unsafe { bytes(encoded, size as usize) }?)?;
        Ok(STATE.lock().publish_context(context, None, 0, None))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertDuplicateCertificateContext(
    context: *const CERT_CONTEXT,
) -> *const CERT_CONTEXT {
    boundary(ptr::null(), || {
        STATE.lock().context_mut(context)?.references += 1;
        Ok(context)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertFreeCertificateContext(context: *const CERT_CONTEXT) -> BOOL {
    boundary(FALSE, || {
        STATE.lock().release_context(context)?;
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertEnumCertificatesInStore(
    handle: HCERTSTORE,
    previous: *const CERT_CONTEXT,
) -> *const CERT_CONTEXT {
    boundary(ptr::null(), || {
        find_certificate(
            &mut STATE.lock(),
            handle,
            CERT_FIND_ANY,
            ptr::null(),
            previous,
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertFindCertificateInStore(
    handle: HCERTSTORE,
    encoding: DWORD,
    flags: DWORD,
    kind: DWORD,
    parameter: *const c_void,
    previous: *const CERT_CONTEXT,
) -> *const CERT_CONTEXT {
    boundary(ptr::null(), || {
        let mut state = STATE.lock();
        if let Err(error) = encoding_check(encoding).and_then(|_| {
            require(
                flags == 0,
                ERROR_NOT_SUPPORTED,
                "Find flags are unsupported",
            )
        }) {
            release_previous(&mut state, previous);
            return Err(error);
        }
        find_certificate(&mut state, handle, kind, parameter, previous)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertGetSubjectCertificateFromStore(
    handle: HCERTSTORE,
    encoding: DWORD,
    information: *mut CERT_INFO,
) -> *const CERT_CONTEXT {
    CertFindCertificateInStore(
        handle,
        encoding,
        0,
        CERT_FIND_SUBJECT_CERT,
        information.cast(),
        ptr::null(),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn CertGetIssuerCertificateFromStore(
    handle: HCERTSTORE,
    subject: *const CERT_CONTEXT,
    previous: *const CERT_CONTEXT,
    flags: *mut DWORD,
) -> *const CERT_CONTEXT {
    boundary(ptr::null(), || {
        require(
            !flags.is_null(),
            E_INVALIDARG,
            "Missing issuer verification flags",
        )?;
        let requested = unsafe { *flags };
        require(
            requested & !(CERT_STORE_SIGNATURE_FLAG | CERT_STORE_TIME_VALIDITY_FLAG) == 0,
            ERROR_NOT_SUPPORTED,
            "Only signature and validity issuer checks are supported",
        )?;
        let source = {
            let state = STATE.lock();
            state.context(subject)?.certificate.clone()
        };
        require(
            !source.self_signed()?,
            CRYPT_E_SELF_SIGNED,
            "Subject is self-signed",
        )?;
        let result = find_certificate(
            &mut STATE.lock(),
            handle,
            CERT_FIND_ISSUER_OF,
            subject.cast(),
            previous,
        )?;
        let issuer = {
            let state = STATE.lock();
            state.context(result)?.certificate.clone()
        };
        let mut remaining = requested;
        if remaining & CERT_STORE_SIGNATURE_FLAG != 0 && source.verify_with(&issuer)? {
            remaining &= !CERT_STORE_SIGNATURE_FLAG;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ApiError::new(ERROR_GEN_FAILURE, "System time predates Unix epoch"))?
            .as_secs() as i64;
        if remaining & CERT_STORE_TIME_VALIDITY_FLAG != 0
            && source.not_before_timestamp()? < now
            && source.not_after_timestamp()? > now
        {
            remaining &= !CERT_STORE_TIME_VALIDITY_FLAG;
        }
        unsafe { *flags = remaining };
        Ok(result)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertAddCertificateContextToStore(
    handle: HCERTSTORE,
    context: *const CERT_CONTEXT,
    disposition: DWORD,
    result: *mut *const CERT_CONTEXT,
) -> BOOL {
    if !result.is_null() {
        unsafe { *result = ptr::null() };
    }
    boundary(FALSE, || {
        let mut state = STATE.lock();
        let source = source_copy(&mut state, context)?;
        let added = add_context(&mut state, handle, &source, disposition, !result.is_null())?;
        if !result.is_null() {
            unsafe { *result = added };
        }
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertAddEncodedCertificateToStore(
    handle: HCERTSTORE,
    encoding: DWORD,
    encoded: *const BYTE,
    size: DWORD,
    disposition: DWORD,
    result: *mut *const CERT_CONTEXT,
) -> BOOL {
    if !result.is_null() {
        unsafe { *result = ptr::null() };
    }
    boundary(FALSE, || {
        encoding_check(encoding)?;
        let source = Context::new(unsafe { bytes(encoded, size as usize) }?)?;
        let added = add_context(
            &mut STATE.lock(),
            handle,
            &source,
            disposition,
            !result.is_null(),
        )?;
        if !result.is_null() {
            unsafe { *result = added };
        }
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertDeleteCertificateFromStore(context: *const CERT_CONTEXT) -> BOOL {
    boundary(FALSE, || {
        delete_context(&mut STATE.lock(), context)?;
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertGetCertificateContextProperty(
    context: *const CERT_CONTEXT,
    property: DWORD,
    data: *mut c_void,
    size: *mut DWORD,
) -> BOOL {
    boundary(FALSE, || {
        let mut state = STATE.lock();
        refresh_context(&mut state, context)?;
        let value = state.context(context)?.property_value(property)?;
        copy_out(&value, data, size)?;
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertSetCertificateContextProperty(
    context: *const CERT_CONTEXT,
    property: DWORD,
    flags: DWORD,
    data: *const c_void,
) -> BOOL {
    boundary(FALSE, || {
        require(
            flags == 0,
            ERROR_NOT_SUPPORTED,
            "Property flags are unsupported",
        )?;
        require(
            supported_property(property),
            ERROR_NOT_SUPPORTED,
            "Certificate property is unsupported",
        )?;
        require(
            !matches!(
                property,
                CERT_SHA1_HASH_PROP_ID | CERT_SHA256_HASH_PROP_ID | CERT_MD5_HASH_PROP_ID
            ),
            ERROR_NOT_SUPPORTED,
            "Computed certificate hashes cannot be overridden",
        )?;
        let mut state = STATE.lock();
        refresh_context(&mut state, context)?;
        let (store_id, view_id, row) = {
            let target = state.context(context)?;
            (target.store_id, target.view_id, target.row)
        };
        require(
            view_id.is_none(),
            ERROR_ACCESS_DENIED,
            "Inherited computer certificate properties are read-only in a user view",
        )?;
        let value = if data.is_null() {
            None
        } else {
            let blob = unsafe { &*(data.cast::<CRYPT_DATA_BLOB>()) };
            let value = blob_slice(blob)?.to_vec();
            if matches!(
                property,
                CERT_FRIENDLY_NAME_PROP_ID | CERT_DESCRIPTION_PROP_ID
            ) {
                let unit = std::mem::size_of::<WCHAR>();
                require(
                    value.len() >= unit
                        && value.len() % unit == 0
                        && value[value.len() - unit..].iter().all(|byte| *byte == 0),
                    E_INVALIDARG,
                    "Text property must be a native-WCHAR string including its terminator",
                )?;
            }
            Some(value)
        };
        if let Some(id) = store_id
            && let Some(store) = state.stores.get_mut(&id)
            && row_exists(store, row)?
        {
            writable(store)?;
            require(
                !store.native,
                ERROR_NOT_SUPPORTED,
                "Native ROOT property persistence is not implemented",
            )?;
            if let Some(value) = &value {
                store.db.execute(
                    "INSERT OR REPLACE INTO properties(cert,property,value) VALUES(?,?,?)",
                    rusqlite::params![row, property, value],
                )?;
            } else {
                store.db.execute(
                    "DELETE FROM properties WHERE cert=? AND property=?",
                    rusqlite::params![row, property],
                )?;
            }
        }
        let target = state.context_mut(context)?;
        if let Some(value) = value {
            target.properties.insert(property, value);
        } else {
            target.properties.remove(&property);
        }
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertEnumCertificateContextProperties(
    context: *const CERT_CONTEXT,
    previous: DWORD,
) -> DWORD {
    boundary(0, || {
        let mut state = STATE.lock();
        refresh_context(&mut state, context)?;
        Ok(state
            .context(context)?
            .properties
            .range((previous + 1)..)
            .next()
            .map(|value| *value.0)
            .unwrap_or(0))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertGetStoreProperty(
    handle: HCERTSTORE,
    property: DWORD,
    data: *mut c_void,
    size: *mut DWORD,
) -> BOOL {
    boundary(FALSE, || {
        require(
            property == CERT_STORE_LOCALIZED_NAME_PROP_ID
                || (CERT_FIRST_USER_PROP_ID..=CERT_LAST_USER_PROP_ID).contains(&property),
            ERROR_NOT_SUPPORTED,
            "Unsupported store property",
        )?;
        let mut state = STATE.lock();
        let store = state.store_mut(handle)?;
        materialize(store, false)?;
        let value: Option<Vec<u8>> = store
            .db
            .query_row(
                "SELECT value FROM store_properties WHERE property=?",
                [property],
                |row| row.get(0),
            )
            .optional()?;
        let value =
            value.ok_or_else(|| ApiError::new(CRYPT_E_NOT_FOUND, "Store property is not set"))?;
        copy_out(&value, data, size)?;
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertSetStoreProperty(
    handle: HCERTSTORE,
    property: DWORD,
    flags: DWORD,
    data: *const c_void,
) -> BOOL {
    boundary(FALSE, || {
        require(
            flags == 0,
            ERROR_NOT_SUPPORTED,
            "Store property flags are unsupported",
        )?;
        require(
            property == CERT_STORE_LOCALIZED_NAME_PROP_ID
                || (CERT_FIRST_USER_PROP_ID..=CERT_LAST_USER_PROP_ID).contains(&property),
            ERROR_NOT_SUPPORTED,
            "Unsupported store property",
        )?;
        let mut state = STATE.lock();
        let store = state.store_mut(handle)?;
        writable(store)?;
        require(
            !store.native,
            ERROR_NOT_SUPPORTED,
            "Native ROOT store-property persistence is not implemented",
        )?;
        if data.is_null() {
            store
                .db
                .execute("DELETE FROM store_properties WHERE property=?", [property])?;
        } else {
            let value = blob_slice(unsafe { &*(data.cast::<CRYPT_DATA_BLOB>()) })?;
            store.db.execute(
                "INSERT OR REPLACE INTO store_properties(property,value) VALUES(?,?)",
                rusqlite::params![property, value],
            )?;
        }
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertControlStore(
    handle: HCERTSTORE,
    flags: DWORD,
    control: DWORD,
    parameter: *const c_void,
) -> BOOL {
    boundary(FALSE, || {
        require(
            flags == 0 && parameter.is_null(),
            ERROR_NOT_SUPPORTED,
            "Control flags and parameters are unsupported",
        )?;
        let mut state = STATE.lock();
        let id = store_key(handle);
        let (native, inherited, contexts, name) = {
            let store = state.store(handle)?;
            (
                store.native,
                !store.inherited.is_empty(),
                store.contexts,
                store.name.clone(),
            )
        };
        match control {
            CERT_STORE_CTRL_RESYNC => {
                if native || inherited {
                    require(
                        contexts == 0,
                        ERROR_BUSY,
                        "Release native contexts before resynchronizing",
                    )?;
                }
                if native {
                    resync_native(state.store_mut(handle)?)?;
                } else if inherited {
                    let replacement = {
                        let paths = state.paths.clone();
                        let mut temporary = State::default();
                        temporary.paths = paths;
                        let handle = open_store(
                            &mut temporary,
                            Provider::SystemA,
                            CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
                            Some(name),
                            None,
                        )?;
                        temporary.stores.remove(&store_key(handle)).unwrap()
                    };
                    let inherited_handle = state.publish_store(replacement);
                    let old = std::mem::replace(
                        &mut state.store_mut(handle)?.inherited,
                        vec![store_key(inherited_handle)],
                    );
                    for id in old {
                        state.stores.remove(&id);
                    }
                    materialize(state.store_mut(handle)?, false)?;
                } else {
                    materialize(state.store_mut(handle)?, false)?;
                }
            }
            CERT_STORE_CTRL_COMMIT => {
                let store = state.store_mut(handle)?;
                writable(store)?;
                store.db.cache_flush()?;
            }
            _ => {
                return Err(ApiError::new(
                    ERROR_NOT_SUPPORTED,
                    "Store control operation is unsupported",
                ));
            }
        }
        let _ = id;
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertSaveStore(
    handle: HCERTSTORE,
    encoding: DWORD,
    save_as: DWORD,
    save_to: DWORD,
    parameter: *mut c_void,
    flags: DWORD,
) -> BOOL {
    boundary(FALSE, || {
        require(
            encoding == PKCS_7_ASN_ENCODING || encoding == X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            ERROR_NOT_SUPPORTED,
            "PKCS#7 save requires PKCS_7_ASN_ENCODING",
        )?;
        require(
            save_as == CERT_STORE_SAVE_AS_PKCS7
                && save_to == CERT_STORE_SAVE_TO_MEMORY
                && flags == 0,
            ERROR_NOT_SUPPORTED,
            "Only PKCS#7 export to memory is implemented",
        )?;
        require(!parameter.is_null(), E_INVALIDARG, "Missing output blob")?;
        let certificates = {
            let mut state = STATE.lock();
            let view_id = store_key(handle);
            let mut source_ids = vec![view_id];
            source_ids.extend(state.store(handle)?.inherited.clone());
            let mut certificates = Vec::new();
            for id in source_ids {
                let store = state.stores.get_mut(&id).unwrap();
                materialize(store, false)?;
                let mut statement = store
                    .db
                    .prepare("SELECT id FROM certificates ORDER BY id")?;
                let rows = statement
                    .query_map([], |row| row.get::<_, i64>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                drop(statement);
                for row in rows {
                    certificates.push(load_context(store, row)?.der);
                }
            }
            certificates
        };
        let certificates = certificates
            .iter()
            .map(|certificate| {
                x509_cert::Certificate::from_der(certificate).map_err(|error| {
                    ApiError::new(
                        ERROR_INVALID_DATA,
                        format!("Cannot decode certificate for PKCS#7: {error}"),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let message = ContentInfo::try_from(certificates).map_err(|error| {
            ApiError::new(
                ERROR_GEN_FAILURE,
                format!("Cannot create PKCS#7 container: {error}"),
            )
        })?;
        let encoded = message.to_der().map_err(|error| {
            ApiError::new(
                ERROR_GEN_FAILURE,
                format!("Cannot encode PKCS#7 container: {error}"),
            )
        })?;
        unsafe {
            let output = &mut *(parameter.cast::<CRYPT_DATA_BLOB>());
            copy_out(&encoded, output.pbData.cast(), &mut output.cbData)?;
        }
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn SysCertUpdateTrustAnchor(
    certificate: *const CERT_CONTEXT,
    install: BOOL,
    options: *const SYS_CERT_NATIVE_OPTIONS,
    flags: DWORD,
) -> BOOL {
    boundary(FALSE, || {
        require(
            flags == SYS_CERT_TRUST_UPDATE_ALLOW,
            ERROR_ACCESS_DENIED,
            "Native trust update requires explicit SYS_CERT_TRUST_UPDATE_ALLOW",
        )?;
        require(
            install == TRUE || install == FALSE,
            E_INVALIDARG,
            "Invalid install argument",
        )?;
        let root = if options.is_null() {
            None
        } else {
            let options = unsafe { &*options };
            require(
                options.cbSize as usize == std::mem::size_of::<SYS_CERT_NATIVE_OPTIONS>(),
                E_INVALIDARG,
                "Invalid native options size",
            )?;
            if options.rootPath.is_null() {
                None
            } else {
                Some(PathBuf::from(
                    unsafe { CStr::from_ptr(options.rootPath) }
                        .to_string_lossy()
                        .into_owned(),
                ))
            }
        };
        let layout = native_layout(root.as_deref())?;
        let cert = STATE.lock().context(certificate)?.certificate.clone();
        update_anchor(&cert, install == TRUE, &layout)?;
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn SysCertImportPfxToStore(
    handle: HCERTSTORE,
    pfx: *const CRYPT_DATA_BLOB,
    password: LPCWSTR,
    flags: DWORD,
) -> BOOL {
    boundary(FALSE, || {
        require(!pfx.is_null(), E_INVALIDARG, "Empty PKCS#12 input")?;
        let certificates = parse_pfx(unsafe { &*pfx }, password, flags)?;
        let mut state = STATE.lock();
        let store = state.store_mut(handle)?;
        require(
            flags & CRYPT_MACHINE_KEYSET == 0 || store.location == CERT_SYSTEM_STORE_LOCAL_MACHINE,
            E_INVALIDARG,
            "Computer keyset requires a computer-scoped destination store",
        )?;
        require(
            flags & CRYPT_USER_KEYSET == 0 || store.location != CERT_SYSTEM_STORE_LOCAL_MACHINE,
            E_INVALIDARG,
            "User keyset cannot target a computer store",
        )?;
        import_pfx(store, &certificates)?;
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn PFXImportCertStore(
    pfx: *mut CRYPT_DATA_BLOB,
    password: LPCWSTR,
    flags: DWORD,
) -> HCERTSTORE {
    boundary(ptr::null_mut(), || {
        require(!pfx.is_null(), E_INVALIDARG, "Empty PKCS#12 input")?;
        let certificates = parse_pfx(unsafe { &*pfx }, password, flags)?;
        let mut state = STATE.lock();
        let machine = flags & CRYPT_MACHINE_KEYSET != 0;
        let directory = if machine {
            state.paths.machine.clone()
        } else {
            user_data_directory(&state.paths)?
        };
        fs::create_dir_all(&directory)?;
        let mode = if machine { 0o755 } else { 0o700 };
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(mode))?;
        let name = store_name(format!(
            "IMPORT-{}",
            hex::encode(rand::random::<[u8; 16]>())
        ))?;
        let handle = open_store(
            &mut state,
            Provider::SystemA,
            (if machine {
                CERT_SYSTEM_STORE_LOCAL_MACHINE
            } else {
                CERT_SYSTEM_STORE_CURRENT_USER
            }) | CERT_STORE_CREATE_NEW_FLAG,
            Some(name.clone()),
            None,
        )?;
        {
            let store = state.store_mut(handle)?;
            import_pfx(store, &certificates)?;
        }
        Ok(handle)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn SysCertGetCertificateFilePath(
    certificate: *const CERT_CONTEXT,
    private_key: BOOL,
    path: *mut c_char,
    size: *mut DWORD,
) -> BOOL {
    boundary(FALSE, || {
        require(
            private_key == TRUE || private_key == FALSE,
            E_INVALIDARG,
            "Invalid key-path selector",
        )?;
        let mut state = STATE.lock();
        let context = state.context_mut(certificate)?;
        let object_path = context.object_path.clone().ok_or_else(|| {
            ApiError::new(
                ERROR_NOT_SUPPORTED,
                "Context has no logical-store object path",
            )
        })?;
        require(
            private_key == FALSE || context.view_id.is_none(),
            ERROR_ACCESS_DENIED,
            "Inherited views do not grant access to machine private keys",
        )?;
        if private_key == TRUE {
            load_private_key(context)?;
            require(
                context.private_key.is_some(),
                CRYPT_E_NOT_FOUND,
                "Certificate has no private-key file",
            )?;
        }
        let selected = if private_key == TRUE {
            context.key_path.clone().unwrap()
        } else {
            object_path.join("certificate.pem")
        };
        let mut value = selected.to_string_lossy().as_bytes().to_vec();
        value.push(0);
        copy_out(&value, path.cast(), size)?;
        Ok(TRUE)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertEnumSystemStoreLocation(
    flags: DWORD,
    argument: *mut c_void,
    callback: PFN_CERT_ENUM_SYSTEM_STORE_LOCATION,
) -> BOOL {
    boundary(FALSE, || {
        require(
            flags == 0,
            ERROR_NOT_SUPPORTED,
            "System-store location enumeration flags are unsupported",
        )?;
        let callback = callback
            .ok_or_else(|| ApiError::new(E_INVALIDARG, "Missing location enumeration callback"))?;
        let current = [
            b'C' as WCHAR,
            b'u' as WCHAR,
            b'r' as WCHAR,
            b'r' as WCHAR,
            b'e' as WCHAR,
            b'n' as WCHAR,
            b't' as WCHAR,
            b'U' as WCHAR,
            b's' as WCHAR,
            b'e' as WCHAR,
            b'r' as WCHAR,
            0,
        ];
        let machine = [
            b'L' as WCHAR,
            b'o' as WCHAR,
            b'c' as WCHAR,
            b'a' as WCHAR,
            b'l' as WCHAR,
            b'M' as WCHAR,
            b'a' as WCHAR,
            b'c' as WCHAR,
            b'h' as WCHAR,
            b'i' as WCHAR,
            b'n' as WCHAR,
            b'e' as WCHAR,
            0,
        ];
        if unsafe {
            callback(
                current.as_ptr(),
                CERT_SYSTEM_STORE_CURRENT_USER,
                ptr::null_mut(),
                argument,
            )
        } == FALSE
        {
            return Ok(FALSE);
        }
        Ok(unsafe {
            callback(
                machine.as_ptr(),
                CERT_SYSTEM_STORE_LOCAL_MACHINE,
                ptr::null_mut(),
                argument,
            )
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CertEnumSystemStore(
    flags: DWORD,
    location_parameter: *mut c_void,
    argument: *mut c_void,
    callback: PFN_CERT_ENUM_SYSTEM_STORE,
) -> BOOL {
    boundary(FALSE, || {
        require(
            flags == CERT_SYSTEM_STORE_CURRENT_USER || flags == CERT_SYSTEM_STORE_LOCAL_MACHINE,
            ERROR_NOT_SUPPORTED,
            "Only current-user and computer store enumeration is supported",
        )?;
        require(
            location_parameter.is_null(),
            ERROR_NOT_SUPPORTED,
            "Remote and relocated Win32 enumeration parameters are unsupported",
        )?;
        let callback = callback
            .ok_or_else(|| ApiError::new(E_INVALIDARG, "Missing store enumeration callback"))?;
        let state = STATE.lock();
        let directory = if flags == CERT_SYSTEM_STORE_CURRENT_USER {
            user_data_directory(&state.paths)?
        } else {
            state.paths.machine.clone()
        };
        let mut names = BTreeSet::from(["CA".to_owned(), "MY".to_owned(), "ROOT".to_owned()]);
        if directory.exists() {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                if entry.file_type()?.is_file()
                    && !entry.file_type()?.is_symlink()
                    && entry.path().extension().and_then(|value| value.to_str()) == Some("db")
                    && let Some(stem) = entry.path().file_stem().and_then(|value| value.to_str())
                {
                    names.insert(store_name(stem.to_owned())?);
                }
            }
        }
        let mut information = CERT_SYSTEM_STORE_INFO {
            cbSize: std::mem::size_of::<CERT_SYSTEM_STORE_INFO>() as DWORD,
        };
        for name in names {
            let mut wide = name.bytes().map(|value| value as WCHAR).collect::<Vec<_>>();
            wide.push(0);
            if unsafe {
                callback(
                    wide.as_ptr().cast(),
                    flags,
                    &mut information,
                    ptr::null_mut(),
                    argument,
                )
            } == FALSE
            {
                return Ok(FALSE);
            }
        }
        Ok(TRUE)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Builder, X509NameBuilder};

    fn certificate() -> Vec<u8> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Rust test").unwrap();
        let name = name.build();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder
            .sign(&key, openssl::hash::MessageDigest::sha256())
            .unwrap();
        builder.build().to_der().unwrap()
    }

    #[test]
    fn memory_round_trip() {
        let der = certificate();
        let context =
            CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), der.len() as DWORD);
        assert!(!context.is_null());
        let store = CertOpenStore(PROVIDER_MEMORY as LPCSTR, 0, 0, 0, ptr::null());
        assert!(!store.is_null());
        assert_eq!(
            CertAddCertificateContextToStore(store, context, CERT_STORE_ADD_NEW, ptr::null_mut()),
            TRUE
        );
        let found = CertEnumCertificatesInStore(store, ptr::null());
        assert!(!found.is_null());
        assert_eq!(unsafe { (*found).cbCertEncoded }, der.len() as DWORD);
        assert_eq!(CertFreeCertificateContext(found), TRUE);
        assert_eq!(CertFreeCertificateContext(context), TRUE);
        assert_eq!(CertCloseStore(store, 0), TRUE);
    }
}
