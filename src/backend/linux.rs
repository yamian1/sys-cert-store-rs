#![allow(clippy::not_unsafe_ptr_arg_deref, non_snake_case)]

use crate::api_types::*;
use crate::cert::{Context, supported_property};
use crate::crl_cache;
use crate::error::{ApiError, boundary, last_error, message_ptr, require, set_error};
use crate::key::PrivateKey;
use crate::native::{native_layout, remove_trusted_certificate, update_anchor};
use crate::store::*;
use base64ct::{Base64, Encoding};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use libc::{c_char, c_void};
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::X509;
use p12_keystore::{
    Certificate as P12Certificate, KeyStore, KeyStoreEntry, Pkcs12ImportPolicy,
    PrivateKey as P12PrivateKey, PrivateKeyChain,
};
use rusqlite::OptionalExtension;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::CStr;
use std::fs;
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;
use x509_parser::prelude::{FromDer, X509Name as NativeX509Name};
use zeroize::Zeroizing;

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
    let mut units = Zeroizing::new(Vec::new());
    let mut cursor = pointer;
    loop {
        let value = unsafe { *cursor };
        if value == 0 {
            break;
        }
        units.push(value);
        cursor = unsafe { cursor.add(1) };
    }
    String::from_utf16(&units).map_err(|_| ApiError::new(E_INVALIDARG, "Invalid UTF-16 string"))
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

fn copy_string_a(value: &str, output: *mut c_char, capacity: DWORD) -> Result<DWORD, ApiError> {
    let required = dword(value.len() + 1)?;
    if output.is_null() {
        return Ok(required);
    }
    require(
        capacity >= required,
        ERROR_MORE_DATA,
        "Output string buffer is too small",
    )?;
    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), output.cast(), value.len());
        *output.add(value.len()) = 0;
    }
    Ok(required)
}

fn pem_payload(value: &str) -> Result<(&str, DWORD), ApiError> {
    let trimmed = value.trim();
    if !trimmed.starts_with("-----BEGIN ") {
        return Ok((trimmed, 0));
    }
    let first = trimmed
        .find('\n')
        .ok_or_else(|| ApiError::new(ERROR_INVALID_DATA, "Truncated PEM header"))?;
    let last = trimmed
        .rfind("-----END ")
        .ok_or_else(|| ApiError::new(ERROR_INVALID_DATA, "Truncated PEM footer"))?;
    require(last > first, ERROR_INVALID_DATA, "Invalid PEM boundaries")?;
    Ok((trimmed[first + 1..last].trim(), first as DWORD + 1))
}

fn decode_base64(value: &str) -> Result<Vec<u8>, ApiError> {
    let compact = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let compact = std::str::from_utf8(&compact)
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid base64 text"))?;
    Base64::decode_vec(compact)
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid base64 encoding"))
}

#[allow(clippy::vec_box)]
fn parse_pkcs7(data: &[u8]) -> Result<Vec<Box<Context>>, ApiError> {
    let content = ContentInfo::from_der(data)
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid PKCS#7 container"))?;
    require(
        content.content_type == const_oid::db::rfc5911::ID_SIGNED_DATA,
        ERROR_NOT_SUPPORTED,
        "Only signed-data PKCS#7 certificate containers are supported",
    )?;
    let signed =
        SignedData::from_der(&content.content.to_der().map_err(|_| {
            ApiError::new(ERROR_INVALID_DATA, "Invalid PKCS#7 signed-data content")
        })?)
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid PKCS#7 signed-data content"))?;
    let certificates = signed
        .certificates
        .ok_or_else(|| ApiError::new(CRYPT_E_NOT_FOUND, "PKCS#7 contains no certificates"))?
        .0
        .iter()
        .filter_map(|value| match value {
            CertificateChoices::Certificate(certificate) => Some(
                certificate
                    .to_der()
                    .map_err(|_| {
                        ApiError::new(
                            ERROR_INVALID_DATA,
                            "Invalid certificate in PKCS#7 container",
                        )
                    })
                    .and_then(Context::new),
            ),
            CertificateChoices::Other(_) => None,
        })
        .collect::<Result<Vec<_>, _>>()?;
    require(
        !certificates.is_empty(),
        CRYPT_E_NOT_FOUND,
        "PKCS#7 contains no certificates",
    )?;

    let mut remaining = certificates
        .into_iter()
        .map(|certificate| {
            let subject = certificate.certificate.subject_raw()?;
            let issuer = certificate.certificate.issuer_raw()?;
            Ok((certificate, subject, issuer))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let mut ordered = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let next = remaining
            .iter()
            .enumerate()
            .position(|(index, (_, _, issuer))| {
                !remaining
                    .iter()
                    .enumerate()
                    .any(|(other, (_, subject, _))| other != index && subject == issuer)
            })
            .unwrap_or(0);
        ordered.push(remaining.remove(next).0);
    }
    Ok(ordered)
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
        PROVIDER_PKCS7 => Ok(Provider::Pkcs7),
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
        Provider::Memory | Provider::Pkcs7 => (None, None),
    };
    if matches!(provider, Provider::Pkcs7) {
        require(
            encoding & PKCS_7_ASN_ENCODING != 0,
            ERROR_NOT_SUPPORTED,
            "PKCS#7 stores require PKCS_7_ASN_ENCODING",
        )?;
        require(!parameter.is_null(), E_INVALIDARG, "Missing PKCS#7 blob")?;
        let certificates = parse_pkcs7(blob_slice(unsafe {
            &*parameter.cast::<CRYPT_DATA_BLOB>()
        })?)?;
        let mut state = STATE.lock();
        let handle = open_store(
            &mut state,
            Provider::Memory,
            flags & !CERT_STORE_READONLY_FLAG,
            None,
            None,
        )?;
        for certificate in &certificates {
            add_context(
                &mut state,
                handle,
                certificate,
                CERT_STORE_ADD_ALWAYS,
                false,
            )?;
        }
        state.store_mut(handle)?.readonly = flags & CERT_STORE_READONLY_FLAG != 0;
        return Ok(handle);
    }
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
                candidate.serial_le() == blob_slice(&information.SerialNumber)?
                    && candidate.issuer_der() == encoded_name(&information.Issuer)?,
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
            source.der().to_vec(),
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

fn rollback_material_transaction(
    store: &Store,
    pending: &mut PendingObjectDirectories,
    error: ApiError,
) -> ApiError {
    let mut failures = Vec::new();
    if let Err(rollback) = store.db.execute_batch("ROLLBACK") {
        failures.push(format!("database rollback failed: {rollback}"));
    }
    if let Err(cleanup) = pending.rollback() {
        failures.push(format!("filesystem rollback failed: {}", cleanup.message));
    }
    if failures.is_empty() {
        error
    } else {
        ApiError::new(
            error.code,
            format!("{}; {}", error.message, failures.join("; ")),
        )
    }
}

fn commit_material_transaction(
    store: &Store,
    mut pending: PendingObjectDirectories,
) -> Result<(), ApiError> {
    match store.db.execute_batch("COMMIT") {
        Ok(()) => {
            pending.commit();
            Ok(())
        }
        Err(error) => Err(rollback_material_transaction(
            store,
            &mut pending,
            error.into(),
        )),
    }
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
                    .is_none_or(|(_, old)| old.der() == source.der()),
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
        let mut pending = PendingObjectDirectories::new();
        let transaction_result = (|| {
            let mut row = existing.as_ref().map(|value| value.0).unwrap_or(0);
            if !use_existing || (source.private_key.is_some() && store.objects.is_some()) {
                if let Some((old_row, _)) = &existing {
                    retire_row(&mut store, *old_row)?;
                }
                let mut material = Context::new(if use_existing {
                    existing.as_ref().unwrap().1.der().to_vec()
                } else {
                    source.der().to_vec()
                })?;
                material.private_key = source.private_key.clone().or_else(|| {
                    existing
                        .as_ref()
                        .and_then(|value| value.1.private_key.clone())
                });
                row = insert_material(&mut store, &material, &mut pending)?;
            } else if source.private_key.is_some() && store.objects.is_none() {
                store.memory.get_mut(&row).unwrap().key = source.private_key.clone();
            }
            write_properties(&store, row, &properties)?;
            Ok::<i64, ApiError>(row)
        })();
        let row = match transaction_result {
            Ok(row) => {
                commit_material_transaction(&store, pending)?;
                row
            }
            Err(error) => {
                return Err(rollback_material_transaction(&store, &mut pending, error));
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
    let secret = Zeroizing::new(if password.is_null() {
        String::new()
    } else {
        unsafe { wide_string(password) }?
    });
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
    let mut pending = PendingObjectDirectories::new();
    for context in certificates {
        if let Err(error) = insert_material(store, context, &mut pending) {
            return Err(rollback_material_transaction(store, &mut pending, error));
        }
    }
    commit_material_transaction(store, pending)
}

#[allow(clippy::vec_box)]
fn export_contexts(
    handle: HCERTSTORE,
    include_private_keys: bool,
) -> Result<Vec<Box<Context>>, ApiError> {
    let mut state = STATE.lock();
    let view_id = store_key(handle);
    let mut source_ids = vec![view_id];
    source_ids.extend(state.store(handle)?.inherited.clone());
    let mut contexts = Vec::new();
    for id in source_ids {
        let store = state.stores.get_mut(&id).unwrap();
        materialize(store, false)?;
        let rows = {
            let mut statement = store
                .db
                .prepare("SELECT id FROM certificates ORDER BY id")?;
            statement
                .query_map([], |row| row.get::<_, i64>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for row in rows {
            let mut context = load_context(store, row)?;
            if include_private_keys {
                load_private_key(&mut context)?;
            }
            contexts.push(context);
        }
    }
    require(
        !contexts.is_empty(),
        CRYPT_E_NOT_FOUND,
        "Certificate store is empty",
    )?;
    Ok(contexts)
}

fn encode_pfx(
    handle: HCERTSTORE,
    secret: &str,
    flags: DWORD,
) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    require(
        flags
            & !(REPORT_NO_PRIVATE_KEY
                | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
                | EXPORT_PRIVATE_KEYS)
            == 0,
        ERROR_NOT_SUPPORTED,
        "PKCS#12 export flags are unsupported",
    )?;
    let include_private_keys = flags
        & (REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | EXPORT_PRIVATE_KEYS)
        != 0;
    let contexts = export_contexts(handle, include_private_keys)?;
    let key_indices = contexts
        .iter()
        .enumerate()
        .filter_map(|(index, context)| context.private_key.as_ref().map(|_| index))
        .collect::<Vec<_>>();
    if flags & EXPORT_PRIVATE_KEYS != 0 {
        require(
            key_indices.len() == 1,
            if key_indices.is_empty() {
                CRYPT_E_NOT_FOUND
            } else {
                ERROR_NOT_SUPPORTED
            },
            if key_indices.is_empty() {
                "Certificate store contains no private key"
            } else {
                "PKCS#12 export with multiple private keys is unsupported"
            },
        )?;
    }

    let key_index = key_indices.first().copied();
    if let Some(key_index) = key_index
        && flags & EXPORT_PRIVATE_KEYS != 0
        && contexts[key_index].private_key.as_ref().unwrap().is_pqc()
    {
        let key = contexts[key_index].private_key.as_ref().unwrap();
        let key = PKey::private_key_from_der(key.to_der()).map_err(ApiError::from)?;
        let certificate = X509::from_der(contexts[key_index].der())?;
        let mut stack = Stack::new()?;
        for (index, issuer) in contexts.iter().enumerate() {
            if index != key_index {
                stack.push(X509::from_der(issuer.der())?)?;
            }
        }
        let mut builder = Pkcs12::builder();
        builder
            .pkey(&key)
            .cert(&certificate)
            .ca(stack)
            .key_algorithm(Nid::AES_256_CBC)
            .cert_algorithm(Nid::AES_256_CBC);
        let encoded = builder
            .build2(secret)
            .and_then(|pfx| pfx.to_der())
            .map_err(ApiError::from)?;
        return Ok(Zeroizing::new(encoded));
    }

    let mut keystore = KeyStore::new();
    if let Some(key_index) = key_index.filter(|_| flags & EXPORT_PRIVATE_KEYS != 0) {
        let ordered = std::iter::once(&contexts[key_index])
            .chain(
                contexts
                    .iter()
                    .enumerate()
                    .filter_map(|(index, context)| (index != key_index).then_some(context)),
            )
            .map(|context| P12Certificate::from_der(context.der()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ApiError::new(ERROR_GEN_FAILURE, error.to_string()))?;
        let key = contexts[key_index].private_key.as_ref().unwrap();
        let private_key = P12PrivateKey::from_der(key.to_der())
            .map_err(|error| ApiError::new(ERROR_GEN_FAILURE, error.to_string()))?;
        let chain = PrivateKeyChain::new(
            contexts[key_index].certificate.sha1_fingerprint(),
            private_key,
            ordered,
        );
        keystore.add_entry("sys-cert-store", KeyStoreEntry::PrivateKeyChain(chain));
    } else {
        for (index, context) in contexts.iter().enumerate() {
            let certificate = P12Certificate::from_der(context.der())
                .map_err(|error| ApiError::new(ERROR_GEN_FAILURE, error.to_string()))?;
            keystore.add_entry(
                &format!("certificate-{index}"),
                KeyStoreEntry::Certificate(certificate),
            );
        }
    }
    let encoded = keystore
        .writer(secret)
        .write()
        .map_err(|error| ApiError::new(ERROR_GEN_FAILURE, error.to_string()))?;
    Ok(Zeroizing::new(encoded))
}

pub fn GetLastError() -> DWORD {
    last_error()
}

pub fn SetLastError(error: DWORD) {
    set_error(error, "");
}

pub fn SysCertGetLastErrorMessage() -> *const c_char {
    message_ptr()
}

/// Converts a readable encoded string into binary data.
///
/// # Safety
///
/// `string` must identify the requested readable string, and non-null output
/// pointers must be writable for the capacities described by their arguments.
pub unsafe fn CryptStringToBinaryA(
    string: LPCSTR,
    string_length: DWORD,
    flags: DWORD,
    binary: *mut BYTE,
    binary_size: *mut DWORD,
    skipped: *mut DWORD,
    actual_flags: *mut DWORD,
) -> BOOL {
    boundary(FALSE, || {
        require(!string.is_null(), E_INVALIDARG, "Null encoded string")?;
        require(
            matches!(
                flags,
                CRYPT_STRING_BASE64HEADER
                    | CRYPT_STRING_BASE64
                    | CRYPT_STRING_BASE64_ANY
                    | CRYPT_STRING_ANY
            ),
            ERROR_NOT_SUPPORTED,
            "String encoding flags are unsupported",
        )?;
        let value = if string_length == 0 {
            unsafe { CStr::from_ptr(string) }
                .to_str()
                .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Encoded text is not UTF-8"))?
                .to_owned()
        } else {
            std::str::from_utf8(unsafe {
                std::slice::from_raw_parts(string.cast::<u8>(), string_length as usize)
            })
            .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Encoded text is not UTF-8"))?
            .to_owned()
        };
        let (payload, skip) = pem_payload(&value)?;
        let decoded = decode_base64(payload)?;
        if !skipped.is_null() {
            unsafe { *skipped = skip };
        }
        if !actual_flags.is_null() {
            unsafe {
                *actual_flags = if skip == 0 {
                    CRYPT_STRING_BASE64
                } else {
                    CRYPT_STRING_BASE64HEADER
                }
            };
        }
        copy_out(&decoded, binary.cast(), binary_size)?;
        Ok(TRUE)
    })
}

/// Converts readable binary data into a string.
///
/// # Safety
///
/// `binary` must be readable for `binary_size` bytes. `string_size` must be
/// writable, and a non-null `string` must cover the supplied capacity.
pub unsafe fn CryptBinaryToStringA(
    binary: *const BYTE,
    binary_size: DWORD,
    flags: DWORD,
    string: *mut c_char,
    string_size: *mut DWORD,
) -> BOOL {
    boundary(FALSE, || {
        require(
            flags == CRYPT_STRING_BASE64HEADER || flags == CRYPT_STRING_BASE64,
            ERROR_NOT_SUPPORTED,
            "Binary string encoding flags are unsupported",
        )?;
        require(!string_size.is_null(), E_INVALIDARG, "Null output size")?;
        let encoded = Base64::encode_string(&unsafe { bytes(binary, binary_size as usize) }?);
        let mut value = String::new();
        if flags == CRYPT_STRING_BASE64HEADER {
            value.push_str("-----BEGIN CERTIFICATE-----\n");
        }
        for line in encoded.as_bytes().chunks(64) {
            value.push_str(std::str::from_utf8(line).unwrap());
            value.push('\n');
        }
        if flags == CRYPT_STRING_BASE64HEADER {
            value.push_str("-----END CERTIFICATE-----\n");
        }
        let required = dword(value.len() + 1)?;
        let capacity = unsafe { *string_size };
        unsafe { *string_size = required };
        if string.is_null() {
            return Ok(TRUE);
        }
        require(
            capacity >= required,
            ERROR_MORE_DATA,
            "Output string buffer is too small",
        )?;
        unsafe {
            ptr::copy_nonoverlapping(value.as_ptr(), string.cast(), value.len());
            *string.add(value.len()) = 0;
        }
        Ok(TRUE)
    })
}

/// Formats an encoded certificate name.
///
/// # Safety
///
/// `name` must point to a live name blob whose data is readable. A non-null
/// `output` must be writable for `output_size` bytes.
pub unsafe fn CertNameToStrA(
    encoding: DWORD,
    name: *const CERT_NAME_BLOB,
    string_type: DWORD,
    output: *mut c_char,
    output_size: DWORD,
) -> DWORD {
    boundary(0, || {
        encoding_check(encoding)?;
        require(!name.is_null(), E_INVALIDARG, "Null encoded name")?;
        require(
            string_type & 0xff == CERT_X500_NAME_STR,
            ERROR_NOT_SUPPORTED,
            "Name string format is unsupported",
        )?;
        let data = blob_slice(unsafe { &*name })?;
        let (remaining, parsed) = NativeX509Name::from_der(data)
            .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid encoded name"))?;
        require(
            remaining.is_empty(),
            ERROR_INVALID_DATA,
            "Invalid encoded name or trailing bytes",
        )?;
        copy_string_a(&parsed.to_string(), output, output_size)
    })
}

/// Reads a formatted name from a live certificate context.
///
/// # Safety
///
/// `certificate` and any name-type-specific `type_parameter` must be valid for
/// the call. A non-null `output` must be writable for `output_size` bytes.
pub unsafe fn CertGetNameStringA(
    certificate: *const CERT_CONTEXT,
    name_type: DWORD,
    flags: DWORD,
    type_parameter: *const c_void,
    output: *mut c_char,
    output_size: DWORD,
) -> DWORD {
    boundary(0, || {
        require(
            name_type == CERT_NAME_RDN_TYPE || name_type == CERT_NAME_SIMPLE_DISPLAY_TYPE,
            ERROR_NOT_SUPPORTED,
            "Certificate name type is unsupported",
        )?;
        require(
            flags & !CERT_NAME_ISSUER_FLAG == 0 && type_parameter.is_null(),
            ERROR_NOT_SUPPORTED,
            "Certificate name options are unsupported",
        )?;
        let state = STATE.lock();
        let context = state.context(certificate)?;
        let value = Context::simple_name(&context.certificate, flags & CERT_NAME_ISSUER_FLAG == 0)?;
        copy_string_a(&value, output, output_size)
    })
}

/// Configures Linux system-store locations.
///
/// # Safety
///
/// A non-null configuration must point to a live structure and to valid
/// terminated strings for every populated field.
pub unsafe fn SysCertConfigureSystemStores(
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

/// Gets the configured location of a certificate context.
///
/// # Safety
///
/// The context must be live and produced by this API. The output pointer must
/// be writable when non-null.
pub unsafe fn SysCertGetCertificateStoreLocation(
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

/// Opens a certificate store through a provider-specific parameter.
///
/// # Safety
///
/// `provider` and `parameter` must satisfy the type, readability, termination,
/// and lifetime requirements of the selected provider.
pub unsafe fn CertOpenStore(
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

/// Opens a UTF-16 named system store.
///
/// # Safety
///
/// `name` must point to a readable, terminated UTF-16 string.
pub unsafe fn CertOpenSystemStoreW(legacy: HCRYPTPROV_LEGACY, name: LPCWSTR) -> HCERTSTORE {
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

/// Opens an ANSI named system store.
///
/// # Safety
///
/// `name` must point to a readable, terminated string.
pub unsafe fn CertOpenSystemStoreA(legacy: HCRYPTPROV_LEGACY, name: LPCSTR) -> HCERTSTORE {
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

pub fn CertDuplicateStore(handle: HCERTSTORE) -> HCERTSTORE {
    boundary(ptr::null_mut(), || {
        STATE.lock().store_mut(handle)?.references += 1;
        Ok(handle)
    })
}

pub fn CertCloseStore(handle: HCERTSTORE, flags: DWORD) -> BOOL {
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

/// Creates an owned certificate-context reference from encoded bytes.
///
/// # Safety
///
/// `encoded` must be readable for `size` bytes, unless the documented
/// zero-length null convention applies.
pub unsafe fn CertCreateCertificateContext(
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

/// Duplicates one live certificate-context reference.
///
/// # Safety
///
/// `context` must be null or a live context accepted by the current backend.
pub unsafe fn CertDuplicateCertificateContext(context: *const CERT_CONTEXT) -> *const CERT_CONTEXT {
    boundary(ptr::null(), || {
        STATE.lock().context_mut(context)?.references += 1;
        Ok(context)
    })
}

/// Releases one owned certificate-context reference.
///
/// # Safety
///
/// `context` must be null or one live owned reference returned by the current
/// backend, and that reference must not be used after this call.
pub unsafe fn CertFreeCertificateContext(context: *const CERT_CONTEXT) -> BOOL {
    boundary(FALSE, || {
        STATE.lock().release_context(context)?;
        Ok(TRUE)
    })
}

/// Advances certificate enumeration in a store.
///
/// # Safety
///
/// `previous` must be null or the live context returned by the preceding
/// enumeration call for `handle`. The call consumes that previous reference.
pub unsafe fn CertEnumCertificatesInStore(
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

/// Finds a certificate using type-specific search data.
///
/// # Safety
///
/// `parameter` must have the type and lifetime required by `kind`. `previous`
/// must be null or a live context from the same store and is consumed.
pub unsafe fn CertFindCertificateInStore(
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

/// Finds a subject certificate from certificate information.
///
/// # Safety
///
/// `information` must point to a live `CERT_INFO` whose nested pointers remain
/// readable for the call.
pub unsafe fn CertGetSubjectCertificateFromStore(
    handle: HCERTSTORE,
    encoding: DWORD,
    information: *mut CERT_INFO,
) -> *const CERT_CONTEXT {
    // SAFETY: this function's contract requires a live CERT_INFO, which is the
    // exact parameter type required by CERT_FIND_SUBJECT_CERT.
    unsafe {
        CertFindCertificateInStore(
            handle,
            encoding,
            0,
            CERT_FIND_SUBJECT_CERT,
            information.cast(),
            ptr::null(),
        )
    }
}

/// Finds an issuer for a live subject context.
///
/// # Safety
///
/// `subject` must be live. `previous` must be null or a live prior result and
/// is consumed. `flags` must be writable.
pub unsafe fn CertGetIssuerCertificateFromStore(
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

/// Adds a live certificate context to a store.
///
/// # Safety
///
/// `context` must be live. A non-null `result` must be writable and its
/// returned reference must later be released exactly once.
pub unsafe fn CertAddCertificateContextToStore(
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

/// Adds encoded certificate bytes to a store.
///
/// # Safety
///
/// `encoded` must be readable for `size` bytes. A non-null `result` must be
/// writable and its returned reference must later be released exactly once.
pub unsafe fn CertAddEncodedCertificateToStore(
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

/// Deletes a certificate and consumes its context reference.
///
/// # Safety
///
/// `context` must be one live owned store context and must not be used after
/// the call, whether deletion succeeds or fails according to backend rules.
pub unsafe fn CertDeleteCertificateFromStore(context: *const CERT_CONTEXT) -> BOOL {
    boundary(FALSE, || {
        delete_context(&mut STATE.lock(), context)?;
        Ok(TRUE)
    })
}

/// Reads a property from a live certificate context.
///
/// # Safety
///
/// `context` must be live, `size` must be writable, and a non-null `data`
/// buffer must cover the capacity supplied through `size`.
pub unsafe fn CertGetCertificateContextProperty(
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

/// Sets a property on a live certificate context.
///
/// # Safety
///
/// `context` must be live. A non-null `data` value must have the property-
/// specific type, readability, and lifetime required by `property`.
pub unsafe fn CertSetCertificateContextProperty(
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

/// Enumerates properties on a live certificate context.
///
/// # Safety
///
/// `context` must be a live context accepted by the current backend.
pub unsafe fn CertEnumCertificateContextProperties(
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

/// Reads a certificate-store property.
///
/// # Safety
///
/// `size` must be writable, and a non-null `data` buffer must cover the
/// capacity supplied through `size`.
pub unsafe fn CertGetStoreProperty(
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

/// Sets a certificate-store property.
///
/// # Safety
///
/// A non-null `data` value must have the property-specific type, readability,
/// and lifetime required by `property`.
pub unsafe fn CertSetStoreProperty(
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

/// Performs a provider-specific store control operation.
///
/// # Safety
///
/// `parameter` must have the type, readability, mutability, and lifetime
/// required by `control`.
pub unsafe fn CertControlStore(
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

/// Saves a certificate store to a caller-selected destination.
///
/// # Safety
///
/// `parameter` must identify writable destination storage of the type and
/// capacity required by `save_to`.
pub unsafe fn CertSaveStore(
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
                    certificates.push(load_context(store, row)?.der().to_vec());
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

#[repr(C)]
struct OwnedChain {
    public: CERT_CHAIN_CONTEXT,
    simple: Box<CERT_SIMPLE_CHAIN>,
    chain_pointers: Box<[*mut CERT_SIMPLE_CHAIN]>,
    elements: Box<[CERT_CHAIN_ELEMENT]>,
    element_pointers: Box<[*mut CERT_CHAIN_ELEMENT]>,
    contexts: Vec<*const CERT_CONTEXT>,
}

fn chain_candidates(
    state: &mut State,
    handle: HCERTSTORE,
) -> Result<Vec<crate::cert::Certificate>, ApiError> {
    if handle.is_null() {
        return Ok(Vec::new());
    }
    let view_id = store_key(handle);
    let mut source_ids = vec![view_id];
    source_ids.extend(state.store(handle)?.inherited.clone());
    let mut result = Vec::new();
    for id in source_ids {
        let store = state.stores.get_mut(&id).unwrap();
        materialize(store, false)?;
        let rows = {
            let mut statement = store
                .db
                .prepare("SELECT id FROM certificates ORDER BY id")?;
            statement
                .query_map([], |row| row.get::<_, i64>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for row in rows {
            result.push(load_context(store, row)?.certificate);
        }
    }
    Ok(result)
}

fn remove_temporary_store(state: &mut State, handle: HCERTSTORE) {
    if let Some(store) = state.stores.remove(&store_key(handle)) {
        for inherited in store.inherited {
            state.stores.remove(&inherited);
        }
    }
}

fn system_chain_candidates(
    state: &mut State,
    name: &str,
) -> Result<Vec<crate::cert::Certificate>, ApiError> {
    let handle = open_store(
        state,
        Provider::SystemW,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
        Some(name.to_owned()),
        None,
    )?;
    let result = chain_candidates(state, handle);
    remove_temporary_store(state, handle);
    result
}

fn insert_chain_candidates(
    destination: &mut BTreeMap<String, crate::cert::Certificate>,
    certificates: impl IntoIterator<Item = crate::cert::Certificate>,
) {
    for certificate in certificates {
        destination
            .entry(hex::encode(certificate.sha256_fingerprint()))
            .or_insert(certificate);
    }
}

fn chain_element_statuses(
    certificates: &[crate::cert::Certificate],
    trusted_roots: &HashSet<String>,
    invalid_signatures: &HashSet<usize>,
    partial: bool,
    cyclic: bool,
) -> Result<(Vec<CERT_TRUST_STATUS>, CERT_TRUST_STATUS), ApiError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ApiError::new(ERROR_GEN_FAILURE, "System time precedes the Unix epoch"))?
        .as_secs() as i64;
    let mut elements = vec![CERT_TRUST_STATUS::default(); certificates.len()];

    for (index, certificate) in certificates.iter().enumerate() {
        if now < certificate.not_before_timestamp()? || now > certificate.not_after_timestamp()? {
            elements[index].dwErrorStatus |= CERT_TRUST_IS_NOT_TIME_VALID;
        }
        if invalid_signatures.contains(&index) {
            elements[index].dwErrorStatus |= CERT_TRUST_IS_NOT_SIGNATURE_VALID;
        }
        if certificate.self_signed()? {
            elements[index].dwInfoStatus |= CERT_TRUST_IS_SELF_SIGNED;
        }
        if index == 0 {
            continue;
        }

        let constraints = certificate.basic_constraints()?;
        let is_ca = constraints.is_some_and(|(is_ca, _)| is_ca);
        if !is_ca {
            elements[index].dwErrorStatus |=
                CERT_TRUST_INVALID_BASIC_CONSTRAINTS | CERT_TRUST_IS_NOT_VALID_FOR_USAGE;
        }
        if certificate.key_usage_allows_certificate_signing()? == Some(false) {
            elements[index].dwErrorStatus |= CERT_TRUST_IS_NOT_VALID_FOR_USAGE;
        }
        if let Some((true, Some(limit))) = constraints {
            let mut subordinate_ca_count = 0;
            for subordinate in &certificates[1..index] {
                if subordinate.is_ca()? && subordinate.subject_raw()? != subordinate.issuer_raw()? {
                    subordinate_ca_count += 1;
                }
            }
            if subordinate_ca_count > limit as usize {
                elements[index].dwErrorStatus |= CERT_TRUST_INVALID_BASIC_CONSTRAINTS;
            }
        }
    }

    let mut chain = CERT_TRUST_STATUS::default();
    if partial {
        chain.dwErrorStatus |= CERT_TRUST_IS_PARTIAL_CHAIN;
    } else if cyclic {
        chain.dwErrorStatus |= CERT_TRUST_IS_CYCLIC;
    } else if let Some(root) = certificates.last()
        && root.self_signed()?
        && !trusted_roots.contains(&hex::encode(root.sha256_fingerprint()))
    {
        let root_status = elements.last_mut().unwrap();
        root_status.dwErrorStatus |= CERT_TRUST_IS_UNTRUSTED_ROOT;
    }
    for status in &elements {
        chain.dwErrorStatus |= status.dwErrorStatus;
        chain.dwInfoStatus |= status.dwInfoStatus;
    }
    Ok((elements, chain))
}

#[allow(clippy::too_many_arguments)]
/// Builds a chain for a live certificate context.
///
/// # Safety
///
/// All non-null input structures must be live with valid nested pointers.
/// `chain_context` must be writable, and its returned chain must be freed once.
pub unsafe fn CertGetCertificateChain(
    chain_engine: HCERTCHAINENGINE,
    certificate: *const CERT_CONTEXT,
    time: *const FILETIME,
    additional_store: HCERTSTORE,
    parameters: *const CERT_CHAIN_PARA,
    flags: DWORD,
    reserved: *mut c_void,
    chain_context: *mut *const CERT_CHAIN_CONTEXT,
) -> BOOL {
    boundary(FALSE, || {
        require(
            chain_engine.is_null()
                && time.is_null()
                && flags == 0
                && reserved.is_null()
                && !parameters.is_null()
                && !chain_context.is_null(),
            ERROR_NOT_SUPPORTED,
            "Only default offline certificate-chain construction is supported",
        )?;
        let parameters = unsafe { &*parameters };
        require(
            parameters.cbSize as usize == std::mem::size_of::<CERT_CHAIN_PARA>()
                && parameters.RequestedUsage.Usage.cUsageIdentifier == 0
                && parameters.RequestedIssuancePolicy.Usage.cUsageIdentifier == 0
                && parameters.dwUrlRetrievalTimeout == 0
                && parameters.fCheckRevocationFreshnessTime == FALSE
                && parameters.dwRevocationFreshnessTime == 0
                && parameters.pftCacheResync.is_null()
                && parameters.pStrongSignPara.is_null()
                && parameters.dwStrongSignFlags == 0,
            ERROR_NOT_SUPPORTED,
            "Certificate-chain parameters are unsupported",
        )?;

        let mut state = STATE.lock();
        let leaf = state.context(certificate)?.certificate.clone();
        let additional = chain_candidates(&mut state, additional_store)?;
        let roots = system_chain_candidates(&mut state, "ROOT")?;
        let trusted_roots = roots
            .iter()
            .map(|certificate| hex::encode(certificate.sha256_fingerprint()))
            .collect::<HashSet<_>>();
        let mut candidates = BTreeMap::new();
        insert_chain_candidates(&mut candidates, additional);
        insert_chain_candidates(&mut candidates, system_chain_candidates(&mut state, "CA")?);
        insert_chain_candidates(&mut candidates, roots);

        let mut certificates = vec![leaf.clone()];
        let mut seen = HashSet::from([hex::encode(leaf.sha256_fingerprint())]);
        let mut invalid_signatures = HashSet::new();
        let mut current = leaf;
        let mut partial = false;
        let mut cyclic = false;
        while !current.self_signed()? {
            let mut issuers = BTreeMap::new();
            let mut name_matches = BTreeMap::new();
            for candidate in candidates.values() {
                if candidate.subject_raw()? == current.issuer_raw()? {
                    let hash = hex::encode(candidate.sha256_fingerprint());
                    name_matches.insert(hash.clone(), candidate.clone());
                    if current.verify_with(candidate)? {
                        issuers.insert(hash, candidate.clone());
                    }
                }
            }
            let signature_valid = !issuers.is_empty();
            if !signature_valid {
                issuers = name_matches;
            }
            let Some((hash, issuer)) = issuers
                .iter()
                .find(|(hash, _)| trusted_roots.contains(*hash))
                .map(|(hash, issuer)| (hash.clone(), issuer.clone()))
                .or_else(|| issuers.pop_first())
            else {
                partial = true;
                break;
            };
            if !signature_valid {
                invalid_signatures.insert(certificates.len() - 1);
            }
            if !seen.insert(hash) {
                cyclic = true;
                break;
            }
            current = issuer.clone();
            certificates.push(issuer);
        }
        let (element_statuses, chain_status) = chain_element_statuses(
            &certificates,
            &trusted_roots,
            &invalid_signatures,
            partial,
            cyclic,
        )?;

        state.context_mut(certificate)?.references += 1;
        let mut context_pointers = vec![certificate];
        for issuer in certificates.iter().skip(1) {
            let context = Context::new(issuer.to_der())?;
            context_pointers.push(state.publish_context(context, None, 0, None));
        }
        drop(state);

        let mut elements = context_pointers
            .iter()
            .zip(element_statuses)
            .map(|(context, status)| CERT_CHAIN_ELEMENT {
                cbSize: std::mem::size_of::<CERT_CHAIN_ELEMENT>() as DWORD,
                pCertContext: *context,
                TrustStatus: status,
                ..CERT_CHAIN_ELEMENT::default()
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let mut element_pointers = elements
            .iter_mut()
            .map(|element| element as *mut CERT_CHAIN_ELEMENT)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let mut simple = Box::new(CERT_SIMPLE_CHAIN {
            cbSize: std::mem::size_of::<CERT_SIMPLE_CHAIN>() as DWORD,
            TrustStatus: chain_status,
            cElement: dword(element_pointers.len())?,
            rgpElement: element_pointers.as_mut_ptr(),
            ..CERT_SIMPLE_CHAIN::default()
        });
        let mut chain_pointers = vec![simple.as_mut() as *mut CERT_SIMPLE_CHAIN].into_boxed_slice();
        let public = CERT_CHAIN_CONTEXT {
            cbSize: std::mem::size_of::<CERT_CHAIN_CONTEXT>() as DWORD,
            TrustStatus: chain_status,
            cChain: 1,
            rgpChain: chain_pointers.as_mut_ptr(),
            ..CERT_CHAIN_CONTEXT::default()
        };
        let owned = Box::new(OwnedChain {
            public,
            simple,
            chain_pointers,
            elements,
            element_pointers,
            contexts: context_pointers,
        });
        let raw = Box::into_raw(owned);
        unsafe {
            *chain_context = &(*raw).public;
        }
        Ok(TRUE)
    })
}

/// Releases one certificate-chain allocation.
///
/// # Safety
///
/// `chain` must be null or the live chain returned by this backend. A non-null
/// chain must be freed exactly once and not accessed afterward.
pub unsafe fn CertFreeCertificateChain(chain: *const CERT_CHAIN_CONTEXT) {
    if chain.is_null() {
        return;
    }
    let owned = unsafe { Box::from_raw(chain.cast_mut().cast::<OwnedChain>()) };
    let mut state = STATE.lock();
    for context in &owned.contexts {
        let _ = state.release_context(*context);
    }
}

/// Verifies policy for a live certificate chain.
///
/// # Safety
///
/// `chain` and `parameters` must point to live structures with valid nested
/// pointers, and `status` must be writable.
pub unsafe fn CertVerifyCertificateChainPolicy(
    policy: LPCSTR,
    chain: *const CERT_CHAIN_CONTEXT,
    parameters: *const CERT_CHAIN_POLICY_PARA,
    status: *mut CERT_CHAIN_POLICY_STATUS,
) -> BOOL {
    boundary(FALSE, || {
        require(
            policy as usize == CERT_CHAIN_POLICY_BASE
                && !chain.is_null()
                && !parameters.is_null()
                && !status.is_null(),
            E_INVALIDARG,
            "Invalid certificate-chain policy arguments",
        )?;
        let parameters = unsafe { &*parameters };
        let status = unsafe { &mut *status };
        require(
            parameters.cbSize as usize == std::mem::size_of::<CERT_CHAIN_POLICY_PARA>()
                && parameters.dwFlags == 0
                && parameters.pvExtraPolicyPara.is_null()
                && status.cbSize as usize == std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>()
                && status.pvExtraPolicyStatus.is_null(),
            ERROR_NOT_SUPPORTED,
            "Certificate-chain policy options are unsupported",
        )?;
        let chain = unsafe { &*chain };
        let simple = unsafe { &**chain.rgpChain };
        let elements =
            unsafe { std::slice::from_raw_parts(simple.rgpElement, simple.cElement as usize) };
        let find_element = |flag| {
            elements
                .iter()
                .position(|element| unsafe { (**element).TrustStatus.dwErrorStatus & flag != 0 })
        };

        let errors = chain.TrustStatus.dwErrorStatus;
        let (error, element) = if errors & CERT_TRUST_IS_UNTRUSTED_ROOT != 0 {
            (
                CERT_E_UNTRUSTEDROOT,
                find_element(CERT_TRUST_IS_UNTRUSTED_ROOT).map(|index| index as i32),
            )
        } else if errors & (CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_IS_CYCLIC) != 0 {
            (CERT_E_CHAINING, None)
        } else if errors & CERT_TRUST_IS_NOT_TIME_VALID != 0 {
            (
                CERT_E_EXPIRED,
                find_element(CERT_TRUST_IS_NOT_TIME_VALID).map(|index| index as i32),
            )
        } else if errors & CERT_TRUST_IS_NOT_SIGNATURE_VALID != 0 {
            (
                TRUST_E_CERT_SIGNATURE,
                find_element(CERT_TRUST_IS_NOT_SIGNATURE_VALID).map(|index| index as i32),
            )
        } else if errors & CERT_TRUST_IS_NOT_VALID_FOR_USAGE != 0 {
            (
                CERT_E_WRONG_USAGE,
                find_element(CERT_TRUST_IS_NOT_VALID_FOR_USAGE).map(|index| index as i32),
            )
        } else if errors & CERT_TRUST_INVALID_BASIC_CONSTRAINTS != 0 {
            (
                TRUST_E_BASIC_CONSTRAINTS,
                find_element(CERT_TRUST_INVALID_BASIC_CONSTRAINTS).map(|index| index as i32),
            )
        } else {
            (ERROR_SUCCESS, None)
        };
        status.dwError = error;
        status.lChainIndex = if error == ERROR_SUCCESS { -1 } else { 0 };
        status.lElementIndex = element.unwrap_or(-1);
        Ok(TRUE)
    })
}

/// Updates native trust for a certificate.
///
/// # Safety
///
/// The certificate must be live, and a non-null options pointer must identify
/// a live options structure with valid nested data.
pub unsafe fn SysCertUpdateTrustAnchor(
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

/// Imports a readable PFX blob into a store.
///
/// # Safety
///
/// The blob and its data must be readable. A non-null password must be a
/// readable terminated UTF-16 string.
pub unsafe fn SysCertImportPfxToStore(
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

/// Imports a readable PFX blob as a certificate store.
///
/// # Safety
///
/// `pfx` and its data must be readable. A non-null password must be a readable
/// terminated UTF-16 string.
pub unsafe fn PFXImportCertStore(
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

/// Exports a certificate store into a PFX blob.
///
/// # Safety
///
/// `pfx` must be writable and any supplied data buffer must cover its stated
/// capacity. Password and parameter pointers must satisfy native requirements.
pub unsafe fn PFXExportCertStoreEx(
    handle: HCERTSTORE,
    pfx: *mut CRYPT_DATA_BLOB,
    password: LPCWSTR,
    parameter: *mut c_void,
    flags: DWORD,
) -> BOOL {
    boundary(FALSE, || {
        require(!pfx.is_null(), E_INVALIDARG, "Missing PKCS#12 output blob")?;
        require(
            parameter.is_null(),
            ERROR_NOT_SUPPORTED,
            "PKCS#12 export parameters are unsupported",
        )?;
        let secret = Zeroizing::new(if password.is_null() {
            String::new()
        } else {
            unsafe { wide_string(password) }?
        });
        let encoded = encode_pfx(handle, &secret, flags)?;
        let output = unsafe { &mut *pfx };
        copy_out(&encoded, output.pbData.cast(), &mut output.cbData)?;
        Ok(TRUE)
    })
}

/// Gets a persisted path for a live certificate context.
///
/// # Safety
///
/// The context must be live, `size` must be writable, and a non-null path
/// buffer must cover the capacity supplied through `size`.
pub unsafe fn SysCertGetCertificateFilePath(
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

/// Populates the .NET CRL cache for an optional account name.
///
/// # Safety
///
/// A non-null account name must point to a readable terminated string.
pub unsafe fn SysCertPopulateDotNetCrlCache(user_name: LPCSTR) -> BOOL {
    boundary(FALSE, || {
        let user_name = if user_name.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(user_name) })
        };
        let paths = STATE.lock().paths.clone();
        crl_cache::populate(user_name, &paths)?;
        Ok(TRUE)
    })
}

/// Enumerates system-store locations through a callback.
///
/// # Safety
///
/// `argument` and callback state must remain valid for the synchronous call.
/// The callback must obey its API contract for all values supplied to it.
pub unsafe fn CertEnumSystemStoreLocation(
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

/// Enumerates system stores through a callback.
///
/// # Safety
///
/// Location data, `argument`, and callback state must remain valid for the
/// synchronous call. The callback must obey its API contract.
///
/// Store names are snapshotted before the first callback. Changes made by a
/// callback are visible to later enumeration calls, not the current call.
pub unsafe fn CertEnumSystemStore(
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
        let paths = STATE.lock().paths.clone();
        let directory = if flags == CERT_SYSTEM_STORE_CURRENT_USER {
            user_data_directory(&paths)?
        } else {
            paths.machine
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
        let information = CERT_SYSTEM_STORE_INFO {
            cbSize: std::mem::size_of::<CERT_SYSTEM_STORE_INFO>() as DWORD,
        };
        for name in names {
            let mut wide = name.encode_utf16().collect::<Vec<_>>();
            wide.push(0);
            if unsafe {
                callback(
                    wide.as_ptr().cast(),
                    flags,
                    &information,
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
        // SAFETY: `der` remains readable for its reported length.
        let context = unsafe {
            CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), der.len() as DWORD)
        };
        assert!(!context.is_null());
        // SAFETY: the memory provider uses no provider parameter.
        let store = unsafe { CertOpenStore(PROVIDER_MEMORY as LPCSTR, 0, 0, 0, ptr::null()) };
        assert!(!store.is_null());
        // SAFETY: `context` is live and no returned context is requested.
        assert_eq!(
            unsafe {
                CertAddCertificateContextToStore(
                    store,
                    context,
                    CERT_STORE_ADD_NEW,
                    ptr::null_mut(),
                )
            },
            TRUE
        );
        // SAFETY: the store is live and this starts a new enumeration.
        let found = unsafe { CertEnumCertificatesInStore(store, ptr::null()) };
        assert!(!found.is_null());
        assert_eq!(unsafe { (*found).cbCertEncoded }, der.len() as DWORD);
        // SAFETY: both pointers are distinct live owned context references.
        assert_eq!(unsafe { CertFreeCertificateContext(found) }, TRUE);
        // SAFETY: `context` is the original live owned reference.
        assert_eq!(unsafe { CertFreeCertificateContext(context) }, TRUE);
        assert_eq!(CertCloseStore(store, 0), TRUE);
    }
}
