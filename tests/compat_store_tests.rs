#![cfg(target_os = "linux")]

#[cfg(scs_bundled_crypto)]
use foreign_types_shared::ForeignType;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
#[cfg(scs_bundled_crypto)]
use openssl::pkey_ctx::PkeyCtx;
use openssl::stack::Stack;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509, X509Extension, X509NameBuilder};
#[cfg(scs_bundled_crypto)]
use p12_keystore::{
    Certificate as P12Certificate, KeyStore, KeyStoreEntry, PrivateKey as P12PrivateKey,
    PrivateKeyChain,
};
use rusqlite::Connection;
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::{LazyLock, Mutex, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sys_cert_store::api_types::*;
use sys_cert_store::*;
use tempfile::TempDir;

static API_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

const PQC_ALGORITHMS: [&str; 7] = [
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "MLDSA44-ECDSA-P256-SHA256",
    "MLDSA65-ECDSA-P256-SHA512",
    "MLDSA65-ECDSA-P384-SHA512",
    "MLDSA87-ECDSA-P384-SHA512",
];

#[cfg(scs_bundled_crypto)]
unsafe extern "C" {
    fn scs_initialize_crypto() -> bool;
}

fn api_lock() -> std::sync::MutexGuard<'static, ()> {
    API_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn last_error() -> DWORD {
    GetLastError()
}

fn last_message() -> String {
    unsafe {
        CStr::from_ptr(SysCertGetLastErrorMessage())
            .to_string_lossy()
            .into_owned()
    }
}

fn assert_ok(value: BOOL) {
    assert_ne!(value, FALSE, "{}: {}", last_error(), last_message());
}

fn cstring(path: impl AsRef<Path>) -> CString {
    CString::new(path.as_ref().as_os_str().as_encoded_bytes()).unwrap()
}

fn wide(value: &str) -> Vec<WCHAR> {
    value.encode_utf16().chain([0]).collect()
}

fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

#[cfg(scs_bundled_crypto)]
fn provider_key(algorithm: &str) -> PKey<Private> {
    let algorithm_name = CString::new(algorithm).unwrap();
    let context = unsafe {
        openssl_sys::EVP_PKEY_CTX_new_from_name(
            ptr::null_mut(),
            algorithm_name.as_ptr(),
            ptr::null(),
        )
    };
    assert!(
        !context.is_null(),
        "bundled provider does not advertise {algorithm}: {}",
        openssl::error::ErrorStack::get()
    );
    let mut context = unsafe { PkeyCtx::<Private>::from_ptr(context) };
    context
        .keygen_init()
        .unwrap_or_else(|error| panic!("cannot initialize {algorithm} key generation: {error}"));
    context
        .keygen()
        .unwrap_or_else(|error| panic!("cannot generate {algorithm} key: {error}"))
}

#[cfg(scs_bundled_crypto)]
fn pqc_certificate(key: &PKey<Private>, serial: u32, common_name: &str) -> X509 {
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let serial = Asn1Integer::from_bn(&BigNum::from_u32(serial).unwrap()).unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.set_pubkey(key).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .unwrap();
    let name = name.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    let certificate = builder.build();
    assert!(
        unsafe { openssl_sys::X509_sign(certificate.as_ptr(), key.as_ptr(), ptr::null()) } > 0,
        "cannot issue {common_name}: {}",
        openssl::error::ErrorStack::get()
    );
    certificate
}

#[cfg(scs_bundled_crypto)]
fn pqc_pfx(key: &PKey<Private>, certificate: &X509, password: &str) -> Vec<u8> {
    let certificate_der = certificate.to_der().unwrap();
    let certificate = P12Certificate::from_der(&certificate_der).unwrap();
    let private_key = P12PrivateKey::from_der(&key.private_key_to_pkcs8().unwrap()).unwrap();
    let chain = PrivateKeyChain::new(
        sys_cert_store::cert::Certificate::from_der(&certificate_der)
            .unwrap()
            .sha1_fingerprint(),
        private_key,
        vec![certificate],
    );
    let mut keystore = KeyStore::new();
    keystore.add_entry("sys-cert-store-r09", KeyStoreEntry::PrivateKeyChain(chain));
    keystore.writer(password).write().unwrap()
}

fn certificate(
    subject_key: &PKey<Private>,
    serial: u32,
    common_name: &str,
    ca: bool,
    issuer: Option<(&X509, &PKey<Private>)>,
    not_before_offset: i64,
    crl_url: Option<&str>,
) -> X509 {
    certificate_with_options(
        subject_key,
        serial,
        common_name,
        ca,
        None,
        None,
        issuer,
        not_before_offset,
        86_400,
        crl_url,
    )
}

#[allow(clippy::too_many_arguments)]
fn certificate_with_options(
    subject_key: &PKey<Private>,
    serial: u32,
    common_name: &str,
    ca: bool,
    path_length: Option<u32>,
    key_cert_sign: Option<bool>,
    issuer: Option<(&X509, &PKey<Private>)>,
    not_before_offset: i64,
    not_after_offset: i64,
    crl_url: Option<&str>,
) -> X509 {
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let serial = Asn1Integer::from_bn(&BigNum::from_u32(serial).unwrap()).unwrap();
    builder.set_serial_number(&serial).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let not_before = Asn1Time::from_unix(now + not_before_offset).unwrap();
    let not_after = Asn1Time::from_unix(now + not_after_offset).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    builder.set_pubkey(subject_key).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .unwrap();
    let name = name.build();
    builder.set_subject_name(&name).unwrap();
    builder
        .set_issuer_name(issuer.map_or(name.as_ref(), |value| value.0.subject_name()))
        .unwrap();
    let constraints = if ca {
        let mut constraints = BasicConstraints::new();
        constraints.critical().ca();
        if let Some(path_length) = path_length {
            constraints.pathlen(path_length);
        }
        constraints.build().unwrap()
    } else {
        BasicConstraints::new().critical().build().unwrap()
    };
    builder.append_extension(constraints).unwrap();
    if let Some(key_cert_sign) = key_cert_sign {
        let mut usage = KeyUsage::new();
        usage.critical();
        if key_cert_sign {
            usage.key_cert_sign().crl_sign();
        } else {
            usage.digital_signature();
        }
        builder.append_extension(usage.build().unwrap()).unwrap();
    }
    if let Some(url) = crl_url {
        let context = builder.x509v3_context(issuer.map(|value| value.0.as_ref()), None);
        #[allow(deprecated)]
        let extension = X509Extension::new_nid(
            None,
            Some(&context),
            Nid::CRL_DISTRIBUTION_POINTS,
            &format!("URI:{url}"),
        )
        .unwrap();
        builder.append_extension(extension).unwrap();
    }
    builder
        .sign(
            issuer.map_or(subject_key, |value| value.1),
            MessageDigest::sha256(),
        )
        .unwrap();
    builder.build()
}

struct Store(HCERTSTORE);

impl Store {
    fn memory() -> Self {
        // SAFETY: the memory provider accepts a null provider parameter.
        Self::new(unsafe { CertOpenStore(PROVIDER_MEMORY as LPCSTR, 0, 0, 0, ptr::null()) })
    }

    fn sqlite(path: &Path, flags: DWORD) -> Self {
        let provider = CString::new("SysCertSQLite").unwrap();
        let path = cstring(path);
        // SAFETY: the provider and path are live terminated C strings.
        Self::new(unsafe { CertOpenStore(provider.as_ptr(), 0, 0, flags, path.as_ptr().cast()) })
    }

    fn scoped(name: &str, scope: DWORD, flags: DWORD) -> Self {
        let name = wide(name);
        // SAFETY: the provider constant is valid and `name` is live,
        // terminated UTF-16.
        Self::new(unsafe {
            CertOpenStore(
                PROVIDER_SYSTEM_W as LPCSTR,
                0,
                0,
                scope | flags,
                name.as_ptr().cast(),
            )
        })
    }

    fn new(handle: HCERTSTORE) -> Self {
        assert!(!handle.is_null(), "{}: {}", last_error(), last_message());
        Self(handle)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        if !self.0.is_null() {
            assert_ok(CertCloseStore(self.0, 0));
        }
    }
}

struct Context(*const CERT_CONTEXT);

impl Context {
    fn from_x509(certificate: &X509) -> Self {
        Self::from_der(&certificate.to_der().unwrap())
    }

    fn from_der(der: &[u8]) -> Self {
        // SAFETY: `der` is readable for its reported length.
        let value = unsafe {
            CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), der.len() as DWORD)
        };
        assert!(!value.is_null(), "{}: {}", last_error(), last_message());
        Self(value)
    }

    fn add(store: &Store, source: &Context, disposition: DWORD) -> Self {
        let mut result = ptr::null();
        // SAFETY: the store and source are live and `result` is writable.
        assert_ok(unsafe {
            CertAddCertificateContextToStore(store.0, source.0, disposition, &mut result)
        });
        Self(result)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper owns one live context reference.
            assert_ok(unsafe { CertFreeCertificateContext(self.0) });
        }
    }
}

fn count(store: &Store) -> usize {
    let mut count = 0;
    let mut previous = ptr::null();
    loop {
        // SAFETY: the store is live and `previous` is null or the preceding
        // enumeration result, which this call consumes.
        let current = unsafe { CertEnumCertificatesInStore(store.0, previous) };
        if current.is_null() {
            assert_eq!(last_error(), CRYPT_E_NOT_FOUND);
            return count;
        }
        count += 1;
        previous = current;
    }
}

fn property(context: &Context, id: DWORD) -> Vec<u8> {
    let mut size = 0;
    // SAFETY: the context is live and null output requests the required size.
    assert_ok(unsafe {
        CertGetCertificateContextProperty(context.0, id, ptr::null_mut(), &mut size)
    });
    let mut value = vec![0; size as usize];
    // SAFETY: the context is live and `value` is writable for `size` bytes.
    assert_ok(unsafe {
        CertGetCertificateContextProperty(context.0, id, value.as_mut_ptr().cast(), &mut size)
    });
    value
}

fn set_property(context: &Context, id: DWORD, value: &[u8]) {
    let blob = CRYPT_DATA_BLOB {
        cbData: value.len() as DWORD,
        pbData: value.as_ptr().cast_mut(),
    };
    // SAFETY: the context and blob remain live for the synchronous call.
    assert_ok(unsafe {
        CertSetCertificateContextProperty(
            context.0,
            id,
            0,
            (&blob as *const CRYPT_DATA_BLOB).cast(),
        )
    });
}

fn material_path(context: &Context, private_key: BOOL) -> PathBuf {
    let mut size = 0;
    // SAFETY: the context is live and null output requests the required size.
    assert_ok(unsafe {
        SysCertGetCertificateFilePath(context.0, private_key, ptr::null_mut(), &mut size)
    });
    let mut bytes = vec![0u8; size as usize];
    // SAFETY: the context is live and `bytes` is writable for `size` bytes.
    assert_ok(unsafe {
        SysCertGetCertificateFilePath(context.0, private_key, bytes.as_mut_ptr().cast(), &mut size)
    });
    bytes.pop();
    PathBuf::from(String::from_utf8(bytes).unwrap())
}

fn build_chain(context: &Context, additional: Option<&Store>) -> *const CERT_CHAIN_CONTEXT {
    let parameters = CERT_CHAIN_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as DWORD,
        ..CERT_CHAIN_PARA::default()
    };
    let mut chain = ptr::null();
    // SAFETY: the context, optional store, parameters, and output slot remain
    // live for the synchronous chain build.
    assert_ok(unsafe {
        CertGetCertificateChain(
            ptr::null_mut(),
            context.0,
            ptr::null(),
            additional.map_or(ptr::null_mut(), |store| store.0),
            &parameters,
            0,
            ptr::null_mut(),
            &mut chain,
        )
    });
    assert!(!chain.is_null());
    chain
}

fn verify_base_policy(chain: *const CERT_CHAIN_CONTEXT) -> CERT_CHAIN_POLICY_STATUS {
    let parameters = CERT_CHAIN_POLICY_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as DWORD,
        ..CERT_CHAIN_POLICY_PARA::default()
    };
    let mut status = CERT_CHAIN_POLICY_STATUS {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as DWORD,
        ..CERT_CHAIN_POLICY_STATUS::default()
    };
    // SAFETY: the chain and initialized policy input/output structures remain
    // live for the synchronous policy check.
    assert_ok(unsafe {
        CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_BASE as LPCSTR,
            chain,
            &parameters,
            &mut status,
        )
    });
    status
}

fn free_chain(chain: *const CERT_CHAIN_CONTEXT) {
    // SAFETY: each helper caller transfers one live chain exactly once.
    unsafe { CertFreeCertificateChain(chain) };
}

unsafe extern "system" fn open_store_during_enumeration(
    _: *const std::ffi::c_void,
    _: DWORD,
    _: *const CERT_SYSTEM_STORE_INFO,
    _: *const std::ffi::c_void,
    argument: *mut std::ffi::c_void,
) -> BOOL {
    // SAFETY: the test passes a live `usize` as the callback argument.
    unsafe { *argument.cast::<usize>() += 1 };
    // SAFETY: the memory provider accepts a null provider parameter.
    let store = unsafe { CertOpenStore(PROVIDER_MEMORY as LPCSTR, 0, 0, 0, ptr::null()) };
    if store.is_null() {
        return FALSE;
    }
    CertCloseStore(store, 0)
}

#[test]
fn memory_stores_dispositions_and_api_errors() {
    let _guard = api_lock();
    let signer = key();
    let root = certificate(&signer, 0x1234, "Memory Root", true, None, -3600, None);
    let newer = certificate(&signer, 0x1234, "Memory Root", true, None, -60, None);
    let source = Context::from_x509(&root);

    let store = Store::memory();
    let added = Context::add(&store, &source, CERT_STORE_ADD_NEW);
    assert_ne!(added.0, source.0);
    assert_eq!(count(&store), 1);
    let hash = property(&added, CERT_SHA256_HASH_PROP_ID);
    assert_eq!(hash.len(), 32);
    set_property(&added, CERT_FIRST_USER_PROP_ID, &[1, 2, 3]);
    assert_eq!(property(&added, CERT_FIRST_USER_PROP_ID), [1, 2, 3]);

    let mut short_size = 1;
    let mut sentinel = 0x5a_u8;
    assert_eq!(
        // SAFETY: the context is live and the one-byte output buffer matches
        // the supplied initial size.
        unsafe {
            CertGetCertificateContextProperty(
                added.0,
                CERT_SHA256_HASH_PROP_ID,
                (&mut sentinel as *mut u8).cast(),
                &mut short_size,
            )
        },
        FALSE
    );
    assert_eq!(
        (last_error(), short_size, sentinel),
        (ERROR_MORE_DATA, 32, 0x5a)
    );

    assert_eq!(
        // SAFETY: the store and source are live; no returned context is
        // requested.
        unsafe {
            CertAddCertificateContextToStore(store.0, source.0, CERT_STORE_ADD_NEW, ptr::null_mut())
        },
        FALSE
    );
    assert_eq!(last_error(), CRYPT_E_EXISTS);
    // SAFETY: a zero length permits a null input pointer.
    assert!(unsafe { CertCreateCertificateContext(0, ptr::null(), 0) }.is_null());
    assert_eq!(last_error(), ERROR_NOT_SUPPORTED);
    assert_eq!(CertCloseStore(ptr::null_mut(), 0), FALSE);
    assert_eq!(last_error(), ERROR_INVALID_HANDLE);

    for disposition in CERT_STORE_ADD_NEW..=CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES {
        let store = Store::memory();
        let old = Context::from_x509(&root);
        let new = Context::from_x509(&newer);
        set_property(&old, CERT_FIRST_USER_PROP_ID, &[1]);
        set_property(&new, CERT_FIRST_USER_PROP_ID + 1, &[2]);
        let original = Context::add(&store, &old, CERT_STORE_ADD_ALWAYS);
        if disposition == CERT_STORE_ADD_NEW {
            assert_eq!(
                // SAFETY: the store and source are live; no returned context
                // is requested.
                unsafe {
                    CertAddCertificateContextToStore(store.0, new.0, disposition, ptr::null_mut())
                },
                FALSE
            );
            assert_eq!(last_error(), CRYPT_E_EXISTS);
            continue;
        }
        let result = Context::add(&store, &new, disposition);
        assert_eq!(
            count(&store),
            if disposition == CERT_STORE_ADD_ALWAYS {
                2
            } else {
                1
            }
        );
        assert_eq!(property(&result, CERT_FIRST_USER_PROP_ID + 1), [2]);
        if matches!(
            disposition,
            CERT_STORE_ADD_USE_EXISTING
                | CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES
                | CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES
        ) {
            assert_eq!(property(&result, CERT_FIRST_USER_PROP_ID), [1]);
        }
        drop(original);
    }
}

#[test]
fn persistent_store_round_trip_and_static_rust_calls() {
    let _guard = api_lock();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("persistent.db");
    let signer = key();
    let cert = certificate(&signer, 7, "Persistent", true, None, -60, None);
    let source = Context::from_x509(&cert);
    {
        let store = Store::sqlite(&path, CERT_STORE_CREATE_NEW_FLAG);
        let added = Context::add(&store, &source, CERT_STORE_ADD_ALWAYS);
        set_property(&added, CERT_FIRST_USER_PROP_ID, &[9, 8, 7]);
        assert_eq!(
            fs::read_to_string(material_path(&added, FALSE)).unwrap(),
            cert.to_pem()
                .map(|v| String::from_utf8(v).unwrap())
                .unwrap()
        );
        // SAFETY: the store is live and this control code accepts null data.
        assert_ok(unsafe { CertControlStore(store.0, 0, CERT_STORE_CTRL_COMMIT, ptr::null()) });
    }
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    {
        let store = Store::sqlite(&path, CERT_STORE_OPEN_EXISTING_FLAG);
        // SAFETY: the store is live and null starts a new enumeration.
        let raw = unsafe { CertEnumCertificatesInStore(store.0, ptr::null()) };
        assert!(!raw.is_null());
        let cert = Context(raw);
        assert_eq!(property(&cert, CERT_FIRST_USER_PROP_ID), [9, 8, 7]);
        assert_eq!(unsafe { (*cert.0).cbCertEncoded as usize }, unsafe {
            std::slice::from_raw_parts((*cert.0).pbCertEncoded, (*cert.0).cbCertEncoded as usize)
                .len()
        });
    }
    assert!(!Store::sqlite(&path, CERT_STORE_READONLY_FLAG).0.is_null());
    let missing = temp.path().join("missing.db");
    let provider = CString::new("SysCertSQLite").unwrap();
    let missing_c = cstring(&missing);
    assert!(
        // SAFETY: the provider and missing path are live terminated C strings.
        unsafe {
            CertOpenStore(
                provider.as_ptr(),
                0,
                0,
                CERT_STORE_OPEN_EXISTING_FLAG,
                missing_c.as_ptr().cast(),
            )
        }
        .is_null()
    );
    assert_eq!(last_error(), ERROR_FILE_NOT_FOUND);
}

#[test]
fn pfx_import_and_private_material() {
    let _guard = api_lock();
    let temp = TempDir::new().unwrap();
    let issuer_key = key();
    let issuer = certificate(&issuer_key, 1, "PFX CA", true, None, -60, None);
    let leaf_key = key();
    let leaf = certificate(
        &leaf_key,
        2,
        "PFX leaf",
        false,
        Some((&issuer, &issuer_key)),
        -60,
        None,
    );
    let mut chain = Stack::new().unwrap();
    chain.push(issuer.clone()).unwrap();
    let mut builder = Pkcs12::builder();
    builder.name("test");
    builder.pkey(&leaf_key);
    builder.cert(&leaf);
    builder.ca(chain);
    let pfx = builder.build2("password").unwrap().to_der().unwrap();
    let blob = CRYPT_DATA_BLOB {
        cbData: pfx.len() as DWORD,
        pbData: pfx.as_ptr().cast_mut(),
    };
    let password = wide("password");
    let wrong = wide("wrong");
    let store = Store::sqlite(&temp.path().join("MY.db"), 0);
    assert_eq!(
        // SAFETY: the store, PFX blob, and terminated password are live.
        unsafe { SysCertImportPfxToStore(store.0, &blob, wrong.as_ptr(), 0) },
        FALSE
    );
    assert_eq!(last_error(), ERROR_INVALID_DATA);
    // SAFETY: the store, PFX blob, and terminated password are live.
    assert_ok(unsafe { SysCertImportPfxToStore(store.0, &blob, password.as_ptr(), 0) });
    assert_eq!(count(&store), 2);
    let subject = wide("PFX leaf");
    // SAFETY: the store and terminated UTF-16 subject are live; null starts a
    // new search.
    let raw = unsafe {
        CertFindCertificateInStore(
            store.0,
            X509_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR_W,
            subject.as_ptr().cast(),
            ptr::null(),
        )
    };
    let leaf_context = Context(raw);
    let cert_path = material_path(&leaf_context, FALSE);
    let key_path = material_path(&leaf_context, TRUE);
    assert!(cert_path.is_file() && key_path.is_file());
    assert_eq!(fs::metadata(&key_path).unwrap().mode() & 0o777, 0o600);
    let recovered = PKey::private_key_from_pem(&fs::read(&key_path).unwrap()).unwrap();
    assert!(recovered.public_eq(&leaf_key));

    // SAFETY: the context is live and null output requests the required size.
    let name_size = unsafe {
        CertGetNameStringA(
            leaf_context.0,
            CERT_NAME_RDN_TYPE,
            0,
            ptr::null(),
            ptr::null_mut(),
            0,
        )
    };
    assert!(name_size > 1);
    let mut name = vec![libc::c_char::default(); name_size as usize];
    assert_eq!(
        // SAFETY: the context is live and `name` is writable for `name_size`
        // elements.
        unsafe {
            CertGetNameStringA(
                leaf_context.0,
                CERT_NAME_RDN_TYPE,
                0,
                ptr::null(),
                name.as_mut_ptr(),
                name_size,
            )
        },
        name_size
    );
    assert!(
        unsafe { CStr::from_ptr(name.as_ptr()) }
            .to_string_lossy()
            .contains("PFX leaf")
    );

    let parameters = CERT_CHAIN_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as DWORD,
        ..CERT_CHAIN_PARA::default()
    };
    let mut chain_context = ptr::null();
    // SAFETY: all input objects and the output slot remain live for the call.
    assert_ok(unsafe {
        CertGetCertificateChain(
            ptr::null_mut(),
            leaf_context.0,
            ptr::null(),
            store.0,
            &parameters,
            0,
            ptr::null_mut(),
            &mut chain_context,
        )
    });
    assert!(!chain_context.is_null());
    unsafe {
        assert_eq!((*chain_context).cChain, 1);
        assert_eq!((**(*chain_context).rgpChain).cElement, 2);
    }
    let policy_parameters = CERT_CHAIN_POLICY_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as DWORD,
        ..CERT_CHAIN_POLICY_PARA::default()
    };
    let mut policy_status = CERT_CHAIN_POLICY_STATUS {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as DWORD,
        ..CERT_CHAIN_POLICY_STATUS::default()
    };
    // SAFETY: the chain and initialized policy input/output structures are
    // live.
    assert_ok(unsafe {
        CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_BASE as LPCSTR,
            chain_context,
            &policy_parameters,
            &mut policy_status,
        )
    });
    assert_eq!(policy_status.dwError, CERT_E_UNTRUSTEDROOT);
    assert_eq!(policy_status.lChainIndex, 0);
    assert_eq!(policy_status.lElementIndex, 1);
    // SAFETY: `chain_context` is the live allocation returned above.
    unsafe { CertFreeCertificateChain(chain_context) };

    let mut exported = CRYPT_DATA_BLOB::default();
    // SAFETY: the store, output blob, and terminated password are live; null
    // blob data requests the required size.
    assert_ok(unsafe {
        PFXExportCertStoreEx(
            store.0,
            &mut exported,
            password.as_ptr(),
            ptr::null_mut(),
            EXPORT_PRIVATE_KEYS,
        )
    });
    let mut exported_bytes = vec![0u8; exported.cbData as usize];
    exported.pbData = exported_bytes.as_mut_ptr();
    // SAFETY: the blob describes the writable `exported_bytes` buffer.
    assert_ok(unsafe {
        PFXExportCertStoreEx(
            store.0,
            &mut exported,
            password.as_ptr(),
            ptr::null_mut(),
            EXPORT_PRIVATE_KEYS,
        )
    });
    let exported_pfx = Pkcs12::from_der(&exported_bytes).unwrap();
    let exported_material = exported_pfx.parse2("password").unwrap();
    assert!(exported_material.pkey.unwrap().public_eq(&leaf_key));
    assert_eq!(exported_material.ca.unwrap().len(), 1);

    fs::write(&key_path, b"corrupted private key").unwrap();
    let mut certificate_only = CRYPT_DATA_BLOB::default();
    // SAFETY: the store, output blob, and terminated password are live; null
    // blob data requests the required size.
    assert_ok(unsafe {
        PFXExportCertStoreEx(
            store.0,
            &mut certificate_only,
            password.as_ptr(),
            ptr::null_mut(),
            0,
        )
    });
    let mut certificate_only_bytes = vec![0u8; certificate_only.cbData as usize];
    certificate_only.pbData = certificate_only_bytes.as_mut_ptr();
    // SAFETY: the blob describes the writable certificate-only output buffer.
    assert_ok(unsafe {
        PFXExportCertStoreEx(
            store.0,
            &mut certificate_only,
            password.as_ptr(),
            ptr::null_mut(),
            0,
        )
    });
    let certificate_only_pfx = Pkcs12::from_der(&certificate_only_bytes)
        .unwrap()
        .parse2("password")
        .unwrap();
    assert!(certificate_only_pfx.pkey.is_none());
    assert_eq!(certificate_only_pfx.ca.unwrap().len(), 2);

    let mut reported = CRYPT_DATA_BLOB::default();
    // SAFETY: the store, output blob, and terminated password are live.
    assert_eq!(
        unsafe {
            PFXExportCertStoreEx(
                store.0,
                &mut reported,
                password.as_ptr(),
                ptr::null_mut(),
                REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY,
            )
        },
        FALSE
    );
    assert_eq!(last_error(), ERROR_INVALID_DATA);

    let mut pkcs7 = CRYPT_DATA_BLOB::default();
    // SAFETY: the store and writable blob are live; null blob data requests
    // the required size.
    assert_ok(unsafe {
        CertSaveStore(
            store.0,
            PKCS_7_ASN_ENCODING,
            CERT_STORE_SAVE_AS_PKCS7,
            CERT_STORE_SAVE_TO_MEMORY,
            (&mut pkcs7 as *mut CRYPT_DATA_BLOB).cast(),
            0,
        )
    });
    let mut pkcs7_bytes = vec![0u8; pkcs7.cbData as usize];
    pkcs7.pbData = pkcs7_bytes.as_mut_ptr();
    // SAFETY: the blob describes the writable `pkcs7_bytes` buffer.
    assert_ok(unsafe {
        CertSaveStore(
            store.0,
            PKCS_7_ASN_ENCODING,
            CERT_STORE_SAVE_AS_PKCS7,
            CERT_STORE_SAVE_TO_MEMORY,
            (&mut pkcs7 as *mut CRYPT_DATA_BLOB).cast(),
            0,
        )
    });
    // SAFETY: `pkcs7` describes the live encoded buffer.
    let pkcs7_store = Store::new(unsafe {
        CertOpenStore(
            PROVIDER_PKCS7 as LPCSTR,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_STORE_READONLY_FLAG,
            (&pkcs7 as *const CRYPT_DATA_BLOB).cast(),
        )
    });
    assert_eq!(count(&pkcs7_store), 2);
}

#[test]
fn failed_material_insertions_remove_new_objects() {
    let _guard = api_lock();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("rollback.db");
    let objects = PathBuf::from(format!("{}.objects", path.display()));
    let store = Store::sqlite(&path, 0);
    let database = Connection::open(&path).unwrap();
    database
        .execute_batch(
            "CREATE TRIGGER fail_certificate_insert
             BEFORE INSERT ON certificates
             BEGIN
                 SELECT RAISE(FAIL, 'injected certificate insertion failure');
             END;",
        )
        .unwrap();

    let standalone = certificate(&key(), 1, "Rollback", false, None, -60, None);
    let source = Context::from_x509(&standalone);
    let mut added = ptr::null();
    // SAFETY: the store, source context, and output slot are live.
    assert_eq!(
        unsafe {
            CertAddCertificateContextToStore(store.0, source.0, CERT_STORE_ADD_ALWAYS, &mut added)
        },
        FALSE
    );
    assert!(added.is_null());
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM certificates", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM garbage", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(fs::read_dir(&objects).unwrap().count(), 0);

    database
        .execute_batch(
            "DROP TRIGGER fail_certificate_insert;
             CREATE TRIGGER fail_second_certificate_insert
             BEFORE INSERT ON certificates
             WHEN (SELECT count(*) FROM certificates) = 1
             BEGIN
                 SELECT RAISE(FAIL, 'injected second certificate insertion failure');
             END;",
        )
        .unwrap();
    let issuer_key = key();
    let issuer = certificate(&issuer_key, 2, "Rollback CA", true, None, -60, None);
    let leaf_key = key();
    let leaf = certificate(
        &leaf_key,
        3,
        "Rollback leaf",
        false,
        Some((&issuer, &issuer_key)),
        -60,
        None,
    );
    let mut chain = Stack::new().unwrap();
    chain.push(issuer).unwrap();
    let mut builder = Pkcs12::builder();
    builder.name("rollback");
    builder.pkey(&leaf_key);
    builder.cert(&leaf);
    builder.ca(chain);
    let pfx = builder.build2("password").unwrap().to_der().unwrap();
    let blob = CRYPT_DATA_BLOB {
        cbData: pfx.len() as DWORD,
        pbData: pfx.as_ptr().cast_mut(),
    };
    let password = wide("password");
    // SAFETY: the store, PFX blob, and terminated password are live.
    assert_eq!(
        unsafe { SysCertImportPfxToStore(store.0, &blob, password.as_ptr(), 0) },
        FALSE
    );
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM certificates", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM garbage", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(fs::read_dir(objects).unwrap().count(), 0);
}

#[test]
fn windows_compatible_chain_trust_and_policy_status() {
    let _guard = api_lock();
    let temp = TempDir::new().unwrap();
    let now_offset = -10 * 86_400;
    let expired_offset = -5 * 86_400;

    let expired_trusted_key = key();
    let expired_trusted = certificate_with_options(
        &expired_trusted_key,
        101,
        "Expired Trusted Root",
        true,
        None,
        Some(true),
        None,
        now_offset,
        expired_offset,
        None,
    );
    let expired_untrusted_key = key();
    let expired_untrusted = certificate_with_options(
        &expired_untrusted_key,
        102,
        "Expired Untrusted Root",
        true,
        None,
        Some(true),
        None,
        now_offset,
        expired_offset,
        None,
    );
    let non_ca_key = key();
    let non_ca = certificate_with_options(
        &non_ca_key,
        103,
        "Not A CA",
        false,
        None,
        Some(false),
        None,
        -60,
        86_400,
        None,
    );
    let non_ca_leaf_key = key();
    let non_ca_leaf = certificate(
        &non_ca_leaf_key,
        104,
        "Non-CA Issued Leaf",
        false,
        Some((&non_ca, &non_ca_key)),
        -60,
        None,
    );
    let path_root_key = key();
    let path_root = certificate_with_options(
        &path_root_key,
        105,
        "Path Length Root",
        true,
        Some(0),
        Some(true),
        None,
        -60,
        86_400,
        None,
    );
    let intermediate_key = key();
    let intermediate = certificate_with_options(
        &intermediate_key,
        106,
        "Intermediate",
        true,
        None,
        Some(true),
        Some((&path_root, &path_root_key)),
        -60,
        86_400,
        None,
    );
    let path_leaf_key = key();
    let path_leaf = certificate(
        &path_leaf_key,
        107,
        "Path Length Leaf",
        false,
        Some((&intermediate, &intermediate_key)),
        -60,
        None,
    );
    let missing_key = key();
    let missing_issuer = certificate(&missing_key, 108, "Missing Issuer", true, None, -60, None);
    let partial_leaf_key = key();
    let partial_leaf = certificate(
        &partial_leaf_key,
        109,
        "Partial Leaf",
        false,
        Some((&missing_issuer, &missing_key)),
        -60,
        None,
    );
    let no_sign_ca_key = key();
    let no_sign_ca = certificate_with_options(
        &no_sign_ca_key,
        110,
        "No Certificate Sign CA",
        true,
        None,
        Some(false),
        None,
        -60,
        86_400,
        None,
    );
    let no_sign_leaf_key = key();
    let no_sign_leaf = certificate(
        &no_sign_leaf_key,
        111,
        "No Certificate Sign Leaf",
        false,
        Some((&no_sign_ca, &no_sign_ca_key)),
        -60,
        None,
    );
    let valid_root_key = key();
    let valid_root = certificate_with_options(
        &valid_root_key,
        112,
        "Valid Trusted Root",
        true,
        None,
        Some(true),
        None,
        -60,
        86_400,
        None,
    );
    let signature_root_key = key();
    let signature_root = certificate_with_options(
        &signature_root_key,
        113,
        "Signature Root",
        true,
        None,
        Some(true),
        None,
        -60,
        86_400,
        None,
    );
    let wrong_signing_key = key();
    let invalid_signature_leaf_key = key();
    let invalid_signature_leaf = certificate(
        &invalid_signature_leaf_key,
        114,
        "Invalid Signature Leaf",
        false,
        Some((&signature_root, &wrong_signing_key)),
        -60,
        None,
    );

    let system = temp.path().join("system");
    fs::create_dir_all(system.join("etc/ssl/certs")).unwrap();
    fs::write(system.join("etc/os-release"), "ID=ubuntu\n").unwrap();
    let mut trusted_bundle = Vec::new();
    for certificate in [
        &expired_trusted,
        &non_ca,
        &path_root,
        &no_sign_ca,
        &valid_root,
        &signature_root,
    ] {
        trusted_bundle.extend(certificate.to_pem().unwrap());
    }
    fs::write(
        system.join("etc/ssl/certs/ca-certificates.crt"),
        trusted_bundle,
    )
    .unwrap();
    let user = cstring(temp.path().join("user"));
    let machine = cstring(temp.path().join("machine"));
    let system_c = cstring(&system);
    let configuration = SYS_CERT_STORE_CONFIGURATION {
        cbSize: size_of::<SYS_CERT_STORE_CONFIGURATION>() as DWORD,
        userStoreDirectory: user.as_ptr(),
        machineStoreDirectory: machine.as_ptr(),
        systemRoot: system_c.as_ptr(),
    };
    // SAFETY: the configuration and its strings remain live throughout this
    // test, and no store survives the final reset.
    assert_ok(unsafe { SysCertConfigureSystemStores(&configuration) });

    {
        let expired_untrusted = Context::from_x509(&expired_untrusted);
        let chain = build_chain(&expired_untrusted, None);
        // SAFETY: `chain` remains live until `free_chain`.
        assert_eq!(
            unsafe { (*chain).TrustStatus.dwErrorStatus },
            CERT_TRUST_IS_NOT_TIME_VALID | CERT_TRUST_IS_UNTRUSTED_ROOT
        );
        let policy = verify_base_policy(chain);
        assert_eq!(
            (policy.dwError, policy.lChainIndex, policy.lElementIndex),
            (CERT_E_UNTRUSTEDROOT, 0, 0)
        );
        free_chain(chain);

        let expired_trusted = Context::from_x509(&expired_trusted);
        let chain = build_chain(&expired_trusted, None);
        // SAFETY: `chain` remains live until `free_chain`.
        assert_eq!(
            unsafe { (*chain).TrustStatus.dwErrorStatus },
            CERT_TRUST_IS_NOT_TIME_VALID
        );
        let policy = verify_base_policy(chain);
        assert_eq!(
            (policy.dwError, policy.lChainIndex, policy.lElementIndex),
            (CERT_E_EXPIRED, 0, 0)
        );
        free_chain(chain);

        let candidates = Store::memory();
        let non_ca_context = Context::from_x509(&non_ca);
        let _non_ca_added = Context::add(&candidates, &non_ca_context, CERT_STORE_ADD_ALWAYS);
        let non_ca_leaf = Context::from_x509(&non_ca_leaf);
        let chain = build_chain(&non_ca_leaf, Some(&candidates));
        // SAFETY: the chain and its first simple chain remain live.
        let simple = unsafe { &**(*chain).rgpChain };
        assert_eq!(
            simple.TrustStatus.dwErrorStatus,
            CERT_TRUST_IS_NOT_VALID_FOR_USAGE | CERT_TRUST_INVALID_BASIC_CONSTRAINTS
        );
        // SAFETY: the two-element chain has a live issuer element at index one.
        assert_eq!(
            unsafe { (**simple.rgpElement.add(1)).TrustStatus.dwErrorStatus },
            CERT_TRUST_IS_NOT_VALID_FOR_USAGE | CERT_TRUST_INVALID_BASIC_CONSTRAINTS
        );
        let policy = verify_base_policy(chain);
        assert_eq!(
            (policy.dwError, policy.lChainIndex, policy.lElementIndex),
            (CERT_E_WRONG_USAGE, 0, 1)
        );
        free_chain(chain);

        let no_sign_candidates = Store::memory();
        let no_sign_ca_context = Context::from_x509(&no_sign_ca);
        let _no_sign_ca_added = Context::add(
            &no_sign_candidates,
            &no_sign_ca_context,
            CERT_STORE_ADD_ALWAYS,
        );
        let no_sign_leaf = Context::from_x509(&no_sign_leaf);
        let chain = build_chain(&no_sign_leaf, Some(&no_sign_candidates));
        // SAFETY: the chain and its two-element simple chain remain live.
        let simple = unsafe { &**(*chain).rgpChain };
        assert_eq!(
            simple.TrustStatus.dwErrorStatus,
            CERT_TRUST_IS_NOT_VALID_FOR_USAGE
        );
        // SAFETY: the issuer is the live element at index one.
        assert_eq!(
            unsafe { (**simple.rgpElement.add(1)).TrustStatus.dwErrorStatus },
            CERT_TRUST_IS_NOT_VALID_FOR_USAGE
        );
        let policy = verify_base_policy(chain);
        assert_eq!(
            (policy.dwError, policy.lChainIndex, policy.lElementIndex),
            (CERT_E_WRONG_USAGE, 0, 1)
        );
        free_chain(chain);

        let path_candidates = Store::memory();
        let intermediate_context = Context::from_x509(&intermediate);
        let _intermediate_added = Context::add(
            &path_candidates,
            &intermediate_context,
            CERT_STORE_ADD_ALWAYS,
        );
        let path_leaf = Context::from_x509(&path_leaf);
        let chain = build_chain(&path_leaf, Some(&path_candidates));
        // SAFETY: the chain and its three-element simple chain remain live.
        let simple = unsafe { &**(*chain).rgpChain };
        assert_eq!(
            simple.TrustStatus.dwErrorStatus,
            CERT_TRUST_INVALID_BASIC_CONSTRAINTS
        );
        // SAFETY: the root is the live element at index two.
        assert_eq!(
            unsafe { (**simple.rgpElement.add(2)).TrustStatus.dwErrorStatus },
            CERT_TRUST_INVALID_BASIC_CONSTRAINTS
        );
        let policy = verify_base_policy(chain);
        assert_eq!(
            (policy.dwError, policy.lChainIndex, policy.lElementIndex),
            (TRUST_E_BASIC_CONSTRAINTS, 0, 2)
        );
        free_chain(chain);

        let signature_candidates = Store::memory();
        let signature_root_context = Context::from_x509(&signature_root);
        let _signature_root_added = Context::add(
            &signature_candidates,
            &signature_root_context,
            CERT_STORE_ADD_ALWAYS,
        );
        let invalid_signature_leaf = Context::from_x509(&invalid_signature_leaf);
        let chain = build_chain(&invalid_signature_leaf, Some(&signature_candidates));
        // SAFETY: the chain and its two-element simple chain remain live.
        let simple = unsafe { &**(*chain).rgpChain };
        assert_eq!(
            simple.TrustStatus.dwErrorStatus,
            CERT_TRUST_IS_NOT_SIGNATURE_VALID
        );
        // SAFETY: the leaf is the live element at index zero.
        assert_eq!(
            unsafe { (**simple.rgpElement).TrustStatus.dwErrorStatus },
            CERT_TRUST_IS_NOT_SIGNATURE_VALID
        );
        let policy = verify_base_policy(chain);
        assert_eq!(
            (policy.dwError, policy.lChainIndex, policy.lElementIndex),
            (TRUST_E_CERT_SIGNATURE, 0, 0)
        );
        free_chain(chain);

        let valid_root = Context::from_x509(&valid_root);
        let chain = build_chain(&valid_root, None);
        // SAFETY: `chain` remains live until `free_chain`.
        assert_eq!(unsafe { (*chain).TrustStatus.dwErrorStatus }, 0);
        let policy = verify_base_policy(chain);
        assert_eq!(
            (policy.dwError, policy.lChainIndex, policy.lElementIndex),
            (ERROR_SUCCESS, -1, -1)
        );
        free_chain(chain);

        let partial_leaf = Context::from_x509(&partial_leaf);
        let chain = build_chain(&partial_leaf, None);
        // SAFETY: `chain` remains live until `free_chain`.
        assert_eq!(
            unsafe { (*chain).TrustStatus.dwErrorStatus },
            CERT_TRUST_IS_PARTIAL_CHAIN
        );
        let policy = verify_base_policy(chain);
        assert_eq!(
            (policy.dwError, policy.lChainIndex, policy.lElementIndex),
            (CERT_E_CHAINING, 0, -1)
        );
        free_chain(chain);
    }

    // SAFETY: null restores default paths after every test-owned handle and
    // context has been released.
    assert_ok(unsafe { SysCertConfigureSystemStores(ptr::null()) });
}

#[test]
fn native_trust_store_and_update_errors() {
    let _guard = api_lock();
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    let bundle = root.join("etc/ssl/certs/ca-certificates.crt");
    let anchors = root.join("usr/local/share/ca-certificates");
    let updater = root.join("usr/sbin/update-ca-certificates");
    fs::create_dir_all(bundle.parent().unwrap()).unwrap();
    fs::create_dir_all(&anchors).unwrap();
    fs::create_dir_all(updater.parent().unwrap()).unwrap();
    fs::write(root.join("etc/os-release"), "ID=ubuntu\n").unwrap();
    let signer = key();
    let x509 = certificate(&signer, 9, "Native Root", true, None, -60, None);
    fs::write(&bundle, x509.to_pem().unwrap()).unwrap();
    fs::write(
        &updater,
        format!(
            "#!/bin/sh\n: > '{}'\nfor f in '{}'/*.crt; do [ ! -f \"$f\" ] || cat \"$f\" >> '{}'; done\n",
            bundle.display(),
            anchors.display(),
            bundle.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&updater, fs::Permissions::from_mode(0o700)).unwrap();
    let root_c = cstring(root);
    let options = SYS_CERT_NATIVE_OPTIONS {
        cbSize: size_of::<SYS_CERT_NATIVE_OPTIONS>() as DWORD,
        rootPath: root_c.as_ptr(),
    };
    let provider = CString::new("SysCertNative").unwrap();
    // SAFETY: the provider and native options remain live for the synchronous
    // open call.
    let store = Store::new(unsafe {
        CertOpenStore(
            provider.as_ptr(),
            0,
            0,
            0,
            (&options as *const SYS_CERT_NATIVE_OPTIONS).cast(),
        )
    });
    assert_eq!(count(&store), 1);
    let context = Context::from_x509(&x509);
    assert_eq!(
        // SAFETY: the context and native options are live.
        unsafe { SysCertUpdateTrustAnchor(context.0, TRUE, &options, 0) },
        FALSE
    );
    assert_eq!(last_error(), ERROR_ACCESS_DENIED);
    // SAFETY: the context and native options are live.
    assert_ok(unsafe {
        SysCertUpdateTrustAnchor(context.0, TRUE, &options, SYS_CERT_TRUST_UPDATE_ALLOW)
    });
    assert_eq!(
        // SAFETY: the context and native options are live.
        unsafe { SysCertUpdateTrustAnchor(context.0, TRUE, &options, SYS_CERT_TRUST_UPDATE_ALLOW) },
        FALSE
    );
    assert_eq!(last_error(), CRYPT_E_EXISTS);
    // SAFETY: the context and native options are live.
    assert_ok(unsafe {
        SysCertUpdateTrustAnchor(context.0, FALSE, &options, SYS_CERT_TRUST_UPDATE_ALLOW)
    });
}

#[test]
fn threading_and_system_scope() {
    let _guard = api_lock();
    let handles = (0..8)
        .map(|index| {
            thread::spawn(move || {
                let signer = key();
                let cert = certificate(&signer, index + 1, "Threaded", true, None, -60, None);
                let source = Context::from_x509(&cert);
                let store = Store::memory();
                let added = Context::add(&store, &source, CERT_STORE_ADD_ALWAYS);
                assert_eq!(property(&added, CERT_SHA256_HASH_PROP_ID).len(), 32);
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap();
    }

    let temp = TempDir::new().unwrap();
    let root_key = key();
    let root = certificate(&root_key, 41, "Machine Root", true, None, -60, None);
    let system = temp.path().join("system");
    fs::create_dir_all(system.join("etc/ssl/certs")).unwrap();
    fs::write(system.join("etc/os-release"), "ID=ubuntu\n").unwrap();
    fs::write(
        system.join("etc/ssl/certs/ca-certificates.crt"),
        root.to_pem().unwrap(),
    )
    .unwrap();
    let user = cstring(temp.path().join("user"));
    let machine = cstring(temp.path().join("machine"));
    let system_c = cstring(&system);
    let configuration = SYS_CERT_STORE_CONFIGURATION {
        cbSize: size_of::<SYS_CERT_STORE_CONFIGURATION>() as DWORD,
        userStoreDirectory: user.as_ptr(),
        machineStoreDirectory: machine.as_ptr(),
        systemRoot: system_c.as_ptr(),
    };
    // SAFETY: the configuration and its C strings remain live while stores
    // use it.
    assert_ok(unsafe { SysCertConfigureSystemStores(&configuration) });
    let mut enumerated = 0_usize;
    // SAFETY: the callback and its counter remain live for the synchronous
    // enumeration call.
    assert_ok(unsafe {
        CertEnumSystemStore(
            CERT_SYSTEM_STORE_CURRENT_USER,
            ptr::null_mut(),
            (&mut enumerated as *mut usize).cast(),
            Some(open_store_during_enumeration),
        )
    });
    assert!(enumerated >= 3);
    {
        let user_my = Store::scoped("MY", CERT_SYSTEM_STORE_CURRENT_USER, 0);
        let machine_my = Store::scoped("MY", CERT_SYSTEM_STORE_LOCAL_MACHINE, 0);
        let user_ca = Store::scoped("CA", CERT_SYSTEM_STORE_CURRENT_USER, 0);
        let machine_ca = Store::scoped("CA", CERT_SYSTEM_STORE_LOCAL_MACHINE, 0);
        let roots = Store::scoped("ROOT", CERT_SYSTEM_STORE_CURRENT_USER, 0);
        assert_eq!(count(&roots), 1);
        let personal_key = key();
        let personal = certificate(&personal_key, 44, "Personal", false, None, -60, None);
        let source = Context::from_x509(&personal);
        let user_added = Context::add(&user_my, &source, CERT_STORE_ADD_ALWAYS);
        let machine_added = Context::add(&machine_my, &source, CERT_STORE_ADD_ALWAYS);
        let mut location = 0;
        // SAFETY: the context is live and `location` is writable.
        assert_ok(unsafe { SysCertGetCertificateStoreLocation(user_added.0, &mut location) });
        assert_eq!(location, CERT_SYSTEM_STORE_CURRENT_USER);
        // SAFETY: the context is live and `location` is writable.
        assert_ok(unsafe { SysCertGetCertificateStoreLocation(machine_added.0, &mut location) });
        assert_eq!(location, CERT_SYSTEM_STORE_LOCAL_MACHINE);
        let intermediate = certificate(&root_key, 43, "Intermediate", true, None, -60, None);
        let intermediate = Context::from_x509(&intermediate);
        let _machine_intermediate = Context::add(&machine_ca, &intermediate, CERT_STORE_ADD_ALWAYS);
        assert_eq!(count(&user_ca), 1);
        // SAFETY: the store is live and null starts a new enumeration.
        let inherited = Context(unsafe { CertEnumCertificatesInStore(user_ca.0, ptr::null()) });
        // SAFETY: the context is live and `location` is writable.
        assert_ok(unsafe { SysCertGetCertificateStoreLocation(inherited.0, &mut location) });
        assert_eq!(location, CERT_SYSTEM_STORE_LOCAL_MACHINE);
        // SAFETY: `inherited` owns a live context.
        let duplicate = unsafe { CertDuplicateCertificateContext(inherited.0) };
        assert!(!duplicate.is_null());
        // SAFETY: `duplicate` is an independently owned live reference and is
        // consumed by this call.
        assert_eq!(unsafe { CertDeleteCertificateFromStore(duplicate) }, FALSE);
        assert_eq!(last_error(), ERROR_ACCESS_DENIED);
    }
    // SAFETY: null restores the default configuration.
    assert_ok(unsafe { SysCertConfigureSystemStores(ptr::null()) });
}

fn generate_crl(temp: &Path, issuer: &X509, issuer_key: &PKey<Private>) -> Vec<u8> {
    let ca = temp.join("ca");
    fs::create_dir_all(ca.join("newcerts")).unwrap();
    fs::write(ca.join("issuer.pem"), issuer.to_pem().unwrap()).unwrap();
    fs::write(
        ca.join("issuer.key"),
        issuer_key.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    fs::write(ca.join("index.txt"), "").unwrap();
    fs::write(ca.join("crlnumber"), "01\n").unwrap();
    let config = ca.join("openssl.cnf");
    fs::write(
        &config,
        format!(
            "[ca]\ndefault_ca=default\n[default]\ndatabase={0}/index.txt\nnew_certs_dir={0}/newcerts\ncertificate={0}/issuer.pem\nprivate_key={0}/issuer.key\ndefault_md=sha256\ndefault_crl_days=1\ncrlnumber={0}/crlnumber\npolicy=policy\n[policy]\ncommonName=supplied\n",
            ca.display()
        ),
    )
    .unwrap();
    let output = ca.join("issuer.crl");
    let status = Command::new("openssl")
        .args(["ca", "-gencrl", "-batch", "-config"])
        .arg(&config)
        .arg("-out")
        .arg(&output)
        .status()
        .unwrap();
    assert!(status.success());
    fs::read(output).unwrap()
}

#[test]
fn dotnet_crl_cache_regression() {
    let _guard = api_lock();
    let temp = TempDir::new().unwrap();
    let issuer_key = key();
    let issuer = certificate(&issuer_key, 201, "CRL Cache Root", true, None, -60, None);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/issuer.crl", listener.local_addr().unwrap());
    let leaf_key = key();
    let leaf = certificate(
        &leaf_key,
        202,
        "CRL Cache Leaf",
        false,
        Some((&issuer, &issuer_key)),
        -60,
        Some(&url),
    );
    let crl = generate_crl(temp.path(), &issuer, &issuer_key);
    let body = crl.clone();
    let (request_started_tx, request_started_rx) = mpsc::channel();
    let (send_response_tx, send_response_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        let mut request = [0u8; 4096];
        let _ = client.read(&mut request).unwrap();
        request_started_tx.send(()).unwrap();
        send_response_rx.recv().unwrap();
        write!(
            client,
            "HTTP/1.0 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        client.write_all(&body).unwrap();
    });

    let system = temp.path().join("system");
    fs::create_dir_all(system.join("etc/ssl/certs")).unwrap();
    fs::write(system.join("etc/os-release"), "ID=ubuntu\n").unwrap();
    fs::write(
        system.join("etc/ssl/certs/ca-certificates.crt"),
        issuer.to_pem().unwrap(),
    )
    .unwrap();
    let user = cstring(temp.path().join("user-store"));
    let machine = cstring(temp.path().join("machine-store"));
    let system_c = cstring(&system);
    let config = SYS_CERT_STORE_CONFIGURATION {
        cbSize: size_of::<SYS_CERT_STORE_CONFIGURATION>() as DWORD,
        userStoreDirectory: user.as_ptr(),
        machineStoreDirectory: machine.as_ptr(),
        systemRoot: system_c.as_ptr(),
    };
    // SAFETY: the configuration and its C strings remain live while stores
    // use it.
    assert_ok(unsafe { SysCertConfigureSystemStores(&config) });
    {
        let personal = Store::scoped("MY", CERT_SYSTEM_STORE_CURRENT_USER, 0);
        let leaf = Context::from_x509(&leaf);
        let _added = Context::add(&personal, &leaf, CERT_STORE_ADD_ALWAYS);
    }
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    let previous_home = std::env::var_os("HOME");
    let previous_no_proxy = std::env::var_os("NO_PROXY");
    unsafe {
        std::env::set_var("HOME", &home);
        std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
    }
    let account = unsafe { libc::getpwuid(libc::geteuid()) };
    assert!(!account.is_null());
    // SAFETY: `account` is live and `pw_name` is a terminated C string owned
    // by the process password database.
    let account_name = unsafe { CStr::from_ptr((*account).pw_name) }.to_owned();
    let populate = thread::spawn(move || {
        // SAFETY: `account_name` remains live for the synchronous call.
        unsafe { SysCertPopulateDotNetCrlCache(account_name.as_ptr()) }
    });
    request_started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("CRL download did not start");
    let (store_result_tx, store_result_rx) = mpsc::channel();
    let store_operation = thread::spawn(move || {
        // SAFETY: the memory provider accepts a null provider parameter.
        let store = unsafe { CertOpenStore(PROVIDER_MEMORY as LPCSTR, 0, 0, 0, ptr::null()) };
        let result = !store.is_null() && CertCloseStore(store, 0) != FALSE;
        store_result_tx.send(result).unwrap();
    });
    let store_available_during_download = store_result_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or(false);
    send_response_tx.send(()).unwrap();
    assert_ok(populate.join().unwrap());
    server.join().unwrap();
    store_operation.join().unwrap();
    assert!(
        store_available_during_download,
        "CRL population held the global state lock during network I/O"
    );
    unsafe {
        match previous_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        match previous_no_proxy {
            Some(value) => std::env::set_var("NO_PROXY", value),
            None => std::env::remove_var("NO_PROXY"),
        }
    }
    let directory = home.join(".dotnet/corefx/cryptography/crls");
    let files = fs::read_dir(&directory)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
    let cached = files[0].path();
    assert_eq!(fs::metadata(&cached).unwrap().mode() & 0o777, 0o600);
    let cached = openssl::x509::X509Crl::from_pem(&fs::read(cached).unwrap()).unwrap();
    let expected = openssl::x509::X509Crl::from_pem(&crl).unwrap();
    assert_eq!(cached.to_der().unwrap(), expected.to_der().unwrap());
    // SAFETY: null restores the default configuration.
    assert_ok(unsafe { SysCertConfigureSystemStores(ptr::null()) });
    let invalid = [0xff_u8, 0];
    assert_eq!(
        // SAFETY: `invalid` is a live terminated byte string; the test
        // intentionally verifies invalid UTF-8 handling.
        unsafe { SysCertPopulateDotNetCrlCache(invalid.as_ptr().cast()) },
        FALSE
    );
    assert_eq!(last_error(), E_INVALIDARG);
}

fn run_certutil(temp: &TempDir, arguments: &[&str]) -> std::process::Output {
    let system = temp.path().join("system");
    fs::create_dir_all(system.join("etc/ssl/certs")).unwrap();
    fs::write(system.join("etc/os-release"), "ID=ubuntu\n").unwrap();
    fs::write(system.join("etc/ssl/certs/ca-certificates.crt"), "").unwrap();
    Command::new(env!("CARGO_BIN_EXE_certutil"))
        .args(["--user-store-dir"])
        .arg(temp.path().join("user"))
        .args(["--machine-store-dir"])
        .arg(temp.path().join("machine"))
        .args(["--system-root"])
        .arg(system)
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn certutil_commands_and_failures() {
    let _guard = api_lock();
    let temp = TempDir::new().unwrap();
    let help = run_certutil(&temp, &["-?"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("not NSS certutil"));

    let signer = key();
    let cert = certificate(&signer, 100, "Tool Root", true, None, -60, None);
    let pem = temp.path().join("root.pem");
    fs::write(&pem, cert.to_pem().unwrap()).unwrap();
    let add = Command::new(env!("CARGO_BIN_EXE_certutil"))
        .args(["--user-store-dir"])
        .arg(temp.path().join("user"))
        .args(["--machine-store-dir"])
        .arg(temp.path().join("machine"))
        .args(["--system-root"])
        .arg(temp.path().join("system"))
        .args(["-user", "-addstore", "MY"])
        .arg(&pem)
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    let list = run_certutil(&temp, &["-user", "-store", "MY"]);
    assert!(list.status.success());
    let output = String::from_utf8_lossy(&list.stdout);
    assert!(output.contains("Tool Root") && output.contains("1 certificate(s)"));

    let pfx_key = key();
    let pfx_certificate = certificate(&pfx_key, 101, "Tool PFX", false, None, -60, None);
    let mut builder = Pkcs12::builder();
    builder.name("tool");
    builder.pkey(&pfx_key);
    builder.cert(&pfx_certificate);
    let pfx = builder.build2("password").unwrap().to_der().unwrap();
    let input_pfx = temp.path().join("input.pfx");
    fs::write(&input_pfx, pfx).unwrap();
    let import = Command::new(env!("CARGO_BIN_EXE_certutil"))
        .args(["--user-store-dir"])
        .arg(temp.path().join("user"))
        .args(["--machine-store-dir"])
        .arg(temp.path().join("machine"))
        .args(["--system-root"])
        .arg(temp.path().join("system"))
        .args(["-user", "-p", "password", "-importPFX", "MY"])
        .arg(&input_pfx)
        .output()
        .unwrap();
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    let output_pfx = temp.path().join("output.pfx");
    let export = Command::new(env!("CARGO_BIN_EXE_certutil"))
        .args(["--user-store-dir"])
        .arg(temp.path().join("user"))
        .args(["--machine-store-dir"])
        .arg(temp.path().join("machine"))
        .args(["--system-root"])
        .arg(temp.path().join("system"))
        .args([
            "-user",
            "-f",
            "-p",
            "password",
            "-exportPFX",
            "MY",
            "subject:Tool PFX",
        ])
        .arg(&output_pfx)
        .arg("NoChain")
        .output()
        .unwrap();
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    let exported = Pkcs12::from_der(&fs::read(output_pfx).unwrap())
        .unwrap()
        .parse2("password")
        .unwrap();
    assert!(exported.pkey.unwrap().public_eq(&pfx_key));

    let pkcs7_path = temp.path().join("store.p7b");
    let save_pkcs7 = Command::new(env!("CARGO_BIN_EXE_certutil"))
        .args(["--user-store-dir"])
        .arg(temp.path().join("user"))
        .args(["--machine-store-dir"])
        .arg(temp.path().join("machine"))
        .args(["--system-root"])
        .arg(temp.path().join("system"))
        .args(["-user", "-f", "--format", "pkcs7", "-store", "MY", "*"])
        .arg(&pkcs7_path)
        .output()
        .unwrap();
    assert!(
        save_pkcs7.status.success(),
        "{}",
        String::from_utf8_lossy(&save_pkcs7.stderr)
    );
    let dump_pkcs7 = Command::new(env!("CARGO_BIN_EXE_certutil"))
        .args(["--user-store-dir"])
        .arg(temp.path().join("user"))
        .args(["--machine-store-dir"])
        .arg(temp.path().join("machine"))
        .args(["--system-root"])
        .arg(temp.path().join("system"))
        .arg("-dump")
        .arg(&pkcs7_path)
        .output()
        .unwrap();
    assert!(
        dump_pkcs7.status.success(),
        "{}",
        String::from_utf8_lossy(&dump_pkcs7.stderr)
    );
    let dumped = String::from_utf8_lossy(&dump_pkcs7.stdout);
    assert!(dumped.contains("Tool Root") && dumped.contains("Tool PFX"));

    let bad = run_certutil(&temp, &["-unknown"]);
    assert_eq!(bad.status.code(), Some(2));
}

#[cfg(not(scs_bundled_crypto))]
#[test]
fn system_openssl_pqc_algorithms_when_available() {
    let _guard = api_lock();
    let temp = TempDir::new().unwrap();
    let Ok(listing) = Command::new("openssl")
        .args(["list", "-public-key-algorithms"])
        .output()
    else {
        eprintln!("system OpenSSL is unavailable; optional PQC cases skipped");
        return;
    };
    if !listing.status.success() {
        eprintln!("system OpenSSL cannot list algorithms; optional PQC cases skipped");
        return;
    }
    let listing = String::from_utf8_lossy(&listing.stdout);
    let mut exercised = 0;
    for algorithm in PQC_ALGORITHMS {
        if !listing
            .to_ascii_lowercase()
            .contains(&algorithm.to_ascii_lowercase())
        {
            continue;
        }
        let key_path = temp.path().join(format!("{algorithm}.key"));
        let cert_path = temp.path().join(format!("{algorithm}.der"));
        let generated = Command::new("openssl")
            .args(["genpkey", "-algorithm", algorithm, "-out"])
            .arg(&key_path)
            .status()
            .unwrap();
        if !generated.success() {
            continue;
        }
        let issued = Command::new("openssl")
            .args(["req", "-new", "-x509", "-key"])
            .arg(&key_path)
            .args([
                "-subj",
                "/CN=PQC interoperability",
                "-days",
                "1",
                "-outform",
                "DER",
                "-out",
            ])
            .arg(&cert_path)
            .status()
            .unwrap();
        if !issued.success() {
            continue;
        }
        let der = fs::read(&cert_path).unwrap();
        let source = Context::from_der(&der);
        let store_path = temp.path().join(format!("{algorithm}.db"));
        {
            let store = Store::sqlite(&store_path, 0);
            let stored = Context::add(&store, &source, CERT_STORE_ADD_ALWAYS);
            let encoded = unsafe {
                std::slice::from_raw_parts(
                    (*stored.0).pbCertEncoded,
                    (*stored.0).cbCertEncoded as usize,
                )
            };
            assert_eq!(encoded, der);
        }
        {
            let store = Store::sqlite(&store_path, CERT_STORE_OPEN_EXISTING_FLAG);
            assert_eq!(count(&store), 1);
        }
        exercised += 1;
    }
    if exercised == 0 {
        eprintln!("system OpenSSL PQC algorithms are unavailable; optional cases skipped");
    }
}

#[cfg(scs_bundled_crypto)]
#[test]
fn bundled_provider_pqc_algorithms_and_pfx_round_trip() {
    let _guard = api_lock();
    assert!(
        unsafe { scs_initialize_crypto() },
        "cannot initialize bundled cryptographic providers"
    );
    let temp = TempDir::new().unwrap();
    let password = wide("password");

    for (index, algorithm) in PQC_ALGORITHMS.into_iter().enumerate() {
        let key = provider_key(algorithm);
        let certificate = pqc_certificate(
            &key,
            u32::try_from(index + 1).unwrap(),
            &format!("R09 {algorithm}"),
        );
        let certificate_der = certificate.to_der().unwrap();
        let key_der = key.private_key_to_pkcs8().unwrap();
        let crate_certificate =
            sys_cert_store::cert::Certificate::from_der(&certificate_der).unwrap();
        assert!(
            crate_certificate.self_signed().unwrap(),
            "{algorithm} certificate verification did not use the bundled provider successfully"
        );
        let crate_key = sys_cert_store::key::PrivateKey::from_der(key_der).unwrap();
        assert!(
            crate_key.matches(&crate_certificate).unwrap(),
            "{algorithm} private key does not match its certificate"
        );

        let pfx = pqc_pfx(&key, &certificate, "password");
        let blob = CRYPT_DATA_BLOB {
            cbData: pfx.len() as DWORD,
            pbData: pfx.as_ptr().cast_mut(),
        };
        let store_path = temp.path().join(format!("{index}.db"));
        {
            let store = Store::sqlite(&store_path, 0);
            assert_ok(unsafe {
                SysCertImportPfxToStore(store.0, &blob, password.as_ptr(), CRYPT_EXPORTABLE)
            });
            assert_eq!(
                count(&store),
                1,
                "{algorithm} PFX import lost its certificate"
            );

            let mut exported = CRYPT_DATA_BLOB::default();
            assert_ok(unsafe {
                PFXExportCertStoreEx(
                    store.0,
                    &mut exported,
                    password.as_ptr(),
                    ptr::null_mut(),
                    EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY,
                )
            });
            let mut exported_bytes = vec![0u8; exported.cbData as usize];
            exported.pbData = exported_bytes.as_mut_ptr();
            assert_ok(unsafe {
                PFXExportCertStoreEx(
                    store.0,
                    &mut exported,
                    password.as_ptr(),
                    ptr::null_mut(),
                    EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY,
                )
            });

            let exported_blob = CRYPT_DATA_BLOB {
                cbData: exported.cbData,
                pbData: exported_bytes.as_mut_ptr(),
            };
            let reimported = Store::sqlite(&temp.path().join(format!("{index}-reimport.db")), 0);
            assert_ok(unsafe {
                SysCertImportPfxToStore(
                    reimported.0,
                    &exported_blob,
                    password.as_ptr(),
                    CRYPT_EXPORTABLE,
                )
            });
            assert_eq!(
                count(&reimported),
                1,
                "{algorithm} exported PFX did not re-import"
            );
        }
        let reopened = Store::sqlite(&store_path, CERT_STORE_OPEN_EXISTING_FLAG);
        assert_eq!(
            count(&reopened),
            1,
            "{algorithm} certificate did not survive store reopen"
        );
    }
}
