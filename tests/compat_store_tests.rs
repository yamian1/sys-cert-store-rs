#![cfg(unix)]

use libc::wchar_t;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::{X509, X509Extension, X509NameBuilder};
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use sys_cert_store::api_types::*;
use sys_cert_store::*;
use tempfile::TempDir;

static API_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

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

fn wide(value: &str) -> Vec<wchar_t> {
    value
        .chars()
        .map(|value| value as wchar_t)
        .chain([0])
        .collect()
}

fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
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
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let serial = Asn1Integer::from_bn(&BigNum::from_u32(serial).unwrap()).unwrap();
    builder.set_serial_number(&serial).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let not_before = Asn1Time::from_unix(now + not_before_offset).unwrap();
    let not_after = Asn1Time::from_unix(now + 86_400).unwrap();
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
        BasicConstraints::new().critical().ca().build().unwrap()
    } else {
        BasicConstraints::new().critical().build().unwrap()
    };
    builder.append_extension(constraints).unwrap();
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
        Self::new(CertOpenStore(
            PROVIDER_MEMORY as LPCSTR,
            0,
            0,
            0,
            ptr::null(),
        ))
    }

    fn sqlite(path: &Path, flags: DWORD) -> Self {
        let provider = CString::new("SysCertSQLite").unwrap();
        let path = cstring(path);
        Self::new(CertOpenStore(
            provider.as_ptr(),
            0,
            0,
            flags,
            path.as_ptr().cast(),
        ))
    }

    fn scoped(name: &str, scope: DWORD, flags: DWORD) -> Self {
        let name = wide(name);
        Self::new(CertOpenStore(
            PROVIDER_SYSTEM_W as LPCSTR,
            0,
            0,
            scope | flags,
            name.as_ptr().cast(),
        ))
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
        let value =
            CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), der.len() as DWORD);
        assert!(!value.is_null(), "{}: {}", last_error(), last_message());
        Self(value)
    }

    fn add(store: &Store, source: &Context, disposition: DWORD) -> Self {
        let mut result = ptr::null();
        assert_ok(CertAddCertificateContextToStore(
            store.0,
            source.0,
            disposition,
            &mut result,
        ));
        Self(result)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if !self.0.is_null() {
            assert_ok(CertFreeCertificateContext(self.0));
        }
    }
}

fn count(store: &Store) -> usize {
    let mut count = 0;
    let mut previous = ptr::null();
    loop {
        let current = CertEnumCertificatesInStore(store.0, previous);
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
    assert_ok(CertGetCertificateContextProperty(
        context.0,
        id,
        ptr::null_mut(),
        &mut size,
    ));
    let mut value = vec![0; size as usize];
    assert_ok(CertGetCertificateContextProperty(
        context.0,
        id,
        value.as_mut_ptr().cast(),
        &mut size,
    ));
    value
}

fn set_property(context: &Context, id: DWORD, value: &[u8]) {
    let blob = CRYPT_DATA_BLOB {
        cbData: value.len() as DWORD,
        pbData: value.as_ptr().cast_mut(),
    };
    assert_ok(CertSetCertificateContextProperty(
        context.0,
        id,
        0,
        (&blob as *const CRYPT_DATA_BLOB).cast(),
    ));
}

fn material_path(context: &Context, private_key: BOOL) -> PathBuf {
    let mut size = 0;
    assert_ok(SysCertGetCertificateFilePath(
        context.0,
        private_key,
        ptr::null_mut(),
        &mut size,
    ));
    let mut bytes = vec![0u8; size as usize];
    assert_ok(SysCertGetCertificateFilePath(
        context.0,
        private_key,
        bytes.as_mut_ptr().cast(),
        &mut size,
    ));
    bytes.pop();
    PathBuf::from(String::from_utf8(bytes).unwrap())
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
        CertGetCertificateContextProperty(
            added.0,
            CERT_SHA256_HASH_PROP_ID,
            (&mut sentinel as *mut u8).cast(),
            &mut short_size,
        ),
        FALSE
    );
    assert_eq!(
        (last_error(), short_size, sentinel),
        (ERROR_MORE_DATA, 32, 0x5a)
    );

    assert_eq!(
        CertAddCertificateContextToStore(store.0, source.0, CERT_STORE_ADD_NEW, ptr::null_mut(),),
        FALSE
    );
    assert_eq!(last_error(), CRYPT_E_EXISTS);
    assert!(CertCreateCertificateContext(0, ptr::null(), 0).is_null());
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
                CertAddCertificateContextToStore(store.0, new.0, disposition, ptr::null_mut(),),
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
        assert_ok(CertControlStore(
            store.0,
            0,
            CERT_STORE_CTRL_COMMIT,
            ptr::null(),
        ));
    }
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    {
        let store = Store::sqlite(&path, CERT_STORE_OPEN_EXISTING_FLAG);
        let raw = CertEnumCertificatesInStore(store.0, ptr::null());
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
        CertOpenStore(
            provider.as_ptr(),
            0,
            0,
            CERT_STORE_OPEN_EXISTING_FLAG,
            missing_c.as_ptr().cast(),
        )
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
        SysCertImportPfxToStore(store.0, &blob, wrong.as_ptr(), 0),
        FALSE
    );
    assert_eq!(last_error(), ERROR_INVALID_DATA);
    assert_ok(SysCertImportPfxToStore(
        store.0,
        &blob,
        password.as_ptr(),
        0,
    ));
    assert_eq!(count(&store), 2);
    let subject = wide("PFX leaf");
    let raw = CertFindCertificateInStore(
        store.0,
        X509_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR_W,
        subject.as_ptr().cast(),
        ptr::null(),
    );
    let leaf_context = Context(raw);
    let cert_path = material_path(&leaf_context, FALSE);
    let key_path = material_path(&leaf_context, TRUE);
    assert!(cert_path.is_file() && key_path.is_file());
    assert_eq!(fs::metadata(&key_path).unwrap().mode() & 0o777, 0o600);
    let recovered = PKey::private_key_from_pem(&fs::read(key_path).unwrap()).unwrap();
    assert!(recovered.public_eq(&leaf_key));

    let name_size = CertGetNameStringA(
        leaf_context.0,
        CERT_NAME_RDN_TYPE,
        0,
        ptr::null(),
        ptr::null_mut(),
        0,
    );
    assert!(name_size > 1);
    let mut name = vec![0i8; name_size as usize];
    assert_eq!(
        CertGetNameStringA(
            leaf_context.0,
            CERT_NAME_RDN_TYPE,
            0,
            ptr::null(),
            name.as_mut_ptr(),
            name_size,
        ),
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
    assert_ok(CertGetCertificateChain(
        ptr::null_mut(),
        leaf_context.0,
        ptr::null(),
        store.0,
        &parameters,
        0,
        ptr::null_mut(),
        &mut chain_context,
    ));
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
    assert_ok(CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_BASE as LPCSTR,
        chain_context,
        &policy_parameters,
        &mut policy_status,
    ));
    assert_eq!(policy_status.dwError, ERROR_SUCCESS);
    CertFreeCertificateChain(chain_context);

    let mut exported = CRYPT_DATA_BLOB::default();
    assert_ok(PFXExportCertStoreEx(
        store.0,
        &mut exported,
        password.as_ptr(),
        ptr::null_mut(),
        EXPORT_PRIVATE_KEYS,
    ));
    let mut exported_bytes = vec![0u8; exported.cbData as usize];
    exported.pbData = exported_bytes.as_mut_ptr();
    assert_ok(PFXExportCertStoreEx(
        store.0,
        &mut exported,
        password.as_ptr(),
        ptr::null_mut(),
        EXPORT_PRIVATE_KEYS,
    ));
    let exported_pfx = Pkcs12::from_der(&exported_bytes).unwrap();
    let exported_material = exported_pfx.parse2("password").unwrap();
    assert!(exported_material.pkey.unwrap().public_eq(&leaf_key));
    assert_eq!(exported_material.ca.unwrap().len(), 1);

    let mut pkcs7 = CRYPT_DATA_BLOB::default();
    assert_ok(CertSaveStore(
        store.0,
        PKCS_7_ASN_ENCODING,
        CERT_STORE_SAVE_AS_PKCS7,
        CERT_STORE_SAVE_TO_MEMORY,
        (&mut pkcs7 as *mut CRYPT_DATA_BLOB).cast(),
        0,
    ));
    let mut pkcs7_bytes = vec![0u8; pkcs7.cbData as usize];
    pkcs7.pbData = pkcs7_bytes.as_mut_ptr();
    assert_ok(CertSaveStore(
        store.0,
        PKCS_7_ASN_ENCODING,
        CERT_STORE_SAVE_AS_PKCS7,
        CERT_STORE_SAVE_TO_MEMORY,
        (&mut pkcs7 as *mut CRYPT_DATA_BLOB).cast(),
        0,
    ));
    let pkcs7_store = Store::new(CertOpenStore(
        PROVIDER_PKCS7 as LPCSTR,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_STORE_READONLY_FLAG,
        (&pkcs7 as *const CRYPT_DATA_BLOB).cast(),
    ));
    assert_eq!(count(&pkcs7_store), 2);
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
    let store = Store::new(CertOpenStore(
        provider.as_ptr(),
        0,
        0,
        0,
        (&options as *const SYS_CERT_NATIVE_OPTIONS).cast(),
    ));
    assert_eq!(count(&store), 1);
    let context = Context::from_x509(&x509);
    assert_eq!(
        SysCertUpdateTrustAnchor(context.0, TRUE, &options, 0),
        FALSE
    );
    assert_eq!(last_error(), ERROR_ACCESS_DENIED);
    assert_ok(SysCertUpdateTrustAnchor(
        context.0,
        TRUE,
        &options,
        SYS_CERT_TRUST_UPDATE_ALLOW,
    ));
    assert_eq!(
        SysCertUpdateTrustAnchor(context.0, TRUE, &options, SYS_CERT_TRUST_UPDATE_ALLOW,),
        FALSE
    );
    assert_eq!(last_error(), CRYPT_E_EXISTS);
    assert_ok(SysCertUpdateTrustAnchor(
        context.0,
        FALSE,
        &options,
        SYS_CERT_TRUST_UPDATE_ALLOW,
    ));
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
    assert_ok(SysCertConfigureSystemStores(&configuration));
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
        assert_ok(SysCertGetCertificateStoreLocation(
            user_added.0,
            &mut location,
        ));
        assert_eq!(location, CERT_SYSTEM_STORE_CURRENT_USER);
        assert_ok(SysCertGetCertificateStoreLocation(
            machine_added.0,
            &mut location,
        ));
        assert_eq!(location, CERT_SYSTEM_STORE_LOCAL_MACHINE);
        let intermediate = certificate(&root_key, 43, "Intermediate", true, None, -60, None);
        let intermediate = Context::from_x509(&intermediate);
        let _machine_intermediate = Context::add(&machine_ca, &intermediate, CERT_STORE_ADD_ALWAYS);
        assert_eq!(count(&user_ca), 1);
        let inherited = Context(CertEnumCertificatesInStore(user_ca.0, ptr::null()));
        assert_ok(SysCertGetCertificateStoreLocation(
            inherited.0,
            &mut location,
        ));
        assert_eq!(location, CERT_SYSTEM_STORE_LOCAL_MACHINE);
        let duplicate = CertDuplicateCertificateContext(inherited.0);
        assert!(!duplicate.is_null());
        assert_eq!(CertDeleteCertificateFromStore(duplicate), FALSE);
        assert_eq!(last_error(), ERROR_ACCESS_DENIED);
    }
    assert_ok(SysCertConfigureSystemStores(ptr::null()));
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
    let server = thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        let mut request = [0u8; 4096];
        let _ = client.read(&mut request).unwrap();
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
    assert_ok(SysCertConfigureSystemStores(&config));
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
    assert_ok(SysCertPopulateDotNetCrlCache(unsafe { (*account).pw_name }));
    server.join().unwrap();
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
    assert_ok(SysCertConfigureSystemStores(ptr::null()));
    let invalid = [0xff_u8, 0];
    assert_eq!(
        SysCertPopulateDotNetCrlCache(invalid.as_ptr().cast()),
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

#[test]
fn pqc_algorithms_when_available_and_interop_round_trip() {
    let _guard = api_lock();
    let temp = TempDir::new().unwrap();
    let algorithms = [
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA65-ECDSA-P256-SHA512",
        "MLDSA65-ECDSA-P384-SHA512",
        "MLDSA87-ECDSA-P384-SHA512",
    ];
    let listing = Command::new("openssl")
        .args(["list", "-public-key-algorithms"])
        .output()
        .unwrap();
    assert!(listing.status.success());
    let listing = String::from_utf8_lossy(&listing.stdout);
    let mut exercised = 0;
    for algorithm in algorithms {
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
        eprintln!("PQC provider algorithms are unavailable; dynamic PQC cases skipped");
    }
}
