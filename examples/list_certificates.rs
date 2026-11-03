use std::ptr;
use sys_cert_store::api_types::{CRYPT_E_NOT_FOUND, FALSE, WCHAR};
use sys_cert_store::{
    CertCloseStore, CertEnumCertificatesInStore, CertOpenSystemStoreW, GetLastError,
    SysCertGetLastErrorMessage,
};

fn last_error_message() -> String {
    let message = SysCertGetLastErrorMessage();
    if message.is_null() {
        return "unknown error".to_owned();
    }
    unsafe { std::ffi::CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned()
}

fn main() {
    let mut name = "ROOT"
        .chars()
        .map(|character| character as WCHAR)
        .collect::<Vec<_>>();
    name.push(0);

    let store = CertOpenSystemStoreW(0, name.as_ptr());
    if store.is_null() {
        eprintln!(
            "Open failed (0x{:x}): {}",
            GetLastError(),
            last_error_message()
        );
        std::process::exit(1);
    }

    let mut count = 0;
    let mut certificate = ptr::null();
    loop {
        certificate = CertEnumCertificatesInStore(store, certificate);
        if certificate.is_null() {
            break;
        }
        count += 1;
    }

    if GetLastError() != CRYPT_E_NOT_FOUND {
        eprintln!(
            "Enumeration failed (0x{:x}): {}",
            GetLastError(),
            last_error_message()
        );
        CertCloseStore(store, 0);
        std::process::exit(1);
    }

    println!("{count} certificates");
    if CertCloseStore(store, 0) == FALSE {
        std::process::exit(1);
    }
}
