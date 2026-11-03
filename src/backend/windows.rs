#![allow(clippy::not_unsafe_ptr_arg_deref, non_snake_case)]

use crate::api_types::*;
use core::ffi::{c_char, c_void};
use std::mem;
use std::ptr;
use windows_sys::Win32::Foundation as foundation;
use windows_sys::Win32::Security::Cryptography as win;

macro_rules! assert_layout {
    ($local:ty, $native:ty) => {
        assert!(mem::size_of::<$local>() == mem::size_of::<$native>());
        assert!(mem::align_of::<$local>() == mem::align_of::<$native>());
    };
}

const _: () = {
    assert_layout!(CRYPT_DATA_BLOB, win::CRYPT_INTEGER_BLOB);
    assert_layout!(CRYPT_BIT_BLOB, win::CRYPT_BIT_BLOB);
    assert_layout!(FILETIME, foundation::FILETIME);
    assert_layout!(CRYPT_ALGORITHM_IDENTIFIER, win::CRYPT_ALGORITHM_IDENTIFIER);
    assert_layout!(CERT_PUBLIC_KEY_INFO, win::CERT_PUBLIC_KEY_INFO);
    assert_layout!(CERT_EXTENSION, win::CERT_EXTENSION);
    assert_layout!(CERT_INFO, win::CERT_INFO);
    assert_layout!(CERT_CONTEXT, win::CERT_CONTEXT);
    assert_layout!(CERT_SYSTEM_STORE_INFO, win::CERT_SYSTEM_STORE_INFO);
    assert_layout!(GUID, windows_sys::core::GUID);
    assert_layout!(CERT_ENHKEY_USAGE, win::CTL_USAGE);
    assert_layout!(CERT_USAGE_MATCH, win::CERT_USAGE_MATCH);
    assert_layout!(CERT_CHAIN_PARA, win::CERT_CHAIN_PARA);
    assert_layout!(CERT_TRUST_STATUS, win::CERT_TRUST_STATUS);
    assert_layout!(CERT_CHAIN_ELEMENT, win::CERT_CHAIN_ELEMENT);
    assert_layout!(CERT_SIMPLE_CHAIN, win::CERT_SIMPLE_CHAIN);
    assert_layout!(CERT_CHAIN_CONTEXT, win::CERT_CHAIN_CONTEXT);
    assert_layout!(CERT_CHAIN_POLICY_PARA, win::CERT_CHAIN_POLICY_PARA);
    assert_layout!(CERT_CHAIN_POLICY_STATUS, win::CERT_CHAIN_POLICY_STATUS);
};

fn not_implemented<T: Copy>(failure: T) -> T {
    unsafe { foundation::SetLastError(ERROR_CALL_NOT_IMPLEMENTED) };
    failure
}

pub fn GetLastError() -> DWORD {
    unsafe { foundation::GetLastError() }
}

pub fn SetLastError(error: DWORD) {
    unsafe { foundation::SetLastError(error) };
}

pub fn SysCertGetLastErrorMessage() -> *const c_char {
    not_implemented(ptr::null())
}

pub fn CryptStringToBinaryA(
    string: LPCSTR,
    string_length: DWORD,
    flags: DWORD,
    binary: *mut BYTE,
    binary_size: *mut DWORD,
    skipped: *mut DWORD,
    actual_flags: *mut DWORD,
) -> BOOL {
    unsafe {
        win::CryptStringToBinaryA(
            string.cast(),
            string_length,
            flags,
            binary,
            binary_size,
            skipped,
            actual_flags,
        )
    }
}

pub fn CryptBinaryToStringA(
    binary: *const BYTE,
    binary_size: DWORD,
    flags: DWORD,
    string: *mut c_char,
    string_size: *mut DWORD,
) -> BOOL {
    unsafe { win::CryptBinaryToStringA(binary, binary_size, flags, string.cast(), string_size) }
}

pub fn CertNameToStrA(
    encoding: DWORD,
    name: *const CERT_NAME_BLOB,
    string_type: DWORD,
    output: *mut c_char,
    output_size: DWORD,
) -> DWORD {
    unsafe {
        win::CertNameToStrA(
            encoding,
            name.cast(),
            string_type,
            output.cast(),
            output_size,
        )
    }
}

pub fn CertGetNameStringA(
    certificate: *const CERT_CONTEXT,
    name_type: DWORD,
    flags: DWORD,
    type_parameter: *const c_void,
    output: *mut c_char,
    output_size: DWORD,
) -> DWORD {
    unsafe {
        win::CertGetNameStringA(
            certificate.cast(),
            name_type,
            flags,
            type_parameter,
            output.cast(),
            output_size,
        )
    }
}

pub fn SysCertConfigureSystemStores(_: *const SYS_CERT_STORE_CONFIGURATION) -> BOOL {
    not_implemented(FALSE)
}

pub fn SysCertGetCertificateStoreLocation(_: *const CERT_CONTEXT, _: *mut DWORD) -> BOOL {
    not_implemented(FALSE)
}

pub fn CertOpenStore(
    provider: LPCSTR,
    encoding: DWORD,
    legacy: HCRYPTPROV_LEGACY,
    flags: DWORD,
    parameter: *const c_void,
) -> HCERTSTORE {
    unsafe { win::CertOpenStore(provider.cast(), encoding, legacy, flags, parameter) }
}

pub fn CertOpenSystemStoreW(legacy: HCRYPTPROV_LEGACY, name: LPCWSTR) -> HCERTSTORE {
    unsafe { win::CertOpenSystemStoreW(legacy, name) }
}

pub fn CertOpenSystemStoreA(legacy: HCRYPTPROV_LEGACY, name: LPCSTR) -> HCERTSTORE {
    unsafe { win::CertOpenSystemStoreA(legacy, name.cast()) }
}

pub fn CertDuplicateStore(handle: HCERTSTORE) -> HCERTSTORE {
    unsafe { win::CertDuplicateStore(handle) }
}

pub fn CertCloseStore(handle: HCERTSTORE, flags: DWORD) -> BOOL {
    unsafe { win::CertCloseStore(handle, flags) }
}

pub fn CertCreateCertificateContext(
    encoding: DWORD,
    encoded: *const BYTE,
    size: DWORD,
) -> *const CERT_CONTEXT {
    unsafe { win::CertCreateCertificateContext(encoding, encoded, size).cast() }
}

pub fn CertDuplicateCertificateContext(context: *const CERT_CONTEXT) -> *const CERT_CONTEXT {
    unsafe { win::CertDuplicateCertificateContext(context.cast()).cast() }
}

pub fn CertFreeCertificateContext(context: *const CERT_CONTEXT) -> BOOL {
    unsafe { win::CertFreeCertificateContext(context.cast()) }
}

pub fn CertEnumCertificatesInStore(
    handle: HCERTSTORE,
    previous: *const CERT_CONTEXT,
) -> *const CERT_CONTEXT {
    unsafe { win::CertEnumCertificatesInStore(handle, previous.cast()).cast() }
}

pub fn CertFindCertificateInStore(
    handle: HCERTSTORE,
    encoding: DWORD,
    flags: DWORD,
    kind: DWORD,
    parameter: *const c_void,
    previous: *const CERT_CONTEXT,
) -> *const CERT_CONTEXT {
    unsafe {
        win::CertFindCertificateInStore(handle, encoding, flags, kind, parameter, previous.cast())
            .cast()
    }
}

pub fn CertGetSubjectCertificateFromStore(
    handle: HCERTSTORE,
    encoding: DWORD,
    information: *mut CERT_INFO,
) -> *const CERT_CONTEXT {
    unsafe { win::CertGetSubjectCertificateFromStore(handle, encoding, information.cast()).cast() }
}

pub fn CertGetIssuerCertificateFromStore(
    handle: HCERTSTORE,
    subject: *const CERT_CONTEXT,
    previous: *const CERT_CONTEXT,
    flags: *mut DWORD,
) -> *const CERT_CONTEXT {
    unsafe {
        win::CertGetIssuerCertificateFromStore(handle, subject.cast(), previous.cast(), flags)
            .cast()
    }
}

pub fn CertAddCertificateContextToStore(
    handle: HCERTSTORE,
    context: *const CERT_CONTEXT,
    disposition: DWORD,
    result: *mut *const CERT_CONTEXT,
) -> BOOL {
    unsafe {
        win::CertAddCertificateContextToStore(handle, context.cast(), disposition, result.cast())
    }
}

pub fn CertAddEncodedCertificateToStore(
    handle: HCERTSTORE,
    encoding: DWORD,
    encoded: *const BYTE,
    size: DWORD,
    disposition: DWORD,
    result: *mut *const CERT_CONTEXT,
) -> BOOL {
    unsafe {
        win::CertAddEncodedCertificateToStore(
            handle,
            encoding,
            encoded,
            size,
            disposition,
            result.cast(),
        )
    }
}

pub fn CertDeleteCertificateFromStore(context: *const CERT_CONTEXT) -> BOOL {
    unsafe { win::CertDeleteCertificateFromStore(context.cast()) }
}

pub fn CertGetCertificateContextProperty(
    context: *const CERT_CONTEXT,
    property: DWORD,
    data: *mut c_void,
    size: *mut DWORD,
) -> BOOL {
    unsafe { win::CertGetCertificateContextProperty(context.cast(), property, data, size) }
}

pub fn CertSetCertificateContextProperty(
    context: *const CERT_CONTEXT,
    property: DWORD,
    flags: DWORD,
    data: *const c_void,
) -> BOOL {
    unsafe { win::CertSetCertificateContextProperty(context.cast(), property, flags, data) }
}

pub fn CertEnumCertificateContextProperties(
    context: *const CERT_CONTEXT,
    previous: DWORD,
) -> DWORD {
    unsafe { win::CertEnumCertificateContextProperties(context.cast(), previous) }
}

pub fn CertGetStoreProperty(
    handle: HCERTSTORE,
    property: DWORD,
    data: *mut c_void,
    size: *mut DWORD,
) -> BOOL {
    unsafe { win::CertGetStoreProperty(handle, property, data, size) }
}

pub fn CertSetStoreProperty(
    handle: HCERTSTORE,
    property: DWORD,
    flags: DWORD,
    data: *const c_void,
) -> BOOL {
    unsafe { win::CertSetStoreProperty(handle, property, flags, data) }
}

pub fn CertControlStore(
    handle: HCERTSTORE,
    flags: DWORD,
    control: DWORD,
    parameter: *const c_void,
) -> BOOL {
    unsafe { win::CertControlStore(handle, flags, control, parameter) }
}

pub fn CertSaveStore(
    handle: HCERTSTORE,
    encoding: DWORD,
    save_as: DWORD,
    save_to: DWORD,
    parameter: *mut c_void,
    flags: DWORD,
) -> BOOL {
    unsafe { win::CertSaveStore(handle, encoding, save_as, save_to, parameter, flags) }
}

#[allow(clippy::too_many_arguments)]
pub fn CertGetCertificateChain(
    chain_engine: HCERTCHAINENGINE,
    certificate: *const CERT_CONTEXT,
    time: *const FILETIME,
    additional_store: HCERTSTORE,
    parameters: *const CERT_CHAIN_PARA,
    flags: DWORD,
    reserved: *mut c_void,
    chain_context: *mut *const CERT_CHAIN_CONTEXT,
) -> BOOL {
    unsafe {
        win::CertGetCertificateChain(
            chain_engine,
            certificate.cast(),
            time.cast(),
            additional_store,
            parameters.cast(),
            flags,
            reserved,
            chain_context.cast(),
        )
    }
}

pub fn CertFreeCertificateChain(chain: *const CERT_CHAIN_CONTEXT) {
    unsafe { win::CertFreeCertificateChain(chain.cast()) };
}

pub fn CertVerifyCertificateChainPolicy(
    policy: LPCSTR,
    chain: *const CERT_CHAIN_CONTEXT,
    parameters: *const CERT_CHAIN_POLICY_PARA,
    status: *mut CERT_CHAIN_POLICY_STATUS,
) -> BOOL {
    unsafe {
        win::CertVerifyCertificateChainPolicy(
            policy.cast(),
            chain.cast(),
            parameters.cast(),
            status.cast(),
        )
    }
}

pub fn SysCertUpdateTrustAnchor(
    _: *const CERT_CONTEXT,
    _: BOOL,
    _: *const SYS_CERT_NATIVE_OPTIONS,
    _: DWORD,
) -> BOOL {
    not_implemented(FALSE)
}

pub fn SysCertImportPfxToStore(
    _: HCERTSTORE,
    _: *const CRYPT_DATA_BLOB,
    _: LPCWSTR,
    _: DWORD,
) -> BOOL {
    not_implemented(FALSE)
}

pub fn PFXImportCertStore(
    pfx: *mut CRYPT_DATA_BLOB,
    password: LPCWSTR,
    flags: DWORD,
) -> HCERTSTORE {
    unsafe { win::PFXImportCertStore(pfx.cast(), password, flags) }
}

pub fn PFXExportCertStoreEx(
    handle: HCERTSTORE,
    pfx: *mut CRYPT_DATA_BLOB,
    password: LPCWSTR,
    parameter: *mut c_void,
    flags: DWORD,
) -> BOOL {
    unsafe {
        win::PFXExportCertStoreEx(handle, pfx.cast(), password, parameter.cast_const(), flags)
    }
}

pub fn SysCertGetCertificateFilePath(
    _: *const CERT_CONTEXT,
    _: BOOL,
    _: *mut c_char,
    _: *mut DWORD,
) -> BOOL {
    not_implemented(FALSE)
}

pub fn SysCertPopulateDotNetCrlCache(_: LPCSTR) -> BOOL {
    not_implemented(FALSE)
}

pub fn CertEnumSystemStoreLocation(
    flags: DWORD,
    argument: *mut c_void,
    callback: PFN_CERT_ENUM_SYSTEM_STORE_LOCATION,
) -> BOOL {
    unsafe { win::CertEnumSystemStoreLocation(flags, argument, callback) }
}

pub fn CertEnumSystemStore(
    flags: DWORD,
    location_parameter: *mut c_void,
    argument: *mut c_void,
    callback: PFN_CERT_ENUM_SYSTEM_STORE,
) -> BOOL {
    let callback = unsafe {
        mem::transmute::<PFN_CERT_ENUM_SYSTEM_STORE, win::PFN_CERT_ENUM_SYSTEM_STORE>(callback)
    };
    unsafe { win::CertEnumSystemStore(flags, location_parameter, argument, callback) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_system_store_round_trip() {
        let mut name = "ROOT".encode_utf16().collect::<Vec<_>>();
        name.push(0);
        let store = CertOpenSystemStoreW(0, name.as_ptr());
        assert!(!store.is_null());
        assert_ne!(CertCloseStore(store, 0), FALSE);
    }

    #[test]
    fn unsupported_extensions_report_not_implemented() {
        assert_eq!(SysCertConfigureSystemStores(ptr::null()), FALSE);
        assert_eq!(GetLastError(), ERROR_CALL_NOT_IMPLEMENTED);
    }
}
