#![allow(non_snake_case)]

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
    unsafe { win::CryptBinaryToStringA(binary, binary_size, flags, string.cast(), string_size) }
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

/// Configures Linux system-store locations.
///
/// # Safety
///
/// A non-null configuration must point to a live structure and to valid
/// terminated strings for every populated field.
pub unsafe fn SysCertConfigureSystemStores(_: *const SYS_CERT_STORE_CONFIGURATION) -> BOOL {
    not_implemented(FALSE)
}

/// Gets the configured location of a certificate context.
///
/// # Safety
///
/// The context must be live and produced by this API. The output pointer must
/// be writable when non-null.
pub unsafe fn SysCertGetCertificateStoreLocation(_: *const CERT_CONTEXT, _: *mut DWORD) -> BOOL {
    not_implemented(FALSE)
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
    unsafe { win::CertOpenStore(provider.cast(), encoding, legacy, flags, parameter) }
}

/// Opens a UTF-16 named system store.
///
/// # Safety
///
/// `name` must point to a readable, terminated UTF-16 string.
pub unsafe fn CertOpenSystemStoreW(legacy: HCRYPTPROV_LEGACY, name: LPCWSTR) -> HCERTSTORE {
    unsafe { win::CertOpenSystemStoreW(legacy, name) }
}

/// Opens an ANSI named system store.
///
/// # Safety
///
/// `name` must point to a readable, terminated string.
pub unsafe fn CertOpenSystemStoreA(legacy: HCRYPTPROV_LEGACY, name: LPCSTR) -> HCERTSTORE {
    unsafe { win::CertOpenSystemStoreA(legacy, name.cast()) }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn CertDuplicateStore(handle: HCERTSTORE) -> HCERTSTORE {
    // Opaque handles are validated by CryptoAPI; no caller-provided memory is
    // read through this value.
    unsafe { win::CertDuplicateStore(handle) }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn CertCloseStore(handle: HCERTSTORE, flags: DWORD) -> BOOL {
    // Opaque handles are validated by CryptoAPI; invalid values are reported
    // as handle errors rather than dereferenced as caller-provided memory.
    unsafe { win::CertCloseStore(handle, flags) }
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
    unsafe { win::CertCreateCertificateContext(encoding, encoded, size).cast() }
}

/// Duplicates one live certificate-context reference.
///
/// # Safety
///
/// `context` must be null or a live context accepted by the current backend.
pub unsafe fn CertDuplicateCertificateContext(context: *const CERT_CONTEXT) -> *const CERT_CONTEXT {
    unsafe { win::CertDuplicateCertificateContext(context.cast()).cast() }
}

/// Releases one owned certificate-context reference.
///
/// # Safety
///
/// `context` must be null or one live owned reference returned by the current
/// backend, and that reference must not be used after this call.
pub unsafe fn CertFreeCertificateContext(context: *const CERT_CONTEXT) -> BOOL {
    unsafe { win::CertFreeCertificateContext(context.cast()) }
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
    unsafe { win::CertEnumCertificatesInStore(handle, previous.cast()).cast() }
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
    unsafe {
        win::CertFindCertificateInStore(handle, encoding, flags, kind, parameter, previous.cast())
            .cast()
    }
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
    unsafe { win::CertGetSubjectCertificateFromStore(handle, encoding, information.cast()).cast() }
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
    unsafe {
        win::CertGetIssuerCertificateFromStore(handle, subject.cast(), previous.cast(), flags)
            .cast()
    }
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
    unsafe {
        win::CertAddCertificateContextToStore(handle, context.cast(), disposition, result.cast())
    }
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

/// Deletes a certificate and consumes its context reference.
///
/// # Safety
///
/// `context` must be one live owned store context and must not be used after
/// the call, whether deletion succeeds or fails according to backend rules.
pub unsafe fn CertDeleteCertificateFromStore(context: *const CERT_CONTEXT) -> BOOL {
    unsafe { win::CertDeleteCertificateFromStore(context.cast()) }
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
    unsafe { win::CertGetCertificateContextProperty(context.cast(), property, data, size) }
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
    unsafe { win::CertSetCertificateContextProperty(context.cast(), property, flags, data) }
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
    unsafe { win::CertEnumCertificateContextProperties(context.cast(), previous) }
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
    unsafe { win::CertGetStoreProperty(handle, property, data, size) }
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
    unsafe { win::CertSetStoreProperty(handle, property, flags, data) }
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
    unsafe { win::CertControlStore(handle, flags, control, parameter) }
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
    unsafe { win::CertSaveStore(handle, encoding, save_as, save_to, parameter, flags) }
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

/// Releases one certificate-chain allocation.
///
/// # Safety
///
/// `chain` must be null or the live chain returned by this backend. A non-null
/// chain must be freed exactly once and not accessed afterward.
pub unsafe fn CertFreeCertificateChain(chain: *const CERT_CHAIN_CONTEXT) {
    unsafe { win::CertFreeCertificateChain(chain.cast()) };
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
    unsafe {
        win::CertVerifyCertificateChainPolicy(
            policy.cast(),
            chain.cast(),
            parameters.cast(),
            status.cast(),
        )
    }
}

/// Updates native trust for a certificate.
///
/// # Safety
///
/// The certificate must be live, and a non-null options pointer must identify
/// a live options structure with valid nested data.
pub unsafe fn SysCertUpdateTrustAnchor(
    _: *const CERT_CONTEXT,
    _: BOOL,
    _: *const SYS_CERT_NATIVE_OPTIONS,
    _: DWORD,
) -> BOOL {
    not_implemented(FALSE)
}

/// Imports a readable PFX blob into a store.
///
/// # Safety
///
/// The blob and its data must be readable. A non-null password must be a
/// readable terminated UTF-16 string.
pub unsafe fn SysCertImportPfxToStore(
    _: HCERTSTORE,
    _: *const CRYPT_DATA_BLOB,
    _: LPCWSTR,
    _: DWORD,
) -> BOOL {
    not_implemented(FALSE)
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
    unsafe { win::PFXImportCertStore(pfx.cast(), password, flags) }
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
    unsafe {
        win::PFXExportCertStoreEx(handle, pfx.cast(), password, parameter.cast_const(), flags)
    }
}

/// Gets a persisted path for a live certificate context.
///
/// # Safety
///
/// The context must be live, `size` must be writable, and a non-null path
/// buffer must cover the capacity supplied through `size`.
pub unsafe fn SysCertGetCertificateFilePath(
    _: *const CERT_CONTEXT,
    _: BOOL,
    _: *mut c_char,
    _: *mut DWORD,
) -> BOOL {
    not_implemented(FALSE)
}

/// Populates the .NET CRL cache for an optional account name.
///
/// # Safety
///
/// A non-null account name must point to a readable terminated string.
pub unsafe fn SysCertPopulateDotNetCrlCache(_: LPCSTR) -> BOOL {
    not_implemented(FALSE)
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
    unsafe { win::CertEnumSystemStoreLocation(flags, argument, callback) }
}

/// Enumerates system stores through a callback.
///
/// # Safety
///
/// Location data, `argument`, and callback state must remain valid for the
/// synchronous call. The callback must obey its API contract.
pub unsafe fn CertEnumSystemStore(
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
        // SAFETY: `name` is a live, terminated UTF-16 string.
        let store = unsafe { CertOpenSystemStoreW(0, name.as_ptr()) };
        assert!(!store.is_null());
        assert_ne!(CertCloseStore(store, 0), FALSE);
    }

    #[test]
    fn unsupported_extensions_report_not_implemented() {
        // SAFETY: null selects the documented default configuration.
        assert_eq!(unsafe { SysCertConfigureSystemStores(ptr::null()) }, FALSE);
        assert_eq!(GetLastError(), ERROR_CALL_NOT_IMPLEMENTED);
    }
}
