#![allow(non_camel_case_types, non_snake_case, dead_code)]

use libc::{c_char, c_int, c_void, wchar_t};

pub type BYTE = u8;
pub type DWORD = u32;
pub type BOOL = i32;
pub type WCHAR = wchar_t;
pub type LPCSTR = *const c_char;
pub type LPCWSTR = *const WCHAR;
pub type HCRYPTPROV_LEGACY = usize;
pub type HCERTSTORE = *mut c_void;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CRYPT_DATA_BLOB {
    pub cbData: DWORD,
    pub pbData: *mut BYTE,
}
pub type CRYPT_INTEGER_BLOB = CRYPT_DATA_BLOB;
pub type CRYPT_HASH_BLOB = CRYPT_DATA_BLOB;
pub type CERT_NAME_BLOB = CRYPT_DATA_BLOB;
pub type CRYPT_OBJID_BLOB = CRYPT_DATA_BLOB;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CRYPT_BIT_BLOB {
    pub cbData: DWORD,
    pub pbData: *mut BYTE,
    pub cUnusedBits: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FILETIME {
    pub dwLowDateTime: DWORD,
    pub dwHighDateTime: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CRYPT_ALGORITHM_IDENTIFIER {
    pub pszObjId: *mut c_char,
    pub Parameters: CRYPT_OBJID_BLOB,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CERT_PUBLIC_KEY_INFO {
    pub Algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub PublicKey: CRYPT_BIT_BLOB,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CERT_EXTENSION {
    pub pszObjId: *mut c_char,
    pub fCritical: BOOL,
    pub Value: CRYPT_OBJID_BLOB,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CERT_INFO {
    pub dwVersion: DWORD,
    pub SerialNumber: CRYPT_INTEGER_BLOB,
    pub SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub Issuer: CERT_NAME_BLOB,
    pub NotBefore: FILETIME,
    pub NotAfter: FILETIME,
    pub Subject: CERT_NAME_BLOB,
    pub SubjectPublicKeyInfo: CERT_PUBLIC_KEY_INFO,
    pub IssuerUniqueId: CRYPT_BIT_BLOB,
    pub SubjectUniqueId: CRYPT_BIT_BLOB,
    pub cExtension: DWORD,
    pub rgExtension: *mut CERT_EXTENSION,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CERT_CONTEXT {
    pub dwCertEncodingType: DWORD,
    pub pbCertEncoded: *mut BYTE,
    pub cbCertEncoded: DWORD,
    pub pCertInfo: *mut CERT_INFO,
    pub hCertStore: HCERTSTORE,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CERT_SYSTEM_STORE_INFO {
    pub cbSize: DWORD,
}

pub type PFN_CERT_ENUM_SYSTEM_STORE = Option<
    unsafe extern "C" fn(
        *const c_void,
        DWORD,
        *mut CERT_SYSTEM_STORE_INFO,
        *mut c_void,
        *mut c_void,
    ) -> BOOL,
>;
pub type PFN_CERT_ENUM_SYSTEM_STORE_LOCATION =
    Option<unsafe extern "C" fn(LPCWSTR, DWORD, *mut c_void, *mut c_void) -> BOOL>;

#[repr(C)]
pub struct SYS_CERT_NATIVE_OPTIONS {
    pub cbSize: DWORD,
    pub rootPath: *const c_char,
}

#[repr(C)]
pub struct SYS_CERT_STORE_CONFIGURATION {
    pub cbSize: DWORD,
    pub userStoreDirectory: *const c_char,
    pub machineStoreDirectory: *const c_char,
    pub systemRoot: *const c_char,
}

pub const X509_ASN_ENCODING: DWORD = 1;
pub const PKCS_7_ASN_ENCODING: DWORD = 0x10000;
pub const CERT_SYSTEM_STORE_CURRENT_USER: DWORD = 0x10000;
pub const CERT_SYSTEM_STORE_LOCAL_MACHINE: DWORD = 0x20000;
pub const CERT_STORE_READONLY_FLAG: DWORD = 0x8000;
pub const CERT_STORE_OPEN_EXISTING_FLAG: DWORD = 0x4000;
pub const CERT_STORE_CREATE_NEW_FLAG: DWORD = 0x2000;
pub const CERT_STORE_ENUM_ARCHIVED_FLAG: DWORD = 0x200;
pub const CERT_CLOSE_STORE_CHECK_FLAG: DWORD = 2;
pub const CERT_CLOSE_STORE_FORCE_FLAG: DWORD = 1;
pub const CERT_STORE_ADD_NEW: DWORD = 1;
pub const CERT_STORE_ADD_USE_EXISTING: DWORD = 2;
pub const CERT_STORE_ADD_REPLACE_EXISTING: DWORD = 3;
pub const CERT_STORE_ADD_ALWAYS: DWORD = 4;
pub const CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES: DWORD = 5;
pub const CERT_STORE_ADD_NEWER: DWORD = 6;
pub const CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES: DWORD = 7;
pub const CERT_KEY_PROV_INFO_PROP_ID: DWORD = 2;
pub const CERT_SHA1_HASH_PROP_ID: DWORD = 3;
pub const CERT_MD5_HASH_PROP_ID: DWORD = 4;
pub const CERT_KEY_CONTEXT_PROP_ID: DWORD = 5;
pub const CERT_FRIENDLY_NAME_PROP_ID: DWORD = 11;
pub const CERT_DESCRIPTION_PROP_ID: DWORD = 13;
pub const CERT_ARCHIVED_PROP_ID: DWORD = 19;
pub const CERT_KEY_IDENTIFIER_PROP_ID: DWORD = 20;
pub const CERT_NCRYPT_KEY_HANDLE_PROP_ID: DWORD = 78;
pub const CERT_SHA256_HASH_PROP_ID: DWORD = 107;
pub const CERT_FIRST_USER_PROP_ID: DWORD = 0x8000;
pub const CERT_LAST_USER_PROP_ID: DWORD = 0xffff;
pub const CERT_STORE_LOCALIZED_NAME_PROP_ID: DWORD = 0x1000;
pub const CERT_FIND_ANY: DWORD = 0;
pub const CERT_FIND_SHA1_HASH: DWORD = 1 << 16;
pub const CERT_FIND_MD5_HASH: DWORD = 4 << 16;
pub const CERT_FIND_SHA256_HASH: DWORD = 22 << 16;
pub const CERT_FIND_SUBJECT_NAME: DWORD = (2 << 16) | 7;
pub const CERT_FIND_ISSUER_NAME: DWORD = (2 << 16) | 4;
pub const CERT_FIND_SUBJECT_STR_A: DWORD = (7 << 16) | 7;
pub const CERT_FIND_SUBJECT_STR_W: DWORD = (8 << 16) | 7;
pub const CERT_FIND_ISSUER_STR_A: DWORD = (7 << 16) | 4;
pub const CERT_FIND_ISSUER_STR_W: DWORD = (8 << 16) | 4;
pub const CERT_FIND_PROPERTY: DWORD = 5 << 16;
pub const CERT_FIND_SUBJECT_CERT: DWORD = 11 << 16;
pub const CERT_FIND_ISSUER_OF: DWORD = 12 << 16;
pub const CERT_FIND_EXISTING: DWORD = 13 << 16;
pub const CERT_FIND_KEY_IDENTIFIER: DWORD = 15 << 16;
pub const CERT_STORE_SIGNATURE_FLAG: DWORD = 1;
pub const CERT_STORE_TIME_VALIDITY_FLAG: DWORD = 2;
pub const CERT_STORE_REVOCATION_FLAG: DWORD = 4;
pub const CERT_STORE_NO_CRL_FLAG: DWORD = 0x10000;
pub const CERT_STORE_NO_ISSUER_FLAG: DWORD = 0x20000;
pub const CERT_STORE_CTRL_RESYNC: DWORD = 1;
pub const CERT_STORE_CTRL_COMMIT: DWORD = 3;
pub const CERT_STORE_SAVE_AS_PKCS7: DWORD = 2;
pub const CERT_STORE_SAVE_TO_MEMORY: DWORD = 2;
pub const CRYPT_EXPORTABLE: DWORD = 1;
pub const CRYPT_USER_KEYSET: DWORD = 0x1000;
pub const CRYPT_MACHINE_KEYSET: DWORD = 0x20;
pub const PKCS12_NO_PERSIST_KEY: DWORD = 0x8000;
pub const SYS_CERT_TRUST_UPDATE_ALLOW: DWORD = 1;
pub const SYS_CERT_STORE_NATIVE_WRITE_FLAG: DWORD = 0x10000000;

pub const ERROR_SUCCESS: DWORD = 0;
pub const ERROR_FILE_NOT_FOUND: DWORD = 2;
pub const ERROR_ACCESS_DENIED: DWORD = 5;
pub const ERROR_INVALID_HANDLE: DWORD = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: DWORD = 8;
pub const ERROR_INVALID_DATA: DWORD = 13;
pub const ERROR_GEN_FAILURE: DWORD = 31;
pub const ERROR_NOT_SUPPORTED: DWORD = 50;
pub const ERROR_INVALID_PARAMETER: DWORD = 87;
pub const ERROR_BUSY: DWORD = 170;
pub const ERROR_MORE_DATA: DWORD = 234;
pub const E_INVALIDARG: DWORD = 0x80070057;
pub const CRYPT_E_NOT_FOUND: DWORD = 0x80092004;
pub const CRYPT_E_EXISTS: DWORD = 0x80092005;
pub const CRYPT_E_SELF_SIGNED: DWORD = 0x80092007;
pub const CRYPT_E_NO_MATCH: DWORD = 0x80092009;
pub const CRYPT_E_PENDING_CLOSE: DWORD = 0x8009200f;

pub const PROVIDER_MEMORY: usize = 2;
pub const PROVIDER_SYSTEM_A: usize = 9;
pub const PROVIDER_SYSTEM_W: usize = 10;

pub fn bool_value(value: bool) -> BOOL {
    if value { TRUE } else { FALSE }
}

pub fn dword(value: usize) -> Result<DWORD, crate::error::ApiError> {
    value.try_into().map_err(|_| {
        crate::error::ApiError::new(ERROR_INVALID_DATA, "Value exceeds DWORD capacity")
    })
}

pub type c_callback_result = c_int;
