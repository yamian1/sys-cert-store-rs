use crate::api_types::*;
use crate::{
    CertCloseStore, CertCreateCertificateContext, CertDuplicateCertificateContext,
    CertEnumCertificatesInStore, CertFreeCertificateChain, CertFreeCertificateContext,
    CertGetCertificateChain, CertOpenStore, CertOpenSystemStoreW, GetLastError,
};
use core::fmt;
use core::ptr;
use std::ptr::NonNull;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    code: DWORD,
}

impl Error {
    pub fn code(self) -> DWORD {
        self.code
    }

    fn last() -> Self {
        Self {
            code: GetLastError(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "certificate-store operation failed (0x{:08x})",
            self.code
        )
    }
}

impl std::error::Error for Error {}

pub struct CertificateStore {
    raw: NonNull<core::ffi::c_void>,
}

impl CertificateStore {
    pub fn open_system(name: &str) -> Result<Self, Error> {
        let name = wide(name);
        // SAFETY: `name` is a live, terminated UTF-16 string for the duration
        // of the synchronous call.
        let raw = unsafe { CertOpenSystemStoreW(0, name.as_ptr()) };
        Self::from_result(raw)
    }

    pub fn open_system_with_flags(name: &str, flags: DWORD) -> Result<Self, Error> {
        let name = wide(name);
        // SAFETY: the provider is the documented integer provider constant and
        // `name` is a live, terminated UTF-16 string for the synchronous call.
        let raw = unsafe {
            CertOpenStore(
                PROVIDER_SYSTEM_W as LPCSTR,
                0,
                0,
                flags,
                name.as_ptr().cast(),
            )
        };
        Self::from_result(raw)
    }

    fn from_result(raw: HCERTSTORE) -> Result<Self, Error> {
        NonNull::new(raw)
            .map(|raw| Self { raw })
            .ok_or_else(Error::last)
    }

    /// Takes ownership of one live store handle.
    ///
    /// # Safety
    ///
    /// `raw` must be a non-null store handle returned by this crate for the
    /// current platform. The caller transfers responsibility for closing that
    /// handle exactly once.
    pub unsafe fn from_raw_owned(raw: HCERTSTORE) -> Result<Self, Error> {
        Self::from_result(raw)
    }

    pub fn as_raw(&self) -> HCERTSTORE {
        self.raw.as_ptr()
    }

    pub fn certificates(&self) -> Result<Vec<CertificateContextHandle>, Error> {
        let mut result = Vec::new();
        let mut previous = ptr::null();
        loop {
            // SAFETY: `self` keeps the store live. `previous` is either null or
            // the result of the preceding call and is consumed by this call.
            let current = unsafe { CertEnumCertificatesInStore(self.as_raw(), previous) };
            if current.is_null() {
                return if GetLastError() == CRYPT_E_NOT_FOUND {
                    Ok(result)
                } else {
                    Err(Error::last())
                };
            }
            // SAFETY: `current` is live until the next enumeration call.
            let duplicate = unsafe { CertDuplicateCertificateContext(current) };
            match CertificateContextHandle::from_result(duplicate) {
                Ok(context) => result.push(context),
                Err(error) => {
                    // SAFETY: enumeration transferred the current live
                    // reference to this call site and no subsequent call will
                    // consume it after this early return.
                    let _ = unsafe { CertFreeCertificateContext(current) };
                    return Err(error);
                }
            }
            previous = current;
        }
    }
}

impl Drop for CertificateStore {
    fn drop(&mut self) {
        let _ = CertCloseStore(self.as_raw(), 0);
    }
}

pub struct CertificateContextHandle {
    raw: NonNull<CERT_CONTEXT>,
}

impl CertificateContextHandle {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let size = DWORD::try_from(der.len()).map_err(|_| Error {
            code: ERROR_INVALID_PARAMETER,
        })?;
        // SAFETY: `der` is readable for `size` bytes for the synchronous call.
        let raw = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), size) };
        Self::from_result(raw)
    }

    fn from_result(raw: *const CERT_CONTEXT) -> Result<Self, Error> {
        NonNull::new(raw.cast_mut())
            .map(|raw| Self { raw })
            .ok_or_else(Error::last)
    }

    /// Takes ownership of one live certificate-context reference.
    ///
    /// # Safety
    ///
    /// `raw` must be a non-null live context returned by this crate for the
    /// current platform. The caller transfers one reference that has not been
    /// released or consumed elsewhere.
    pub unsafe fn from_raw_owned(raw: *const CERT_CONTEXT) -> Result<Self, Error> {
        Self::from_result(raw)
    }

    pub fn try_clone(&self) -> Result<Self, Error> {
        // SAFETY: this wrapper owns a live reference for the duration of the
        // call; duplication creates an independent owned reference.
        let raw = unsafe { CertDuplicateCertificateContext(self.as_ptr()) };
        Self::from_result(raw)
    }

    pub fn as_ptr(&self) -> *const CERT_CONTEXT {
        self.raw.as_ptr()
    }
}

impl Drop for CertificateContextHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns exactly one live reference and Drop runs at
        // most once.
        let _ = unsafe { CertFreeCertificateContext(self.as_ptr()) };
    }
}

pub struct CertificateChainHandle {
    raw: NonNull<CERT_CHAIN_CONTEXT>,
}

impl CertificateChainHandle {
    pub fn build(
        certificate: &CertificateContextHandle,
        additional_store: Option<&CertificateStore>,
    ) -> Result<Self, Error> {
        let parameters = CERT_CHAIN_PARA {
            cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as DWORD,
            ..CERT_CHAIN_PARA::default()
        };
        let mut raw = ptr::null();
        // SAFETY: the wrappers keep the context and optional store live, the
        // parameter structure is initialized, and `raw` is writable.
        let succeeded = unsafe {
            CertGetCertificateChain(
                ptr::null_mut(),
                certificate.as_ptr(),
                ptr::null(),
                additional_store.map_or(ptr::null_mut(), CertificateStore::as_raw),
                &parameters,
                0,
                ptr::null_mut(),
                &mut raw,
            )
        };
        if succeeded == FALSE {
            return Err(Error::last());
        }
        Self::from_result(raw)
    }

    fn from_result(raw: *const CERT_CHAIN_CONTEXT) -> Result<Self, Error> {
        NonNull::new(raw.cast_mut())
            .map(|raw| Self { raw })
            .ok_or_else(Error::last)
    }

    /// Takes ownership of one live certificate-chain allocation.
    ///
    /// # Safety
    ///
    /// `raw` must be a non-null live chain returned by this crate for the
    /// current platform. The caller transfers responsibility for freeing that
    /// chain exactly once.
    pub unsafe fn from_raw_owned(raw: *const CERT_CHAIN_CONTEXT) -> Result<Self, Error> {
        Self::from_result(raw)
    }

    pub fn as_ptr(&self) -> *const CERT_CHAIN_CONTEXT {
        self.raw.as_ptr()
    }
}

impl Drop for CertificateChainHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns exactly one live chain and Drop runs at
        // most once.
        unsafe { CertFreeCertificateChain(self.as_ptr()) };
    }
}

fn wide(value: &str) -> Vec<WCHAR> {
    value.encode_utf16().chain([0]).collect()
}
