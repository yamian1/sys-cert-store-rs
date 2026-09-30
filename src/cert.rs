use crate::error::{ApiError, require};
use crate::ffi::*;
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use openssl::hash::{MessageDigest, hash};
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509, X509NameRef};
use openssl_sys as ossl;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::ptr;
use std::sync::Arc;

#[repr(C)]
struct X509PubkeyOpaque {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn ASN1_TIME_to_tm(time: *const ossl::ASN1_TIME, value: *mut libc::tm) -> libc::c_int;
    fn X509_get0_serialNumber(x509: *const ossl::X509) -> *const ossl::ASN1_INTEGER;
    fn X509_get0_tbs_sigalg(x509: *const ossl::X509) -> *const ossl::X509_ALGOR;
    fn X509_get0_notBefore(x509: *const ossl::X509) -> *const ossl::ASN1_TIME;
    fn X509_get0_notAfter(x509: *const ossl::X509) -> *const ossl::ASN1_TIME;
    fn X509_get_X509_PUBKEY(x509: *const ossl::X509) -> *mut X509PubkeyOpaque;
    fn X509_PUBKEY_get0_param(
        object: *mut *mut ossl::ASN1_OBJECT,
        public_key: *mut *const u8,
        public_key_length: *mut libc::c_int,
        algorithm: *mut *mut ossl::X509_ALGOR,
        pubkey: *mut X509PubkeyOpaque,
    ) -> libc::c_int;
    fn X509_get0_pubkey_bitstr(x509: *const ossl::X509) -> *const ossl::ASN1_BIT_STRING;
    fn X509_get0_uids(
        x509: *const ossl::X509,
        issuer: *mut *const ossl::ASN1_BIT_STRING,
        subject: *mut *const ossl::ASN1_BIT_STRING,
    );
}

pub type Properties = BTreeMap<DWORD, Vec<u8>>;

pub struct Context {
    pub public: CERT_CONTEXT,
    pub info: CERT_INFO,
    pub certificate: X509,
    pub der: Vec<u8>,
    buffers: Vec<Box<[u8]>>,
    strings: Vec<CString>,
    extensions: Vec<CERT_EXTENSION>,
    pub properties: Properties,
    pub private_key: Option<Arc<PKey<Private>>>,
    pub object_path: Option<std::path::PathBuf>,
    pub key_path: Option<std::path::PathBuf>,
    pub store_id: Option<usize>,
    pub view_id: Option<usize>,
    pub row: i64,
    pub references: usize,
}

unsafe impl Send for Context {}

impl Context {
    pub fn new(der: Vec<u8>) -> Result<Box<Self>, ApiError> {
        require(
            !der.is_empty() && der.len() <= i32::MAX as usize,
            ERROR_INVALID_DATA,
            "Empty or oversized certificate",
        )?;
        let certificate = X509::from_der(&der).map_err(|_| {
            ApiError::new(
                ERROR_INVALID_DATA,
                "Invalid DER certificate or trailing bytes",
            )
        })?;
        require(
            certificate.to_der()? == der,
            ERROR_INVALID_DATA,
            "Invalid DER certificate or trailing bytes",
        )?;
        let mut result = Box::new(Self {
            public: CERT_CONTEXT::default(),
            info: CERT_INFO::default(),
            certificate,
            der,
            buffers: Vec::new(),
            strings: Vec::new(),
            extensions: Vec::new(),
            properties: BTreeMap::new(),
            private_key: None,
            object_path: None,
            key_path: None,
            store_id: None,
            view_id: None,
            row: 0,
            references: 1,
        });
        result.populate()?;
        Ok(result)
    }

    fn keep(&mut self, data: Vec<u8>) -> CRYPT_DATA_BLOB {
        self.buffers.push(data.into_boxed_slice());
        let value = self.buffers.last_mut().unwrap();
        CRYPT_DATA_BLOB {
            cbData: value.len() as DWORD,
            pbData: value.as_mut_ptr(),
        }
    }

    fn oid(&mut self, object: *const ossl::ASN1_OBJECT) -> Result<*mut libc::c_char, ApiError> {
        let length = unsafe { ossl::OBJ_obj2txt(ptr::null_mut(), 0, object, 1) };
        require(length > 0, ERROR_INVALID_DATA, "Invalid object identifier")?;
        let mut bytes = vec![0u8; length as usize + 1];
        unsafe { ossl::OBJ_obj2txt(bytes.as_mut_ptr().cast(), bytes.len() as i32, object, 1) };
        let value = CString::from_vec_with_nul(bytes)
            .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid object identifier"))?;
        self.strings.push(value);
        Ok(self.strings.last().unwrap().as_ptr().cast_mut())
    }

    fn algorithm(
        &mut self,
        algorithm: *const ossl::X509_ALGOR,
    ) -> Result<CRYPT_ALGORITHM_IDENTIFIER, ApiError> {
        let mut object = ptr::null();
        unsafe { ossl::X509_ALGOR_get0(&mut object, ptr::null_mut(), ptr::null_mut(), algorithm) };
        Ok(CRYPT_ALGORITHM_IDENTIFIER {
            pszObjId: self.oid(object)?,
            Parameters: CRYPT_DATA_BLOB::default(),
        })
    }

    fn bit_blob(&mut self, bits: *const ossl::ASN1_BIT_STRING) -> CRYPT_BIT_BLOB {
        if bits.is_null() {
            return CRYPT_BIT_BLOB::default();
        }
        let size = unsafe { ossl::ASN1_STRING_length(bits.cast()) }.max(0) as usize;
        let data = unsafe { ossl::ASN1_STRING_get0_data(bits.cast()) };
        let value = if size == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, size) }.to_vec()
        };
        let blob = self.keep(value);
        CRYPT_BIT_BLOB {
            cbData: blob.cbData,
            pbData: blob.pbData,
            cUnusedBits: 0,
        }
    }

    fn name_der(&mut self, name: *const ossl::X509_NAME) -> Result<CRYPT_DATA_BLOB, ApiError> {
        let size = unsafe { ossl::i2d_X509_NAME(name, ptr::null_mut()) };
        require(size > 0, ERROR_INVALID_DATA, "ASN.1 encoding failed")?;
        let mut bytes = vec![0u8; size as usize];
        let mut cursor = bytes.as_mut_ptr();
        require(
            unsafe { ossl::i2d_X509_NAME(name, &mut cursor) } == size,
            ERROR_INVALID_DATA,
            "ASN.1 encoding failed",
        )?;
        Ok(self.keep(bytes))
    }

    fn filetime(time: *const ossl::ASN1_TIME) -> Result<FILETIME, ApiError> {
        let mut value: libc::tm = unsafe { std::mem::zeroed() };
        require(
            unsafe { ASN1_TIME_to_tm(time, &mut value) } == 1,
            ERROR_INVALID_DATA,
            "Invalid certificate validity time",
        )?;
        let seconds = unsafe { libc::timegm(&mut value) } as i64 + 11_644_473_600;
        require(
            seconds >= 0,
            ERROR_NOT_SUPPORTED,
            "Certificate time predates FILETIME epoch",
        )?;
        let ticks = seconds as u64 * 10_000_000;
        Ok(FILETIME {
            dwLowDateTime: ticks as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        })
    }

    fn populate(&mut self) -> Result<(), ApiError> {
        let x = self.certificate.as_ptr();
        self.info.dwVersion = unsafe { ossl::X509_get_version(x) } as DWORD;

        let serial = unsafe { X509_get0_serialNumber(x) };
        let serial_type = unsafe { ossl::ASN1_STRING_type(serial.cast()) };
        require(
            serial_type != (ossl::V_ASN1_INTEGER | 0x100),
            ERROR_NOT_SUPPORTED,
            "Negative certificate serial numbers are unsupported",
        )?;
        let serial_size = unsafe { ossl::ASN1_STRING_length(serial.cast()) }.max(0) as usize;
        let serial_data = unsafe { ossl::ASN1_STRING_get0_data(serial.cast()) };
        let mut serial_bytes =
            unsafe { std::slice::from_raw_parts(serial_data, serial_size) }.to_vec();
        serial_bytes.reverse();
        self.info.SerialNumber = self.keep(serial_bytes);

        self.info.SignatureAlgorithm = self.algorithm(unsafe { X509_get0_tbs_sigalg(x) })?;
        self.info.Issuer = self.name_der(unsafe { ossl::X509_get_issuer_name(x) })?;
        self.info.Subject = self.name_der(unsafe { ossl::X509_get_subject_name(x) })?;
        self.info.NotBefore = Self::filetime(unsafe { X509_get0_notBefore(x) })?;
        self.info.NotAfter = Self::filetime(unsafe { X509_get0_notAfter(x) })?;

        let public = unsafe { X509_get_X509_PUBKEY(x) };
        let mut algorithm = ptr::null_mut();
        require(
            unsafe {
                X509_PUBKEY_get0_param(
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut algorithm,
                    public,
                )
            } == 1,
            ERROR_INVALID_DATA,
            "Invalid certificate public key",
        )?;
        self.info.SubjectPublicKeyInfo.Algorithm = self.algorithm(algorithm)?;
        self.info.SubjectPublicKeyInfo.PublicKey =
            self.bit_blob(unsafe { X509_get0_pubkey_bitstr(x) });

        let mut issuer_id = ptr::null();
        let mut subject_id = ptr::null();
        unsafe { X509_get0_uids(x, &mut issuer_id, &mut subject_id) };
        self.info.IssuerUniqueId = self.bit_blob(issuer_id);
        self.info.SubjectUniqueId = self.bit_blob(subject_id);

        let count = unsafe { ossl::X509_get_ext_count(x) };
        for index in 0..count {
            let extension = unsafe { ossl::X509_get_ext(x, index) };
            let data = unsafe { ossl::X509_EXTENSION_get_data(extension) };
            let size = unsafe { ossl::ASN1_STRING_length(data.cast()) }.max(0) as usize;
            let pointer = unsafe { ossl::ASN1_STRING_get0_data(data.cast()) };
            let value = unsafe { std::slice::from_raw_parts(pointer, size) }.to_vec();
            let blob = self.keep(value);
            let oid = self.oid(unsafe { ossl::X509_EXTENSION_get_object(extension) })?;
            self.extensions.push(CERT_EXTENSION {
                pszObjId: oid,
                fCritical: unsafe { ossl::X509_EXTENSION_get_critical(extension) },
                Value: blob,
            });
        }
        self.info.cExtension = self.extensions.len() as DWORD;
        self.info.rgExtension = self.extensions.as_mut_ptr();
        self.public.dwCertEncodingType = X509_ASN_ENCODING;
        self.public.pbCertEncoded = self.der.as_mut_ptr();
        self.public.cbCertEncoded = self.der.len() as DWORD;
        self.public.pCertInfo = &mut self.info;
        Ok(())
    }

    pub fn public_ptr(&self) -> *const CERT_CONTEXT {
        &self.public
    }

    pub fn issuer_der(&self) -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(self.info.Issuer.pbData, self.info.Issuer.cbData as usize)
        }
        .to_vec()
    }

    pub fn serial_le(&self) -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(
                self.info.SerialNumber.pbData,
                self.info.SerialNumber.cbData as usize,
            )
        }
        .to_vec()
    }

    pub fn same_identity(&self, other: &Context) -> bool {
        self.issuer_der() == other.issuer_der() && self.serial_le() == other.serial_le()
    }

    pub fn simple_name(name: &X509NameRef) -> String {
        name.entries()
            .map(|entry| {
                entry
                    .data()
                    .to_string()
                    .unwrap_or_else(|_| "<invalid>".into())
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn property_value(&self, property: DWORD) -> Result<Vec<u8>, ApiError> {
        require(
            supported_property(property),
            ERROR_NOT_SUPPORTED,
            "Certificate property is not supported",
        )?;
        if let Some(value) = self.properties.get(&property) {
            return Ok(value.clone());
        }
        let digest = match property {
            CERT_SHA1_HASH_PROP_ID => Some(MessageDigest::sha1()),
            CERT_SHA256_HASH_PROP_ID => Some(MessageDigest::sha256()),
            CERT_MD5_HASH_PROP_ID => Some(MessageDigest::md5()),
            _ => None,
        };
        if let Some(digest) = digest {
            return Ok(hash(digest, &self.der)?.to_vec());
        }
        if property == CERT_KEY_IDENTIFIER_PROP_ID {
            if let Some(identifier) = self.certificate.subject_key_id() {
                return Ok(identifier.as_slice().to_vec());
            }
            return Ok(hash(
                MessageDigest::sha1(),
                &self.certificate.public_key()?.public_key_to_der()?,
            )?
            .to_vec());
        }
        Err(ApiError::new(
            CRYPT_E_NOT_FOUND,
            "Certificate property is not set",
        ))
    }
}

pub fn supported_property(property: DWORD) -> bool {
    matches!(
        property,
        CERT_FRIENDLY_NAME_PROP_ID
            | CERT_DESCRIPTION_PROP_ID
            | CERT_ARCHIVED_PROP_ID
            | CERT_KEY_IDENTIFIER_PROP_ID
            | CERT_SHA1_HASH_PROP_ID
            | CERT_SHA256_HASH_PROP_ID
            | CERT_MD5_HASH_PROP_ID
    ) || (CERT_FIRST_USER_PROP_ID..=CERT_LAST_USER_PROP_ID).contains(&property)
}

pub fn names_equal(left: &X509NameRef, right: &X509NameRef) -> bool {
    unsafe { ossl::X509_NAME_cmp(left.as_ptr(), right.as_ptr()) == 0 }
}
