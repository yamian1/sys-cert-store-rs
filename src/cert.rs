use crate::crypto::{is_pqc_oid, verify_pqc_certificate};
use crate::error::{ApiError, require};
use crate::ffi::*;
use crate::key::PrivateKey;
use base64ct::{Base64, Encoding};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::Arc;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::*;

pub type Properties = BTreeMap<DWORD, Vec<u8>>;

#[derive(Clone)]
pub struct Certificate {
    der: Vec<u8>,
}

impl Certificate {
    pub fn from_der(der: &[u8]) -> Result<Self, ApiError> {
        require(
            !der.is_empty() && der.len() <= i32::MAX as usize,
            ERROR_INVALID_DATA,
            "Empty or oversized certificate",
        )?;
        let (remaining, _) = parse_x509_certificate(der)
            .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid DER certificate"))?;
        require(
            remaining.is_empty(),
            ERROR_INVALID_DATA,
            "Invalid DER certificate or trailing bytes",
        )?;
        Ok(Self { der: der.to_vec() })
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self, ApiError> {
        let (_, block) = parse_x509_pem(pem)
            .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid certificate PEM object"))?;
        require(
            block.label == "CERTIFICATE",
            ERROR_INVALID_DATA,
            "Invalid certificate PEM label",
        )?;
        Self::from_der(&block.contents)
    }

    fn parsed(&self) -> Result<X509Certificate<'_>, ApiError> {
        parse_x509_certificate(&self.der)
            .map(|(_, certificate)| certificate)
            .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid DER certificate"))
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.der.clone()
    }

    pub fn to_pem(&self) -> Vec<u8> {
        let encoded = Base64::encode_string(&self.der);
        let mut result = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            result.push_str(std::str::from_utf8(chunk).unwrap());
            result.push('\n');
        }
        result.push_str("-----END CERTIFICATE-----\n");
        result.into_bytes()
    }

    pub fn signature_oid(&self) -> Result<String, ApiError> {
        Ok(self.parsed()?.signature_algorithm.algorithm.to_id_string())
    }

    pub fn public_key_oid(&self) -> Result<String, ApiError> {
        Ok(self
            .parsed()?
            .public_key()
            .algorithm
            .algorithm
            .to_id_string())
    }

    pub fn subject_raw(&self) -> Result<Vec<u8>, ApiError> {
        Ok(self.parsed()?.subject().as_raw().to_vec())
    }

    pub fn issuer_raw(&self) -> Result<Vec<u8>, ApiError> {
        Ok(self.parsed()?.issuer().as_raw().to_vec())
    }

    pub fn subject_text(&self) -> Result<String, ApiError> {
        Ok(self.parsed()?.subject().to_string())
    }

    pub fn issuer_text(&self) -> Result<String, ApiError> {
        Ok(self.parsed()?.issuer().to_string())
    }

    pub fn not_before_timestamp(&self) -> Result<i64, ApiError> {
        Ok(self.parsed()?.validity().not_before.timestamp())
    }

    pub fn not_after_timestamp(&self) -> Result<i64, ApiError> {
        Ok(self.parsed()?.validity().not_after.timestamp())
    }

    pub fn not_before_text(&self) -> Result<String, ApiError> {
        Ok(self.parsed()?.validity().not_before.to_string())
    }

    pub fn not_after_text(&self) -> Result<String, ApiError> {
        Ok(self.parsed()?.validity().not_after.to_string())
    }

    pub fn serial_hex(&self) -> Result<String, ApiError> {
        let serial = self.parsed()?.raw_serial().to_vec();
        let first = serial
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(serial.len().saturating_sub(1));
        Ok(hex::encode(&serial[first..]))
    }

    pub fn sha1_fingerprint(&self) -> Vec<u8> {
        Sha1::digest(&self.der).to_vec()
    }

    pub fn sha256_fingerprint(&self) -> Vec<u8> {
        Sha256::digest(&self.der).to_vec()
    }

    pub fn subject_public_key_info(&self) -> Result<Vec<u8>, ApiError> {
        Ok(self.parsed()?.public_key().raw.to_vec())
    }

    pub fn subject_key_identifier(&self) -> Result<Option<Vec<u8>>, ApiError> {
        for extension in self.parsed()?.extensions() {
            if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension()
            {
                return Ok(Some(identifier.0.to_vec()));
            }
        }
        Ok(None)
    }

    pub fn is_ca(&self) -> Result<bool, ApiError> {
        for extension in self.parsed()?.extensions() {
            if let ParsedExtension::BasicConstraints(constraints) = extension.parsed_extension() {
                return Ok(constraints.ca);
            }
        }
        Ok(false)
    }

    pub fn verify_with(&self, issuer: &Certificate) -> Result<bool, ApiError> {
        if is_pqc_oid(&self.signature_oid()?) {
            return verify_pqc_certificate(&self.der, &issuer.der);
        }
        let certificate = self.parsed()?;
        let issuer = issuer.parsed()?;
        Ok(certificate
            .verify_signature(Some(issuer.public_key()))
            .is_ok())
    }

    pub fn self_signed(&self) -> Result<bool, ApiError> {
        Ok(self.subject_raw()? == self.issuer_raw()? && self.verify_with(self)?)
    }
}

pub struct Context {
    pub public: CERT_CONTEXT,
    pub info: CERT_INFO,
    pub certificate: Certificate,
    pub der: Vec<u8>,
    buffers: Vec<Box<[u8]>>,
    strings: Vec<CString>,
    extensions: Vec<CERT_EXTENSION>,
    pub properties: Properties,
    pub private_key: Option<Arc<PrivateKey>>,
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
        let certificate = Certificate::from_der(&der)?;
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

    fn oid(&mut self, value: String) -> Result<*mut libc::c_char, ApiError> {
        let value = CString::new(value)
            .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid object identifier"))?;
        self.strings.push(value);
        Ok(self.strings.last().unwrap().as_ptr().cast_mut())
    }

    fn algorithm(&mut self, oid: String) -> Result<CRYPT_ALGORITHM_IDENTIFIER, ApiError> {
        Ok(CRYPT_ALGORITHM_IDENTIFIER {
            pszObjId: self.oid(oid)?,
            Parameters: CRYPT_DATA_BLOB::default(),
        })
    }

    fn bit_blob(&mut self, data: &[u8], unused_bits: u8) -> CRYPT_BIT_BLOB {
        let blob = self.keep(data.to_vec());
        CRYPT_BIT_BLOB {
            cbData: blob.cbData,
            pbData: blob.pbData,
            cUnusedBits: unused_bits as DWORD,
        }
    }

    fn filetime(timestamp: i64) -> Result<FILETIME, ApiError> {
        let seconds = timestamp + 11_644_473_600;
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
        let (
            version,
            serial,
            signature_oid,
            issuer,
            subject,
            not_before,
            not_after,
            public_key_oid,
            public_key,
            public_key_unused_bits,
            issuer_uid,
            subject_uid,
            extensions,
        ) = {
            let certificate = self.certificate.parsed()?;
            (
                certificate.version().0 as DWORD,
                certificate.raw_serial().to_vec(),
                certificate.signature_algorithm.algorithm.to_id_string(),
                certificate.issuer().as_raw().to_vec(),
                certificate.subject().as_raw().to_vec(),
                certificate.validity().not_before.timestamp(),
                certificate.validity().not_after.timestamp(),
                certificate.public_key().algorithm.algorithm.to_id_string(),
                certificate.public_key().subject_public_key.data.to_vec(),
                certificate.public_key().subject_public_key.unused_bits,
                certificate
                    .tbs_certificate
                    .issuer_uid
                    .as_ref()
                    .map(|value| (value.0.data.to_vec(), value.0.unused_bits)),
                certificate
                    .tbs_certificate
                    .subject_uid
                    .as_ref()
                    .map(|value| (value.0.data.to_vec(), value.0.unused_bits)),
                certificate
                    .extensions()
                    .iter()
                    .map(|extension| {
                        (
                            extension.oid.to_id_string(),
                            extension.critical,
                            extension.value.to_vec(),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        };
        self.info.dwVersion = version;

        require(
            serial.first().is_none_or(|byte| byte & 0x80 == 0),
            ERROR_NOT_SUPPORTED,
            "Negative certificate serial numbers are unsupported",
        )?;
        let mut serial_bytes = serial;
        serial_bytes.reverse();
        self.info.SerialNumber = self.keep(serial_bytes);

        self.info.SignatureAlgorithm = self.algorithm(signature_oid)?;
        self.info.Issuer = self.keep(issuer);
        self.info.Subject = self.keep(subject);
        self.info.NotBefore = Self::filetime(not_before)?;
        self.info.NotAfter = Self::filetime(not_after)?;

        self.info.SubjectPublicKeyInfo.Algorithm = self.algorithm(public_key_oid)?;
        self.info.SubjectPublicKeyInfo.PublicKey =
            self.bit_blob(&public_key, public_key_unused_bits);

        if let Some((data, unused_bits)) = issuer_uid {
            self.info.IssuerUniqueId = self.bit_blob(&data, unused_bits);
        }
        if let Some((data, unused_bits)) = subject_uid {
            self.info.SubjectUniqueId = self.bit_blob(&data, unused_bits);
        }

        for (extension_oid, critical, value) in extensions {
            let blob = self.keep(value);
            let oid = self.oid(extension_oid)?;
            self.extensions.push(CERT_EXTENSION {
                pszObjId: oid,
                fCritical: bool_value(critical),
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

    pub fn simple_name(certificate: &Certificate, subject: bool) -> Result<String, ApiError> {
        if subject {
            certificate.subject_text()
        } else {
            certificate.issuer_text()
        }
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
        match property {
            CERT_SHA1_HASH_PROP_ID => return Ok(Sha1::digest(&self.der).to_vec()),
            CERT_SHA256_HASH_PROP_ID => return Ok(Sha256::digest(&self.der).to_vec()),
            CERT_MD5_HASH_PROP_ID => return Ok(Md5::digest(&self.der).to_vec()),
            _ => {}
        }
        if property == CERT_KEY_IDENTIFIER_PROP_ID {
            if let Some(identifier) = self.certificate.subject_key_identifier()? {
                return Ok(identifier);
            }
            return Ok(Sha1::digest(self.certificate.subject_public_key_info()?).to_vec());
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
