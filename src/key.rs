use crate::cert::Certificate;
use crate::crypto::{is_pqc_oid, pqc_private_key_matches, validate_pqc_private_key};
use crate::error::ApiError;
use crate::ffi::{ERROR_INVALID_DATA, ERROR_NOT_SUPPORTED};
use base64ct::{Base64, Encoding};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use pkcs8::PrivateKeyInfo;
use rsa::{RsaPrivateKey, RsaPublicKey};
use zeroize::Zeroize;

const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const P256: &str = "1.2.840.10045.3.1.7";
const P384: &str = "1.3.132.0.34";
const P521: &str = "1.3.132.0.35";

pub struct PrivateKey {
    der: Vec<u8>,
    oid: String,
    parameter_oid: Option<String>,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.der.zeroize();
    }
}

impl PrivateKey {
    pub fn from_der(der: Vec<u8>) -> Result<Self, ApiError> {
        let information = PrivateKeyInfo::try_from(der.as_slice())
            .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid PKCS#8 private key"))?;
        let oid = information.algorithm.oid.to_string();
        let parameter_oid = information
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.decode_as::<pkcs8::ObjectIdentifier>().ok())
            .map(|oid| oid.to_string());
        let key = Self {
            der,
            oid,
            parameter_oid,
        };
        if key.is_pqc() {
            validate_pqc_private_key(&key.der)?;
        } else {
            key.public_key_der()?;
        }
        Ok(key)
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self, ApiError> {
        let text = std::str::from_utf8(pem)
            .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid PKCS#8 PEM"))?;
        const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
        const END: &str = "-----END PRIVATE KEY-----";
        let start = text
            .find(BEGIN)
            .map(|value| value + BEGIN.len())
            .ok_or_else(|| ApiError::new(ERROR_INVALID_DATA, "Invalid PKCS#8 PEM label"))?;
        let end = text[start..]
            .find(END)
            .map(|value| start + value)
            .ok_or_else(|| ApiError::new(ERROR_INVALID_DATA, "Truncated PKCS#8 PEM"))?;
        let encoded = text[start..end]
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        let der = Base64::decode_vec(
            std::str::from_utf8(&encoded)
                .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid PKCS#8 PEM"))?,
        )
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid PKCS#8 PEM encoding"))?;
        Self::from_der(der)
    }

    pub fn to_der(&self) -> &[u8] {
        &self.der
    }

    pub fn to_pem(&self) -> Vec<u8> {
        let encoded = Base64::encode_string(&self.der);
        let mut result = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            result.push_str(std::str::from_utf8(chunk).unwrap());
            result.push('\n');
        }
        result.push_str("-----END PRIVATE KEY-----\n");
        result.into_bytes()
    }

    pub fn oid(&self) -> &str {
        &self.oid
    }

    pub fn is_pqc(&self) -> bool {
        is_pqc_oid(&self.oid)
    }

    pub fn matches(&self, certificate: &Certificate) -> Result<bool, ApiError> {
        if self.is_pqc() || is_pqc_oid(&certificate.public_key_oid()?) {
            return pqc_private_key_matches(certificate.to_der().as_slice(), &self.der);
        }
        Ok(self.public_key_der()? == certificate.subject_public_key_info()?)
    }

    fn public_key_der(&self) -> Result<Vec<u8>, ApiError> {
        let unsupported = || {
            ApiError::new(
                ERROR_NOT_SUPPORTED,
                format!("Unsupported classical private-key algorithm {}", self.oid),
            )
        };
        match self.oid.as_str() {
            RSA_ENCRYPTION => {
                let private =
                    RsaPrivateKey::from_pkcs8_der(&self.der).map_err(|_| unsupported())?;
                RsaPublicKey::from(&private)
                    .to_public_key_der()
                    .map(|value| value.as_bytes().to_vec())
                    .map_err(|_| unsupported())
            }
            EC_PUBLIC_KEY => match self.parameter_oid.as_deref() {
                Some(P256) => {
                    let private =
                        p256::SecretKey::from_pkcs8_der(&self.der).map_err(|_| unsupported())?;
                    private
                        .public_key()
                        .to_public_key_der()
                        .map(|value| value.as_bytes().to_vec())
                        .map_err(|_| unsupported())
                }
                Some(P384) => {
                    let private =
                        p384::SecretKey::from_pkcs8_der(&self.der).map_err(|_| unsupported())?;
                    private
                        .public_key()
                        .to_public_key_der()
                        .map(|value| value.as_bytes().to_vec())
                        .map_err(|_| unsupported())
                }
                Some(P521) => {
                    let private =
                        p521::SecretKey::from_pkcs8_der(&self.der).map_err(|_| unsupported())?;
                    private
                        .public_key()
                        .to_public_key_der()
                        .map(|value| value.as_bytes().to_vec())
                        .map_err(|_| unsupported())
                }
                _ => Err(unsupported()),
            },
            _ => Err(unsupported()),
        }
    }
}
