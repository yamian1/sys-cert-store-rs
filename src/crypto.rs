use crate::error::ApiError;
#[cfg(scs_bundled_crypto)]
use crate::ffi::ERROR_GEN_FAILURE;
use crate::ffi::ERROR_INVALID_DATA;
use openssl::pkey::PKey;
use openssl::x509::X509;

#[cfg(scs_bundled_crypto)]
unsafe extern "C" {
    fn scs_initialize_crypto() -> bool;
}

pub fn initialize() -> Result<(), ApiError> {
    #[cfg(scs_bundled_crypto)]
    if !unsafe { scs_initialize_crypto() } {
        return Err(ApiError::new(
            ERROR_GEN_FAILURE,
            "Cannot initialize statically linked cryptographic providers",
        ));
    }
    Ok(())
}

pub fn is_pqc_oid(oid: &str) -> bool {
    matches!(
        oid,
        "2.16.840.1.101.3.4.3.17"
            | "2.16.840.1.101.3.4.3.18"
            | "2.16.840.1.101.3.4.3.19"
            | "1.3.6.1.5.5.7.6.40"
            | "1.3.6.1.5.5.7.6.45"
            | "1.3.6.1.5.5.7.6.46"
            | "1.3.6.1.5.5.7.6.49"
    )
}

pub fn verify_pqc_certificate(certificate: &[u8], issuer: &[u8]) -> Result<bool, ApiError> {
    initialize()?;
    let certificate = X509::from_der(certificate)
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid PQC certificate"))?;
    let issuer = X509::from_der(issuer)
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid PQC issuer certificate"))?;
    let issuer_key = issuer.public_key()?;
    Ok(certificate.verify(&issuer_key)?)
}

pub fn validate_pqc_private_key(key: &[u8]) -> Result<(), ApiError> {
    initialize()?;
    PKey::private_key_from_der(key)
        .map(|_| ())
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid PQC PKCS#8 private key"))
}

pub fn pqc_private_key_matches(certificate: &[u8], key: &[u8]) -> Result<bool, ApiError> {
    initialize()?;
    let certificate = X509::from_der(certificate)
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid certificate"))?;
    let key = PKey::private_key_from_der(key)
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid PQC PKCS#8 private key"))?;
    Ok(certificate.public_key()?.public_eq(&key))
}
