use crate::error::ApiError;
#[cfg(scs_bundled_crypto)]
use crate::ffi::ERROR_GEN_FAILURE;

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
