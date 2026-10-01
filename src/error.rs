use crate::ffi::*;
use std::cell::{Cell, RefCell};
use std::ffi::CString;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[derive(Debug)]
pub struct ApiError {
    pub code: DWORD,
    pub message: String,
}

impl ApiError {
    pub fn new(code: DWORD, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<openssl::error::ErrorStack> for ApiError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::new(ERROR_INVALID_DATA, value.to_string())
    }
}

impl From<std::io::Error> for ApiError {
    fn from(value: std::io::Error) -> Self {
        let code = match value.kind() {
            std::io::ErrorKind::NotFound => ERROR_FILE_NOT_FOUND,
            std::io::ErrorKind::PermissionDenied => ERROR_ACCESS_DENIED,
            _ => ERROR_GEN_FAILURE,
        };
        Self::new(code, value.to_string())
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(value: rusqlite::Error) -> Self {
        use rusqlite::ErrorCode;
        let code = match &value {
            rusqlite::Error::SqliteFailure(error, _) => match error.code {
                ErrorCode::ReadOnly
                | ErrorCode::PermissionDenied
                | ErrorCode::AuthorizationForStatementDenied => ERROR_ACCESS_DENIED,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => ERROR_BUSY,
                ErrorCode::OutOfMemory => ERROR_NOT_ENOUGH_MEMORY,
                ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => ERROR_INVALID_DATA,
                _ => ERROR_GEN_FAILURE,
            },
            _ => ERROR_GEN_FAILURE,
        };
        Self::new(code, value.to_string())
    }
}

thread_local! {
    static LAST_ERROR: Cell<DWORD> = const { Cell::new(ERROR_SUCCESS) };
    static LAST_MESSAGE: RefCell<CString> = RefCell::new(CString::new("").unwrap());
}

pub fn last_error() -> DWORD {
    LAST_ERROR.with(Cell::get)
}

pub fn set_error(code: DWORD, message: &str) {
    LAST_ERROR.with(|slot| slot.set(code));
    let safe = message.replace('\0', "\\0");
    LAST_MESSAGE.with(|slot| *slot.borrow_mut() = CString::new(safe).unwrap());
}

pub fn message_ptr() -> *const libc::c_char {
    LAST_MESSAGE.with(|slot| slot.borrow().as_ptr())
}

pub fn boundary<T: Copy>(failure: T, operation: impl FnOnce() -> Result<T, ApiError>) -> T {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            set_error(error.code, &error.message);
            failure
        }
        Err(_) => {
            set_error(ERROR_GEN_FAILURE, "Unexpected panic at the C API boundary");
            failure
        }
    }
}

pub fn require(condition: bool, code: DWORD, message: impl Into<String>) -> Result<(), ApiError> {
    if condition {
        Ok(())
    } else {
        Err(ApiError::new(code, message))
    }
}
