//! Multi-platform certificate-store APIs.
//!
//! Prefer the owning types in [`safe`] for ordinary application code. The
//! Win32-shaped functions re-exported at the crate root remain available for
//! compatibility, but pointer- and ownership-sensitive operations require an
//! explicit unsafe boundary:
//!
//! ```compile_fail
//! sys_cert_store::CertFreeCertificateChain(std::ptr::null());
//! ```

#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::missing_safety_doc)]
#![deny(clippy::not_unsafe_ptr_arg_deref)]

pub mod api_types;
pub mod safe;

#[cfg(target_os = "linux")]
pub mod cert;
#[cfg(target_os = "linux")]
mod crl_cache;
#[cfg(target_os = "linux")]
mod crypto;
#[cfg(target_os = "linux")]
mod error;
#[cfg(target_os = "linux")]
pub mod key;
#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
mod store;

#[cfg(target_os = "linux")]
#[path = "backend/linux.rs"]
mod backend;

#[cfg(target_os = "windows")]
#[path = "backend/windows.rs"]
mod backend;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!("sys-cert-store currently supports Windows and Linux");

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use backend::*;
