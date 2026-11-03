#![allow(non_snake_case)]

pub mod api_types;

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
