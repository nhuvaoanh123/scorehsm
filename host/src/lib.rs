//! scorehsm-host — HSM host library
//!
//! Provides a unified crypto API with two backends:
//! - Software fallback: rustcrypto — runs anywhere, no hardware needed (CI)
//! - Hardware backend: USB CDC to STM32L552 Nucleo — real key isolation
//!
//! Key material never leaves the HSM. All operations use opaque key handles.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod backend;
pub mod error;
pub mod types;
