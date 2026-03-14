//! Error types for scorehsm-host.

use thiserror::Error;

/// All errors returned by the scorehsm-host library.
#[derive(Debug, Error)]
pub enum HsmError {
    /// Key handle does not refer to a provisioned key.
    #[error("invalid key handle")]
    InvalidKeyHandle,

    /// Key store has no free slot.
    #[error("key store full")]
    KeyStoreFull,

    /// Cryptographic operation failed.
    #[error("crypto operation failed: {0}")]
    CryptoFail(String),

    /// AES-GCM authentication tag mismatch — ciphertext is corrupt or tampered.
    #[error("authentication tag mismatch")]
    TagMismatch,

    /// USB communication error (hardware backend only).
    #[error("USB communication error: {0}")]
    UsbError(String),

    /// HSM not initialized.
    #[error("HSM not initialized — call init() first")]
    NotInitialized,

    /// Invalid parameter supplied by caller.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),

    /// Operation not supported by the active backend.
    #[error("operation not supported by this backend")]
    Unsupported,

    /// Monotonic counter replay detected — token already consumed.
    #[error("replay detected: counter {0} not greater than last seen {1}")]
    ReplayDetected(u64, u64),
}

/// Convenience result alias.
pub type HsmResult<T> = Result<T, HsmError>;
