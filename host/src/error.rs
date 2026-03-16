// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

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

    /// Monotonic counter replay detected — token already consumed (HSM-REQ-047).
    ///
    /// Used by `update.rs` (firmware update verification) and `feature_activation.rs`.
    /// This error is **outside the ASIL B scope**: HSM-REQ-047 is a functional
    /// requirement in the extended API (Section 13 of requirements.md) and does not
    /// carry an ASIL designation. It is not traced through the FSR → TSR → SSR chain.
    #[error("replay detected: counter {0} not greater than last seen {1}")]
    ReplayDetected(u64, u64),

    // ── SSR / ISO 26262-6 ASIL B error variants ──────────────────────────────
    /// USB frame CRC-32 check failed — frame corrupted or wrong device (HSM-REQ-050).
    #[error("USB frame CRC mismatch — frame rejected")]
    CrcMismatch,

    /// Command/response sequence number mismatch (HSM-REQ-051).
    #[error("sequence number mismatch — protocol error")]
    ProtocolError,

    /// Sequence number reached u32::MAX — library must be re-initialized (HSM-REQ-051).
    #[error("sequence number overflow — re-initialization required")]
    SequenceOverflow,

    /// Command timed out waiting for L55 response (HSM-REQ-052).
    #[error("HSM command timeout")]
    Timeout,

    /// Library is in safe state — all operations blocked until re-init (HSM-REQ-062).
    #[error("library in safe state — call hsm_reinit() to recover")]
    SafeState,

    /// Operation rate limit exceeded for this operation class (HSM-REQ-060).
    #[error("rate limit exceeded for operation — retry later")]
    RateLimitExceeded,

    /// Nonce counter exhausted for this key — key rotation required (HSM-REQ-054).
    #[error("nonce counter exhausted — rotate the key")]
    NonceExhausted,

    /// Maximum concurrent session limit reached (HSM-REQ-059).
    #[error("maximum concurrent sessions reached")]
    ResourceExhausted,

    /// Library initialization failed (device handshake, version check) (HSM-REQ-068).
    #[error("HSM initialization failed: {0}")]
    InitializationFailed(String),

    /// Power-on self-test (KAT) failed — hardware may be compromised (HSM-REQ-074/075).
    #[error("self-test (KAT) failed — hardware unsafe")]
    SelfTestFailed,

    /// USB device identity changed after initialization — rogue device (HSM-REQ-069).
    #[error("device identity changed — possible rogue device")]
    DeviceIdentityChanged,

    /// Internal integrity violation (key store checksum failure) (HSM-REQ-065).
    #[error("internal integrity violation")]
    IntegrityViolation,

    /// X.509 certificate has expired (HSM-REQ-070).
    #[error("certificate has expired")]
    CertificateExpired,

    /// X.509 certificate is not yet valid (HSM-REQ-070).
    #[error("certificate is not yet valid")]
    CertificateNotYetValid,

    /// System clock unavailable — certificate operations cannot be performed (HSM-REQ-071).
    #[error("system clock unavailable — cannot validate certificate")]
    ClockUnavailable,

    /// L55 firmware reported a hardware fault opcode (HSM-REQ-063).
    #[error("L55 hardware fault reported")]
    HardwareFault,

    /// AEAD authentication tag verification failed — output buffer zeroed (HSM-REQ-072).
    #[error("AEAD authentication failed — ciphertext or tag tampered")]
    AuthenticationFailed,

    /// HKDF called with empty info string — domain separation required (HSM-REQ-056).
    #[error("HKDF info string must be non-empty (domain separation required)")]
    InvalidArgument,
}

/// Convenience result alias.
pub type HsmResult<T> = Result<T, HsmError>;
