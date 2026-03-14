//! IDS (Intrusion Detection System) hook — HSM-REQ-038.
//!
//! Consumers implement `IdsHook` and attach it to an `HsmSession`. Every
//! security-relevant operation calls `on_event` synchronously before returning.
//! The hook is typically wired to a vehicle security monitor (IDPS) over a
//! local socket or shared-memory ring buffer.

use crate::types::{KeyHandle, KeyType};

/// A security-relevant event emitted by the HSM session.
#[derive(Debug, Clone)]
pub enum IdsEvent {
    /// A new key was generated.
    KeyGenerated {
        /// Opaque handle of the generated key.
        handle: KeyHandle,
        /// Type of the generated key.
        key_type: KeyType,
    },
    /// A key slot was deleted.
    KeyDeleted {
        /// Opaque handle of the deleted key.
        handle: KeyHandle,
    },
    /// An ECDSA signature was produced.
    EcdsaSigned {
        /// Opaque handle of the signing key.
        handle: KeyHandle,
        /// SHA-256 digest that was signed.
        digest: [u8; 32],
    },
    /// An AES-GCM decryption authentication tag failed to verify.
    DecryptFailed {
        /// Opaque handle of the decryption key.
        handle: KeyHandle,
    },
    /// A rate limit threshold was exceeded.
    RateLimitExceeded {
        /// Name of the rate-limited operation (e.g. `"sign"`, `"decrypt"`).
        operation: &'static str,
        /// Current call count within the window.
        count: u32,
    },
    /// A repeated failure counter tripped (possible brute-force attempt).
    RepeatedFailure {
        /// Cumulative failure count.
        count: u32,
    },
    /// An unknown key handle was presented (possible replay or tampering).
    UnknownHandle {
        /// The unrecognised handle value.
        handle: KeyHandle,
    },
    /// A firmware update image was rejected — bad signature or version rollback.
    UpdateRejected {
        /// Human-readable reason string.
        reason: &'static str,
    },
    /// A feature activation token was rejected — bad signature or counter replay.
    ActivationRejected {
        /// Human-readable reason string.
        reason: &'static str,
    },
}

/// Implementors receive IDS events from `HsmSession`.
pub trait IdsHook: Send + Sync {
    /// Called synchronously on every security-relevant event.
    ///
    /// Implementations must not block — use a lock-free queue or channel.
    fn on_event(&self, event: IdsEvent);
}

/// A no-op hook used when no IDS integration is needed.
pub struct NullIds;

impl IdsHook for NullIds {
    fn on_event(&self, _event: IdsEvent) {}
}

/// A logging hook that prints events via `eprintln!`.
///
/// Useful for development and CI; replace with a real IDPS sink in production.
pub struct LoggingIds;

impl IdsHook for LoggingIds {
    fn on_event(&self, event: IdsEvent) {
        eprintln!("[scorehsm IDS] {:?}", event);
    }
}
