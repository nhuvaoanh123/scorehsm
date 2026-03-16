// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! Secure feature activation — HSM-REQ-049.
//!
//! Features are enabled by presenting a signed activation token. The token
//! includes a monotonic counter that prevents replay attacks.
//!
//! # Token wire format
//!
//! ```text
//! feature_id  : N bytes  (UTF-8, no null terminator)
//! 0x00        : 1 byte   (separator)
//! counter     : 8 bytes  (big-endian u64)
//! ─────────────────────────────────────────────────────────────────────────────
//! message     = feature_id || 0x00 || counter_be
//! digest      = SHA-256(message)
//! signature   : variable (DER-encoded ECDSA-P256 over digest)
//! ```
//!
//! The feature authority signs the message offline with its private key.
//! The feature authority's public key (65-byte uncompressed P-256 point) is
//! provisioned via the certificate management subsystem (HSM-REQ-018).
//!
//! # IDS Events
//! - `IdsEvent::ActivationRejected` — emitted before returning any error.

use sha2::{Digest, Sha256};

use crate::{
    error::{HsmError, HsmResult},
    ids::{IdsEvent, IdsHook, NullIds},
};

/// A parsed feature activation token.
#[derive(Debug, Clone)]
pub struct ActivationToken<'a> {
    /// Feature identifier (e.g. `"ADAPTIVE_CRUISE_CONTROL"`).
    pub feature_id: &'a str,
    /// Monotonic activation counter — must be strictly greater than `last_counter`.
    pub counter: u64,
    /// DER-encoded ECDSA-P256 signature over SHA-256(`feature_id` || 0x00 || `counter` BE).
    pub signature_der: &'a [u8],
}

impl<'a> ActivationToken<'a> {
    /// Build the canonical message bytes that were signed.
    fn signed_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(self.feature_id.len() + 1 + 8);
        msg.extend_from_slice(self.feature_id.as_bytes());
        msg.push(0x00);
        msg.extend_from_slice(&self.counter.to_be_bytes());
        msg
    }
}

/// Verify a feature activation token.
///
/// # Arguments
/// - `token` — the token to verify.
/// - `authority_pk` — 65-byte uncompressed P-256 public key of the feature authority.
/// - `last_counter` — the highest counter value previously accepted for this feature.
///   The caller is responsible for persisting this value in authenticated storage.
/// - `ids` — IDS hook; receives `ActivationRejected` on any failure.
///
/// # Returns
/// `Ok(())` if the token is valid and the counter is fresh.
/// The caller must then persist `token.counter` as the new `last_counter`.
///
/// # Errors
/// - `HsmError::ReplayDetected` — counter ≤ `last_counter`.
/// - `HsmError::CryptoFail` — public key or signature is malformed / invalid.
pub fn verify_activation_token(
    token: &ActivationToken<'_>,
    authority_pk: &[u8; 65],
    last_counter: u64,
    ids: &dyn IdsHook,
) -> HsmResult<()> {
    // 1. Replay check.
    if token.counter <= last_counter {
        ids.on_event(IdsEvent::ActivationRejected {
            reason: "counter replay",
        });
        return Err(HsmError::ReplayDetected(token.counter, last_counter));
    }

    // 2. Compute SHA-256(message).
    let msg = token.signed_message();
    let digest: [u8; 32] = Sha256::digest(&msg).into();

    // 3. Parse feature authority public key.
    use p256::{
        ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey},
        PublicKey,
    };
    let pk = PublicKey::from_sec1_bytes(authority_pk).map_err(|_| {
        ids.on_event(IdsEvent::ActivationRejected {
            reason: "invalid authority key",
        });
        HsmError::CryptoFail("invalid feature authority public key".into())
    })?;
    let vk = VerifyingKey::from(&pk);

    // 4. Parse DER signature.
    let sig = p256::ecdsa::Signature::from_der(token.signature_der).map_err(|_| {
        ids.on_event(IdsEvent::ActivationRejected {
            reason: "signature parse failed",
        });
        HsmError::CryptoFail("malformed activation token signature".into())
    })?;

    // 5. Verify.
    if vk.verify_prehash(&digest, &sig).is_err() {
        ids.on_event(IdsEvent::ActivationRejected {
            reason: "signature invalid",
        });
        return Err(HsmError::CryptoFail(
            "activation token signature verification failed".into(),
        ));
    }

    Ok(())
}

/// Convenience: `verify_activation_token` with `NullIds`.
pub fn verify_activation_token_no_ids(
    token: &ActivationToken<'_>,
    authority_pk: &[u8; 65],
    last_counter: u64,
) -> HsmResult<()> {
    verify_activation_token(token, authority_pk, last_counter, &NullIds)
}
