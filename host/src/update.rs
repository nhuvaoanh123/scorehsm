// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! Secure firmware update verification — HSM-REQ-047.
//!
//! Verifies that a firmware update image carries a valid ECDSA-P256 signature
//! from the code-signing authority before the image is applied. Rollback
//! protection is enforced by comparing the image version counter against the
//! currently installed version.
//!
//! Signature format: DER-encoded ECDSA-P256 signature over SHA-256(image_bytes).
//!
//! The code-signing public key (65-byte uncompressed EC point) is obtained by
//! calling `crate::cert::extract_ec_public_key()` on the provisioned code-signing
//! certificate (HSM-REQ-018). The caller is responsible for verifying the
//! certificate chain before passing the public key here.
//!
//! # IDS Events
//! - `IdsEvent::UpdateRejected` — emitted before returning any error.

use sha2::{Digest, Sha256};

use crate::{
    error::{HsmError, HsmResult},
    ids::{IdsEvent, IdsHook, NullIds},
};

/// Verify a firmware update image against a code-signing public key.
///
/// # Arguments
/// - `image` — raw firmware image bytes.
/// - `signature_der` — DER-encoded ECDSA-P256 signature over SHA-256(`image`).
/// - `code_signing_pk` — 65-byte uncompressed EC point of the signing authority.
/// - `image_version` — monotonic version number embedded in the image header.
/// - `installed_version` — version currently installed on the device.
/// - `ids` — IDS hook; receives `UpdateRejected` on any failure.
///
/// # Errors
/// - `HsmError::CryptoFail` — signature invalid or public key malformed.
/// - `HsmError::InvalidParam` — version rollback detected.
pub fn verify_update_image(
    image: &[u8],
    signature_der: &[u8],
    code_signing_pk: &[u8; 65],
    image_version: u32,
    installed_version: u32,
    ids: &dyn IdsHook,
) -> HsmResult<()> {
    // 1. Rollback check.
    if image_version <= installed_version {
        ids.on_event(IdsEvent::UpdateRejected {
            reason: "version rollback",
        });
        return Err(HsmError::InvalidParam(format!(
            "update version {image_version} not greater than installed {installed_version}"
        )));
    }

    // 2. SHA-256(image).
    let digest: [u8; 32] = Sha256::digest(image).into();

    // 3. Parse code-signing public key.
    use p256::{
        ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey},
        PublicKey,
    };
    let pk = PublicKey::from_sec1_bytes(code_signing_pk).map_err(|_| {
        ids.on_event(IdsEvent::UpdateRejected {
            reason: "invalid code-signing key",
        });
        HsmError::CryptoFail("invalid code-signing public key".into())
    })?;
    let vk = VerifyingKey::from(&pk);

    // 4. Parse DER signature.
    let sig = p256::ecdsa::Signature::from_der(signature_der).map_err(|_| {
        ids.on_event(IdsEvent::UpdateRejected {
            reason: "signature parse failed",
        });
        HsmError::CryptoFail("invalid update signature encoding".into())
    })?;

    // 5. Verify.
    if vk.verify_prehash(&digest, &sig).is_err() {
        ids.on_event(IdsEvent::UpdateRejected {
            reason: "signature invalid",
        });
        return Err(HsmError::CryptoFail(
            "firmware image signature verification failed".into(),
        ));
    }

    Ok(())
}

/// Convenience: `verify_update_image` with `NullIds`.
pub fn verify_update_image_no_ids(
    image: &[u8],
    signature_der: &[u8],
    code_signing_pk: &[u8; 65],
    image_version: u32,
    installed_version: u32,
) -> HsmResult<()> {
    verify_update_image(
        image,
        signature_der,
        code_signing_pk,
        image_version,
        installed_version,
        &NullIds,
    )
}
