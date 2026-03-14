//! Secure firmware update tests — HSM-REQ-047.

use scorehsm_host::{
    ids::{IdsEvent, IdsHook},
    update::{verify_update_image, verify_update_image_no_ids},
};
use std::sync::{Arc, Mutex};

// ── Local signing helpers (stand-in for offline release toolchain) ────────────

fn sign_image(image: &[u8], sk_bytes: &[u8; 32]) -> Vec<u8> {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(image).into();
    let sk = SigningKey::from_bytes(sk_bytes.into()).unwrap();
    let sig: p256::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
    sig.to_der().as_bytes().to_vec()
}

fn pubkey_from_scalar(scalar: &[u8; 32]) -> [u8; 65] {
    use p256::ecdsa::SigningKey;
    let sk = SigningKey::from_bytes(scalar.into()).unwrap();
    let pk = sk.verifying_key().to_encoded_point(false);
    pk.as_bytes().try_into().unwrap()
}

// ── Recording IDS hook ────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct RecordingIds {
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingIds {
    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

impl IdsHook for RecordingIds {
    fn on_event(&self, event: IdsEvent) {
        self.events.lock().unwrap().push(format!("{event:?}"));
    }
}

// ── Test key (deterministic scalar) ──────────────────────────────────────────

const TEST_SK: [u8; 32] = [
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
];

/// Valid signature on a known image is accepted.
#[test]
fn test_update_valid_signature_accepted() {
    let image = b"firmware_v2_payload";
    let sig = sign_image(image, &TEST_SK);
    let pk = pubkey_from_scalar(&TEST_SK);
    assert!(
        verify_update_image_no_ids(image, &sig, &pk, 2, 1).is_ok(),
        "valid firmware signature must be accepted"
    );
}

/// Modified image fails signature check and emits IDS event.
#[test]
fn test_update_tampered_image_rejected() {
    let image = b"firmware_v2_payload";
    let sig = sign_image(image, &TEST_SK);
    let pk = pubkey_from_scalar(&TEST_SK);
    let tampered = b"firmware_v2_payloax";  // one byte changed

    let ids = RecordingIds::default();
    let result = verify_update_image(tampered, &sig, &pk, 2, 1, &ids);

    assert!(result.is_err(), "tampered image must be rejected");
    assert!(
        ids.events().iter().any(|e| e.contains("UpdateRejected")),
        "UpdateRejected IDS event must be emitted"
    );
}

/// Version rollback is rejected and IDS event emitted.
#[test]
fn test_update_version_rollback_rejected() {
    let image = b"firmware_v1_downgrade";
    let sig = sign_image(image, &TEST_SK);
    let pk = pubkey_from_scalar(&TEST_SK);

    let ids = RecordingIds::default();
    let result = verify_update_image(image, &sig, &pk, 1, 2, &ids);

    assert!(result.is_err(), "rollback must be rejected");
    assert!(
        ids.events().iter().any(|e| e.contains("UpdateRejected")),
        "UpdateRejected must be emitted for rollback"
    );
}

/// Same version (not strictly greater) is also rejected.
#[test]
fn test_update_same_version_rejected() {
    let image = b"firmware_v2_same";
    let sig = sign_image(image, &TEST_SK);
    let pk = pubkey_from_scalar(&TEST_SK);
    assert!(
        verify_update_image_no_ids(image, &sig, &pk, 2, 2).is_err(),
        "same version must be rejected"
    );
}

/// Signature from a different key is rejected.
#[test]
fn test_update_wrong_key_rejected() {
    let image = b"firmware_v2_payload";
    let other_sk = [0x42u8; 32];
    let sig = sign_image(image, &other_sk);    // signed with wrong key
    let pk = pubkey_from_scalar(&TEST_SK);     // verification uses correct key

    let ids = RecordingIds::default();
    let result = verify_update_image(image, &sig, &pk, 2, 1, &ids);

    assert!(result.is_err(), "signature from wrong key must be rejected");
    assert!(ids.events().iter().any(|e| e.contains("UpdateRejected")));
}

/// Empty image still passes after rollback guard clears.
#[test]
fn test_update_empty_image_accepted() {
    let image = b"";
    let sig = sign_image(image, &TEST_SK);
    let pk = pubkey_from_scalar(&TEST_SK);
    assert!(verify_update_image_no_ids(image, &sig, &pk, 1, 0).is_ok());
}

/// Version 0 → 1 is a valid first update.
#[test]
fn test_update_first_install_accepted() {
    let image = b"initial_fw_v1";
    let sig = sign_image(image, &TEST_SK);
    let pk = pubkey_from_scalar(&TEST_SK);
    assert!(verify_update_image_no_ids(image, &sig, &pk, 1, 0).is_ok());
}

/// Large version jump (0 → u32::MAX) is accepted — no upper bound on version.
#[test]
fn test_update_large_version_jump_accepted() {
    let image = b"future_fw";
    let sig = sign_image(image, &TEST_SK);
    let pk = pubkey_from_scalar(&TEST_SK);
    assert!(verify_update_image_no_ids(image, &sig, &pk, u32::MAX, 0).is_ok());
}

// ── Property-based tests ───────────────────────────────────────────────────────

use proptest::prelude::*;

proptest! {
    /// For any arbitrary image payload, a freshly computed valid signature is accepted.
    #[test]
    fn prop_update_any_image_valid_sig_accepted(
        image in proptest::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let sig = sign_image(&image, &TEST_SK);
        let pk = pubkey_from_scalar(&TEST_SK);
        prop_assert!(
            verify_update_image_no_ids(&image, &sig, &pk, 1, 0).is_ok(),
            "any image with valid sig must be accepted"
        );
    }

    /// Flipping any bit in the image invalidates an otherwise-valid signature.
    #[test]
    fn prop_update_bit_flip_rejected(
        image in proptest::collection::vec(any::<u8>(), 1..=4096),
        byte_idx in any::<prop::sample::Index>(),
        bit in 0u8..8u8,
    ) {
        let sig = sign_image(&image, &TEST_SK);
        let pk = pubkey_from_scalar(&TEST_SK);

        let mut tampered = image.clone();
        let idx = byte_idx.index(tampered.len());
        tampered[idx] ^= 1 << bit;

        if tampered != image {
            prop_assert!(
                verify_update_image_no_ids(&tampered, &sig, &pk, 1, 0).is_err(),
                "bit-flipped image must be rejected"
            );
        }
    }
}
