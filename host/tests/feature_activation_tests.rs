//! Secure feature activation tests — HSM-REQ-049.

use scorehsm_host::{
    error::HsmError,
    feature_activation::{verify_activation_token, verify_activation_token_no_ids, ActivationToken},
    ids::{IdsEvent, IdsHook},
};
use std::sync::{Arc, Mutex};

// ── Local helpers ─────────────────────────────────────────────────────────────

fn sign_token(feature_id: &str, counter: u64, sk_bytes: &[u8; 32]) -> Vec<u8> {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use sha2::{Digest, Sha256};
    let mut msg = feature_id.as_bytes().to_vec();
    msg.push(0x00);
    msg.extend_from_slice(&counter.to_be_bytes());
    let digest: [u8; 32] = Sha256::digest(&msg).into();
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

// ── Test key ──────────────────────────────────────────────────────────────────

const AUTH_SK: [u8; 32] = [
    0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
    0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,
];

// ── Happy path ────────────────────────────────────────────────────────────────

/// Valid token with fresh counter is accepted.
#[test]
fn test_activation_valid_token_accepted() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let sig = sign_token("LANE_KEEP_ASSIST", 1, &AUTH_SK);
    let token = ActivationToken { feature_id: "LANE_KEEP_ASSIST", counter: 1, signature_der: &sig };
    assert!(verify_activation_token_no_ids(&token, &pk, 0).is_ok());
}

/// Counter strictly greater than last is accepted.
#[test]
fn test_activation_higher_counter_accepted() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let sig = sign_token("AEB", 100, &AUTH_SK);
    let token = ActivationToken { feature_id: "AEB", counter: 100, signature_der: &sig };
    assert!(verify_activation_token_no_ids(&token, &pk, 50).is_ok());
}

/// First activation (last_counter = 0, token counter = 1) succeeds.
#[test]
fn test_activation_first_activation_accepted() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let sig = sign_token("SPORT_PACKAGE", 1, &AUTH_SK);
    let token = ActivationToken { feature_id: "SPORT_PACKAGE", counter: 1, signature_der: &sig };
    assert!(verify_activation_token_no_ids(&token, &pk, 0).is_ok());
}

// ── Replay protection ─────────────────────────────────────────────────────────

/// Counter equal to last_counter is rejected as replay.
#[test]
fn test_activation_same_counter_rejected() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let sig = sign_token("SPORT_MODE", 5, &AUTH_SK);
    let token = ActivationToken { feature_id: "SPORT_MODE", counter: 5, signature_der: &sig };

    let ids = RecordingIds::default();
    let result = verify_activation_token(&token, &pk, 5, &ids);

    assert!(matches!(result, Err(HsmError::ReplayDetected(5, 5))));
    assert!(ids.events().iter().any(|e| e.contains("ActivationRejected")));
}

/// Counter less than last_counter is rejected as replay.
#[test]
fn test_activation_old_counter_rejected() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let sig = sign_token("SPORT_MODE", 3, &AUTH_SK);
    let token = ActivationToken { feature_id: "SPORT_MODE", counter: 3, signature_der: &sig };

    let ids = RecordingIds::default();
    let result = verify_activation_token(&token, &pk, 10, &ids);

    assert!(matches!(result, Err(HsmError::ReplayDetected(3, 10))));
    assert!(ids.events().iter().any(|e| e.contains("ActivationRejected")));
}

/// Counter = 0 is always a replay (last_counter ≥ 0 by invariant).
#[test]
fn test_activation_zero_counter_rejected() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let sig = sign_token("FEATURE_Z", 0, &AUTH_SK);
    let token = ActivationToken { feature_id: "FEATURE_Z", counter: 0, signature_der: &sig };
    // last_counter = 0 → counter (0) <= last_counter (0) → replay
    assert!(matches!(
        verify_activation_token_no_ids(&token, &pk, 0),
        Err(HsmError::ReplayDetected(0, 0))
    ));
}

// ── Signature verification ────────────────────────────────────────────────────

/// Token signed by a different key is rejected.
#[test]
fn test_activation_wrong_key_rejected() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let other_sk = [0x01u8; 32];
    let sig = sign_token("AUTOPILOT", 1, &other_sk);
    let token = ActivationToken { feature_id: "AUTOPILOT", counter: 1, signature_der: &sig };

    let ids = RecordingIds::default();
    assert!(verify_activation_token(&token, &pk, 0, &ids).is_err());
    assert!(ids.events().iter().any(|e| e.contains("ActivationRejected")));
}

/// Token signed for a different feature_id is rejected.
#[test]
fn test_activation_feature_id_mismatch_rejected() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let sig = sign_token("FEATURE_A", 1, &AUTH_SK);
    let token = ActivationToken { feature_id: "FEATURE_B", counter: 1, signature_der: &sig };

    let ids = RecordingIds::default();
    assert!(verify_activation_token(&token, &pk, 0, &ids).is_err());
    assert!(ids.events().iter().any(|e| e.contains("ActivationRejected")));
}

/// Token counter tampered after signing (counter=1 sig used with counter=2).
#[test]
fn test_activation_counter_mismatch_in_signature_rejected() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let sig = sign_token("TURBO", 1, &AUTH_SK);
    let token = ActivationToken { feature_id: "TURBO", counter: 2, signature_der: &sig };

    let ids = RecordingIds::default();
    let result = verify_activation_token(&token, &pk, 0, &ids);
    assert!(result.is_err(), "counter mismatch in signature must be rejected");
    assert!(ids.events().iter().any(|e| e.contains("ActivationRejected")));
}

/// Malformed DER signature is rejected.
#[test]
fn test_activation_malformed_signature_rejected() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let token = ActivationToken {
        feature_id: "FEATURE_X",
        counter: 1,
        signature_der: &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01],
    };

    let ids = RecordingIds::default();
    assert!(verify_activation_token(&token, &pk, 0, &ids).is_err());
    assert!(ids.events().iter().any(|e| e.contains("ActivationRejected")));
}

/// Empty signature bytes are rejected.
#[test]
fn test_activation_empty_signature_rejected() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let token = ActivationToken { feature_id: "F", counter: 1, signature_der: &[] };
    let ids = RecordingIds::default();
    assert!(verify_activation_token(&token, &pk, 0, &ids).is_err());
    assert!(ids.events().iter().any(|e| e.contains("ActivationRejected")));
}

/// Empty feature_id is a valid identifier (no restriction on format).
#[test]
fn test_activation_empty_feature_id_accepted() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let sig = sign_token("", 1, &AUTH_SK);
    let token = ActivationToken { feature_id: "", counter: 1, signature_der: &sig };
    assert!(verify_activation_token_no_ids(&token, &pk, 0).is_ok());
}

/// u64::MAX counter is accepted if larger than last_counter.
#[test]
fn test_activation_max_counter_accepted() {
    let pk = pubkey_from_scalar(&AUTH_SK);
    let sig = sign_token("PREMIUM", u64::MAX, &AUTH_SK);
    let token = ActivationToken { feature_id: "PREMIUM", counter: u64::MAX, signature_der: &sig };
    assert!(verify_activation_token_no_ids(&token, &pk, u64::MAX - 1).is_ok());
}

// ── Property-based tests ───────────────────────────────────────────────────────

use proptest::prelude::*;

proptest! {
    /// Any valid (feature_id, counter > 0) pair with correct signature is accepted.
    #[test]
    fn prop_activation_any_feature_valid_sig_accepted(
        feature_id in "[A-Z_]{1,32}",
        counter in 1u64..=u64::MAX,
    ) {
        let pk = pubkey_from_scalar(&AUTH_SK);
        let sig = sign_token(&feature_id, counter, &AUTH_SK);
        let token = ActivationToken {
            feature_id: &feature_id,
            counter,
            signature_der: &sig,
        };
        prop_assert!(
            verify_activation_token_no_ids(&token, &pk, counter - 1).is_ok(),
            "valid token must always be accepted"
        );
    }

    /// A token signed for feature_id A must not verify as feature_id B.
    #[test]
    fn prop_activation_wrong_feature_id_rejected(
        feature_a in "[A-Z_]{1,16}",
        feature_b in "[A-Z_]{1,16}",
        counter in 1u64..=u64::MAX,
    ) {
        prop_assume!(feature_a != feature_b);
        let pk = pubkey_from_scalar(&AUTH_SK);
        let sig = sign_token(&feature_a, counter, &AUTH_SK);
        let token = ActivationToken {
            feature_id: &feature_b,  // different feature
            counter,
            signature_der: &sig,
        };
        prop_assert!(
            verify_activation_token_no_ids(&token, &pk, counter - 1).is_err(),
            "token signed for feature A must not verify as feature B"
        );
    }
}
