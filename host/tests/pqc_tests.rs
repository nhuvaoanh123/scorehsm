//! Post-quantum cryptography tests — HSM-REQ-033.
//!
//! Tests ML-DSA (Dilithium-3) and ML-KEM (Kyber-768) software implementations.
//!
//! Feature-gated: `cargo test --features pqc`

use scorehsm_host::pqc::{
    mldsa_keygen, mldsa_sign, mldsa_verify, mlkem_decapsulate, mlkem_encapsulate, mlkem_keygen,
};

// ── ML-DSA (Dilithium-3) ──────────────────────────────────────────────────────

/// ML-DSA keygen + sign + verify roundtrip succeeds.
/// Traces: HSM-REQ-033 / feat_req__sec_crypt__pqc
#[test]
fn test_mldsa_sign_verify_roundtrip() {
    let kp = mldsa_keygen();
    let message = b"Dilithium-3 test message for HSM-REQ-033";
    let sig = mldsa_sign(&kp.secret_key, message).unwrap();
    let ok = mldsa_verify(&kp.public_key, message, &sig).unwrap();
    assert!(ok, "ML-DSA signature must verify against original message");
}

/// ML-DSA signature over a different message is rejected.
/// Traces: HSM-REQ-033 / feat_req__sec_crypt__pqc
#[test]
fn test_mldsa_wrong_message_rejected() {
    let kp = mldsa_keygen();
    let message = b"correct message";
    let sig = mldsa_sign(&kp.secret_key, message).unwrap();
    let ok = mldsa_verify(&kp.public_key, b"tampered message", &sig).unwrap();
    assert!(
        !ok,
        "ML-DSA signature must not verify against different message"
    );
}

// ── ML-KEM (Kyber-768) ───────────────────────────────────────────────────────

/// ML-KEM encapsulate + decapsulate roundtrip produces equal shared secrets.
/// Traces: HSM-REQ-033 / feat_req__sec_crypt__pqc
#[test]
fn test_mlkem_encap_decap_roundtrip() {
    let kp = mlkem_keygen();
    let (ciphertext, ss_enc) = mlkem_encapsulate(&kp.public_key).unwrap();
    let ss_dec = mlkem_decapsulate(&kp.secret_key, &ciphertext).unwrap();
    assert_eq!(
        ss_enc, ss_dec,
        "ML-KEM shared secrets must match after encap/decap"
    );
    assert!(!ss_enc.is_empty(), "shared secret must not be empty");
    assert_ne!(
        ss_enc,
        vec![0u8; ss_enc.len()],
        "shared secret must not be all-zero"
    );
}

/// ML-KEM decapsulation with wrong ciphertext produces a different shared secret.
/// Traces: HSM-REQ-033 / feat_req__sec_crypt__pqc
#[test]
fn test_mlkem_wrong_ciphertext_different_secret() {
    let kp = mlkem_keygen();
    let (ciphertext, ss_correct) = mlkem_encapsulate(&kp.public_key).unwrap();

    // Flip one byte of the ciphertext
    let mut bad_ct = ciphertext.clone();
    bad_ct[0] ^= 0xff;

    // ML-KEM uses implicit rejection — decaps with wrong CT must NOT panic
    // and must produce a different (random-looking) shared secret.
    match mlkem_decapsulate(&kp.secret_key, &bad_ct) {
        Ok(ss_bad) => {
            assert_ne!(
                ss_bad, ss_correct,
                "wrong ciphertext must produce different shared secret"
            );
        }
        Err(_) => {
            // Explicit rejection is also acceptable
        }
    }
}
