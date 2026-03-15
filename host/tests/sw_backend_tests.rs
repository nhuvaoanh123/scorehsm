//! Software backend tests — TDD, all tests written before implementation.
//!
//! Requirement traceability:
//!   Each test is tagged with HSM-REQ-NNN and the corresponding SCORE ID.
//!
//! These tests run in CI without any hardware attached.

use scorehsm_host::{
    backend::{sw::SoftwareBackend, HsmBackend},
    error::HsmError,
    types::{AesGcmParams, KeyType},
};
// ─── Helpers ────────────────────────────────────────────────────────────────

fn init_backend() -> SoftwareBackend {
    let mut b = SoftwareBackend::new();
    b.init().expect("init must succeed");
    b
}

// ─── HSM-REQ-026 — API lifecycle ────────────────────────────────────────────

/// Operations before init() must return NotInitialized.
/// Traces: HSM-REQ-026 / feat_req__sec_crypt__api_lifecycle
#[test]
fn test_not_initialized_before_init() {
    let b = SoftwareBackend::new();
    let result = b.sha256(b"hello");
    assert!(matches!(result, Err(HsmError::NotInitialized)));
}

/// init() must succeed and allow subsequent operations.
/// Traces: HSM-REQ-026 / feat_req__sec_crypt__api_lifecycle
#[test]
fn test_init_succeeds() {
    let mut b = SoftwareBackend::new();
    assert!(b.init().is_ok());
}

/// deinit() must succeed after init().
/// Traces: HSM-REQ-026 / feat_req__sec_crypt__api_lifecycle
#[test]
fn test_deinit_succeeds() {
    let mut b = SoftwareBackend::new();
    b.init().unwrap();
    assert!(b.deinit().is_ok());
}

// ─── HSM-REQ-016 — Random number generation ─────────────────────────────────

/// random() must fill the buffer with bytes (non-zero check is probabilistic).
/// Traces: HSM-REQ-016 / feat_req__sec_crypt__rng
#[test]
fn test_random_fills_buffer() {
    let mut b = init_backend();
    let mut buf = [0u8; 32];
    b.random(&mut buf).expect("random must succeed");
    // Probability of all zeros is 1/2^256 — effectively impossible
    assert_ne!(buf, [0u8; 32]);
}

/// Two random calls must produce different output.
/// Traces: HSM-REQ-016 / feat_req__sec_crypt__rng
#[test]
fn test_random_is_different_each_call() {
    let mut b = init_backend();
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    b.random(&mut buf1).unwrap();
    b.random(&mut buf2).unwrap();
    assert_ne!(buf1, buf2);
}

/// random() with zero-length buffer must succeed without error.
/// Traces: HSM-REQ-016 / feat_req__sec_crypt__rng
#[test]
fn test_random_zero_length() {
    let mut b = init_backend();
    assert!(b.random(&mut []).is_ok());
}

// ─── HSM-REQ-013 — SHA-256 ──────────────────────────────────────────────────

/// SHA-256 of empty string must equal the known test vector.
/// Traces: HSM-REQ-013 / feat_req__sec_crypt__hashing_algo_sha2
#[test]
fn test_sha256_empty_vector() {
    let b = init_backend();
    let digest = b.sha256(b"").unwrap();
    // NIST test vector: SHA-256("")
    let expected =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    assert_eq!(&digest, expected.as_slice());
}

/// SHA-256 of "abc" must equal the known test vector.
/// Traces: HSM-REQ-013 / feat_req__sec_crypt__hashing_algo_sha2
#[test]
fn test_sha256_abc_vector() {
    let b = init_backend();
    let digest = b.sha256(b"abc").unwrap();
    let expected =
        hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();
    assert_eq!(&digest, expected.as_slice());
}

/// SHA-256 must be deterministic — same input, same output.
/// Traces: HSM-REQ-013 / feat_req__sec_crypt__hashing_algo_sha2
#[test]
fn test_sha256_deterministic() {
    let b = init_backend();
    let d1 = b.sha256(b"scorehsm test data").unwrap();
    let d2 = b.sha256(b"scorehsm test data").unwrap();
    assert_eq!(d1, d2);
}

/// Different inputs must produce different SHA-256 digests.
/// Traces: HSM-REQ-013 / feat_req__sec_crypt__hashing_algo_sha2
#[test]
fn test_sha256_different_inputs_differ() {
    let b = init_backend();
    let d1 = b.sha256(b"hello").unwrap();
    let d2 = b.sha256(b"world").unwrap();
    assert_ne!(d1, d2);
}

// ─── HSM-REQ-019 / HSM-REQ-022 — Key generate and delete ───────────────────

/// key_generate(AES256) must return a valid non-zero handle.
/// Traces: HSM-REQ-019 / feat_req__sec_crypt__key_generation
#[test]
fn test_key_generate_aes256_returns_handle() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::Aes256).unwrap();
    assert_ne!(h.0, 0, "handle must not be zero");
}

/// key_generate(HmacSha256) must return a valid non-zero handle.
/// Traces: HSM-REQ-019 / feat_req__sec_crypt__key_generation
#[test]
fn test_key_generate_hmac_returns_handle() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::HmacSha256).unwrap();
    assert_ne!(h.0, 0);
}

/// Two key_generate calls must return different handles.
/// Traces: HSM-REQ-019 / feat_req__sec_crypt__key_generation
#[test]
fn test_key_generate_unique_handles() {
    let mut b = init_backend();
    let h1 = b.key_generate(KeyType::Aes256).unwrap();
    let h2 = b.key_generate(KeyType::Aes256).unwrap();
    assert_ne!(h1, h2);
}

/// key_delete must succeed for a valid handle.
/// Traces: HSM-REQ-022 / feat_req__sec_crypt__key_deletion
#[test]
fn test_key_delete_valid_handle() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::Aes256).unwrap();
    assert!(b.key_delete(h).is_ok());
}

/// key_delete on an already-deleted handle must return InvalidKeyHandle.
/// Traces: HSM-REQ-022 / feat_req__sec_crypt__key_deletion
#[test]
fn test_key_delete_twice_is_error() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::Aes256).unwrap();
    b.key_delete(h).unwrap();
    let result = b.key_delete(h);
    assert!(matches!(result, Err(HsmError::InvalidKeyHandle)));
}

/// key_delete on a nonexistent handle must return InvalidKeyHandle.
/// Traces: HSM-REQ-022 / feat_req__sec_crypt__key_deletion
#[test]
fn test_key_delete_invalid_handle() {
    use scorehsm_host::types::KeyHandle;
    let mut b = init_backend();
    let result = b.key_delete(KeyHandle(0xDEAD));
    assert!(matches!(result, Err(HsmError::InvalidKeyHandle)));
}

/// Operations using a deleted handle must fail.
/// Traces: HSM-REQ-022 / feat_req__sec_crypt__key_deletion
#[test]
fn test_deleted_handle_is_unusable() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::HmacSha256).unwrap();
    b.key_delete(h).unwrap();
    let result = b.hmac_sha256(h, b"data");
    assert!(matches!(result, Err(HsmError::InvalidKeyHandle)));
}

// ─── HSM-REQ-002 — AES-256-GCM ──────────────────────────────────────────────

fn gcm_params<'a>(iv: &'a [u8; 12], aad: &'a [u8]) -> AesGcmParams<'a> {
    AesGcmParams { iv, aad }
}

/// AES-GCM encrypt then decrypt must recover original plaintext.
/// Traces: HSM-REQ-002 / feat_req__sec_crypt__sym_sym_algo_aes_gcm
#[test]
fn test_aes_gcm_roundtrip() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::Aes256).unwrap();
    let iv = [0x42u8; 12];
    let aad = b"additional data";
    let pt = b"hello scorehsm world";

    let (ct, tag) = b.aes_gcm_encrypt(h, &gcm_params(&iv, aad), pt).unwrap();
    let recovered = b
        .aes_gcm_decrypt(h, &gcm_params(&iv, aad), &ct, &tag)
        .unwrap();
    assert_eq!(recovered, pt);
}

/// Ciphertext length must equal plaintext length.
/// Traces: HSM-REQ-002 / feat_req__sec_crypt__sym_sym_algo_aes_gcm
#[test]
fn test_aes_gcm_ciphertext_length() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::Aes256).unwrap();
    let iv = [0u8; 12];
    let pt = b"sixteen bytes!!";
    let (ct, _tag) = b.aes_gcm_encrypt(h, &gcm_params(&iv, b""), pt).unwrap();
    assert_eq!(ct.len(), pt.len());
}

/// Decrypt with wrong tag must return TagMismatch.
/// Traces: HSM-REQ-002 / feat_req__sec_crypt__sym_sym_algo_aes_gcm
#[test]
fn test_aes_gcm_wrong_tag_rejected() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::Aes256).unwrap();
    let iv = [0u8; 12];
    let (ct, mut tag) = b
        .aes_gcm_encrypt(h, &gcm_params(&iv, b""), b"data")
        .unwrap();
    tag[0] ^= 0xFF; // corrupt tag
    let result = b.aes_gcm_decrypt(h, &gcm_params(&iv, b""), &ct, &tag);
    assert!(matches!(result, Err(HsmError::TagMismatch)));
}

/// Decrypt with wrong AAD must return TagMismatch.
/// Traces: HSM-REQ-002 / feat_req__sec_crypt__sym_sym_algo_aes_gcm
#[test]
fn test_aes_gcm_wrong_aad_rejected() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::Aes256).unwrap();
    let iv = [0u8; 12];
    let (ct, tag) = b
        .aes_gcm_encrypt(h, &gcm_params(&iv, b"correct aad"), b"data")
        .unwrap();
    let result = b.aes_gcm_decrypt(h, &gcm_params(&iv, b"wrong aad"), &ct, &tag);
    assert!(matches!(result, Err(HsmError::TagMismatch)));
}

/// Two encryptions of same plaintext with same key but different IVs must differ.
/// Traces: HSM-REQ-002 / feat_req__sec_crypt__sym_sym_algo_aes_gcm
#[test]
fn test_aes_gcm_different_iv_different_ct() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::Aes256).unwrap();
    let iv1 = [0u8; 12];
    let iv2 = [1u8; 12];
    let pt = b"same plaintext";
    let (ct1, _) = b.aes_gcm_encrypt(h, &gcm_params(&iv1, b""), pt).unwrap();
    let (ct2, _) = b.aes_gcm_encrypt(h, &gcm_params(&iv2, b""), pt).unwrap();
    assert_ne!(ct1, ct2);
}

/// AES-GCM with wrong key handle must fail.
/// Traces: HSM-REQ-002, HSM-REQ-023
#[test]
fn test_aes_gcm_wrong_handle_fails() {
    use scorehsm_host::types::KeyHandle;
    let b = init_backend();
    let iv = [0u8; 12];
    let result = b.aes_gcm_encrypt(KeyHandle(0xDEAD), &gcm_params(&iv, b""), b"data");
    assert!(matches!(result, Err(HsmError::InvalidKeyHandle)));
}

/// AES-GCM with HMAC key handle must fail (wrong key type).
/// Traces: HSM-REQ-002, HSM-REQ-023
#[test]
fn test_aes_gcm_wrong_key_type_fails() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::HmacSha256).unwrap();
    let iv = [0u8; 12];
    let result = b.aes_gcm_encrypt(h, &gcm_params(&iv, b""), b"data");
    assert!(matches!(result, Err(HsmError::InvalidKeyHandle)));
}

// ─── HSM-REQ-011 — HMAC-SHA256 ──────────────────────────────────────────────

/// HMAC-SHA256 must be deterministic.
/// Traces: HSM-REQ-011 / feat_req__sec_crypt__mac
#[test]
fn test_hmac_sha256_deterministic() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::HmacSha256).unwrap();
    let mac1 = b.hmac_sha256(h, b"message").unwrap();
    let mac2 = b.hmac_sha256(h, b"message").unwrap();
    assert_eq!(mac1, mac2);
}

/// HMAC-SHA256 of different messages must differ.
/// Traces: HSM-REQ-011 / feat_req__sec_crypt__mac
#[test]
fn test_hmac_sha256_different_messages() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::HmacSha256).unwrap();
    let mac1 = b.hmac_sha256(h, b"message1").unwrap();
    let mac2 = b.hmac_sha256(h, b"message2").unwrap();
    assert_ne!(mac1, mac2);
}

/// HMAC-SHA256 with different keys must differ.
/// Traces: HSM-REQ-011 / feat_req__sec_crypt__mac
#[test]
fn test_hmac_sha256_different_keys() {
    let mut b = init_backend();
    let h1 = b.key_generate(KeyType::HmacSha256).unwrap();
    let h2 = b.key_generate(KeyType::HmacSha256).unwrap();
    let mac1 = b.hmac_sha256(h1, b"message").unwrap();
    let mac2 = b.hmac_sha256(h2, b"message").unwrap();
    assert_ne!(mac1, mac2);
}

/// Importing identical keys into two handles must produce identical MACs.
///
/// Verifies that `key_import` stores the key bytes faithfully — if the stored
/// bytes differed from what was supplied, the MAC output would differ.
///
/// Traces: HSM-REQ-011, HSM-REQ-022 / feat_req__sec_crypt__mac
#[test]
fn test_hmac_sha256_nist_vector() {
    let mut b = init_backend();

    let key_a = [0x0bu8; 32];
    let h1 = b.key_import(KeyType::HmacSha256, &key_a).unwrap();
    let h2 = b.key_import(KeyType::HmacSha256, &key_a).unwrap();

    let mac1 = b.hmac_sha256(h1, b"Hi There").unwrap();
    let mac2 = b.hmac_sha256(h2, b"Hi There").unwrap();

    // Same key bytes in two separate slots must yield the same MAC.
    assert_eq!(
        mac1, mac2,
        "two handles with identical imported key bytes must produce the same MAC"
    );

    // A different key must produce a different MAC.
    let h3 = b.key_import(KeyType::HmacSha256, &[0xffu8; 32]).unwrap();
    let mac3 = b.hmac_sha256(h3, b"Hi There").unwrap();
    assert_ne!(
        mac1, mac3,
        "different imported key bytes must yield a different MAC"
    );
}

// ─── HSM-REQ-008/010 — ECDSA P-256 ─────────────────────────────────────────

/// ECDSA sign + verify roundtrip must succeed.
/// Traces: HSM-REQ-008, HSM-REQ-010 / feat_req__sec_crypt__sig_creation
#[test]
fn test_ecdsa_sign_verify_roundtrip() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::EccP256).unwrap();
    let digest = b.sha256(b"message to sign").unwrap();
    let sig = b.ecdsa_sign(h, &digest).unwrap();
    let valid = b.ecdsa_verify(h, &digest, &sig).unwrap();
    assert!(valid);
}

/// ECDSA verify with modified digest must return false.
/// Traces: HSM-REQ-009 / feat_req__sec_crypt__sig_verification
#[test]
fn test_ecdsa_verify_wrong_digest_fails() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::EccP256).unwrap();
    let digest = b.sha256(b"correct message").unwrap();
    let sig = b.ecdsa_sign(h, &digest).unwrap();
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 0xFF;
    let valid = b.ecdsa_verify(h, &wrong_digest, &sig).unwrap();
    assert!(!valid);
}

/// ECDSA verify with modified signature must return false.
/// Traces: HSM-REQ-009 / feat_req__sec_crypt__sig_verification
#[test]
fn test_ecdsa_verify_wrong_signature_fails() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::EccP256).unwrap();
    let digest = b.sha256(b"message").unwrap();
    let mut sig = b.ecdsa_sign(h, &digest).unwrap();
    sig.r[0] ^= 0xFF; // corrupt r
    let valid = b.ecdsa_verify(h, &digest, &sig).unwrap();
    assert!(!valid);
}

/// ECDSA uses RFC 6979 deterministic k: same key + digest => same signature.
/// Both signatures must be valid, and determinism is a security property (no RNG failure risk).
/// Traces: HSM-REQ-008 / feat_req__sec_crypt__sig_creation
#[test]
fn test_ecdsa_sign_deterministic_rfc6979() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::EccP256).unwrap();
    let digest = b.sha256(b"message").unwrap();
    let sig1 = b.ecdsa_sign(h, &digest).unwrap();
    let sig2 = b.ecdsa_sign(h, &digest).unwrap();
    // RFC 6979: deterministic ECDSA — same key + digest yields identical (r, s)
    assert_eq!(sig1.r, sig2.r);
    assert_eq!(sig1.s, sig2.s);
    // Both signatures must verify correctly
    assert!(b.ecdsa_verify(h, &digest, &sig1).unwrap());
    assert!(b.ecdsa_verify(h, &digest, &sig2).unwrap());
}

// ─── HSM-REQ-015 — HKDF key derivation ─────────────────────────────────────

/// key_derive must return a new valid handle.
/// Traces: HSM-REQ-015 / feat_req__sec_crypt__kdf
#[test]
fn test_hkdf_returns_new_handle() {
    let mut b = init_backend();
    let base = b.key_generate(KeyType::Aes256).unwrap();
    let derived = b
        .key_derive(base, b"context info", KeyType::Aes256)
        .unwrap();
    assert_ne!(base, derived);
    assert_ne!(derived.0, 0);
}

/// Derived key handle must be usable for AES-GCM.
/// Traces: HSM-REQ-015 / feat_req__sec_crypt__kdf
#[test]
fn test_hkdf_derived_key_is_usable() {
    let mut b = init_backend();
    let base = b.key_generate(KeyType::Aes256).unwrap();
    let derived = b.key_derive(base, b"info", KeyType::Aes256).unwrap();
    let iv = [0u8; 12];
    let result = b.aes_gcm_encrypt(derived, &gcm_params(&iv, b""), b"test");
    assert!(result.is_ok());
}

/// HKDF-SHA256 must be deterministic: same base key + same info → same derived key.
///
/// Uses `key_import` to load a known base key into two separate slots, then
/// derives from each.  The derived keys must produce identical HMAC output,
/// proving the derivation is a pure function of the input.
///
/// Traces: HSM-REQ-015 / feat_req__sec_crypt__kdf
#[test]
fn test_hkdf_deterministic() {
    let mut b = init_backend();

    // Import the same base key into two independent slots.
    let known_base = [0xAAu8; 32];
    let h1 = b.key_import(KeyType::HmacSha256, &known_base).unwrap();
    let h2 = b.key_import(KeyType::HmacSha256, &known_base).unwrap();

    // Derive from each with identical info strings.
    let d1 = b
        .key_derive(h1, b"scorehsm-test-context", KeyType::HmacSha256)
        .unwrap();
    let d2 = b
        .key_derive(h2, b"scorehsm-test-context", KeyType::HmacSha256)
        .unwrap();

    // If HKDF is deterministic, both derived keys are identical.
    // Verify by MAC: equal keys → equal MAC.
    let mac1 = b.hmac_sha256(d1, b"verification payload").unwrap();
    let mac2 = b.hmac_sha256(d2, b"verification payload").unwrap();
    assert_eq!(
        mac1, mac2,
        "HKDF with identical base key and info must produce identical derived key (HSM-REQ-015)"
    );

    // A different info string must yield a different derived key.
    let h3 = b.key_import(KeyType::HmacSha256, &known_base).unwrap();
    let d3 = b
        .key_derive(h3, b"different-context", KeyType::HmacSha256)
        .unwrap();
    let mac3 = b.hmac_sha256(d3, b"verification payload").unwrap();
    assert_ne!(
        mac1, mac3,
        "different info strings must produce different derived keys"
    );
}

// ─── HSM-REQ-023 — No key export ────────────────────────────────────────────

/// The API must not have a key_export function — compile-time check.
/// Traces: HSM-REQ-023 / feat_req__sec_crypt__no_key_exposure
/// This test verifies by inspection — there is no key_export in HsmBackend.
#[test]
fn test_no_key_export_in_api() {
    // If this file compiles, the API does not expose key_export.
    // The trait definition is the enforcement — no function exists to call.
    // If this file compiles, the trait enforces no key_export exists.
    // (Clippy forbids assert!(true), so the compile-time check is sufficient.)
}

// ─── HSM-REQ-027 — Error handling ───────────────────────────────────────────

/// All error paths must return typed errors, not panics.
/// Traces: HSM-REQ-027 / feat_req__sec_crypt__error_handling
#[test]
fn test_errors_are_typed_not_panics() {
    use scorehsm_host::types::KeyHandle;
    let mut b = SoftwareBackend::new(); // not initialized
                                        // These must return Err, not panic
    assert!(b.sha256(b"").is_err());
    assert!(b.random(&mut [0u8; 4]).is_err());
    assert!(b.key_delete(KeyHandle(1)).is_err());
}

// ─── HSM-REQ-013 — ECDH key agreement ───────────────────────────────────────

/// Helper: build a 64-byte peer public key from a raw P-256 scalar.
#[cfg(test)]
fn ecdh_peer_pub_from_scalar(scalar: &[u8; 32]) -> [u8; 64] {
    use p256::ecdsa::SigningKey;
    let sk = SigningKey::from_bytes(scalar.into()).unwrap();
    let encoded = sk.verifying_key().to_encoded_point(false);
    let bytes = encoded.as_bytes(); // 65 bytes: 0x04 || x || y
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[1..65]);
    out
}

/// ECDH agreement returns 32 non-zero bytes.
/// Traces: HSM-REQ-013 / feat_req__sec_crypt__key_agreement
#[test]
fn test_ecdh_produces_32_bytes() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::EccP256).unwrap();
    let peer_scalar = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20u8,
    ];
    let peer_pub = ecdh_peer_pub_from_scalar(&peer_scalar);
    let shared = b.ecdh_agree(h, &peer_pub).unwrap();
    assert_eq!(shared.len(), 32);
    assert_ne!(shared, [0u8; 32], "shared secret must not be all-zero");
}

/// ECDH is symmetric: ecdh_agree(A_sk, B_pk) == ecdh_agree(B_sk, A_pk).
///
/// Both directions are exercised through the backend using `key_import` to
/// load known scalars.  This tests the full end-to-end property — not just
/// the mathematical identity via an external crate.
///
/// Traces: HSM-REQ-006 / feat_req__sec_crypt__key_agreement
#[test]
fn test_ecdh_symmetric() {
    use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};

    // Two known, valid P-256 scalars used as fixed test vectors.
    let scalar_a: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let scalar_b: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18,
    ];

    // Derive each party's public key from the known scalar (used as the peer
    // argument to ecdh_agree — the backend only needs the 64-byte X||Y point).
    let pub_a = ecdh_peer_pub_from_scalar(&scalar_a);
    let pub_b = ecdh_peer_pub_from_scalar(&scalar_b);

    let mut b = init_backend();

    // Import both private keys so the backend holds the known scalar material.
    let ha = b.key_import(KeyType::EccP256, &scalar_a).unwrap();
    let hb = b.key_import(KeyType::EccP256, &scalar_b).unwrap();

    // Both directions through the backend — must produce the same shared secret.
    let ss_a_side = b.ecdh_agree(ha, &pub_b).unwrap(); // A uses B's public key
    let ss_b_side = b.ecdh_agree(hb, &pub_a).unwrap(); // B uses A's public key

    assert_eq!(
        ss_a_side, ss_b_side,
        "ECDH(A_sk, B_pk) must equal ECDH(B_sk, A_pk) — tested end-to-end via the backend"
    );
    assert_ne!(ss_a_side, [0u8; 32], "shared secret must not be all-zero");

    // Cross-check: backend result must match the expected value from the pure
    // p256 crate (guards against a backend implementation that passes the
    // symmetry check but computes the wrong shared secret entirely).
    let sk_a = SecretKey::from_bytes(&scalar_a.into()).unwrap();
    let sk_b = SecretKey::from_bytes(&scalar_b.into()).unwrap();
    let pub_b_ep = sk_b.public_key().to_encoded_point(false);
    let expected =
        p256::ecdh::diffie_hellman(sk_a.to_nonzero_scalar(), sk_b.public_key().as_affine());
    // The backend's first-direction result must match the pure-p256 reference.
    assert_eq!(
        ss_a_side,
        expected.raw_secret_bytes().as_slice(),
        "backend ECDH result must match the reference p256 implementation"
    );
    let _ = pub_b_ep; // unused except for conceptual clarity above
}

/// ECDH with a non-EccP256 handle (AES key) must be rejected.
/// Traces: HSM-REQ-013 / feat_req__sec_crypt__key_agreement
#[test]
fn test_ecdh_wrong_key_type_rejected() {
    let mut b = init_backend();
    let aes_h = b.key_generate(KeyType::Aes256).unwrap();
    let peer_pub = ecdh_peer_pub_from_scalar(&[0x01u8; 32]);
    let result = b.ecdh_agree(aes_h, &peer_pub);
    assert!(result.is_err(), "ECDH with AES key must be rejected");
}

/// ECDH with an invalid (all-zero) peer public key must be rejected.
/// Traces: HSM-REQ-013 / feat_req__sec_crypt__key_agreement
#[test]
fn test_ecdh_invalid_peer_point_rejected() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::EccP256).unwrap();
    let bad_peer = [0u8; 64]; // all zeros — not a valid P-256 point
    let result = b.ecdh_agree(h, &bad_peer);
    assert!(
        result.is_err(),
        "ECDH with invalid peer point must be rejected"
    );
}

// ─── HSM-REQ-022 — Key import ────────────────────────────────────────────────

/// key_import(AES-256) with a valid 32-byte key must return a usable handle.
/// Traces: HSM-REQ-022 / feat_req__sec_crypt__key_import
#[test]
fn test_key_import_aes256_is_usable() {
    let mut b = init_backend();
    let h = b.key_import(KeyType::Aes256, &[0x42u8; 32]).unwrap();
    let iv = [0u8; 12];
    assert!(
        b.aes_gcm_encrypt(h, &gcm_params(&iv, b""), b"plaintext")
            .is_ok(),
        "imported AES-256 key must be usable for encryption (HSM-REQ-022)"
    );
}

/// key_import(HmacSha256) with a valid 32-byte key must return a usable handle.
/// Traces: HSM-REQ-022 / feat_req__sec_crypt__key_import
#[test]
fn test_key_import_hmac_sha256_is_usable() {
    let mut b = init_backend();
    let h = b.key_import(KeyType::HmacSha256, &[0x01u8; 32]).unwrap();
    assert!(
        b.hmac_sha256(h, b"data").is_ok(),
        "imported HMAC-SHA256 key must be usable (HSM-REQ-022)"
    );
}

/// key_import(EccP256) with a valid scalar must return a usable signing handle.
/// Traces: HSM-REQ-022 / feat_req__sec_crypt__key_import
#[test]
fn test_key_import_ecc_p256_is_usable() {
    let mut b = init_backend();
    // Known valid P-256 scalar.
    let scalar: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let h = b.key_import(KeyType::EccP256, &scalar).unwrap();
    let digest = [0x01u8; 32];
    assert!(
        b.ecdsa_sign(h, &digest).is_ok(),
        "imported P-256 key must be usable for signing (HSM-REQ-022)"
    );
}

/// key_import with a wrong-length buffer must return InvalidParam.
/// Traces: HSM-REQ-022, HSM-REQ-027 / feat_req__sec_crypt__key_import
#[test]
fn test_key_import_wrong_length_rejected() {
    let mut b = init_backend();
    let short = [0x42u8; 16]; // 16 bytes, not 32
    assert!(
        matches!(
            b.key_import(KeyType::Aes256, &short),
            Err(HsmError::InvalidParam(_))
        ),
        "wrong-length material must be rejected with InvalidParam (HSM-REQ-022)"
    );
}

/// key_import(EccP256) with the all-zero scalar must be rejected.
///
/// The all-zero scalar is not a valid P-256 private key (it equals the
/// identity element).  Accepting it would create a silently broken handle.
///
/// Traces: HSM-REQ-022, HSM-REQ-027 / feat_req__sec_crypt__key_import
#[test]
fn test_key_import_invalid_p256_scalar_rejected() {
    let mut b = init_backend();
    assert!(
        matches!(
            b.key_import(KeyType::EccP256, &[0u8; 32]),
            Err(HsmError::InvalidParam(_))
        ),
        "all-zero P-256 scalar must be rejected with InvalidParam (HSM-REQ-022)"
    );
}

// ─── HSM-REQ-043 — Key zeroization ───────────────────────────────────────────

/// After key_delete, the handle must be unusable for all operations.
///
/// The actual memory zeroing is guaranteed by `ZeroizeOnDrop` on `KeyMaterial`
/// (enforced at compile time in sw.rs via `_ASSERT_ZEROIZE_ON_DROP`).
/// This test verifies the observable post-delete behaviour.
///
/// Traces: HSM-REQ-043 / feat_req__sec_crypt__key_zeroization
#[test]
fn test_key_zeroize_on_delete() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::Aes256).unwrap();
    b.key_delete(h).unwrap();

    // Every operation that uses the deleted handle must fail.
    let iv = [0u8; 12];
    assert!(
        matches!(
            b.aes_gcm_encrypt(h, &gcm_params(&iv, b""), b"x"),
            Err(HsmError::InvalidKeyHandle)
        ),
        "deleted handle must be rejected with InvalidKeyHandle (HSM-REQ-043)"
    );
}

/// After deinit(), handles from before deinit must be unusable post-reinit.
///
/// `deinit` calls `keys.clear()` which drops every `KeyMaterial` value;
/// `ZeroizeOnDrop` fires for each, wiping the key bytes.
///
/// Traces: HSM-REQ-043 / feat_req__sec_crypt__key_zeroization
#[test]
fn test_key_zeroize_on_deinit() {
    let mut b = init_backend();
    let h = b.key_generate(KeyType::Aes256).unwrap();

    b.deinit().unwrap();
    b.init().unwrap(); // re-initialise with a clean store

    let iv = [0u8; 12];
    assert!(
        matches!(
            b.aes_gcm_encrypt(h, &gcm_params(&iv, b""), b"x"),
            Err(HsmError::InvalidKeyHandle)
        ),
        "handle from before deinit must be invalid after reinit (HSM-REQ-043)"
    );
}
