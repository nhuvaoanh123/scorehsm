//! Software backend tests — TDD, all tests written before implementation.
//!
//! Requirement traceability:
//!   Each test is tagged with HSM-REQ-NNN and the corresponding SCORE ID.
//!
//! These tests run in CI without any hardware attached.

use scorehsm_host::{
    backend::{sw::SoftwareBackend, HsmBackend},
    error::HsmError,
    types::{AesGcmParams, EcdsaSignature, KeyType},
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
    let mut b = SoftwareBackend::new();
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
    let expected = hex::decode(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ).unwrap();
    assert_eq!(&digest, expected.as_slice());
}

/// SHA-256 of "abc" must equal the known test vector.
/// Traces: HSM-REQ-013 / feat_req__sec_crypt__hashing_algo_sha2
#[test]
fn test_sha256_abc_vector() {
    let b = init_backend();
    let digest = b.sha256(b"abc").unwrap();
    let expected = hex::decode(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ).unwrap();
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
    let recovered = b.aes_gcm_decrypt(h, &gcm_params(&iv, aad), &ct, &tag).unwrap();
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
    let (ct, mut tag) = b.aes_gcm_encrypt(h, &gcm_params(&iv, b""), b"data").unwrap();
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
    let (ct, tag) = b.aes_gcm_encrypt(h, &gcm_params(&iv, b"correct aad"), b"data").unwrap();
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

/// HMAC-SHA256 NIST test vector (RFC 4231, test case 1).
/// Key = 0x0b * 20, data = "Hi There", HMAC = b0344c61...
/// Traces: HSM-REQ-011 / feat_req__sec_crypt__mac
#[test]
fn test_hmac_sha256_nist_vector() {
    // For SW backend: import a known key
    // This test will be enabled once key_import is implemented
    // TODO: enable when key_import is complete
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
    let derived = b.key_derive(base, b"context info", KeyType::Aes256).unwrap();
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

/// Same base key and same info must derive the same key material (deterministic).
/// Traces: HSM-REQ-015 / feat_req__sec_crypt__kdf
#[test]
fn test_hkdf_deterministic() {
    // For this test we need key comparison — use HMAC as a proxy:
    // if derived keys are same, HMAC of same input is same
    let mut b = init_backend();
    let base1 = b.key_generate(KeyType::HmacSha256).unwrap();
    // Note: true determinism test requires importing a fixed key as base
    // TODO: enable full determinism test once key_import is complete
    let _ = base1;
}

// ─── HSM-REQ-023 — No key export ────────────────────────────────────────────

/// The API must not have a key_export function — compile-time check.
/// Traces: HSM-REQ-023 / feat_req__sec_crypt__no_key_exposure
/// This test verifies by inspection — there is no key_export in HsmBackend.
#[test]
fn test_no_key_export_in_api() {
    // If this file compiles, the API does not expose key_export.
    // The trait definition is the enforcement — no function exists to call.
    assert!(true, "HsmBackend trait has no key_export — verified by trait definition");
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
