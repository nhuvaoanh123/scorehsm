// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! POST/KAT integration tests — HSM-REQ-074/075.
//!
//! Verifies that the power-on self-test KAT vectors pass and that
//! individual crypto primitives produce expected results.

use scorehsm_host::safety::run_post;

/// ITP-POST-01: Full POST passes on healthy system.
#[test]
fn itp_post_full_passes() {
    run_post().expect("POST should pass");
}

/// ITP-POST-02: SHA-256 KAT produces correct NIST vector.
#[test]
fn itp_post_sha256_kat_matches_nist() {
    use sha2::{Digest, Sha256};
    let hash: [u8; 32] = Sha256::digest(b"abc").into();
    assert_eq!(
        hash,
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ],
        "SHA-256(abc) KAT mismatch"
    );
}

/// ITP-POST-03: AES-256-GCM encrypt/decrypt round-trip preserves plaintext.
#[test]
fn itp_post_aes_gcm_roundtrip() {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&[0x42u8; 32]);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&[0x00u8; 12]);
    let plaintext = b"integration-test-POST";
    let ct = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
    let pt = cipher.decrypt(nonce, ct.as_ref()).unwrap();
    assert_eq!(pt, plaintext, "AES-GCM round-trip failed");
}

/// ITP-POST-04: ECDSA P-256 pairwise consistency (sign + verify).
#[test]
fn itp_post_ecdsa_pairwise() {
    use p256::ecdsa::{signature::Signer, signature::Verifier, SigningKey};
    let sk = SigningKey::from_slice(&[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ])
    .unwrap();
    let vk = sk.verifying_key();
    let msg = b"integration-test-ECDSA";
    let sig: p256::ecdsa::Signature = sk.sign(msg);
    vk.verify(msg, &sig)
        .expect("ECDSA pairwise verification failed");
}
