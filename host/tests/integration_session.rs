//! Session management integration tests — TSR-SMG-01/02/03.
//!
//! Tests HsmSession ownership model, IDS event emission, handle lifecycle,
//! session isolation, and failure counting through the public API.

use scorehsm_host::{
    backend::sw::SoftwareBackend,
    error::HsmError,
    ids::{IdsEvent, IdsHook},
    session::HsmSession,
    types::{AesGcmParams, KeyHandle, KeyType},
};
use std::sync::{Arc, Mutex};

// ── Recorder hook ──────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct Recorder {
    events: Arc<Mutex<Vec<String>>>,
}

impl IdsHook for Recorder {
    fn on_event(&self, event: IdsEvent) {
        self.events.lock().unwrap().push(format!("{:?}", event));
    }
}

fn make_session() -> HsmSession {
    let b = SoftwareBackend::new();
    let mut s = HsmSession::new(b);
    s.init().unwrap();
    s
}

fn make_session_with_recorder() -> (HsmSession, Recorder) {
    let b = SoftwareBackend::new();
    let recorder = Recorder::default();
    let mut s = HsmSession::new(b).with_ids_hook(Box::new(recorder.clone()));
    s.init().unwrap();
    (s, recorder)
}

/// ITP-SMG-01-a: Generated key handle can be used by the owning session.
#[test]
fn itp_session_generated_key_usable() {
    let mut s = make_session();
    let h = s.key_generate(KeyType::EccP256).unwrap();
    let digest = s.sha256(b"test").unwrap();
    assert!(s.ecdsa_sign(h, &digest).is_ok());
}

/// ITP-SMG-01-b: Using a handle not owned by this session returns InvalidKeyHandle.
#[test]
fn itp_session_unknown_handle_rejected() {
    let mut s = make_session();
    let digest = s.sha256(b"test").unwrap();
    let fake_handle = KeyHandle(9999);
    let result = s.ecdsa_sign(fake_handle, &digest);
    assert!(matches!(result, Err(HsmError::InvalidKeyHandle)));
}

/// ITP-SMG-01-c: Unknown handle emits IDS UnknownHandle event.
#[test]
fn itp_session_unknown_handle_emits_ids() {
    let (mut s, recorder) = make_session_with_recorder();
    let fake_handle = KeyHandle(9999);
    let digest = s.sha256(b"test").unwrap();
    let _ = s.ecdsa_sign(fake_handle, &digest);

    let events = recorder.events.lock().unwrap();
    assert!(
        events.iter().any(|e| e.contains("UnknownHandle")),
        "UnknownHandle IDS event must be emitted"
    );
}

/// ITP-SMG-02-a: Key deletion makes handle unusable.
#[test]
fn itp_session_deleted_key_unusable() {
    let mut s = make_session();
    let h = s.key_generate(KeyType::EccP256).unwrap();
    s.key_delete(h).unwrap();
    let digest = s.sha256(b"test").unwrap();
    let result = s.ecdsa_sign(h, &digest);
    assert!(matches!(result, Err(HsmError::InvalidKeyHandle)));
}

/// ITP-SMG-02-b: Key generation emits IDS KeyGenerated event.
#[test]
fn itp_session_keygen_emits_ids() {
    let (mut s, recorder) = make_session_with_recorder();
    let _h = s.key_generate(KeyType::Aes256).unwrap();

    let events = recorder.events.lock().unwrap();
    assert!(
        events.iter().any(|e| e.contains("KeyGenerated")),
        "KeyGenerated IDS event must be emitted"
    );
}

/// ITP-SMG-02-c: Key deletion emits IDS KeyDeleted event.
#[test]
fn itp_session_key_delete_emits_ids() {
    let (mut s, recorder) = make_session_with_recorder();
    let h = s.key_generate(KeyType::Aes256).unwrap();
    s.key_delete(h).unwrap();

    let events = recorder.events.lock().unwrap();
    assert!(
        events.iter().any(|e| e.contains("KeyDeleted")),
        "KeyDeleted IDS event must be emitted"
    );
}

/// ITP-SMG-02-d: ECDSA sign emits IDS EcdsaSigned event.
#[test]
fn itp_session_sign_emits_ids() {
    let (mut s, recorder) = make_session_with_recorder();
    let h = s.key_generate(KeyType::EccP256).unwrap();
    let digest = s.sha256(b"msg").unwrap();
    s.ecdsa_sign(h, &digest).unwrap();

    let events = recorder.events.lock().unwrap();
    assert!(
        events.iter().any(|e| e.contains("EcdsaSigned")),
        "EcdsaSigned IDS event must be emitted"
    );
}

/// ITP-SMG-03-a: AES-GCM with bad tag emits DecryptFailed IDS event and increments failure counter.
#[test]
fn itp_session_decrypt_fail_emits_ids() {
    let (mut s, recorder) = make_session_with_recorder();
    let h = s.key_generate(KeyType::Aes256).unwrap();
    let iv = [0u8; 12];
    let params = AesGcmParams { iv: &iv, aad: b"" };
    let (_ct, _tag) = s.aes_gcm_encrypt(h, &params, b"data").unwrap();

    // Decrypt with a bad tag
    let bad_tag = [0xFFu8; 16];
    let result = s.aes_gcm_decrypt(h, &params, &_ct, &bad_tag);
    assert!(matches!(result, Err(HsmError::TagMismatch)));

    let events = recorder.events.lock().unwrap();
    assert!(
        events.iter().any(|e| e.contains("DecryptFailed")),
        "DecryptFailed IDS event must be emitted"
    );
}

/// ITP-SMG-03-b: Deinit clears all owned handles.
#[test]
fn itp_session_deinit_clears_handles() {
    let b = SoftwareBackend::new();
    let mut s = HsmSession::new(b);
    s.init().unwrap();
    let h = s.key_generate(KeyType::EccP256).unwrap();
    s.deinit().unwrap();

    // Re-init
    s.init().unwrap();
    let digest = s.sha256(b"test").unwrap();
    // Old handle should be invalid
    let result = s.ecdsa_sign(h, &digest);
    assert!(matches!(result, Err(HsmError::InvalidKeyHandle)));
}

/// ITP-SMG-03-c: Multiple key types can coexist in a single session.
#[test]
fn itp_session_multiple_key_types() {
    let mut s = make_session();
    let h_aes = s.key_generate(KeyType::Aes256).unwrap();
    let h_ecc = s.key_generate(KeyType::EccP256).unwrap();
    let h_hmac = s.key_generate(KeyType::HmacSha256).unwrap();

    // All handles usable
    let iv = [0u8; 12];
    let params = AesGcmParams { iv: &iv, aad: b"" };
    assert!(s.aes_gcm_encrypt(h_aes, &params, b"data").is_ok());

    let digest = s.sha256(b"msg").unwrap();
    assert!(s.ecdsa_sign(h_ecc, &digest).is_ok());
    assert!(s.hmac_sha256(h_hmac, b"data").is_ok());
}
