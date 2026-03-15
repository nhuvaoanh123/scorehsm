//! Safe state integration tests — TSR-SSG-01/02.
//!
//! Tests library state machine, safe-state blocking, recovery via reinit,
//! KeyStoreChecksum integrity, and shared state across sessions.

use scorehsm_host::{
    backend::sw::SoftwareBackend,
    error::HsmError,
    safety::{KeyStoreChecksum, LibraryState, State},
    session::HsmSession,
    types::KeyType,
};
use std::collections::HashSet;
use std::sync::Arc;

fn make_session_with_state(state: Arc<LibraryState>) -> HsmSession {
    let b = SoftwareBackend::new();
    let mut s = HsmSession::new(b).with_library_state(state);
    s.init().unwrap();
    s
}

/// ITP-SSG-01-a: Safe state blocks key generation.
#[test]
fn itp_safe_state_blocks_keygen() {
    let state = Arc::new(LibraryState::new());
    let mut s = make_session_with_state(state.clone());

    // Normal operation works
    assert!(s.key_generate(KeyType::EccP256).is_ok());

    // Enter safe state
    state.enter_safe_state("test trigger");
    let result = s.key_generate(KeyType::EccP256);
    assert!(matches!(result, Err(HsmError::SafeState)));
}

/// ITP-SSG-01-b: Safe state blocks ECDSA sign.
#[test]
fn itp_safe_state_blocks_sign() {
    let state = Arc::new(LibraryState::new());
    let mut s = make_session_with_state(state.clone());
    let h = s.key_generate(KeyType::EccP256).unwrap();
    let digest = s.sha256(b"msg").unwrap();

    state.enter_safe_state("test trigger");
    let result = s.ecdsa_sign(h, &digest);
    assert!(matches!(result, Err(HsmError::SafeState)));
}

/// ITP-SSG-01-c: Safe state blocks AES-GCM encrypt.
#[test]
fn itp_safe_state_blocks_encrypt() {
    let state = Arc::new(LibraryState::new());
    let mut s = make_session_with_state(state.clone());
    let h = s.key_generate(KeyType::Aes256).unwrap();

    state.enter_safe_state("test trigger");
    let iv = [0u8; 12];
    let params = scorehsm_host::types::AesGcmParams { iv: &iv, aad: b"" };
    let result = s.aes_gcm_encrypt(h, &params, b"data");
    assert!(matches!(result, Err(HsmError::SafeState)));
}

/// ITP-SSG-01-d: Safe state blocks random generation.
#[test]
fn itp_safe_state_blocks_random() {
    let state = Arc::new(LibraryState::new());
    let mut s = make_session_with_state(state.clone());

    state.enter_safe_state("test trigger");
    let mut buf = [0u8; 8];
    let result = s.random(&mut buf);
    assert!(matches!(result, Err(HsmError::SafeState)));
}

/// ITP-SSG-01-e: SHA-256 is NOT blocked by safe state (no key material).
#[test]
fn itp_safe_state_allows_sha256() {
    let state = Arc::new(LibraryState::new());
    let s = {
        let b = SoftwareBackend::new();
        let mut s = HsmSession::new(b).with_library_state(state.clone());
        s.init().unwrap();
        s
    };

    state.enter_safe_state("test trigger");
    // sha256 does not check library state — it's a pure hash
    assert!(s.sha256(b"data").is_ok());
}

/// ITP-SSG-01-f: Recovery via reinit allows operations again.
#[test]
fn itp_safe_state_reinit_recovers() {
    let state = Arc::new(LibraryState::new());
    let mut s = make_session_with_state(state.clone());
    let _h = s.key_generate(KeyType::EccP256).unwrap();

    // Enter safe state
    state.enter_safe_state("test trigger");
    assert!(matches!(
        s.key_generate(KeyType::EccP256),
        Err(HsmError::SafeState)
    ));

    // Recover
    state.reinit().unwrap();
    assert_eq!(state.current(), State::Uninitialized);

    // Re-init session
    s.init().unwrap();
    assert!(s.key_generate(KeyType::EccP256).is_ok());
}

/// ITP-SSG-01-g: Shared library state blocks both sessions.
#[test]
fn itp_safe_state_shared_across_sessions() {
    let state = Arc::new(LibraryState::new());

    let mut s1 = make_session_with_state(state.clone());
    let mut s2 = make_session_with_state(state.clone());

    // Both sessions work initially
    assert!(s1.key_generate(KeyType::EccP256).is_ok());
    assert!(s2.key_generate(KeyType::Aes256).is_ok());

    // Safe state in one blocks both
    state.enter_safe_state("shared failure");
    assert!(matches!(
        s1.key_generate(KeyType::EccP256),
        Err(HsmError::SafeState)
    ));
    assert!(matches!(
        s2.key_generate(KeyType::Aes256),
        Err(HsmError::SafeState)
    ));
}

/// ITP-SSG-02-a: KeyStoreChecksum passes after normal handle mutations.
#[test]
fn itp_checksum_passes_after_mutations() {
    let cs = KeyStoreChecksum::new();
    let mut handles = HashSet::new();

    // Insert and verify
    handles.insert(1);
    cs.update(&handles);
    assert!(cs.verify(&handles).is_ok());

    // Insert more and verify
    handles.insert(2);
    handles.insert(3);
    cs.update(&handles);
    assert!(cs.verify(&handles).is_ok());

    // Remove and verify
    handles.remove(&2);
    cs.update(&handles);
    assert!(cs.verify(&handles).is_ok());
}

/// ITP-SSG-02-b: KeyStoreChecksum detects silent handle insertion.
#[test]
fn itp_checksum_detects_insertion() {
    let cs = KeyStoreChecksum::new();
    let mut handles = HashSet::new();
    handles.insert(1);
    cs.update(&handles);

    // Silently add a handle without updating checksum
    handles.insert(42);
    assert!(matches!(
        cs.verify(&handles),
        Err(HsmError::IntegrityViolation)
    ));
}

/// ITP-SSG-02-c: KeyStoreChecksum detects silent handle removal.
#[test]
fn itp_checksum_detects_removal() {
    let cs = KeyStoreChecksum::new();
    let mut handles = HashSet::new();
    handles.insert(1);
    handles.insert(2);
    cs.update(&handles);

    // Silently remove a handle
    handles.remove(&1);
    assert!(matches!(
        cs.verify(&handles),
        Err(HsmError::IntegrityViolation)
    ));
}
