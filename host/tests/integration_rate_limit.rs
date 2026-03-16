// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! Rate limiter integration tests — TSR-RLG-01.
//!
//! Tests token-bucket rate limiting through the HsmSession API
//! using MockClock for deterministic time control.

use scorehsm_host::{
    backend::sw::SoftwareBackend,
    error::HsmError,
    safety::MockClock,
    session::{HsmSession, OpLimit, RateLimits},
    types::KeyType,
};
use std::sync::Arc;
use std::time::Duration;

fn make_session_with_clock(limits: RateLimits, clock: Arc<MockClock>) -> HsmSession {
    let b = SoftwareBackend::new();
    let mut s = HsmSession::new(b)
        .with_clock(clock)
        .with_rate_limits(limits);
    s.init().unwrap();
    s
}

/// ITP-RLG-01-a: Operations within burst limit succeed.
#[test]
fn itp_rate_limit_within_burst_succeeds() {
    let clock = Arc::new(MockClock::new());
    let limits = RateLimits {
        sign: OpLimit::new(5, 60),
        decrypt: OpLimit::new(100, 60),
        random: OpLimit::new(100, 60),
        derive: OpLimit::new(100, 60),
    };
    let mut s = make_session_with_clock(limits, clock);
    let h = s.key_generate(KeyType::EccP256).unwrap();
    let digest = s.sha256(b"msg").unwrap();

    // Burst of 5 should succeed
    for _ in 0..5 {
        assert!(s.ecdsa_sign(h, &digest).is_ok());
    }
}

/// ITP-RLG-01-b: Operations exceeding burst limit are rejected.
#[test]
fn itp_rate_limit_exceeds_burst_rejected() {
    let clock = Arc::new(MockClock::new());
    let limits = RateLimits {
        sign: OpLimit::new(2, 60),
        decrypt: OpLimit::new(100, 60),
        random: OpLimit::new(100, 60),
        derive: OpLimit::new(100, 60),
    };
    let mut s = make_session_with_clock(limits, clock);
    let h = s.key_generate(KeyType::EccP256).unwrap();
    let digest = s.sha256(b"msg").unwrap();

    s.ecdsa_sign(h, &digest).unwrap();
    s.ecdsa_sign(h, &digest).unwrap();
    let result = s.ecdsa_sign(h, &digest);
    assert!(matches!(result, Err(HsmError::RateLimitExceeded)));
}

/// ITP-RLG-01-c: Tokens refill after time advance (MockClock).
#[test]
fn itp_rate_limit_refills_with_mock_clock() {
    let clock = Arc::new(MockClock::new());
    let limits = RateLimits {
        sign: OpLimit::new(1, 1), // 1 per second, burst = 1
        decrypt: OpLimit::new(100, 60),
        random: OpLimit::new(100, 60),
        derive: OpLimit::new(100, 60),
    };
    let mut s = make_session_with_clock(limits, clock.clone());
    let h = s.key_generate(KeyType::EccP256).unwrap();
    let digest = s.sha256(b"msg").unwrap();

    // First sign uses the burst token
    assert!(s.ecdsa_sign(h, &digest).is_ok());
    // Second sign fails — no tokens
    assert!(matches!(
        s.ecdsa_sign(h, &digest),
        Err(HsmError::RateLimitExceeded)
    ));

    // Advance clock by 2 seconds — should refill 1 token (capped at burst=1)
    clock.advance(Duration::from_secs(2));
    assert!(
        s.ecdsa_sign(h, &digest).is_ok(),
        "should succeed after refill"
    );
}

/// ITP-RLG-01-d: Different operation classes have independent limits.
#[test]
fn itp_rate_limit_independent_op_classes() {
    let clock = Arc::new(MockClock::new());
    let limits = RateLimits {
        sign: OpLimit::new(1, 60),
        decrypt: OpLimit::new(1, 60),
        random: OpLimit::new(1, 60),
        derive: OpLimit::new(100, 60),
    };
    let mut s = make_session_with_clock(limits, clock);

    let h_aes = s.key_generate(KeyType::Aes256).unwrap();
    let h_ecc = s.key_generate(KeyType::EccP256).unwrap();
    let digest = s.sha256(b"msg").unwrap();
    let iv = [0u8; 12];
    let params = scorehsm_host::types::AesGcmParams { iv: &iv, aad: b"" };
    let (ct, tag) = s.aes_gcm_encrypt(h_aes, &params, b"data").unwrap();

    // Each class allows 1 call
    assert!(s.ecdsa_sign(h_ecc, &digest).is_ok());
    assert!(s.aes_gcm_decrypt(h_aes, &params, &ct, &tag).is_ok());
    let mut buf = [0u8; 8];
    assert!(s.random(&mut buf).is_ok());

    // Second call in each class fails
    assert!(matches!(
        s.ecdsa_sign(h_ecc, &digest),
        Err(HsmError::RateLimitExceeded)
    ));
    assert!(matches!(
        s.aes_gcm_decrypt(h_aes, &params, &ct, &tag),
        Err(HsmError::RateLimitExceeded)
    ));
    assert!(matches!(
        s.random(&mut buf),
        Err(HsmError::RateLimitExceeded)
    ));
}

/// ITP-RLG-01-e: Rate limit emits IDS event.
#[test]
fn itp_rate_limit_emits_ids_event() {
    use scorehsm_host::ids::{IdsEvent, IdsHook};
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct Recorder {
        events: Arc<Mutex<Vec<String>>>,
    }
    impl IdsHook for Recorder {
        fn on_event(&self, event: IdsEvent) {
            self.events.lock().unwrap().push(format!("{:?}", event));
        }
    }

    let clock = Arc::new(MockClock::new());
    let recorder = Recorder::default();
    let limits = RateLimits {
        sign: OpLimit::new(1, 60),
        decrypt: OpLimit::new(100, 60),
        random: OpLimit::new(100, 60),
        derive: OpLimit::new(100, 60),
    };
    let b = SoftwareBackend::new();
    let mut s = HsmSession::new(b)
        .with_ids_hook(Box::new(recorder.clone()))
        .with_clock(clock)
        .with_rate_limits(limits);
    s.init().unwrap();
    let h = s.key_generate(KeyType::EccP256).unwrap();
    let digest = s.sha256(b"msg").unwrap();

    let _ = s.ecdsa_sign(h, &digest); // ok
    let _ = s.ecdsa_sign(h, &digest); // rate limited

    let events = recorder.events.lock().unwrap();
    assert!(
        events.iter().any(|e| e.contains("RateLimitExceeded")),
        "RateLimitExceeded IDS event must be emitted"
    );
}
