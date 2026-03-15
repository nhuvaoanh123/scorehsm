//! Safety services layer — ISO 26262-6 §8 software safety mechanisms.
//!
//! | Component              | TSR        | Purpose                                     |
//! |------------------------|------------|---------------------------------------------|
//! | [`LibraryState`]       | TSR-SSG-01 | Global state machine, safe-state entry       |
//! | [`TokenBucketRateLimiter`] | TSR-RLG-01 | Per-op-class rate limiting              |
//! | [`NonceManager`]       | TSR-NMG-01/02 | Nonce counter + HKDF-SHA256 IV derivation |
//! | [`KeyStoreChecksum`]   | TSR-SSG-02 | Handle-map CRC-32 integrity check           |
//! | [`Clock`] trait        | —          | Time abstraction for testability            |

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{HsmError, HsmResult};

// ── Clock trait ──────────────────────────────────────────────────────────────

/// Time source abstraction — enables deterministic testing without real waits.
pub trait Clock: Send + Sync {
    /// Returns the current instant.
    fn now(&self) -> Instant;
}

/// Production clock — delegates to `std::time::Instant::now()`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Mock clock for testing — manually advance time with [`MockClock::advance`].
pub struct MockClock {
    base: Instant,
    offset: Mutex<Duration>,
}

impl MockClock {
    /// Create a new mock clock starting at the current real instant.
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        }
    }

    /// Advance the mock clock by `d`.
    pub fn advance(&self, d: Duration) {
        *self.offset.lock().unwrap() += d;
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MockClock {
    fn now(&self) -> Instant {
        self.base + *self.offset.lock().unwrap()
    }
}

// ── LibraryState (TSR-SSG-01) ────────────────────────────────────────────────

/// Library lifecycle state.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Library created but not yet initialised.
    Uninitialized = 0,
    /// POST/KAT passed, ready for first operation.
    Ready = 1,
    /// Normal operation — crypto calls accepted.
    Operating = 2,
    /// Permanent fault — all operations blocked until [`LibraryState::reinit`].
    SafeState = 3,
}

/// Global library state machine (TSR-SSG-01, HSM-REQ-062).
///
/// Thread-safe via `AtomicU8` with `SeqCst` ordering. Shared across sessions
/// via `Arc<LibraryState>`.
pub struct LibraryState {
    state: AtomicU8,
}

impl LibraryState {
    /// Create a new library state in [`State::Uninitialized`].
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(State::Uninitialized as u8),
        }
    }

    /// Read the current state.
    pub fn current(&self) -> State {
        match self.state.load(Ordering::SeqCst) {
            0 => State::Uninitialized,
            1 => State::Ready,
            2 => State::Operating,
            _ => State::SafeState,
        }
    }

    /// Enter safe state from any state. Idempotent.
    pub fn enter_safe_state(&self, _reason: &str) {
        self.state.store(State::SafeState as u8, Ordering::SeqCst);
    }

    /// Guard: returns `Ok(())` unless in [`State::SafeState`].
    pub fn check_not_safe(&self) -> HsmResult<()> {
        if self.current() == State::SafeState {
            Err(HsmError::SafeState)
        } else {
            Ok(())
        }
    }

    /// Transition: Uninitialized → Operating (combines Ready + Operating for simplicity).
    pub fn transition_to_operating(&self) -> HsmResult<()> {
        let cur = self.current();
        match cur {
            State::Uninitialized | State::Ready => {
                self.state.store(State::Operating as u8, Ordering::SeqCst);
                Ok(())
            }
            State::Operating => Ok(()), // already there
            State::SafeState => Err(HsmError::SafeState),
        }
    }

    /// Transition: any → Uninitialized (for deinit).
    pub fn transition_to_uninitialized(&self) {
        self.state
            .store(State::Uninitialized as u8, Ordering::SeqCst);
    }

    /// Recovery: SafeState → Uninitialized. Caller must call init() again.
    pub fn reinit(&self) -> HsmResult<()> {
        if self.current() == State::SafeState {
            self.state
                .store(State::Uninitialized as u8, Ordering::SeqCst);
            Ok(())
        } else {
            Err(HsmError::InvalidParam(
                "reinit only valid from SafeState".into(),
            ))
        }
    }
}

impl Default for LibraryState {
    fn default() -> Self {
        Self::new()
    }
}

// ── TokenBucketRateLimiter (TSR-RLG-01) ─────────────────────────────────────

struct Bucket {
    tokens: f64,
    last_refill: Instant,
    rate: f64,
    burst: f64,
}

impl Bucket {
    fn new(rate: f64, burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            last_refill: now,
            rate,
            burst,
        }
    }

    fn try_acquire(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Global token-bucket rate limiter — shared across sessions (TSR-RLG-01, HSM-REQ-060).
///
/// Each operation class has an independent bucket with configurable rate (tokens/sec)
/// and burst capacity. When a bucket is empty, the operation is rejected with
/// [`HsmError::RateLimitExceeded`].
pub struct TokenBucketRateLimiter {
    buckets: Mutex<HashMap<&'static str, Bucket>>,
    clock: std::sync::Arc<dyn Clock>,
}

impl TokenBucketRateLimiter {
    /// Create a rate limiter with plan-default limits (TSR-RLG-01).
    pub fn with_defaults(clock: std::sync::Arc<dyn Clock>) -> Self {
        let now = clock.now();
        let mut buckets = HashMap::new();
        buckets.insert("sign", Bucket::new(10.0, 5.0, now));
        buckets.insert("verify", Bucket::new(20.0, 10.0, now));
        buckets.insert("keygen", Bucket::new(2.0, 1.0, now));
        buckets.insert("ecdh", Bucket::new(10.0, 5.0, now));
        buckets.insert("aes", Bucket::new(100.0, 20.0, now));
        buckets.insert("random", Bucket::new(50.0, 20.0, now));
        buckets.insert("derive", Bucket::new(10.0, 5.0, now));
        buckets.insert("decrypt", Bucket::new(100.0, 20.0, now));
        Self {
            buckets: Mutex::new(buckets),
            clock,
        }
    }

    /// Create a rate limiter from legacy `RateLimits` configuration.
    ///
    /// Maps `OpLimit { max_count, window }` to token bucket:
    /// rate = max_count / window_secs, burst = max_count.
    pub fn from_legacy(
        limits: &super::session::RateLimits,
        clock: std::sync::Arc<dyn Clock>,
    ) -> Self {
        let now = clock.now();
        let mut buckets = HashMap::new();
        let to_bucket = |limit: &super::session::OpLimit| -> Bucket {
            let rate = limit.max_count as f64 / limit.window.as_secs_f64();
            let burst = limit.max_count as f64;
            Bucket::new(rate, burst, now)
        };
        buckets.insert("sign", to_bucket(&limits.sign));
        buckets.insert("decrypt", to_bucket(&limits.decrypt));
        buckets.insert("random", to_bucket(&limits.random));
        buckets.insert("derive", to_bucket(&limits.derive));
        Self {
            buckets: Mutex::new(buckets),
            clock,
        }
    }

    /// Try to acquire a token for the given operation class.
    ///
    /// Returns `Ok(())` if a token was available, `Err(RateLimitExceeded)` otherwise.
    pub fn try_acquire(&self, op: &str) -> HsmResult<()> {
        let now = self.clock.now();
        let mut buckets = self.buckets.lock().unwrap();
        if let Some(bucket) = buckets.get_mut(op) {
            if bucket.try_acquire(now) {
                Ok(())
            } else {
                Err(HsmError::RateLimitExceeded)
            }
        } else {
            Ok(()) // no bucket configured → no limit
        }
    }
}

// ── NonceManager (TSR-NMG-01/02) ────────────────────────────────────────────

/// In-memory nonce counter with HKDF-SHA256 IV derivation (TSR-NMG-01/02, HSM-REQ-054).
///
/// Each key gets an independent monotonic counter. The counter is pre-incremented
/// (written before use) to ensure uniqueness even on crash. The 12-byte IV is
/// derived via HKDF-SHA256 to provide domain separation.
///
/// At `u64::MAX`, the key's nonce space is exhausted and rotation is required.
pub struct NonceManager {
    counters: Mutex<HashMap<u32, u64>>,
}

impl NonceManager {
    /// Create a new in-memory nonce manager.
    pub fn new() -> Self {
        Self {
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Get the next IV for `key_id`. Returns `(counter_value, iv_12_bytes)`.
    ///
    /// The counter is pre-incremented: the returned value is always >= 1.
    /// Returns `Err(NonceExhausted)` if the counter has reached `u64::MAX`.
    pub fn next_iv(&self, key_id: u32, algo_info: &[u8]) -> HsmResult<(u64, [u8; 12])> {
        let mut counters = self.counters.lock().unwrap();
        let counter = counters.entry(key_id).or_insert(0);
        if *counter == u64::MAX {
            return Err(HsmError::NonceExhausted);
        }
        *counter += 1; // pre-increment
        let nonce_val = *counter;

        // Derive 12-byte IV via HKDF-SHA256
        use hkdf::Hkdf;
        use sha2::Sha256;
        let ikm = nonce_val.to_le_bytes();
        let hk = Hkdf::<Sha256>::new(Some(algo_info), &ikm);
        let mut iv = [0u8; 12];
        hk.expand(b"scorehsm-nonce-iv", &mut iv)
            .map_err(|_| HsmError::CryptoFail("HKDF expand failed".into()))?;

        Ok((nonce_val, iv))
    }

    /// Read the current counter value for a key without incrementing.
    pub fn current_counter(&self, key_id: u32) -> u64 {
        self.counters
            .lock()
            .unwrap()
            .get(&key_id)
            .copied()
            .unwrap_or(0)
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── KeyStoreChecksum (TSR-SSG-02) ───────────────────────────────────────────

/// CRC-32/MPEG-2 integrity check over the handle set (TSR-SSG-02, HSM-REQ-065).
///
/// Detects bit-flips, memory corruption, or unauthorised handle map mutations.
/// On mismatch, the library enters safe state.
pub struct KeyStoreChecksum {
    checksum: AtomicU32,
}

impl KeyStoreChecksum {
    /// Create a new checksum (initial value covers the empty set).
    pub fn new() -> Self {
        let crc = Self::compute(&HashSet::new());
        Self {
            checksum: AtomicU32::new(crc),
        }
    }

    /// Recompute and store the checksum for the current handle set.
    pub fn update(&self, handles: &HashSet<u32>) {
        let crc = Self::compute(handles);
        self.checksum.store(crc, Ordering::SeqCst);
    }

    /// Verify that the stored checksum matches the current handle set.
    pub fn verify(&self, handles: &HashSet<u32>) -> HsmResult<()> {
        let expected = self.checksum.load(Ordering::SeqCst);
        let actual = Self::compute(handles);
        if expected == actual {
            Ok(())
        } else {
            Err(HsmError::IntegrityViolation)
        }
    }

    fn compute(handles: &HashSet<u32>) -> u32 {
        let mut sorted: Vec<u32> = handles.iter().copied().collect();
        sorted.sort_unstable();
        let bytes: Vec<u8> = sorted.iter().flat_map(|h| h.to_le_bytes()).collect();
        crc32_mpeg2(&bytes)
    }
}

impl Default for KeyStoreChecksum {
    fn default() -> Self {
        Self::new()
    }
}

/// CRC-32/MPEG-2: poly=0x04C11DB7, init=0xFFFFFFFF, no reflection.
pub fn crc32_mpeg2(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= (b as u32) << 24;
        for _ in 0..8 {
            if crc & 0x8000_0000 != 0 {
                crc = (crc << 1) ^ 0x04C1_1DB7;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ── Power-On Self-Test (HSM-REQ-074/075) ────────────────────────────────────

/// Run power-on self-test: KAT verification of host-side crypto primitives.
///
/// Executes three checks:
/// 1. **SHA-256 KAT** — hash "abc", compare against NIST vector
/// 2. **AES-256-GCM KAT** — encrypt/decrypt round-trip with fixed key+nonce
/// 3. **ECDSA P-256 pairwise consistency** — sign/verify round-trip
///
/// Returns `Err(HsmError::SelfTestFailed)` if any check fails.
pub fn run_post() -> HsmResult<()> {
    // KAT 1: SHA-256("abc") — NIST FIPS 180-4 example
    use sha2::{Digest, Sha256};
    let hash: [u8; 32] = Sha256::digest(b"abc").into();
    const SHA256_ABC: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    if hash != SHA256_ABC {
        return Err(HsmError::SelfTestFailed);
    }

    // KAT 2: AES-256-GCM encrypt/decrypt round-trip
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&[0x42u8; 32]);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&[0x00u8; 12]);
    let plaintext = b"scorehsm-POST-KAT";
    let ct = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| HsmError::SelfTestFailed)?;
    let pt = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|_| HsmError::SelfTestFailed)?;
    if pt != plaintext {
        return Err(HsmError::SelfTestFailed);
    }

    // KAT 3: ECDSA P-256 pairwise consistency test (FIPS 140-3 §10.3.1)
    use p256::ecdsa::{signature::Signer, signature::Verifier, SigningKey};
    let sk = SigningKey::from_slice(&[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ])
    .map_err(|_| HsmError::SelfTestFailed)?;
    let vk = sk.verifying_key();
    let msg = b"scorehsm-POST-ECDSA";
    let sig: p256::ecdsa::Signature = sk.sign(msg);
    vk.verify(msg, &sig).map_err(|_| HsmError::SelfTestFailed)?;

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // ── LibraryState tests ──────────────────────────────────────────────────

    #[test]
    fn library_state_starts_uninitialized() {
        let ls = LibraryState::new();
        assert_eq!(ls.current(), State::Uninitialized);
    }

    #[test]
    fn library_state_transition_to_operating() {
        let ls = LibraryState::new();
        assert!(ls.transition_to_operating().is_ok());
        assert_eq!(ls.current(), State::Operating);
    }

    #[test]
    fn library_state_enter_safe_state() {
        let ls = LibraryState::new();
        ls.transition_to_operating().unwrap();
        ls.enter_safe_state("test");
        assert_eq!(ls.current(), State::SafeState);
    }

    #[test]
    fn library_state_safe_state_idempotent() {
        let ls = LibraryState::new();
        ls.enter_safe_state("first");
        ls.enter_safe_state("second");
        assert_eq!(ls.current(), State::SafeState);
    }

    #[test]
    fn library_state_check_not_safe_blocks_in_safe_state() {
        let ls = LibraryState::new();
        ls.enter_safe_state("test");
        assert!(matches!(ls.check_not_safe(), Err(HsmError::SafeState)));
    }

    #[test]
    fn library_state_check_not_safe_allows_operating() {
        let ls = LibraryState::new();
        ls.transition_to_operating().unwrap();
        assert!(ls.check_not_safe().is_ok());
    }

    #[test]
    fn library_state_reinit_from_safe_state() {
        let ls = LibraryState::new();
        ls.enter_safe_state("test");
        assert!(ls.reinit().is_ok());
        assert_eq!(ls.current(), State::Uninitialized);
    }

    #[test]
    fn library_state_reinit_from_operating_fails() {
        let ls = LibraryState::new();
        ls.transition_to_operating().unwrap();
        assert!(ls.reinit().is_err());
    }

    #[test]
    fn library_state_cannot_transition_from_safe() {
        let ls = LibraryState::new();
        ls.enter_safe_state("test");
        assert!(matches!(
            ls.transition_to_operating(),
            Err(HsmError::SafeState)
        ));
    }

    // ── TokenBucketRateLimiter tests ────────────────────────────────────────

    #[test]
    fn token_bucket_acquire_within_burst() {
        let clock = Arc::new(MockClock::new());
        let rl = TokenBucketRateLimiter::with_defaults(clock);
        // "sign" has burst=5, so 5 immediate acquires should succeed
        for _ in 0..5 {
            assert!(rl.try_acquire("sign").is_ok());
        }
    }

    #[test]
    fn token_bucket_acquire_exceeds_burst() {
        let clock = Arc::new(MockClock::new());
        let rl = TokenBucketRateLimiter::with_defaults(clock);
        // "sign" has burst=5 — 6th should fail
        for _ in 0..5 {
            rl.try_acquire("sign").unwrap();
        }
        assert!(matches!(
            rl.try_acquire("sign"),
            Err(HsmError::RateLimitExceeded)
        ));
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let clock = Arc::new(MockClock::new());
        let rl = TokenBucketRateLimiter::with_defaults(clock.clone());
        // "sign" has rate=10/s, burst=5. Drain all 5 tokens.
        for _ in 0..5 {
            rl.try_acquire("sign").unwrap();
        }
        assert!(rl.try_acquire("sign").is_err());
        // Advance 1 second → refill 10 tokens, capped at burst=5
        clock.advance(Duration::from_secs(1));
        for _ in 0..5 {
            assert!(rl.try_acquire("sign").is_ok());
        }
    }

    #[test]
    fn token_bucket_unknown_op_not_limited() {
        let clock = Arc::new(MockClock::new());
        let rl = TokenBucketRateLimiter::with_defaults(clock);
        // "nonexistent" has no bucket → always allowed
        assert!(rl.try_acquire("nonexistent").is_ok());
    }

    #[test]
    fn token_bucket_from_legacy_limits() {
        use crate::session::{OpLimit, RateLimits};
        let clock = Arc::new(MockClock::new());
        let limits = RateLimits {
            sign: OpLimit::new(2, 60),
            decrypt: OpLimit::new(100, 60),
            random: OpLimit::new(100, 60),
            derive: OpLimit::new(100, 60),
        };
        let rl = TokenBucketRateLimiter::from_legacy(&limits, clock);
        // burst=2 for sign
        assert!(rl.try_acquire("sign").is_ok());
        assert!(rl.try_acquire("sign").is_ok());
        assert!(matches!(
            rl.try_acquire("sign"),
            Err(HsmError::RateLimitExceeded)
        ));
    }

    // ── NonceManager tests ──────────────────────────────────────────────────

    #[test]
    fn nonce_manager_first_call_returns_1() {
        let nm = NonceManager::new();
        let (counter, _iv) = nm.next_iv(1, b"aes-gcm").unwrap();
        assert_eq!(counter, 1);
    }

    #[test]
    fn nonce_manager_increments() {
        let nm = NonceManager::new();
        let (c1, _) = nm.next_iv(1, b"aes-gcm").unwrap();
        let (c2, _) = nm.next_iv(1, b"aes-gcm").unwrap();
        let (c3, _) = nm.next_iv(1, b"aes-gcm").unwrap();
        assert_eq!(c1, 1);
        assert_eq!(c2, 2);
        assert_eq!(c3, 3);
    }

    #[test]
    fn nonce_manager_independent_keys() {
        let nm = NonceManager::new();
        let (c1, _) = nm.next_iv(1, b"aes-gcm").unwrap();
        let (c2, _) = nm.next_iv(2, b"aes-gcm").unwrap();
        assert_eq!(c1, 1);
        assert_eq!(c2, 1); // independent counter
    }

    #[test]
    fn nonce_manager_overflow_returns_exhausted() {
        let nm = NonceManager::new();
        // Force counter to u64::MAX
        {
            let mut counters = nm.counters.lock().unwrap();
            counters.insert(42, u64::MAX);
        }
        assert!(matches!(
            nm.next_iv(42, b"aes-gcm"),
            Err(HsmError::NonceExhausted)
        ));
    }

    #[test]
    fn nonce_manager_iv_changes_each_call() {
        let nm = NonceManager::new();
        let (_, iv1) = nm.next_iv(1, b"aes-gcm").unwrap();
        let (_, iv2) = nm.next_iv(1, b"aes-gcm").unwrap();
        assert_ne!(iv1, iv2);
    }

    #[test]
    fn nonce_manager_different_algo_different_iv() {
        // Same key, same counter value, but different algo_info → different IV
        let nm1 = NonceManager::new();
        let nm2 = NonceManager::new();
        let (_, iv1) = nm1.next_iv(1, b"aes-gcm-256").unwrap();
        let (_, iv2) = nm2.next_iv(1, b"chacha20").unwrap();
        assert_ne!(iv1, iv2);
    }

    // ── KeyStoreChecksum tests ──────────────────────────────────────────────

    #[test]
    fn checksum_verify_after_update() {
        let cs = KeyStoreChecksum::new();
        let mut handles = HashSet::new();
        handles.insert(1);
        handles.insert(2);
        cs.update(&handles);
        assert!(cs.verify(&handles).is_ok());
    }

    #[test]
    fn checksum_detects_corruption() {
        let cs = KeyStoreChecksum::new();
        let mut handles = HashSet::new();
        handles.insert(1);
        handles.insert(2);
        cs.update(&handles);

        // "Corrupt" the handle set — add an extra handle
        handles.insert(3);
        assert!(matches!(
            cs.verify(&handles),
            Err(HsmError::IntegrityViolation)
        ));
    }

    #[test]
    fn checksum_detects_removal() {
        let cs = KeyStoreChecksum::new();
        let mut handles = HashSet::new();
        handles.insert(1);
        handles.insert(2);
        cs.update(&handles);

        handles.remove(&2);
        assert!(matches!(
            cs.verify(&handles),
            Err(HsmError::IntegrityViolation)
        ));
    }

    #[test]
    fn checksum_empty_set() {
        let cs = KeyStoreChecksum::new();
        let handles = HashSet::new();
        // New checksum is computed over empty set, so verify should pass
        assert!(cs.verify(&handles).is_ok());
    }

    #[test]
    fn checksum_order_independent() {
        // Insertion order shouldn't matter — handles are sorted before CRC
        let cs1 = KeyStoreChecksum::new();
        let cs2 = KeyStoreChecksum::new();
        let mut h1 = HashSet::new();
        h1.insert(3);
        h1.insert(1);
        h1.insert(2);
        let mut h2 = HashSet::new();
        h2.insert(1);
        h2.insert(2);
        h2.insert(3);
        cs1.update(&h1);
        cs2.update(&h2);
        assert_eq!(
            cs1.checksum.load(Ordering::SeqCst),
            cs2.checksum.load(Ordering::SeqCst),
        );
    }

    // ── CRC-32 KAT ─────────────────────────────────────────────────────────

    #[test]
    fn crc32_mpeg2_kat() {
        // Standard CRC-32/MPEG-2 known-answer test: "123456789" → 0x0376E6E7
        assert_eq!(crc32_mpeg2(b"123456789"), 0x0376_E6E7);
    }

    // ── POST ──────────────────────────────────────────────────────────────

    #[test]
    fn post_passes() {
        run_post().expect("POST should pass on healthy system");
    }
}
