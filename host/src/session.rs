//! `HsmSession` — access-control wrapper over `HsmBackend` — HSM-REQ-037/038/039.
//!
//! `HsmSession` enforces:
//! - Handle ownership: a session can only use key handles it generated or imported.
//! - Rate limiting: per-operation call counters with configurable limits.
//! - IDS event reporting: every security-relevant event is forwarded to the hook.
//!
//! Usage:
//! ```rust,ignore
//! let backend = SoftwareBackend::new();
//! let mut session = HsmSession::new(backend)
//!     .with_ids_hook(Box::new(LoggingIds))
//!     .with_rate_limit(RateLimits::default());
//! session.init()?;
//! let h = session.key_generate(KeyType::EccP256)?;
//! let digest = session.sha256(b"data")?;
//! let sig = session.ecdsa_sign(h, &digest)?;
//! ```

use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::{
    backend::HsmBackend,
    error::{HsmError, HsmResult},
    ids::{IdsEvent, IdsHook, NullIds},
    types::{AesGcmParams, EcdsaSignature, KeyHandle, KeyType},
};

// ── Rate limiter ──────────────────────────────────────────────────────────────

/// Per-operation rate limit: max `max_count` calls within `window`.
#[derive(Clone, Debug)]
pub struct OpLimit {
    /// Maximum number of calls allowed within the time window.
    pub max_count: u32,
    /// Length of the sliding time window.
    pub window: Duration,
}

impl OpLimit {
    /// Create a new per-operation limit.
    pub fn new(max_count: u32, window_secs: u64) -> Self {
        Self { max_count, window: Duration::from_secs(window_secs) }
    }
}

/// Rate limits for each HSM operation category.
#[derive(Clone, Debug)]
pub struct RateLimits {
    /// Limit for ECDSA sign operations.
    pub sign:    OpLimit,
    /// Limit for AES-GCM decrypt operations.
    pub decrypt: OpLimit,
    /// Limit for random byte generation.
    pub random:  OpLimit,
    /// Limit for key derivation (HKDF) operations.
    pub derive:  OpLimit,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            sign:    OpLimit::new(1000, 60),  // 1000 signatures/min
            decrypt: OpLimit::new(1000, 60),  // 1000 decrypts/min
            random:  OpLimit::new(500, 60),   // 500 random calls/min
            derive:  OpLimit::new(100, 60),   // 100 derives/min
        }
    }
}

struct Counter {
    count: u32,
    window_start: Instant,
}

impl Counter {
    fn new() -> Self { Self { count: 0, window_start: Instant::now() } }

    /// Returns true if within limit, false if limit exceeded.
    fn check(&mut self, limit: &OpLimit) -> bool {
        if self.window_start.elapsed() > limit.window {
            self.count = 0;
            self.window_start = Instant::now();
        }
        self.count += 1;
        self.count <= limit.max_count
    }
}

struct RateLimiter {
    sign:    Counter,
    decrypt: Counter,
    random:  Counter,
    derive:  Counter,
    limits:  RateLimits,
}

impl RateLimiter {
    fn new(limits: RateLimits) -> Self {
        Self {
            sign:    Counter::new(),
            decrypt: Counter::new(),
            random:  Counter::new(),
            derive:  Counter::new(),
            limits,
        }
    }

    fn check_sign(&mut self)    -> bool { self.sign.check(&self.limits.sign.clone()) }
    fn check_decrypt(&mut self) -> bool { self.decrypt.check(&self.limits.decrypt.clone()) }
    fn check_random(&mut self)  -> bool { self.random.check(&self.limits.random.clone()) }
    fn check_derive(&mut self)  -> bool { self.derive.check(&self.limits.derive.clone()) }
}

// ── HsmSession ────────────────────────────────────────────────────────────────

/// Access-control wrapper around any `HsmBackend`.
///
/// Create with `HsmSession::new(backend)`, configure, then call `init()`.
pub struct HsmSession {
    backend:        Box<dyn HsmBackend>,
    owned_handles:  HashSet<u32>,  // set of handle values owned by this session
    ids:            Box<dyn IdsHook>,
    rate:           RateLimiter,
    fail_count:     u32,           // consecutive failure counter for IDS
}

impl HsmSession {
    /// Create a session wrapping `backend`.
    pub fn new<B: HsmBackend + 'static>(backend: B) -> Self {
        Self {
            backend:       Box::new(backend),
            owned_handles: HashSet::new(),
            ids:           Box::new(NullIds),
            rate:          RateLimiter::new(RateLimits::default()),
            fail_count:    0,
        }
    }

    /// Attach an IDS hook. Returns `self` for method chaining.
    pub fn with_ids_hook(mut self, hook: Box<dyn IdsHook>) -> Self {
        self.ids = hook;
        self
    }

    /// Set rate limits. Returns `self` for method chaining.
    pub fn with_rate_limits(mut self, limits: RateLimits) -> Self {
        self.rate = RateLimiter::new(limits);
        self
    }

    // ── Ownership helpers ─────────────────────────────────────────────────────

    fn assert_owned(&mut self, h: KeyHandle) -> HsmResult<()> {
        if self.owned_handles.contains(&h.0) {
            Ok(())
        } else {
            self.ids.on_event(IdsEvent::UnknownHandle { handle: h });
            Err(HsmError::InvalidKeyHandle)
        }
    }

    fn record_fail(&mut self) {
        self.fail_count += 1;
        if self.fail_count % 10 == 0 {
            self.ids.on_event(IdsEvent::RepeatedFailure { count: self.fail_count });
        }
    }

    // ── Delegating API ────────────────────────────────────────────────────────

    /// Initialise the underlying backend.
    pub fn init(&mut self) -> HsmResult<()> {
        self.backend.init()
    }

    /// Deinitialise. All owned handles become invalid.
    pub fn deinit(&mut self) -> HsmResult<()> {
        self.owned_handles.clear();
        self.backend.deinit()
    }

    /// Generate a key. The returned handle is owned by this session.
    pub fn key_generate(&mut self, key_type: KeyType) -> HsmResult<KeyHandle> {
        let h = self.backend.key_generate(key_type)?;
        self.owned_handles.insert(h.0);
        self.ids.on_event(IdsEvent::KeyGenerated { handle: h, key_type });
        Ok(h)
    }

    /// Delete a key owned by this session.
    pub fn key_delete(&mut self, handle: KeyHandle) -> HsmResult<()> {
        self.assert_owned(handle)?;
        self.backend.key_delete(handle)?;
        self.owned_handles.remove(&handle.0);
        self.ids.on_event(IdsEvent::KeyDeleted { handle });
        Ok(())
    }

    /// Derive a new key from an existing owned key.
    pub fn key_derive(
        &mut self,
        base: KeyHandle,
        info: &[u8],
        out_type: KeyType,
    ) -> HsmResult<KeyHandle> {
        self.assert_owned(base)?;
        if !self.rate.check_derive() {
            self.ids.on_event(IdsEvent::RateLimitExceeded { operation: "derive", count: self.rate.derive.count });
            return Err(HsmError::UsbError("rate limit exceeded: derive".into()));
        }
        let h = self.backend.key_derive(base, info, out_type)?;
        self.owned_handles.insert(h.0);
        Ok(h)
    }

    /// Import a wrapped key. The returned handle is owned by this session.
    pub fn key_import(&mut self, key_type: KeyType, wrapped: &[u8]) -> HsmResult<KeyHandle> {
        let h = self.backend.key_import(key_type, wrapped)?;
        self.owned_handles.insert(h.0);
        Ok(h)
    }

    /// Generate random bytes.
    pub fn random(&mut self, out: &mut [u8]) -> HsmResult<()> {
        if !self.rate.check_random() {
            self.ids.on_event(IdsEvent::RateLimitExceeded { operation: "random", count: self.rate.random.count });
            return Err(HsmError::UsbError("rate limit exceeded: random".into()));
        }
        self.backend.random(out)
    }

    /// SHA-256 hash (no ownership check — hash doesn't use key material).
    pub fn sha256(&self, data: &[u8]) -> HsmResult<[u8; 32]> {
        self.backend.sha256(data)
    }

    /// HMAC-SHA256 — key must be owned by this session.
    pub fn hmac_sha256(&mut self, handle: KeyHandle, data: &[u8]) -> HsmResult<[u8; 32]> {
        self.assert_owned(handle)?;
        self.backend.hmac_sha256(handle, data)
    }

    /// AES-256-GCM encrypt.
    pub fn aes_gcm_encrypt(
        &mut self,
        handle: KeyHandle,
        params: &AesGcmParams,
        plaintext: &[u8],
    ) -> HsmResult<(Vec<u8>, [u8; 16])> {
        self.assert_owned(handle)?;
        self.backend.aes_gcm_encrypt(handle, params, plaintext)
    }

    /// AES-256-GCM decrypt.
    pub fn aes_gcm_decrypt(
        &mut self,
        handle: KeyHandle,
        params: &AesGcmParams,
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> HsmResult<Vec<u8>> {
        self.assert_owned(handle)?;
        if !self.rate.check_decrypt() {
            self.ids.on_event(IdsEvent::RateLimitExceeded { operation: "decrypt", count: self.rate.decrypt.count });
            return Err(HsmError::UsbError("rate limit exceeded: decrypt".into()));
        }
        match self.backend.aes_gcm_decrypt(handle, params, ciphertext, tag) {
            Ok(pt) => Ok(pt),
            Err(HsmError::TagMismatch) => {
                self.record_fail();
                self.ids.on_event(IdsEvent::DecryptFailed { handle });
                Err(HsmError::TagMismatch)
            }
            Err(e) => Err(e),
        }
    }

    /// ECDSA sign.
    pub fn ecdsa_sign(
        &mut self,
        handle: KeyHandle,
        digest: &[u8; 32],
    ) -> HsmResult<EcdsaSignature> {
        self.assert_owned(handle)?;
        if !self.rate.check_sign() {
            self.ids.on_event(IdsEvent::RateLimitExceeded { operation: "sign", count: self.rate.sign.count });
            return Err(HsmError::UsbError("rate limit exceeded: sign".into()));
        }
        let sig = self.backend.ecdsa_sign(handle, digest)?;
        self.ids.on_event(IdsEvent::EcdsaSigned { handle, digest: *digest });
        Ok(sig)
    }

    /// ECDSA verify.
    pub fn ecdsa_verify(
        &mut self,
        handle: KeyHandle,
        digest: &[u8; 32],
        signature: &EcdsaSignature,
    ) -> HsmResult<bool> {
        self.assert_owned(handle)?;
        self.backend.ecdsa_verify(handle, digest, signature)
    }

    /// ECDH key agreement.
    pub fn ecdh_agree(&mut self, handle: KeyHandle, peer_pub: &[u8; 64]) -> HsmResult<[u8; 32]> {
        self.assert_owned(handle)?;
        self.backend.ecdh_agree(handle, peer_pub)
    }
}
