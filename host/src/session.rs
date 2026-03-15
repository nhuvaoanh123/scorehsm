//! `HsmSession` — access-control wrapper over `HsmBackend` — HSM-REQ-037/038/039.
//!
//! `HsmSession` enforces:
//! - Handle ownership: a session can only use key handles it generated or imported.
//! - Rate limiting: global token-bucket rate limiter (TSR-RLG-01).
//! - Library state: blocks all operations in safe state (TSR-SSG-01).
//! - Handle-map integrity: CRC-32 checksum on insert/remove (TSR-SSG-02).
//! - IDS event reporting: every security-relevant event is forwarded to the hook.
//!
//! Usage:
//! ```rust,ignore
//! let backend = SoftwareBackend::new();
//! let mut session = HsmSession::new(backend)
//!     .with_ids_hook(Box::new(LoggingIds))
//!     .with_rate_limits(RateLimits::default());
//! session.init()?;
//! let h = session.key_generate(KeyType::EccP256)?;
//! let digest = session.sha256(b"data")?;
//! let sig = session.ecdsa_sign(h, &digest)?;
//! ```

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    backend::HsmBackend,
    error::{HsmError, HsmResult},
    ids::{IdsEvent, IdsHook, NullIds},
    safety::{Clock, KeyStoreChecksum, LibraryState, SystemClock, TokenBucketRateLimiter},
    types::{AesGcmParams, EcdsaSignature, KeyHandle, KeyType},
};

// ── Rate limit configuration (legacy types — preserved for backward compat) ──

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
        Self {
            max_count,
            window: Duration::from_secs(window_secs),
        }
    }
}

/// Rate limits for each HSM operation category.
#[derive(Clone, Debug)]
pub struct RateLimits {
    /// Limit for ECDSA sign operations.
    pub sign: OpLimit,
    /// Limit for AES-GCM decrypt operations.
    pub decrypt: OpLimit,
    /// Limit for random byte generation.
    pub random: OpLimit,
    /// Limit for key derivation (HKDF) operations.
    pub derive: OpLimit,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            sign: OpLimit::new(1000, 60),    // 1000 signatures/min
            decrypt: OpLimit::new(1000, 60), // 1000 decrypts/min
            random: OpLimit::new(500, 60),   // 500 random calls/min
            derive: OpLimit::new(100, 60),   // 100 derives/min
        }
    }
}

// ── HsmSession ────────────────────────────────────────────────────────────────

/// Access-control wrapper around any `HsmBackend`.
///
/// Create with `HsmSession::new(backend)`, configure, then call `init()`.
pub struct HsmSession {
    backend: Box<dyn HsmBackend>,
    owned_handles: HashSet<u32>,
    ids: Box<dyn IdsHook>,
    rate: Arc<TokenBucketRateLimiter>,
    library_state: Arc<LibraryState>,
    checksum: KeyStoreChecksum,
    clock: Arc<dyn Clock>,
    fail_count: u32,
    rate_reject_count: u32,
}

impl HsmSession {
    /// Create a session wrapping `backend`.
    pub fn new<B: HsmBackend + 'static>(backend: B) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let rate = Arc::new(TokenBucketRateLimiter::with_defaults(clock.clone()));
        Self {
            backend: Box::new(backend),
            owned_handles: HashSet::new(),
            ids: Box::new(NullIds),
            rate,
            library_state: Arc::new(LibraryState::new()),
            checksum: KeyStoreChecksum::new(),
            clock,
            fail_count: 0,
            rate_reject_count: 0,
        }
    }

    /// Attach an IDS hook. Returns `self` for method chaining.
    pub fn with_ids_hook(mut self, hook: Box<dyn IdsHook>) -> Self {
        self.ids = hook;
        self
    }

    /// Set rate limits (legacy API — converts to token bucket internally).
    pub fn with_rate_limits(mut self, limits: RateLimits) -> Self {
        self.rate = Arc::new(TokenBucketRateLimiter::from_legacy(
            &limits,
            self.clock.clone(),
        ));
        self
    }

    /// Set the clock source (for testing with [`MockClock`](crate::safety::MockClock)).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock.clone();
        self.rate = Arc::new(TokenBucketRateLimiter::with_defaults(clock));
        self
    }

    /// Share a library state across multiple sessions.
    pub fn with_library_state(mut self, state: Arc<LibraryState>) -> Self {
        self.library_state = state;
        self
    }

    /// Inject a pre-configured rate limiter (for sharing across sessions).
    pub fn with_rate_limiter(mut self, rl: Arc<TokenBucketRateLimiter>) -> Self {
        self.rate = rl;
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
        if self.fail_count.is_multiple_of(10) {
            self.ids.on_event(IdsEvent::RepeatedFailure {
                count: self.fail_count,
            });
        }
    }

    /// Helper: check rate limit and emit IDS event on rejection.
    fn check_rate(&mut self, op: &'static str) -> HsmResult<()> {
        if let Err(HsmError::RateLimitExceeded) = self.rate.try_acquire(op) {
            self.rate_reject_count += 1;
            self.ids.on_event(IdsEvent::RateLimitExceeded {
                operation: op,
                count: self.rate_reject_count,
            });
            return Err(HsmError::RateLimitExceeded);
        }
        Ok(())
    }

    // ── Delegating API ────────────────────────────────────────────────────────

    /// Initialise the underlying backend and transition to operating state.
    pub fn init(&mut self) -> HsmResult<()> {
        self.backend.init()?;
        self.library_state.transition_to_operating()
    }

    /// Deinitialise. All owned handles become invalid.
    pub fn deinit(&mut self) -> HsmResult<()> {
        self.owned_handles.clear();
        self.checksum.update(&self.owned_handles);
        self.library_state.transition_to_uninitialized();
        self.backend.deinit()
    }

    /// Generate a key. The returned handle is owned by this session.
    pub fn key_generate(&mut self, key_type: KeyType) -> HsmResult<KeyHandle> {
        self.library_state.check_not_safe()?;
        let h = self.backend.key_generate(key_type)?;
        self.owned_handles.insert(h.0);
        self.checksum.update(&self.owned_handles);
        self.ids.on_event(IdsEvent::KeyGenerated {
            handle: h,
            key_type,
        });
        Ok(h)
    }

    /// Delete a key owned by this session.
    pub fn key_delete(&mut self, handle: KeyHandle) -> HsmResult<()> {
        self.library_state.check_not_safe()?;
        self.assert_owned(handle)?;
        self.backend.key_delete(handle)?;
        self.owned_handles.remove(&handle.0);
        self.checksum.update(&self.owned_handles);
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
        self.library_state.check_not_safe()?;
        self.assert_owned(base)?;
        self.check_rate("derive")?;
        let h = self.backend.key_derive(base, info, out_type)?;
        self.owned_handles.insert(h.0);
        self.checksum.update(&self.owned_handles);
        Ok(h)
    }

    /// Import a wrapped key. The returned handle is owned by this session.
    pub fn key_import(&mut self, key_type: KeyType, wrapped: &[u8]) -> HsmResult<KeyHandle> {
        self.library_state.check_not_safe()?;
        let h = self.backend.key_import(key_type, wrapped)?;
        self.owned_handles.insert(h.0);
        self.checksum.update(&self.owned_handles);
        Ok(h)
    }

    /// Generate random bytes.
    pub fn random(&mut self, out: &mut [u8]) -> HsmResult<()> {
        self.library_state.check_not_safe()?;
        self.check_rate("random")?;
        self.backend.random(out)
    }

    /// SHA-256 hash (no ownership check — hash doesn't use key material).
    pub fn sha256(&self, data: &[u8]) -> HsmResult<[u8; 32]> {
        self.library_state.check_not_safe()?;
        self.backend.sha256(data)
    }

    /// HMAC-SHA256 — key must be owned by this session.
    pub fn hmac_sha256(&mut self, handle: KeyHandle, data: &[u8]) -> HsmResult<[u8; 32]> {
        self.library_state.check_not_safe()?;
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
        self.library_state.check_not_safe()?;
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
        self.library_state.check_not_safe()?;
        self.assert_owned(handle)?;
        self.check_rate("decrypt")?;
        match self
            .backend
            .aes_gcm_decrypt(handle, params, ciphertext, tag)
        {
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
        self.library_state.check_not_safe()?;
        self.assert_owned(handle)?;
        self.check_rate("sign")?;
        let sig = self.backend.ecdsa_sign(handle, digest)?;
        self.ids.on_event(IdsEvent::EcdsaSigned {
            handle,
            digest: *digest,
        });
        Ok(sig)
    }

    /// ECDSA verify.
    pub fn ecdsa_verify(
        &mut self,
        handle: KeyHandle,
        digest: &[u8; 32],
        signature: &EcdsaSignature,
    ) -> HsmResult<bool> {
        self.library_state.check_not_safe()?;
        self.assert_owned(handle)?;
        self.backend.ecdsa_verify(handle, digest, signature)
    }

    /// ECDH key agreement.
    pub fn ecdh_agree(&mut self, handle: KeyHandle, peer_pub: &[u8; 64]) -> HsmResult<[u8; 32]> {
        self.library_state.check_not_safe()?;
        self.assert_owned(handle)?;
        self.check_rate("ecdh")?;
        let shared = self.backend.ecdh_agree(handle, peer_pub)?;
        self.ids.on_event(IdsEvent::EcdhAgreed { handle });
        Ok(shared)
    }
}
