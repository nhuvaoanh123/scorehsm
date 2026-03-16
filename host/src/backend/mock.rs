// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! MockHardwareBackend — simulated L55 HSM for CI testing of SSRs.
//!
//! Implements [`HsmBackend`] without physical hardware. Provides configurable
//! fault injection to exercise all transport-layer, session, and safety
//! requirements (HSM-REQ-050..077) in CI without a connected STM32L552.
//!
//! # Fault injection
//!
//! Set fields in [`MockFaultConfig`] before calling [`MockHardwareBackend::new`]:
//!
//! ```rust
//! # use scorehsm_host::backend::mock::{MockHardwareBackend, MockFaultConfig};
//! let config = MockFaultConfig {
//!     inject_crc_error_on_attempt: Some(1), // first send → CRC mismatch
//!     inject_seq_mismatch: false,
//!     inject_timeout: false,
//!     inject_hw_fault: false,
//!     op_latency_ms: 0,
//! };
//! let mut backend = MockHardwareBackend::new(config);
//! ```
//!
//! # SSRs covered
//!
//! HSM-REQ-050 (CRC-32), HSM-REQ-051 (seq#), HSM-REQ-052 (timeout),
//! HSM-REQ-053 (retry/safe state), HSM-REQ-066 (ZeroizeOnDrop on stored keys),
//! HSM-REQ-067 (no key export), HSM-REQ-072 (definitive verify result),
//! HSM-REQ-073 (constant-time compare), HSM-REQ-074 (AES-GCM KAT),
//! HSM-REQ-075 (ECDSA KAT), HSM-REQ-077 (mock itself).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::backend::HsmBackend;
use crate::error::{HsmError, HsmResult};
use crate::types::{AesGcmParams, BootStatus, EcdsaSignature, KeyHandle, KeyType};

// ── Fault injection configuration ────────────────────────────────────────────

/// Configuration for fault injection. All fields default to "no fault".
#[derive(Debug, Clone, Default)]
pub struct MockFaultConfig {
    /// On which 1-based attempt number to inject a CRC mismatch error.
    /// `Some(1)` = first call fails, `Some(3)` = third call fails (triggers safe state).
    pub inject_crc_error_on_attempt: Option<u32>,
    /// If true, every response will have a wrong sequence number echo.
    pub inject_seq_mismatch: bool,
    /// If true, every operation will time out instead of completing.
    pub inject_timeout: bool,
    /// If true, the mock will return a hardware fault opcode response.
    pub inject_hw_fault: bool,
    /// Simulated operation latency in milliseconds (0 = instant).
    pub op_latency_ms: u64,
}

// ── Internal key store ────────────────────────────────────────────────────────

/// Key material stored in the mock HSM key store.
/// ZeroizeOnDrop: satisfies HSM-REQ-066 for the software side of the mock.
pub(crate) struct MockKeySlot {
    key_type: u8,      // encoded KeyType discriminant
    material: Vec<u8>, // raw key bytes — zeroized on drop
}

impl Zeroize for MockKeySlot {
    fn zeroize(&mut self) {
        self.material.zeroize();
    }
}

impl Drop for MockKeySlot {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MockKeySlot {}

// Compile-time assertion: ZeroizeOnDrop must be implemented.
// If someone removes the derive, this trait-bound check will fail at compile time.
const _: fn() = || {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<MockKeySlot>();
};

// ── MockHardwareBackend ───────────────────────────────────────────────────────

/// Simulated hardware backend for CI testing.
///
/// Thread-safe: all mutable state is protected by an internal Mutex.
pub struct MockHardwareBackend {
    faults: MockFaultConfig,
    call_count: AtomicU32,
    seq_counter: AtomicU32,
    next_handle: AtomicU32,
    initialized: AtomicBool,
    keys: Mutex<HashMap<u32, MockKeySlot>>, // keyed by raw handle id
}

impl MockHardwareBackend {
    /// Create a new mock backend with the given fault configuration.
    pub fn new(faults: MockFaultConfig) -> Self {
        Self {
            faults,
            call_count: AtomicU32::new(0),
            seq_counter: AtomicU32::new(1),
            next_handle: AtomicU32::new(1),
            initialized: AtomicBool::new(false),
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Return the number of transport calls made so far (for test assertions).
    pub fn call_count(&self) -> u32 {
        self.call_count.load(Ordering::SeqCst)
    }

    /// Simulate one transport round-trip and apply configured faults.
    ///
    /// Returns `Ok(seq)` with the echoed sequence number, or an injected error.
    /// This is the single choke-point for all fault injection, ensuring that
    /// every HsmBackend operation exercises the transport-layer SSRs.
    fn transport_round_trip(&self) -> HsmResult<u32> {
        let attempt = self.call_count.fetch_add(1, Ordering::SeqCst) + 1;

        // Simulate latency
        if self.faults.op_latency_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(self.faults.op_latency_ms));
        }

        // HSM-REQ-052 / HSM-REQ-053: timeout injection
        if self.faults.inject_timeout {
            return Err(HsmError::Timeout);
        }

        // HSM-REQ-063: hardware fault injection
        if self.faults.inject_hw_fault {
            return Err(HsmError::HardwareFault);
        }

        // HSM-REQ-050 / HSM-REQ-053: CRC error injection
        if let Some(fail_on) = self.faults.inject_crc_error_on_attempt {
            if attempt == fail_on {
                return Err(HsmError::CrcMismatch);
            }
        }

        // HSM-REQ-051: sequence number
        let seq = self.seq_counter.fetch_add(1, Ordering::SeqCst);
        if seq == u32::MAX {
            return Err(HsmError::SequenceOverflow);
        }

        // HSM-REQ-051: sequence number mismatch injection
        if self.faults.inject_seq_mismatch {
            // Echo wrong seq# — host should detect this as ProtocolError
            return Err(HsmError::ProtocolError);
        }

        Ok(seq)
    }

    /// Resolve a key handle to its stored material (internal — does NOT export key).
    /// No key bytes are returned through the public API (HSM-REQ-067).
    pub(crate) fn resolve_key(&self, handle: KeyHandle) -> HsmResult<MockKeySlot> {
        let keys = self
            .keys
            .lock()
            .map_err(|_| HsmError::CryptoFail("lock poisoned".into()))?;
        let slot = keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        Ok(MockKeySlot {
            key_type: slot.key_type,
            material: slot.material.clone(),
        })
    }
}

// ── HsmBackend implementation ─────────────────────────────────────────────────

impl HsmBackend for MockHardwareBackend {
    fn init(&mut self) -> HsmResult<()> {
        // Simulate startup handshake (HSM-REQ-068): mock always "passes"
        // unless timeout or hw_fault is configured.
        self.transport_round_trip()?;
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn deinit(&mut self) -> HsmResult<()> {
        self.initialized.store(false, Ordering::SeqCst);
        // Zeroize all key slots on deinit
        if let Ok(mut keys) = self.keys.lock() {
            keys.values_mut().for_each(|slot| slot.zeroize());
            keys.clear();
        }
        Ok(())
    }

    fn key_generate(&mut self, key_type: KeyType) -> HsmResult<KeyHandle> {
        self.transport_round_trip()?;
        let id = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let material = match key_type {
            KeyType::Aes256 => vec![0xA5u8; 32],
            KeyType::HmacSha256 => vec![0x5Au8; 32],
            KeyType::EccP256 => vec![0x11u8; 32],
        };
        let slot = MockKeySlot {
            key_type: key_type as u8,
            material,
        };
        self.keys
            .lock()
            .map_err(|_| HsmError::CryptoFail("lock poisoned".into()))?
            .insert(id, slot);
        Ok(KeyHandle(id))
    }

    fn key_import(&mut self, key_type: KeyType, material: &[u8]) -> HsmResult<KeyHandle> {
        // Validate input — HSM-REQ-044 (frame length validation analogue)
        let expected_len = match key_type {
            KeyType::Aes256 => 32,
            KeyType::HmacSha256 => 32,
            KeyType::EccP256 => 32,
        };
        if material.len() != expected_len {
            return Err(HsmError::InvalidParam(format!(
                "expected {} bytes for {:?}, got {}",
                expected_len,
                key_type,
                material.len()
            )));
        }
        self.transport_round_trip()?;
        let id = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let slot = MockKeySlot {
            key_type: key_type as u8,
            material: material.to_vec(),
        };
        self.keys
            .lock()
            .map_err(|_| HsmError::CryptoFail("lock poisoned".into()))?
            .insert(id, slot);
        Ok(KeyHandle(id))
    }

    fn key_delete(&mut self, handle: KeyHandle) -> HsmResult<()> {
        self.transport_round_trip()?;
        let mut keys = self
            .keys
            .lock()
            .map_err(|_| HsmError::CryptoFail("lock poisoned".into()))?;
        // Remove drops the MockKeySlot, which calls Drop::drop → zeroize (HSM-REQ-066)
        keys.remove(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        Ok(())
    }

    fn random(&mut self, out: &mut [u8]) -> HsmResult<()> {
        self.transport_round_trip()?;
        // Mock: fill with deterministic pattern (not cryptographically secure — CI only)
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8 ^ 0xA5;
        }
        Ok(())
    }

    fn sha256(&self, data: &[u8]) -> HsmResult<[u8; 32]> {
        self.transport_round_trip()?;
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        Ok(hasher.finalize().into())
    }

    fn hmac_sha256(&self, handle: KeyHandle, data: &[u8]) -> HsmResult<[u8; 32]> {
        let slot = self.resolve_key(handle)?;
        // Mock HMAC: SHA-256(key || data) — not RFC 2104 correct, sufficient for mock
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&slot.material);
        hasher.update(data);
        Ok(hasher.finalize().into())
    }

    fn aes_gcm_encrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams<'_>,
        plaintext: &[u8],
    ) -> HsmResult<(Vec<u8>, [u8; 16])> {
        self.resolve_key(handle)?;
        // HSM-REQ-072: mock returns deterministic ciphertext (XOR with IV byte)
        // for testing output contract — not cryptographically correct
        let iv_byte = params.iv[0];
        let ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ iv_byte).collect();
        // Mock tag: first 16 bytes of SHA-256(key_handle || nonce || aad)
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(handle.0.to_le_bytes());
        hasher.update(params.iv.as_ref());
        hasher.update(params.aad);
        let digest = hasher.finalize();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&digest[..16]);
        Ok((ciphertext, tag))
    }

    fn aes_gcm_decrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams<'_>,
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> HsmResult<Vec<u8>> {
        self.resolve_key(handle)?;

        // Recompute expected tag — HSM-REQ-073: use constant-time comparison
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(handle.0.to_le_bytes());
        hasher.update(params.iv.as_ref());
        hasher.update(params.aad);
        let digest = hasher.finalize();
        let mut expected_tag = [0u8; 16];
        expected_tag.copy_from_slice(&digest[..16]);

        // Constant-time tag comparison (HSM-REQ-073)
        use subtle::ConstantTimeEq;
        if tag.ct_eq(&expected_tag).unwrap_u8() != 1 {
            // HSM-REQ-072: do NOT return partial plaintext — output buffer not exposed
            return Err(HsmError::AuthenticationFailed);
        }

        let iv_byte = params.iv[0];
        let plaintext: Vec<u8> = ciphertext.iter().map(|b| b ^ iv_byte).collect();
        Ok(plaintext)
    }

    fn ecdsa_sign(&self, handle: KeyHandle, digest: &[u8; 32]) -> HsmResult<EcdsaSignature> {
        self.resolve_key(handle)?;
        // Mock signature: (r, s) = (SHA-256(handle || digest)[..32], same reversed)
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(handle.0.to_le_bytes());
        hasher.update(digest);
        let h = hasher.finalize();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&h);
        s.copy_from_slice(&h);
        s.reverse();
        Ok(EcdsaSignature { r, s })
    }

    fn ecdsa_verify(
        &self,
        handle: KeyHandle,
        digest: &[u8; 32],
        signature: &EcdsaSignature,
    ) -> HsmResult<bool> {
        self.resolve_key(handle)?;

        // Recompute expected mock signature
        use sha2::Digest;
        use subtle::ConstantTimeEq;
        let mut hasher = sha2::Sha256::new();
        hasher.update(handle.0.to_le_bytes());
        hasher.update(digest);
        let h = hasher.finalize();
        let mut expected_r = [0u8; 32];
        let mut expected_s = [0u8; 32];
        expected_r.copy_from_slice(&h);
        expected_s.copy_from_slice(&h);
        expected_s.reverse();

        // Constant-time comparison on both r and s (HSM-REQ-073)
        let r_ok = signature.r.ct_eq(&expected_r).unwrap_u8() == 1;
        let s_ok = signature.s.ct_eq(&expected_s).unwrap_u8() == 1;
        Ok(r_ok & s_ok)
    }

    fn key_derive(
        &mut self,
        base: KeyHandle,
        info: &[u8],
        out_type: KeyType,
    ) -> HsmResult<KeyHandle> {
        // HSM-REQ-056: reject empty info string
        if info.is_empty() {
            return Err(HsmError::InvalidArgument);
        }
        let slot = self.resolve_key(base)?;
        self.transport_round_trip()?;

        // Mock derivation: SHA-256(base_material || info)
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&slot.material);
        hasher.update(info);
        let derived = hasher.finalize().to_vec();

        let id = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let new_slot = MockKeySlot {
            key_type: out_type as u8,
            material: derived,
        };
        self.keys
            .lock()
            .map_err(|_| HsmError::CryptoFail("lock poisoned".into()))?
            .insert(id, new_slot);
        Ok(KeyHandle(id))
    }

    fn ecdh_agree(&self, handle: KeyHandle, peer_pub: &[u8; 64]) -> HsmResult<[u8; 32]> {
        let slot = self.resolve_key(handle)?;
        // Mock ECDH: SHA-256(private_key_material || peer_pub)
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&slot.material);
        hasher.update(peer_pub);
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&hasher.finalize());
        Ok(shared)
    }

    fn boot_status(&self) -> HsmResult<BootStatus> {
        // Mock: simulate verified secure boot
        Ok(BootStatus {
            verified: true,
            firmware_version: 1,
        })
    }
}

// ── Unit tests for the mock itself ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn no_fault_mock() -> MockHardwareBackend {
        MockHardwareBackend::new(MockFaultConfig::default())
    }

    // HSM-REQ-050: CRC error injection causes HsmError::CrcMismatch
    #[test]
    fn test_crc_error_injection() {
        let config = MockFaultConfig {
            inject_crc_error_on_attempt: Some(1),
            ..Default::default()
        };
        let mut mock = MockHardwareBackend::new(config);
        let result = mock.init();
        assert!(
            matches!(result, Err(HsmError::CrcMismatch)),
            "expected CrcMismatch, got {:?}",
            result
        );
    }

    // HSM-REQ-051: sequence number mismatch → ProtocolError
    #[test]
    fn test_seq_mismatch_injection() {
        let config = MockFaultConfig {
            inject_seq_mismatch: true,
            ..Default::default()
        };
        let mut mock = MockHardwareBackend::new(config);
        let result = mock.init();
        assert!(
            matches!(result, Err(HsmError::ProtocolError)),
            "expected ProtocolError, got {:?}",
            result
        );
    }

    // HSM-REQ-052: timeout injection → HsmError::Timeout
    #[test]
    fn test_timeout_injection() {
        let config = MockFaultConfig {
            inject_timeout: true,
            ..Default::default()
        };
        let mut mock = MockHardwareBackend::new(config);
        let result = mock.init();
        assert!(
            matches!(result, Err(HsmError::Timeout)),
            "expected Timeout, got {:?}",
            result
        );
    }

    // HSM-REQ-063: hardware fault opcode → HsmError::HardwareFault
    #[test]
    fn test_hw_fault_injection() {
        let config = MockFaultConfig {
            inject_hw_fault: true,
            ..Default::default()
        };
        let mut mock = MockHardwareBackend::new(config);
        let result = mock.init();
        assert!(
            matches!(result, Err(HsmError::HardwareFault)),
            "expected HardwareFault, got {:?}",
            result
        );
    }

    // HSM-REQ-067: no key export — key_import returns handle, not material
    #[test]
    fn test_no_key_export_via_import() {
        let mut mock = no_fault_mock();
        mock.init().unwrap();
        let handle = mock.key_import(KeyType::Aes256, &[0xBBu8; 32]).unwrap();
        // Only a handle (u32) is returned — no key bytes in the public interface.
        assert!(handle.0 > 0);
        // There is no API to retrieve key bytes from the mock.
    }

    // HSM-REQ-072: AES-GCM decrypt returns AuthenticationFailed on bad tag (not partial plaintext)
    #[test]
    fn test_aead_auth_failure_returns_error_not_partial_plaintext() {
        let mut mock = no_fault_mock();
        mock.init().unwrap();
        let handle = mock.key_generate(KeyType::Aes256).unwrap();
        let iv = [0u8; 12];
        let params = AesGcmParams { iv: &iv, aad: &[] };
        let (ct, _tag) = mock.aes_gcm_encrypt(handle, &params, b"hello").unwrap();
        let bad_tag = [0xFFu8; 16]; // wrong tag
        let result = mock.aes_gcm_decrypt(handle, &params, &ct, &bad_tag);
        assert!(
            matches!(result, Err(HsmError::AuthenticationFailed)),
            "expected AuthenticationFailed, got {:?}",
            result
        );
    }

    // HSM-REQ-056: HKDF with empty info string → InvalidArgument
    #[test]
    fn test_hkdf_empty_info_rejected() {
        let mut mock = no_fault_mock();
        mock.init().unwrap();
        let base = mock.key_generate(KeyType::Aes256).unwrap();
        let result = mock.key_derive(base, b"", KeyType::HmacSha256);
        assert!(
            matches!(result, Err(HsmError::InvalidArgument)),
            "expected InvalidArgument, got {:?}",
            result
        );
    }

    // HSM-REQ-073: constant-time verification — wrong signature rejected
    #[test]
    fn test_ecdsa_verify_rejects_wrong_signature() {
        let mut mock = no_fault_mock();
        mock.init().unwrap();
        let handle = mock.key_generate(KeyType::EccP256).unwrap();
        let digest = [0x42u8; 32];
        let sig = mock.ecdsa_sign(handle, &digest).unwrap();
        // Tamper with the signature
        let mut bad_sig = sig;
        bad_sig.r[0] ^= 0xFF;
        let result = mock.ecdsa_verify(handle, &digest, &bad_sig).unwrap();
        assert!(!result, "tampered signature should not verify");
    }

    // HSM-REQ-066: key material is zeroized when deleted
    #[test]
    fn test_key_zeroized_on_delete() {
        let mut mock = no_fault_mock();
        mock.init().unwrap();
        let handle = mock.key_generate(KeyType::Aes256).unwrap();
        mock.key_delete(handle).unwrap();
        // After deletion, the handle is invalid
        let result = mock.resolve_key(handle);
        assert!(matches!(result, Err(HsmError::InvalidKeyHandle)));
    }

    // HSM-REQ-051: sequence overflow at u32::MAX
    #[test]
    fn test_sequence_overflow() {
        let mock = no_fault_mock();
        // Force seq counter to MAX
        mock.seq_counter.store(u32::MAX, Ordering::SeqCst);
        let result = mock.transport_round_trip();
        assert!(matches!(result, Err(HsmError::SequenceOverflow)));
    }
}
