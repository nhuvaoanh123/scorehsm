//! Backend abstraction — software fallback and hardware (USB/L55).

use crate::error::HsmResult;
use crate::types::{AesGcmParams, EcdsaSignature, KeyHandle, KeyType};

pub mod sw;

#[cfg(feature = "hw-backend")]
pub mod hw;

/// Core backend trait — implemented by both software fallback and hardware backend.
///
/// All operations use key handles. Key material never crosses this interface.
pub trait HsmBackend: Send + Sync {
    /// Initialize the backend.
    fn init(&mut self) -> HsmResult<()>;

    /// Generate a new key of the given type. Returns an opaque handle.
    fn key_generate(&mut self, key_type: KeyType) -> HsmResult<KeyHandle>;

    /// Import a wrapped (encrypted) key. Returns an opaque handle.
    fn key_import(&mut self, key_type: KeyType, wrapped: &[u8]) -> HsmResult<KeyHandle>;

    /// Delete a key slot and zeroize key material.
    fn key_delete(&mut self, handle: KeyHandle) -> HsmResult<()>;

    /// Generate random bytes from the entropy source.
    fn random(&mut self, out: &mut [u8]) -> HsmResult<()>;

    /// SHA-256 hash.
    fn sha256(&self, data: &[u8]) -> HsmResult<[u8; 32]>;

    /// HMAC-SHA256.
    fn hmac_sha256(&self, handle: KeyHandle, data: &[u8]) -> HsmResult<[u8; 32]>;

    /// AES-256-GCM encrypt.
    ///
    /// Returns (ciphertext, tag). Ciphertext is the same length as plaintext.
    fn aes_gcm_encrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams,
        plaintext: &[u8],
    ) -> HsmResult<(Vec<u8>, [u8; 16])>;

    /// AES-256-GCM decrypt and verify.
    ///
    /// Returns plaintext. Returns `HsmError::TagMismatch` if tag fails.
    fn aes_gcm_decrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams,
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> HsmResult<Vec<u8>>;

    /// ECDSA P-256 sign. Signs a pre-computed SHA-256 digest (32 bytes).
    fn ecdsa_sign(&self, handle: KeyHandle, digest: &[u8; 32]) -> HsmResult<EcdsaSignature>;

    /// ECDSA P-256 verify.
    fn ecdsa_verify(
        &self,
        handle: KeyHandle,
        digest: &[u8; 32],
        signature: &EcdsaSignature,
    ) -> HsmResult<bool>;

    /// HKDF-SHA256 key derivation. Derives a new key slot from an existing one.
    fn hkdf_derive(
        &mut self,
        base: KeyHandle,
        info: &[u8],
        out_type: KeyType,
    ) -> HsmResult<KeyHandle>;
}
