//! Software fallback backend — rustcrypto, no hardware required.
//!
//! Used in CI and on any Linux machine without the L55 attached.
//! Satisfies all algorithmic requirements but NOT hardware isolation
//! requirements (os_protection, no_key_exposure, reverse_eng_protection).

use std::collections::HashMap;

use crate::error::{HsmError, HsmResult};
use crate::types::{AesGcmParams, EcdsaSignature, KeyHandle, KeyType};

use super::HsmBackend;

/// Key material stored in-process (software backend only).
enum KeyMaterial {
    Aes256([u8; 32]),
    HmacSha256([u8; 32]),
    EccP256(Vec<u8>), // DER-encoded private key
}

/// Software fallback backend.
pub struct SoftwareBackend {
    initialized: bool,
    next_handle: u32,
    keys: HashMap<u32, KeyMaterial>,
}

impl SoftwareBackend {
    /// Create a new software backend instance.
    pub fn new() -> Self {
        Self {
            initialized: false,
            next_handle: 1,
            keys: HashMap::new(),
        }
    }

    fn check_init(&self) -> HsmResult<()> {
        if self.initialized {
            Ok(())
        } else {
            Err(HsmError::NotInitialized)
        }
    }

    fn alloc_handle(&mut self) -> KeyHandle {
        let h = KeyHandle(self.next_handle);
        self.next_handle += 1;
        h
    }
}

impl Default for SoftwareBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmBackend for SoftwareBackend {
    fn init(&mut self) -> HsmResult<()> {
        self.initialized = true;
        Ok(())
    }

    fn key_generate(&mut self, key_type: KeyType) -> HsmResult<KeyHandle> {
        self.check_init()?;
        use rand_core::OsRng;

        let material = match key_type {
            KeyType::Aes256 | KeyType::HmacSha256 => {
                let mut key = [0u8; 32];
                use rand_core::RngCore;
                OsRng.fill_bytes(&mut key);
                if key_type == KeyType::Aes256 {
                    KeyMaterial::Aes256(key)
                } else {
                    KeyMaterial::HmacSha256(key)
                }
            }
            KeyType::EccP256 => {
                // TODO: generate P-256 key pair using p256 crate
                return Err(HsmError::Unsupported);
            }
        };

        let handle = self.alloc_handle();
        self.keys.insert(handle.0, material);
        Ok(handle)
    }

    fn key_import(&mut self, _key_type: KeyType, _wrapped: &[u8]) -> HsmResult<KeyHandle> {
        // TODO: unwrap using a wrapping key (KEK)
        Err(HsmError::Unsupported)
    }

    fn key_delete(&mut self, handle: KeyHandle) -> HsmResult<()> {
        self.check_init()?;
        self.keys.remove(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        Ok(())
    }

    fn random(&mut self, out: &mut [u8]) -> HsmResult<()> {
        self.check_init()?;
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(out);
        Ok(())
    }

    fn sha256(&self, data: &[u8]) -> HsmResult<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(data);
        Ok(digest.into())
    }

    fn hmac_sha256(&self, handle: KeyHandle, data: &[u8]) -> HsmResult<[u8; 32]> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::HmacSha256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(raw)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().into())
    }

    fn aes_gcm_encrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams,
        plaintext: &[u8],
    ) -> HsmResult<(Vec<u8>, [u8; 16])> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::Aes256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce,
        };
        let cipher = Aes256Gcm::new_from_slice(raw)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let nonce = Nonce::from_slice(params.iv);
        let payload = Payload { msg: plaintext, aad: params.aad };
        let result = cipher
            .encrypt(nonce, payload)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        // aes-gcm appends the 16-byte tag at the end
        let (ct, tag_slice) = result.split_at(result.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_slice);
        Ok((ct.to_vec(), tag))
    }

    fn aes_gcm_decrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams,
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> HsmResult<Vec<u8>> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::Aes256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce,
        };
        let cipher = Aes256Gcm::new_from_slice(raw)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let nonce = Nonce::from_slice(params.iv);
        // reconstruct ciphertext+tag as aes-gcm expects
        let mut ct_with_tag = ciphertext.to_vec();
        ct_with_tag.extend_from_slice(tag);
        let payload = Payload { msg: &ct_with_tag, aad: params.aad };
        cipher
            .decrypt(nonce, payload)
            .map_err(|_| HsmError::TagMismatch)
    }

    fn ecdsa_sign(&self, _handle: KeyHandle, _digest: &[u8; 32]) -> HsmResult<EcdsaSignature> {
        // TODO: implement using p256 crate
        Err(HsmError::Unsupported)
    }

    fn ecdsa_verify(
        &self,
        _handle: KeyHandle,
        _digest: &[u8; 32],
        _signature: &EcdsaSignature,
    ) -> HsmResult<bool> {
        // TODO: implement using p256 crate
        Err(HsmError::Unsupported)
    }

    fn hkdf_derive(
        &mut self,
        _base: KeyHandle,
        _info: &[u8],
        _out_type: KeyType,
    ) -> HsmResult<KeyHandle> {
        // TODO: implement using hkdf crate
        Err(HsmError::Unsupported)
    }
}
