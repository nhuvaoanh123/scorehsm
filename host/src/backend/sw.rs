//! Software fallback backend — rustcrypto, no hardware required.
//!
//! Used in CI and on any Linux machine without the L55 attached.
//! Satisfies all algorithmic requirements but NOT hardware isolation
//! requirements (os_protection, no_key_exposure, reverse_eng_protection).
//!
//! HSM-REQ-045: compile-time warning when built without hw-backend.
#![cfg_attr(
    not(feature = "hw-backend"),
    allow(unused)
)]

use std::collections::HashMap;

use crate::error::{HsmError, HsmResult};
use crate::types::{AesGcmParams, EcdsaSignature, KeyHandle, KeyType};

use super::HsmBackend;

/// Key material stored in-process (software backend only).
///
/// Key material is held in heap memory. This does NOT satisfy HSM-REQ-031/036
/// (TrustZone isolation). The hardware backend does.
enum KeyMaterial {
    Aes256([u8; 32]),
    HmacSha256([u8; 32]),
    /// P-256 private scalar (big-endian, 32 bytes).
    EccP256([u8; 32]),
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

    fn deinit(&mut self) -> HsmResult<()> {
        self.initialized = false;
        self.keys.clear();
        Ok(())
    }

    fn key_generate(&mut self, key_type: KeyType) -> HsmResult<KeyHandle> {
        self.check_init()?;
        use rand_core::{OsRng, RngCore};

        let material = match key_type {
            KeyType::Aes256 => {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                KeyMaterial::Aes256(key)
            }
            KeyType::HmacSha256 => {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                KeyMaterial::HmacSha256(key)
            }
            KeyType::EccP256 => {
                use p256::ecdsa::SigningKey;
                let signing_key = SigningKey::random(&mut OsRng);
                let bytes: [u8; 32] = signing_key.to_bytes().into();
                KeyMaterial::EccP256(bytes)
            }
        };

        let handle = self.alloc_handle();
        self.keys.insert(handle.0, material);
        Ok(handle)
    }

    fn key_import(&mut self, _key_type: KeyType, _wrapped: &[u8]) -> HsmResult<KeyHandle> {
        // TODO: unwrap using a wrapping key (KEK) — HSM-REQ-020
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
        self.check_init()?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        Ok(out)
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
        // aes-gcm appends the 16-byte tag at the end of the ciphertext
        let tag_offset = result.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&result[tag_offset..]);
        Ok((result[..tag_offset].to_vec(), tag))
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
        // Reconstruct ciphertext+tag as aes-gcm expects
        let mut ct_with_tag = ciphertext.to_vec();
        ct_with_tag.extend_from_slice(tag);
        let payload = Payload { msg: &ct_with_tag, aad: params.aad };
        cipher
            .decrypt(nonce, payload)
            .map_err(|_| HsmError::TagMismatch)
    }

    fn ecdsa_sign(&self, handle: KeyHandle, digest: &[u8; 32]) -> HsmResult<EcdsaSignature> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::EccP256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        let signing_key = SigningKey::from_bytes(raw.into())
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let sig: p256::ecdsa::Signature = signing_key
            .sign_prehash(digest)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let (r_bytes, s_bytes) = sig.split_bytes();
        Ok(EcdsaSignature { r: r_bytes.into(), s: s_bytes.into() })
    }

    fn ecdsa_verify(
        &self,
        handle: KeyHandle,
        digest: &[u8; 32],
        signature: &EcdsaSignature,
    ) -> HsmResult<bool> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::EccP256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, SigningKey, VerifyingKey};
        let signing_key = SigningKey::from_bytes(raw.into())
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let verifying_key = VerifyingKey::from(&signing_key);
        let sig = Signature::from_scalars(signature.r, signature.s)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        match verifying_key.verify_prehash(digest, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn key_derive(
        &mut self,
        base: KeyHandle,
        info: &[u8],
        out_type: KeyType,
    ) -> HsmResult<KeyHandle> {
        self.check_init()?;
        // Copy the IKM out first (before mutable borrow of self.keys for insert)
        let ikm: [u8; 32] = {
            let key = self.keys.get(&base.0).ok_or(HsmError::InvalidKeyHandle)?;
            match key {
                KeyMaterial::Aes256(k) | KeyMaterial::HmacSha256(k) | KeyMaterial::EccP256(k) => *k,
            }
        };
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let material = match out_type {
            KeyType::Aes256 => KeyMaterial::Aes256(okm),
            KeyType::HmacSha256 => KeyMaterial::HmacSha256(okm),
            KeyType::EccP256 => KeyMaterial::EccP256(okm),
        };
        let handle = self.alloc_handle();
        self.keys.insert(handle.0, material);
        Ok(handle)
    }

    fn ecdh_agree(&self, handle: KeyHandle, peer_pub: &[u8; 64]) -> HsmResult<[u8; 32]> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::EccP256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use p256::{
            ecdh::EphemeralSecret,
            elliptic_curve::sec1::FromEncodedPoint,
            EncodedPoint, PublicKey, SecretKey,
        };
        // Reconstruct peer public key from uncompressed 64-byte representation
        // peer_pub is [x: 32 bytes || y: 32 bytes] without the 0x04 prefix
        let mut encoded = [0u8; 65];
        encoded[0] = 0x04;
        encoded[1..].copy_from_slice(peer_pub);
        let ep = EncodedPoint::from_bytes(&encoded)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let peer_key = PublicKey::from_encoded_point(&ep)
            .into_option()
            .ok_or_else(|| HsmError::CryptoFail("invalid peer public key".into()))?;
        let secret_key = SecretKey::from_bytes(raw.into())
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let shared = p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_key.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes());
        Ok(out)
    }
}
