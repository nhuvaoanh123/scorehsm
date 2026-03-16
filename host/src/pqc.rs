// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! Post-quantum cryptography — HSM-REQ-033.
//!
//! Software-only implementations of ML-DSA (Dilithium-3) and ML-KEM (Kyber-768).
//! Key material is NOT stored in the hardware HSM — PQC runs entirely on the host
//! using the `pqcrypto-dilithium` and `pqcrypto-kyber` crates.
//!
//! Feature-gated behind `pqc`.

#[cfg(feature = "pqc")]
pub use pqc_impl::*;

#[cfg(feature = "pqc")]
mod pqc_impl {
    use crate::error::{HsmError, HsmResult};
    use pqcrypto_dilithium::dilithium3::{
        self, PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey, SignedMessage,
    };
    use pqcrypto_kyber::kyber768::{
        self, Ciphertext as KyberCiphertext, PublicKey as KyberPublicKey,
        SecretKey as KyberSecretKey,
    };
    use pqcrypto_traits::{
        kem::{Ciphertext as _, SharedSecret as _},
        sign::SignedMessage as _,
    };

    // ── ML-DSA (Dilithium-3) ─────────────────────────────────────────────────

    /// ML-DSA key pair.
    pub struct MlDsaKeyPair {
        /// Dilithium-3 public key (used for verification).
        pub public_key: DilithiumPublicKey,
        /// Dilithium-3 secret key (used for signing).
        pub secret_key: DilithiumSecretKey,
    }

    /// Generate a fresh ML-DSA (Dilithium-3) key pair.
    pub fn mldsa_keygen() -> MlDsaKeyPair {
        let (pk, sk) = dilithium3::keypair();
        MlDsaKeyPair {
            public_key: pk,
            secret_key: sk,
        }
    }

    /// Sign `message` with an ML-DSA secret key. Returns the detached signature.
    pub fn mldsa_sign(sk: &DilithiumSecretKey, message: &[u8]) -> HsmResult<Vec<u8>> {
        let signed = dilithium3::sign(message, sk);
        // Extract detached signature = signed_message[..sig_len]
        let sig_len = signed.as_bytes().len() - message.len();
        Ok(signed.as_bytes()[..sig_len].to_vec())
    }

    /// Verify an ML-DSA detached `signature` over `message`.
    pub fn mldsa_verify(
        pk: &DilithiumPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        // Reconstruct signed message = signature || message
        let mut sm_bytes = signature.to_vec();
        sm_bytes.extend_from_slice(message);
        match SignedMessage::from_bytes(&sm_bytes) {
            Err(_) => Ok(false),
            Ok(sm) => match dilithium3::open(&sm, pk) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            },
        }
    }

    // ── ML-KEM (Kyber-768) ───────────────────────────────────────────────────

    /// ML-KEM key pair.
    pub struct MlKemKeyPair {
        /// Kyber-768 public key (distributed to senders for encapsulation).
        pub public_key: KyberPublicKey,
        /// Kyber-768 secret key (used for decapsulation).
        pub secret_key: KyberSecretKey,
    }

    /// Generate a fresh ML-KEM (Kyber-768) key pair for the recipient.
    pub fn mlkem_keygen() -> MlKemKeyPair {
        let (pk, sk) = kyber768::keypair();
        MlKemKeyPair {
            public_key: pk,
            secret_key: sk,
        }
    }

    /// Encapsulate: sender generates a ciphertext and shared secret using the
    /// recipient's public key.
    ///
    /// Returns `(ciphertext_bytes, shared_secret_bytes)`.
    pub fn mlkem_encapsulate(pk: &KyberPublicKey) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        let (ss, ct) = kyber768::encapsulate(pk);
        Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
    }

    /// Decapsulate: recipient recovers the shared secret from the ciphertext
    /// using their secret key.
    ///
    /// Returns the 32-byte shared secret.
    pub fn mlkem_decapsulate(sk: &KyberSecretKey, ct_bytes: &[u8]) -> HsmResult<Vec<u8>> {
        let ct = KyberCiphertext::from_bytes(ct_bytes)
            .map_err(|_| HsmError::CryptoFail("invalid Kyber ciphertext".into()))?;
        let ss = kyber768::decapsulate(&ct, sk);
        Ok(ss.as_bytes().to_vec())
    }
}
