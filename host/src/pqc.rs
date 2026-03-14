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
    use pqcrypto_dilithium::dilithium3::{
        self, PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
        SignedMessage,
    };
    use pqcrypto_kyber::kyber768::{
        self, PublicKey as KyberPublicKey, SecretKey as KyberSecretKey,
        Ciphertext as KyberCiphertext, SharedSecret as KyberSharedSecret,
    };
    use pqcrypto_traits::{
        sign::{PublicKey as _, SecretKey as _, SignedMessage as _},
        kem::{PublicKey as _, SecretKey as _, Ciphertext as _, SharedSecret as _},
    };
    use crate::error::{HsmError, HsmResult};

    // ── ML-DSA (Dilithium-3) ─────────────────────────────────────────────────

    /// ML-DSA key pair.
    pub struct MlDsaKeyPair {
        pub public_key:  DilithiumPublicKey,
        pub secret_key:  DilithiumSecretKey,
    }

    /// Generate a fresh ML-DSA (Dilithium-3) key pair.
    pub fn mldsa_keygen() -> MlDsaKeyPair {
        let (pk, sk) = dilithium3::keypair();
        MlDsaKeyPair { public_key: pk, secret_key: sk }
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
        pub public_key: KyberPublicKey,
        pub secret_key: KyberSecretKey,
    }

    /// Generate a fresh ML-KEM (Kyber-768) key pair for the recipient.
    pub fn mlkem_keygen() -> MlKemKeyPair {
        let (pk, sk) = kyber768::keypair();
        MlKemKeyPair { public_key: pk, secret_key: sk }
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
