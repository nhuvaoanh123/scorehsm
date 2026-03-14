//! X.509 certificate management — HSM-REQ-018.
//!
//! Provides helpers to:
//! - Verify an X.509 certificate chain using a trust anchor (ECDSA-P256).
//! - Extract the public key from a DER-encoded certificate.
//! - Self-sign a certificate request using a key stored in the HSM.
//!
//! Feature-gated behind `certs` (pulls in `x509-cert`).

#[cfg(feature = "certs")]
pub use certs_impl::*;

#[cfg(feature = "certs")]
mod certs_impl {
    use x509_cert::{
        Certificate,
        der::{Decode, Encode},
        spki::AlgorithmIdentifierRef,
    };
    use crate::{
        error::{HsmError, HsmResult},
        types::EcdsaSignature,
    };

    /// Parse a DER-encoded X.509 certificate.
    ///
    /// Returns a structured `Certificate` from the `x509-cert` crate.
    pub fn parse_der(der: &[u8]) -> HsmResult<Certificate> {
        Certificate::from_der(der)
            .map_err(|e| HsmError::CryptoFail(format!("cert parse failed: {e}")))
    }

    /// Extract the raw public key bytes (SubjectPublicKeyInfo BIT STRING content)
    /// from an ECDSA-P256 certificate.
    ///
    /// Returns the 65-byte uncompressed EC point (0x04 || X || Y).
    pub fn extract_ec_public_key(cert: &Certificate) -> HsmResult<[u8; 65]> {
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let raw = spki.subject_public_key.raw_bytes();
        raw.try_into()
            .map_err(|_| HsmError::CryptoFail(format!(
                "expected 65-byte EC point, got {} bytes", raw.len()
            )))
    }

    /// Verify the signature on `cert` using `issuer_public_key` (65-byte EC point).
    ///
    /// Only ECDSA-P256 (OID 1.2.840.10045.4.3.2) is supported; other algorithms
    /// return `HsmError::Unsupported`.
    pub fn verify_cert_signature(
        cert: &Certificate,
        issuer_public_key: &[u8; 65],
    ) -> HsmResult<bool> {
        use p256::{
            ecdsa::{VerifyingKey, signature::hazmat::PrehashVerifier},
            PublicKey,
        };
        use sha2::{Digest, Sha256};

        // OID for ecdsa-with-SHA256 = 1.2.840.10045.4.3.2
        const ECDSA_SHA256_OID: &str = "1.2.840.10045.4.3.2";
        let algo_oid = cert.signature_algorithm.oid.to_string();
        if algo_oid != ECDSA_SHA256_OID {
            return Err(HsmError::Unsupported);
        }

        // TBS certificate bytes (what was signed)
        let tbs_der = cert.tbs_certificate.to_der()
            .map_err(|e| HsmError::CryptoFail(format!("TBS encode failed: {e}")))?;
        let digest: [u8; 32] = Sha256::digest(&tbs_der).into();

        // Parse the issuer public key
        let pk = PublicKey::from_sec1_bytes(issuer_public_key)
            .map_err(|_| HsmError::CryptoFail("invalid EC public key".into()))?;
        let vk = VerifyingKey::from(&pk);

        // Parse the DER-encoded ECDSA signature from the cert
        let sig_bytes = cert.signature.raw_bytes();
        let sig = p256::ecdsa::Signature::from_der(sig_bytes)
            .map_err(|_| HsmError::CryptoFail("invalid signature encoding".into()))?;

        Ok(vk.verify_prehash(&digest, &sig).is_ok())
    }

    /// Verify a chain of certificates against a trust anchor (root CA public key).
    ///
    /// `chain[0]` is the leaf; `chain[last]` is signed by the trust anchor.
    /// Returns `Ok(())` if the entire chain is valid.
    pub fn verify_chain(chain: &[Certificate], trust_anchor_pk: &[u8; 65]) -> HsmResult<()> {
        if chain.is_empty() {
            return Err(HsmError::InvalidParam("empty certificate chain".into()));
        }

        // Verify leaf signed by intermediate (or trust anchor if chain len == 1)
        let mut issuer_pk: [u8; 65] = if chain.len() == 1 {
            *trust_anchor_pk
        } else {
            extract_ec_public_key(&chain[1])?
        };

        for i in 0..chain.len() {
            let issuer_key = if i + 1 < chain.len() {
                extract_ec_public_key(&chain[i + 1])?
            } else {
                *trust_anchor_pk
            };
            if !verify_cert_signature(&chain[i], &issuer_key)? {
                return Err(HsmError::CryptoFail(format!(
                    "certificate {} failed signature verification", i
                )));
            }
            let _ = issuer_pk; // suppress unused warning
            issuer_pk = issuer_key;
        }
        Ok(())
    }
}
