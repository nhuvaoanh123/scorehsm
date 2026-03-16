// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

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
    use crate::error::{HsmError, HsmResult};
    use x509_cert::{
        der::{Decode, Encode},
        Certificate,
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
        raw.try_into().map_err(|_| {
            HsmError::CryptoFail(format!(
                "expected 65-byte EC point, got {} bytes",
                raw.len()
            ))
        })
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
            ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey},
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
        let tbs_der = cert
            .tbs_certificate
            .to_der()
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

    /// Check that a certificate is currently valid (notBefore ≤ now ≤ notAfter).
    ///
    /// Returns:
    /// - `Ok(())` if the certificate is within its validity window.
    /// - `Err(HsmError::CertificateNotYetValid)` if `now < notBefore`.
    /// - `Err(HsmError::CertificateExpired)` if `now > notAfter`.
    /// - `Err(HsmError::ClockUnavailable)` if the system clock is unavailable.
    pub fn check_validity(cert: &Certificate) -> HsmResult<()> {
        use std::time::SystemTime;
        use x509_cert::der::DateTime;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| HsmError::ClockUnavailable)?;
        let now_secs = now.as_secs();

        let validity = &cert.tbs_certificate.validity;

        // Convert notBefore to unix timestamp
        let not_before: DateTime = validity.not_before.to_date_time();
        let nb_unix = datetime_to_unix(&not_before).ok_or(HsmError::ClockUnavailable)?;

        // Convert notAfter to unix timestamp
        let not_after: DateTime = validity.not_after.to_date_time();
        let na_unix = datetime_to_unix(&not_after).ok_or(HsmError::ClockUnavailable)?;

        if now_secs < nb_unix {
            return Err(HsmError::CertificateNotYetValid);
        }
        if now_secs > na_unix {
            return Err(HsmError::CertificateExpired);
        }
        Ok(())
    }

    /// Approximate conversion of x509-cert DateTime to Unix timestamp.
    ///
    /// Handles years 2000-2099 (sufficient for X.509 certificates in embedded HSM).
    fn datetime_to_unix(dt: &x509_cert::der::DateTime) -> Option<u64> {
        // Days in each month (non-leap year)
        const DAYS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

        let y = dt.year() as u64;
        let m = dt.month() as u64;
        let d = dt.day() as u64;
        let hh = dt.hour() as u64;
        let mm = dt.minutes() as u64;
        let ss = dt.seconds() as u64;

        // Count days from 1970-01-01 to the start of year y
        let mut days: u64 = 0;
        for yr in 1970..y {
            days += if is_leap(yr) { 366 } else { 365 };
        }
        // Add days for months in year y
        for mo in 1..m {
            days += DAYS[(mo - 1) as usize];
            if mo == 2 && is_leap(y) {
                days += 1;
            }
        }
        // Add days of month
        days += d.checked_sub(1)?; // day-of-month is 1-based

        Some(days * 86400 + hh * 3600 + mm * 60 + ss)
    }

    fn is_leap(y: u64) -> bool {
        (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
    }

    /// Verify a chain of certificates against a trust anchor (root CA public key).
    ///
    /// `chain[0]` is the leaf; `chain[last]` must be signed by `trust_anchor_pk`.
    /// Each certificate in the chain must be signed by its immediate successor.
    ///
    /// Returns `Ok(())` if every signature in the chain is valid.
    ///
    /// # Errors
    ///
    /// - `HsmError::InvalidParam` — chain is empty.
    /// - `HsmError::CryptoFail`  — any signature in the chain is invalid, or
    ///   a public key cannot be extracted from an intermediate certificate.
    /// - `HsmError::Unsupported` — a certificate uses an algorithm other than
    ///   ECDSA-P256 (OID 1.2.840.10045.4.3.2).
    pub fn verify_chain(chain: &[Certificate], trust_anchor_pk: &[u8; 65]) -> HsmResult<()> {
        if chain.is_empty() {
            return Err(HsmError::InvalidParam("empty certificate chain".into()));
        }

        // Walk from leaf (index 0) to root (index len-1).
        // Each certificate's issuer key is the next certificate's subject key,
        // except for the root whose issuer is the out-of-band trust anchor.
        for i in 0..chain.len() {
            let issuer_key: [u8; 65] = if i + 1 < chain.len() {
                extract_ec_public_key(&chain[i + 1])?
            } else {
                *trust_anchor_pk
            };
            if !verify_cert_signature(&chain[i], &issuer_key)? {
                return Err(HsmError::CryptoFail(format!(
                    "certificate {} signature verification failed",
                    i
                )));
            }
        }
        Ok(())
    }
}
