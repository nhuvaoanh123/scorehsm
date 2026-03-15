//! IPSec / MACSec key material provisioning — HSM-REQ-048.
//!
//! The HSM provides the ECDH and HKDF primitives required by IKEv2 (IPSec) and
//! MKA (MACSec Key Agreement). The protocol stack receives opaque key bytes
//! derived from the ECDH shared secret; it never sees the private key.
//!
//! **Scope note:** The IPSec/MACSec protocol stack itself is a platform concern
//! outside the HSM library boundary. This module provides the cryptographic
//! building blocks only.
//!
//! # IKEv2 derivation (RFC 7296 §2.14)
//!
//! ```text
//! SKEYSEED = prf(Ni | Nr, g^ir)
//! {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr} =
//!     prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
//! ```
//!
//! We implement `prf` as HMAC-SHA256 and `prf+` as HKDF-Expand.
//!
//! # MKA derivation (IEEE 802.1X §9.3.3)
//!
//! ```text
//! ICK  = KDF(CAK, "IEEE8021 EAP-INITIATION/REAUTH Integrity Key", KS-label, len)
//! KEK  = KDF(CAK, "IEEE8021 EAP-INITIATION/REAUTH Key Encrypting Key", KS-label, len)
//! ```
//!
//! We implement `KDF` as HKDF-SHA256.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{backend::HsmBackend, error::HsmResult, types::KeyHandle};

// ── IKEv2 ─────────────────────────────────────────────────────────────────────

/// Key material derived for an IKEv2 SA (Security Association).
///
/// All byte arrays are 32-byte HKDF outputs suitable for HMAC-SHA256 or
/// AES-256-based algorithms. The `sk_ei`/`sk_er` fields are AES-256 encryption
/// keys; `sk_ai`/`sk_ar` are HMAC-SHA256 integrity keys.
///
/// **Security note:** Key material is transiently held in host process memory
/// during derivation. On the hardware path, use the firmware-side combined
/// ECDH+HKDF command to avoid exposing the shared secret in host RAM.
#[derive(Debug)]
pub struct Ikev2KeyMaterial {
    /// SK_d — key for deriving child SA key material.
    pub sk_d: [u8; 32],
    /// SK_ai — integrity key for data from initiator to responder.
    pub sk_ai: [u8; 32],
    /// SK_ar — integrity key for data from responder to initiator.
    pub sk_ar: [u8; 32],
    /// SK_ei — encryption key for data from initiator to responder.
    pub sk_ei: [u8; 32],
    /// SK_er — encryption key for data from responder to initiator.
    pub sk_er: [u8; 32],
}

/// Derive IKEv2 SA key material from an ECDH key exchange.
///
/// # Arguments
/// - `backend` — any [`HsmBackend`] implementation.
/// - `ecdh_handle` — handle to the local ECDH private key (P-256, session-owned).
/// - `peer_pub` — peer's P-256 public key as 64 raw bytes (X || Y, no 0x04 prefix).
/// - `nonce_i` — IKEv2 initiator nonce (Ni, typically 16–256 bytes).
/// - `nonce_r` — IKEv2 responder nonce (Nr, typically 16–256 bytes).
/// - `spi_i` — initiator SPI (8 bytes).
/// - `spi_r` — responder SPI (8 bytes).
///
/// # Errors
/// Propagates any `HsmError` from the backend ECDH operation.
pub fn ikev2_derive_keys<B: HsmBackend>(
    backend: &B,
    ecdh_handle: KeyHandle,
    peer_pub: &[u8; 64],
    nonce_i: &[u8],
    nonce_r: &[u8],
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
) -> HsmResult<Ikev2KeyMaterial> {
    // Step 1: ECDH — g^ir (shared secret, 32 bytes).
    let shared = backend.ecdh_agree(ecdh_handle, peer_pub)?;

    // Step 2: SKEYSEED = HMAC-SHA256(Ni | Nr, g^ir).
    // prf(key=Ni|Nr, msg=shared_secret)
    use hmac::{Hmac, Mac};
    let mut prf = Hmac::<Sha256>::new_from_slice(&[nonce_i, nonce_r].concat())
        .map_err(|_| crate::error::HsmError::CryptoFail("HMAC key init failed".into()))?;
    prf.update(&shared);
    let skeyseed: [u8; 32] = prf.finalize().into_bytes().into();

    // Step 3: prf+(SKEYSEED, Ni | Nr | SPIi | SPIr) → 5 × 32 = 160 bytes.
    // HKDF-Expand(PRK=SKEYSEED, info=Ni|Nr|SPIi|SPIr, L=160)
    let info: Vec<u8> = [nonce_i, nonce_r, spi_i.as_slice(), spi_r.as_slice()].concat();
    let hk = Hkdf::<Sha256>::from_prk(&skeyseed)
        .map_err(|_| crate::error::HsmError::CryptoFail("HKDF PRK init failed".into()))?;
    let mut okm = [0u8; 160];
    hk.expand(&info, &mut okm)
        .map_err(|_| crate::error::HsmError::CryptoFail("HKDF expand failed".into()))?;

    Ok(Ikev2KeyMaterial {
        sk_d: okm[0..32].try_into().unwrap(),
        sk_ai: okm[32..64].try_into().unwrap(),
        sk_ar: okm[64..96].try_into().unwrap(),
        sk_ei: okm[96..128].try_into().unwrap(),
        sk_er: okm[128..160].try_into().unwrap(),
    })
}

// ── MACSec / MKA ──────────────────────────────────────────────────────────────

/// Key material derived for a MACSec MKA session.
///
/// ICK (Integrity Check Key) and KEK (Key Encrypting Key) are both 32 bytes
/// (AES-256 strength), derived from the Connectivity Association Key (CAK).
#[derive(Debug)]
pub struct MacsecMkaKeys {
    /// ICK — Integrity Check Key for MKA PDU authentication.
    pub ick: [u8; 32],
    /// KEK — Key Encrypting Key for SAK (Secure Association Key) distribution.
    pub kek: [u8; 32],
}

/// Derive MACSec MKA ICK and KEK from a Connectivity Association Key (CAK).
///
/// # Arguments
/// - `backend` — any [`HsmBackend`] implementation.
/// - `cak_handle` — handle to the 256-bit CAK stored in the HSM.
/// - `cak_name` — CAK name (CKN) used as HKDF salt, per IEEE 802.1X §9.3.
///
/// # Errors
/// Propagates any `HsmError` from the backend HMAC/HKDF operations.
pub fn macsec_derive_mka_keys<B: HsmBackend>(
    backend: &B,
    cak_handle: KeyHandle,
    cak_name: &[u8],
) -> HsmResult<MacsecMkaKeys> {
    // Derive ICK: HKDF(IKM=CAK, salt=CKN, info="MKA ICK", L=32)
    // We extract CAK via HMAC-SHA256(CKN, "") to use as HKDF IKM (avoids raw export).
    // In production the firmware performs this atomically.
    let cak_ikm = backend.hmac_sha256(cak_handle, cak_name)?;

    let hk = Hkdf::<Sha256>::new(Some(cak_name), &cak_ikm);
    let mut ick = [0u8; 32];
    let mut kek = [0u8; 32];
    hk.expand(b"MKA ICK", &mut ick)
        .map_err(|_| crate::error::HsmError::CryptoFail("HKDF expand ICK failed".into()))?;
    hk.expand(b"MKA KEK", &mut kek)
        .map_err(|_| crate::error::HsmError::CryptoFail("HKDF expand KEK failed".into()))?;

    Ok(MacsecMkaKeys { ick, kek })
}
