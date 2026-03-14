//! Shared types used across the scorehsm-host API.

/// Opaque key handle. Value 0 is reserved/invalid.
/// Key material never leaves the HSM — callers only hold handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHandle(pub u32);

impl KeyHandle {
    /// The invalid/uninitialized handle value.
    pub const INVALID: Self = KeyHandle(0);
}

/// Supported key types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// AES-256 symmetric key.
    Aes256,
    /// HMAC-SHA256 key.
    HmacSha256,
    /// ECC P-256 key pair.
    EccP256,
}

/// Supported algorithms — algorithm-agnostic API, ready for PQC extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// AES-256-GCM authenticated encryption.
    Aes256Gcm,
    /// AES-256-CBC.
    Aes256Cbc,
    /// AES-256-CCM.
    Aes256Ccm,
    /// HMAC-SHA256.
    HmacSha256,
    /// ECDSA with P-256.
    EcdsaP256,
    /// ECDH with P-256.
    EcdhP256,
    /// SHA-256.
    Sha256,
    /// HKDF with SHA-256.
    HkdfSha256,
    /// ML-DSA (Dilithium) — software only.
    #[cfg(feature = "pqc")]
    MlDsa,
    /// ML-KEM (Kyber) — software only.
    #[cfg(feature = "pqc")]
    MlKem,
}

/// Secure boot status reported by `HsmBackend::boot_status()` — HSM-REQ-046.
///
/// The software backend returns a synthetic "not applicable" value.
/// The hardware backend queries the firmware for the boot verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootStatus {
    /// `true` if the firmware image was verified against the OTP public key at reset.
    ///
    /// `false` for the software backend (no secure boot hardware).
    pub verified: bool,
    /// Monotonic firmware version counter embedded in the image header.
    ///
    /// Zero for the software backend.
    pub firmware_version: u32,
}

/// AES-GCM operation parameters.
pub struct AesGcmParams<'a> {
    /// 96-bit IV / nonce.
    pub iv: &'a [u8; 12],
    /// Additional authenticated data (may be empty).
    pub aad: &'a [u8],
}

/// ECDSA signature (r, s) in big-endian.
#[derive(Debug, Clone)]
pub struct EcdsaSignature {
    /// r component (32 bytes, big-endian).
    pub r: [u8; 32],
    /// s component (32 bytes, big-endian).
    pub s: [u8; 32],
}
