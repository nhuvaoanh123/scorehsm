//! Crypto operations — all soft-crypto, no hardware acceleration for now.
//!
//! Hardware peripherals (AES, PKA, HASH, RNG) are at Secure addresses on
//! STM32L552 and will be wired in via TrustZone NSC veneers in a future
//! iteration. The software fallback is identical to the host SW backend,
//! ensuring protocol-level correctness in the interim.

use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce, aead::{AeadInPlace, KeyInit}};
use p256::{
    ecdsa::{SigningKey, VerifyingKey},
    PublicKey,
};
use rand_core::{RngCore, CryptoRng};

/// SHA-256 hash of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// HMAC-SHA256 of `data` using `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], ()> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| ())?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// AES-256-GCM encrypt. `iv` must be 12 bytes. Returns ciphertext || tag (16B).
pub fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<heapless::Vec<u8, 640>, ()> {
    let aes_key = AesKey::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(iv);
    let pt_len = plaintext.len();
    if pt_len > 512 { return Err(()); }
    let mut buf = [0u8; 512];
    buf[..pt_len].copy_from_slice(plaintext);
    let tag = cipher.encrypt_in_place_detached(nonce, aad, &mut buf[..pt_len])
        .map_err(|_| ())?;
    let mut out = heapless::Vec::new();
    out.extend_from_slice(&buf[..pt_len]).map_err(|_| ())?;
    out.extend_from_slice(tag.as_slice()).map_err(|_| ())?;
    Ok(out)
}

/// AES-256-GCM decrypt. `ciphertext` must include the 16-byte tag.
pub fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<heapless::Vec<u8, 624>, ()> {
    if ciphertext.len() < 16 { return Err(()); }
    let aes_key = AesKey::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(iv);
    let ct_len = ciphertext.len() - 16;
    if ct_len > 512 { return Err(()); }
    let tag = aes_gcm::aead::generic_array::GenericArray::from_slice(&ciphertext[ct_len..]);
    let mut buf = [0u8; 512];
    buf[..ct_len].copy_from_slice(&ciphertext[..ct_len]);
    cipher.decrypt_in_place_detached(nonce, aad, &mut buf[..ct_len], tag)
        .map_err(|_| ())?;
    let mut out = heapless::Vec::new();
    out.extend_from_slice(&buf[..ct_len]).map_err(|_| ())?;
    Ok(out)
}

/// Generate an AES-256 key using `rng`. Returns 32 bytes.
pub fn gen_aes256_key(rng: &mut impl RngCore) -> [u8; 32] {
    let mut k = [0u8; 32];
    rng.fill_bytes(&mut k);
    k
}

/// Generate an HMAC-SHA256 key using `rng`. Returns 32 bytes.
pub fn gen_hmac_key(rng: &mut impl RngCore) -> [u8; 32] {
    let mut k = [0u8; 32];
    rng.fill_bytes(&mut k);
    k
}

/// Generate a P-256 private key scalar using `rng`. Returns 32 bytes.
pub fn gen_ecc_p256_key(rng: &mut (impl RngCore + CryptoRng)) -> [u8; 32] {
    let sk = SigningKey::random(rng);
    sk.to_bytes().into()
}

/// ECDSA-P256 sign. `private_key` is the 32-byte scalar; `digest` is 32 bytes.
/// Returns (r, s) each 32 bytes.
pub fn ecdsa_sign(private_key: &[u8], digest: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), ()> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let sk = SigningKey::from_bytes(private_key.into()).map_err(|_| ())?;
    let sig: p256::ecdsa::Signature = sk.sign_prehash(digest).map_err(|_| ())?;
    let r: [u8; 32] = sig.r().to_bytes().into();
    let s: [u8; 32] = sig.s().to_bytes().into();
    Ok((r, s))
}

/// ECDSA-P256 verify. Returns true if valid.
pub fn ecdsa_verify(
    private_key: &[u8],
    digest: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<bool, ()> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let sk = SigningKey::from_bytes(private_key.into()).map_err(|_| ())?;
    let vk = VerifyingKey::from(&sk);
    let sig = p256::ecdsa::Signature::from_scalars(
        *p256::FieldBytes::from_slice(r),
        *p256::FieldBytes::from_slice(s),
    ).map_err(|_| ())?;
    Ok(vk.verify_prehash(digest, &sig).is_ok())
}

/// ECDH key agreement. `private_key` = 32B scalar; `peer_pub` = 65B uncompressed.
/// Returns 32-byte shared secret.
pub fn ecdh(private_key: &[u8], peer_pub: &[u8]) -> Result<[u8; 32], ()> {
    // For ECDH on P-256, we use the raw multiplication path via p256 crate
    let sk = p256::SecretKey::from_bytes(private_key.into()).map_err(|_| ())?;
    let pk = PublicKey::from_sec1_bytes(peer_pub).map_err(|_| ())?;
    let shared = p256::elliptic_curve::ecdh::diffie_hellman(
        sk.to_nonzero_scalar(),
        pk.as_affine(),
    );
    let secret_bytes: p256::FieldBytes = shared.raw_secret_bytes().clone();
    let mut out = [0u8; 32];
    out.copy_from_slice(&secret_bytes);
    Ok(out)
}

/// HKDF-SHA256 derive. `base_key` is the IKM; returns `out_len` bytes.
pub fn hkdf_sha256(
    base_key: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out: &mut [u8],
) -> Result<(), ()> {
    let hk = Hkdf::<Sha256>::new(salt, base_key);
    hk.expand(info, out).map_err(|_| ())
}
