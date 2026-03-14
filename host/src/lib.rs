//! scorehsm-host — HSM host library
//!
//! Provides a unified crypto API with two backends:
//! - Software fallback: rustcrypto — runs anywhere, no hardware needed (CI)
//! - Hardware backend: USB CDC to STM32L552 Nucleo — real key isolation
//!
//! Key material never leaves the HSM. All operations use opaque key handles.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod backend;
pub mod error;
pub mod types;

pub mod ids;
pub mod session;

pub mod update;
pub mod onboard_comm;
pub mod feature_activation;

#[cfg(feature = "certs")]
pub mod cert;

#[cfg(feature = "pqc")]
pub mod pqc;

#[cfg(test)]
mod sha2_sanity {
    /// Inline reference SHA-256 — no sha2 dep, proves whether the test env is broken
    fn sha256_ref(msg: &[u8]) -> [u8; 32] {
        const K: [u32; 64] = [
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
        ];
        let mut h = [0x6a09e667u32,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
        // Pad: message || 0x80 || zeros || bit_length_big_endian_64
        let bit_len = (msg.len() as u64).wrapping_mul(8);
        let pad_len = if msg.len() % 64 < 56 { 56 - msg.len() % 64 } else { 120 - msg.len() % 64 };
        let mut padded = msg.to_vec();
        padded.push(0x80);
        padded.resize(padded.len() + pad_len - 1, 0u8);
        padded.extend_from_slice(&bit_len.to_be_bytes());
        for block in padded.chunks(64) {
            let mut w = [0u32; 64];
            for i in 0..16 { w[i] = u32::from_be_bytes(block[4*i..][..4].try_into().unwrap()); }
            for i in 16..64 {
                let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
                let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
                w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
            }
            let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut hh] = h;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh=g; g=f; f=e; e=d.wrapping_add(t1); d=c; c=b; b=a; a=t1.wrapping_add(t2);
            }
            let [h0,h1,h2,h3,h4,h5,h6,h7] = h;
            h = [h0.wrapping_add(a),h1.wrapping_add(b),h2.wrapping_add(c),h3.wrapping_add(d),
                 h4.wrapping_add(e),h5.wrapping_add(f),h6.wrapping_add(g),h7.wrapping_add(hh)];
        }
        let mut out = [0u8; 32];
        for (i, &w) in h.iter().enumerate() { out[i*4..][..4].copy_from_slice(&w.to_be_bytes()); }
        out
    }

    #[test]
    fn sha256_known_vectors() {
        // Verify with multiple NIST test vectors to pinpoint if "abc" expected or impl is wrong
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let empty = sha256_ref(b"");
        eprintln!("SHA-256(\"\")   = {:02x?}", empty);
        let empty_expected = [
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55u8,
        ];
        assert_eq!(empty, empty_expected, "SHA-256 of empty string wrong");

        // SHA-256("The quick brown fox jumps over the lazy dog")
        // = d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
        let fox = sha256_ref(b"The quick brown fox jumps over the lazy dog");
        eprintln!("SHA-256(fox)  = {:02x?}", fox);
        let fox_expected = [
            0xd7,0xa8,0xfb,0xb3,0x07,0xd7,0x80,0x94,0x69,0xca,0x9a,0xbc,0xb0,0x08,0x2e,0x4f,
            0x8d,0x56,0x51,0xe4,0x6d,0x3c,0xdb,0x76,0x2d,0x02,0xd0,0xbf,0x37,0xc9,0xe5,0x92u8,
        ];
        assert_eq!(fox, fox_expected, "SHA-256 of fox string wrong");

        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        // Verified: OpenSSL, .NET SHA256, sha2 Rust crate all agree on this value
        let abc = sha256_ref(b"abc");
        eprintln!("SHA-256(abc)  = {:02x?}", abc);
        let abc_expected = [
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
            0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
            0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xadu8,
        ];
        assert_eq!(abc, abc_expected, "SHA-256(abc) wrong");
    }

    #[test]
    fn sha256_via_sha2_crate() {
        use sha2::{Digest, Sha256};
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(b"abc"));
        eprintln!("sha2 abc: {:02x?}", out);
        let ref_out = sha256_ref(b"abc");
        assert_eq!(out, ref_out, "sha2 crate differs from inline ref impl");
    }

    #[test]
    fn arithmetic_sanity() {
        // Verify u32 rotate_right works — this is the key primitive in SHA-256
        let x: u32 = 0x510e527f;
        let rotr6 = x.rotate_right(6);
        let rotr11 = x.rotate_right(11);
        let rotr25 = x.rotate_right(25);
        eprintln!("ROTR(0x510e527f, 6)  = {:#010x}", rotr6);
        eprintln!("ROTR(0x510e527f, 11) = {:#010x}", rotr11);
        eprintln!("ROTR(0x510e527f, 25) = {:#010x}", rotr25);
        eprintln!("XOR: {:#010x}", rotr6 ^ rotr11 ^ rotr25);
        // 0x510e527f in binary: bits [31:0] rotated right 6 = (0x510e527f >> 6) | (0x510e527f << 26)
        let manual_rotr6 = (x >> 6) | (x << 26);
        assert_eq!(rotr6, manual_rotr6, "rotate_right(6) != manual shift");
        // wrapping_add sanity
        let a: u32 = 0xffff_ffff;
        let b: u32 = 1;
        assert_eq!(a.wrapping_add(b), 0, "wrapping_add overflow broken");
    }
}
