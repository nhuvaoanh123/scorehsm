//! USB frame protocol — matches the host-side framing in `scorehsm-host`.
//!
//! Frame format (§2.1 of architecture.md):
//! ```text
//! [MAGIC:2][CMD:1][SEQ:1][LEN:2LE][PAYLOAD:LEN][CRC16:2LE]
//! ```
//! MAGIC = 0xAB 0xCD for commands; 0xCD 0xAB would be a corrupted frame.
//! CRC-16/CCITT over bytes [0 .. 6+LEN-1], poly 0x1021, init 0xFFFF.

use heapless::Vec;

pub const MAGIC: [u8; 2]  = [0xAB, 0xCD];
pub const MAX_PAYLOAD: usize = 512;
pub const FRAME_OVERHEAD: usize = 8; // MAGIC(2)+CMD(1)+SEQ(1)+LEN(2)+CRC(2)
pub const MAX_FRAME: usize = FRAME_OVERHEAD + MAX_PAYLOAD;

// ── Opcodes ──────────────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    Init        = 0x01,
    Random      = 0x02,
    Sha256      = 0x03,
    HmacSha256  = 0x04,
    AesGcmEnc   = 0x05,
    AesGcmDec   = 0x06,
    EcdsaSign   = 0x07,
    EcdsaVerify = 0x08,
    KeyGenerate = 0x09,
    KeyDelete   = 0x0A,
    KeyDerive   = 0x0B,
    KeyImport   = 0x0C,
    Capability  = 0x0D,
}

impl TryFrom<u8> for Cmd {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            0x01 => Ok(Cmd::Init),
            0x02 => Ok(Cmd::Random),
            0x03 => Ok(Cmd::Sha256),
            0x04 => Ok(Cmd::HmacSha256),
            0x05 => Ok(Cmd::AesGcmEnc),
            0x06 => Ok(Cmd::AesGcmDec),
            0x07 => Ok(Cmd::EcdsaSign),
            0x08 => Ok(Cmd::EcdsaVerify),
            0x09 => Ok(Cmd::KeyGenerate),
            0x0A => Ok(Cmd::KeyDelete),
            0x0B => Ok(Cmd::KeyDerive),
            0x0C => Ok(Cmd::KeyImport),
            0x0D => Ok(Cmd::Capability),
            _ => Err(()),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rsp {
    Ok          = 0x80,
    Random      = 0x81,
    Sha256      = 0x82,
    Mac         = 0x83,
    AesCipher   = 0x84,
    AesPlain    = 0x85,
    EcdsaSig    = 0x86,
    EcdsaValid  = 0x87,
    KeyHandle   = 0x88,
    EcdhSecret  = 0x89,
    Capability  = 0x8A,
    ErrUnknownCmd  = 0xF0,
    ErrBadFrame    = 0xF1,
    ErrBadKey      = 0xF2,
    ErrCrypto      = 0xF3,
    ErrNotInit     = 0xF4,
    ErrBadParam    = 0xF5,
    ErrRateLimit   = 0xF6,
}

// ── CRC-16/CCITT ─────────────────────────────────────────────────────────────

/// CRC-16/CCITT: poly=0x1021, init=0xFFFF, no reflection.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ── Frame ─────────────────────────────────────────────────────────────────────

pub struct Frame<'a> {
    pub cmd: Cmd,
    pub seq: u8,
    pub payload: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    BadMagic,
    BadLength,
    BadCrc,
    UnknownCmd,
}

/// Parse a raw frame from `buf`. Returns the frame and the number of bytes consumed.
pub fn parse_frame(buf: &[u8]) -> Result<Frame<'_>, ParseError> {
    if buf.len() < FRAME_OVERHEAD {
        return Err(ParseError::TooShort);
    }
    if buf[0] != MAGIC[0] || buf[1] != MAGIC[1] {
        return Err(ParseError::BadMagic);
    }
    let cmd_byte = buf[2];
    let seq      = buf[3];
    let len      = u16::from_le_bytes([buf[4], buf[5]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(ParseError::BadLength);
    }
    let total = FRAME_OVERHEAD + len;
    if buf.len() < total {
        return Err(ParseError::TooShort);
    }
    let frame_data = &buf[..total - 2];
    let crc_bytes  = &buf[total - 2..total];
    let expected   = crc16(frame_data);
    let received   = u16::from_le_bytes([crc_bytes[0], crc_bytes[1]]);
    if expected != received {
        return Err(ParseError::BadCrc);
    }
    let cmd = Cmd::try_from(cmd_byte).map_err(|_| ParseError::UnknownCmd)?;
    Ok(Frame { cmd, seq, payload: &buf[6..6 + len] })
}

/// Serialise a response into `out`. Returns the number of bytes written.
/// Returns None if `payload` is too large or `out` is too small.
pub fn build_response(
    rsp: Rsp,
    seq: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let len = payload.len();
    if len > MAX_PAYLOAD {
        return None;
    }
    let total = FRAME_OVERHEAD + len;
    if out.len() < total {
        return None;
    }
    out[0] = MAGIC[0];
    out[1] = MAGIC[1];
    out[2] = rsp as u8;
    out[3] = seq;
    out[4] = (len & 0xFF) as u8;
    out[5] = ((len >> 8) & 0xFF) as u8;
    out[6..6 + len].copy_from_slice(payload);
    let crc = crc16(&out[..6 + len]);
    out[6 + len]     = (crc & 0xFF) as u8;
    out[6 + len + 1] = ((crc >> 8) & 0xFF) as u8;
    Some(total)
}

// ── Tests (host-side, no embassy) ────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_empty() {
        // CRC-16/CCITT("") = 0xFFFF
        assert_eq!(crc16(&[]), 0xFFFF);
    }

    #[test]
    fn crc16_known() {
        // CRC-16/CCITT("123456789") = 0x29B1
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn roundtrip_init() {
        // Build a CMD_INIT frame by hand
        let mut frame_buf = [0u8; MAX_FRAME];
        let payload: &[u8] = &[];
        let total = FRAME_OVERHEAD + payload.len();
        frame_buf[0] = MAGIC[0];
        frame_buf[1] = MAGIC[1];
        frame_buf[2] = Cmd::Init as u8;
        frame_buf[3] = 0x01; // seq
        frame_buf[4] = 0x00; // len lo
        frame_buf[5] = 0x00; // len hi
        let crc = crc16(&frame_buf[..6]);
        frame_buf[6] = (crc & 0xFF) as u8;
        frame_buf[7] = ((crc >> 8) & 0xFF) as u8;

        let f = parse_frame(&frame_buf[..total]).unwrap();
        assert_eq!(f.cmd, Cmd::Init);
        assert_eq!(f.seq, 0x01);
        assert!(f.payload.is_empty());
    }

    #[test]
    fn bad_magic_rejected() {
        let buf = [0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF];
        assert_eq!(parse_frame(&buf), Err(ParseError::BadMagic));
    }

    #[test]
    fn bad_crc_rejected() {
        let mut buf = [0xAB, 0xCD, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        buf[6] = 0xDE; buf[7] = 0xAD; // wrong CRC
        assert_eq!(parse_frame(&buf), Err(ParseError::BadCrc));
    }
}
