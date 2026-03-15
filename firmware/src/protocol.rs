//! USB frame protocol — matches the host-side framing in `scorehsm-host`.
//!
//! Frame format (§2.1 of architecture.md):
//! ```text
//! [MAGIC:2][CMD:1][SEQ:4LE][LEN:2LE][PAYLOAD:LEN][CRC32:4LE]
//! ```
//! MAGIC = 0xAB 0xCD for commands; 0xCD 0xAB would be a corrupted frame.
//! CRC-32/MPEG-2 over bytes [0 .. 9+LEN-1], poly 0x04C11DB7, init 0xFFFFFFFF.

pub const MAGIC: [u8; 2]  = [0xAB, 0xCD];
pub const MAX_PAYLOAD: usize = 512;
pub const FRAME_OVERHEAD: usize = 13; // MAGIC(2)+CMD(1)+SEQ(4)+LEN(2)+CRC32(4)
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

// ── CRC-32/MPEG-2 (TSR-TIG-01, HSM-REQ-050) ────────────────────────────────
//
// Parameters: poly=0x04C11DB7, init=0xFFFFFFFF, RefIn=false, RefOut=false,
// XorOut=0x00000000.  KAT: crc32_mpeg2(&[0x00;4]) == 0x2144_DF1C.

/// CRC-32/MPEG-2: poly=0x04C11DB7, init=0xFFFFFFFF, no reflection.
pub fn crc32_mpeg2(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= (b as u32) << 24;
        for _ in 0..8 {
            if crc & 0x8000_0000 != 0 {
                crc = (crc << 1) ^ 0x04C1_1DB7;
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
    pub seq: u32,
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
    let seq      = u32::from_le_bytes([buf[3], buf[4], buf[5], buf[6]]);
    let len      = u16::from_le_bytes([buf[7], buf[8]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(ParseError::BadLength);
    }
    let total = FRAME_OVERHEAD + len;
    if buf.len() < total {
        return Err(ParseError::TooShort);
    }
    let frame_data = &buf[..total - 4];
    let crc_bytes  = &buf[total - 4..total];
    let expected   = crc32_mpeg2(frame_data);
    let received   = u32::from_le_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
    if expected != received {
        return Err(ParseError::BadCrc);
    }
    let cmd = Cmd::try_from(cmd_byte).map_err(|_| ParseError::UnknownCmd)?;
    Ok(Frame { cmd, seq, payload: &buf[9..9 + len] })
}

/// Serialise a response into `out`. Returns the number of bytes written.
/// Returns None if `payload` is too large or `out` is too small.
pub fn build_response(
    rsp: Rsp,
    seq: u32,
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
    let seq_bytes = seq.to_le_bytes();
    out[3] = seq_bytes[0];
    out[4] = seq_bytes[1];
    out[5] = seq_bytes[2];
    out[6] = seq_bytes[3];
    out[7] = (len & 0xFF) as u8;
    out[8] = ((len >> 8) & 0xFF) as u8;
    out[9..9 + len].copy_from_slice(payload);
    let crc = crc32_mpeg2(&out[..9 + len]);
    out[9 + len]     =  (crc        & 0xFF) as u8;
    out[9 + len + 1] = ((crc >>  8) & 0xFF) as u8;
    out[9 + len + 2] = ((crc >> 16) & 0xFF) as u8;
    out[9 + len + 3] = ((crc >> 24) & 0xFF) as u8;
    Some(total)
}

// ── Tests (host-side, no embassy) ────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_mpeg2_empty() {
        // CRC-32/MPEG-2("") = 0xFFFFFFFF (init value, no data processed)
        assert_eq!(crc32_mpeg2(&[]), 0xFFFF_FFFF);
    }

    #[test]
    fn crc32_mpeg2_known_answer() {
        // KAT from TSR-TIG-01: CRC-32/MPEG-2 of four zero bytes = 0x2144DF1C
        assert_eq!(crc32_mpeg2(&[0x00; 4]), 0x2144_DF1C);
    }

    #[test]
    fn roundtrip_init() {
        // Build a CMD_INIT frame by hand with CRC-32/MPEG-2 and u32 seq
        let mut frame_buf = [0u8; MAX_FRAME];
        let payload: &[u8] = &[];
        let total = FRAME_OVERHEAD + payload.len();
        frame_buf[0] = MAGIC[0];
        frame_buf[1] = MAGIC[1];
        frame_buf[2] = Cmd::Init as u8;
        // SEQ = 0x00000001 (4 bytes LE)
        frame_buf[3] = 0x01;
        frame_buf[4] = 0x00;
        frame_buf[5] = 0x00;
        frame_buf[6] = 0x00;
        // LEN = 0x0000
        frame_buf[7] = 0x00;
        frame_buf[8] = 0x00;
        let crc = crc32_mpeg2(&frame_buf[..9]);
        frame_buf[9]  =  (crc        & 0xFF) as u8;
        frame_buf[10] = ((crc >>  8) & 0xFF) as u8;
        frame_buf[11] = ((crc >> 16) & 0xFF) as u8;
        frame_buf[12] = ((crc >> 24) & 0xFF) as u8;

        let f = parse_frame(&frame_buf[..total]).unwrap();
        assert_eq!(f.cmd, Cmd::Init);
        assert_eq!(f.seq, 0x00000001);
        assert!(f.payload.is_empty());
    }

    #[test]
    fn bad_magic_rejected() {
        // 13 bytes minimum for FRAME_OVERHEAD
        let buf = [0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_frame(&buf), Err(ParseError::BadMagic));
    }

    #[test]
    fn bad_crc_rejected() {
        let mut buf = [0u8; 13];
        buf[0] = 0xAB;
        buf[1] = 0xCD;
        buf[2] = 0x01; // CMD = Init
        // SEQ = 0 (4 bytes), LEN = 0 (2 bytes), CRC = wrong (4 bytes)
        buf[9]  = 0xDE;
        buf[10] = 0xAD;
        buf[11] = 0xBE;
        buf[12] = 0xEF;
        assert_eq!(parse_frame(&buf), Err(ParseError::BadCrc));
    }
}
