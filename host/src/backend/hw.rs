//! Hardware backend — USB CDC transport to STM32L552 Nucleo HSM.
//!
//! Implements `HsmBackend` by serialising each operation into a binary frame,
//! sending it over a USB CDC serial port, waiting for the response frame, and
//! deserialising the result.
//!
//! Frame format (§2.1 of architecture.md):
//! ```text
//! [MAGIC:2][CMD:1][SEQ:1][LEN:2LE][PAYLOAD:LEN][CRC16:2LE]
//! ```
//! MAGIC = 0xAB 0xCD; CRC-16/CCITT poly=0x1021 init=0xFFFF.

use std::sync::Mutex;
use serialport::SerialPort;
use std::time::Duration;

use crate::{
    backend::HsmBackend,
    error::{HsmError, HsmResult},
    types::{AesGcmParams, EcdsaSignature, KeyHandle, KeyType},
};

// ── Protocol constants (must match firmware/src/protocol.rs) ─────────────────

const MAGIC: [u8; 2]     = [0xAB, 0xCD];
const MAX_PAYLOAD: usize  = 512;
const FRAME_OVERHEAD: usize = 8;

#[repr(u8)]
#[allow(dead_code)]
enum Cmd {
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
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq)]
enum Rsp {
    Ok         = 0x80,
    Random     = 0x81,
    Sha256     = 0x82,
    Mac        = 0x83,
    AesCipher  = 0x84,
    AesPlain   = 0x85,
    EcdsaSig   = 0x86,
    EcdsaValid = 0x87,
    KeyHandle  = 0x88,
    ErrUnknownCmd = 0xF0,
    ErrBadFrame   = 0xF1,
    ErrBadKey     = 0xF2,
    ErrCrypto     = 0xF3,
    ErrNotInit    = 0xF4,
    ErrBadParam   = 0xF5,
    ErrRateLimit  = 0xF6,
}

impl TryFrom<u8> for Rsp {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            0x80 => Ok(Rsp::Ok),
            0x81 => Ok(Rsp::Random),
            0x82 => Ok(Rsp::Sha256),
            0x83 => Ok(Rsp::Mac),
            0x84 => Ok(Rsp::AesCipher),
            0x85 => Ok(Rsp::AesPlain),
            0x86 => Ok(Rsp::EcdsaSig),
            0x87 => Ok(Rsp::EcdsaValid),
            0x88 => Ok(Rsp::KeyHandle),
            0xF0 => Ok(Rsp::ErrUnknownCmd),
            0xF1 => Ok(Rsp::ErrBadFrame),
            0xF2 => Ok(Rsp::ErrBadKey),
            0xF3 => Ok(Rsp::ErrCrypto),
            0xF4 => Ok(Rsp::ErrNotInit),
            0xF5 => Ok(Rsp::ErrBadParam),
            0xF6 => Ok(Rsp::ErrRateLimit),
            _ => Err(()),
        }
    }
}

// ── CRC-16/CCITT ─────────────────────────────────────────────────────────────

fn crc16(data: &[u8]) -> u16 {
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

// ── Inner state protected by Mutex ───────────────────────────────────────────

struct Inner {
    port: Option<Box<dyn SerialPort + Send>>,
    seq: u8,
    initialized: bool,
}

impl Inner {
    fn build_frame(&self, cmd: Cmd, payload: &[u8]) -> HsmResult<Vec<u8>> {
        if payload.len() > MAX_PAYLOAD {
            return Err(HsmError::InvalidParam("payload too large".into()));
        }
        let len = payload.len();
        let total = FRAME_OVERHEAD + len;
        let mut frame = vec![0u8; total];
        frame[0] = MAGIC[0];
        frame[1] = MAGIC[1];
        frame[2] = cmd as u8;
        frame[3] = self.seq;
        frame[4] = (len & 0xFF) as u8;
        frame[5] = ((len >> 8) & 0xFF) as u8;
        frame[6..6 + len].copy_from_slice(payload);
        let crc = crc16(&frame[..6 + len]);
        frame[6 + len]     = (crc & 0xFF) as u8;
        frame[6 + len + 1] = ((crc >> 8) & 0xFF) as u8;
        Ok(frame)
    }

    fn send_recv(&mut self, cmd: Cmd, payload: &[u8]) -> HsmResult<(Rsp, Vec<u8>)> {
        let frame = self.build_frame(cmd, payload)?;
        let port = self.port.as_mut().ok_or_else(|| HsmError::UsbError("not open".into()))?;

        // Write frame
        use std::io::Write;
        port.write_all(&frame)
            .map_err(|e| HsmError::UsbError(e.to_string()))?;

        // Read response header
        let mut hdr = [0u8; FRAME_OVERHEAD];
        read_exact(port, &mut hdr)?;

        if hdr[0] != MAGIC[0] || hdr[1] != MAGIC[1] {
            return Err(HsmError::UsbError("bad response magic".into()));
        }
        let rsp_len = u16::from_le_bytes([hdr[4], hdr[5]]) as usize;
        if rsp_len > MAX_PAYLOAD {
            return Err(HsmError::UsbError("response payload too large".into()));
        }

        // Read payload + CRC
        let mut rest = vec![0u8; rsp_len + 2];
        read_exact(port, &mut rest)?;

        // Verify CRC over header + payload
        let mut full = hdr.to_vec();
        full.extend_from_slice(&rest[..rsp_len]);
        let expected = crc16(&full);
        let received = u16::from_le_bytes([rest[rsp_len], rest[rsp_len + 1]]);
        if expected != received {
            return Err(HsmError::UsbError(format!(
                "CRC mismatch: expected {:#06x} got {:#06x}", expected, received
            )));
        }

        // Check sequence echo
        if hdr[3] != self.seq {
            return Err(HsmError::UsbError(format!(
                "seq mismatch: expected {} got {}", self.seq, hdr[3]
            )));
        }
        self.seq = self.seq.wrapping_add(1);

        let rsp = Rsp::try_from(hdr[2])
            .map_err(|_| HsmError::UsbError(format!("unknown response opcode {:#04x}", hdr[2])))?;
        let rsp_payload = rest[..rsp_len].to_vec();

        // Map error responses
        match rsp {
            Rsp::ErrBadKey    => Err(HsmError::InvalidKeyHandle),
            Rsp::ErrNotInit   => Err(HsmError::NotInitialized),
            Rsp::ErrBadParam  => Err(HsmError::InvalidParam("bad parameter".into())),
            Rsp::ErrCrypto    => Err(HsmError::CryptoFail("firmware crypto error".into())),
            Rsp::ErrBadFrame  => Err(HsmError::UsbError("firmware rejected frame".into())),
            Rsp::ErrRateLimit => Err(HsmError::UsbError("firmware rate limited".into())),
            Rsp::ErrUnknownCmd => Err(HsmError::Unsupported),
            _ => Ok((rsp, rsp_payload)),
        }
    }
}

fn read_exact(port: &mut Box<dyn SerialPort + Send>, buf: &mut [u8]) -> HsmResult<()> {
    use std::io::Read;
    let mut pos = 0;
    while pos < buf.len() {
        let n = port.read(&mut buf[pos..])
            .map_err(|e| HsmError::UsbError(e.to_string()))?;
        if n == 0 {
            return Err(HsmError::UsbError("serial port closed".into()));
        }
        pos += n;
    }
    Ok(())
}

// ── Hardware backend (public) ─────────────────────────────────────────────────

/// USB CDC hardware backend — routes every `HsmBackend` call through the
/// binary frame protocol to the STM32L552 Nucleo HSM.
pub struct HardwareBackend {
    inner: Mutex<Inner>,
    port_path: String,
}

impl HardwareBackend {
    /// Create a new hardware backend.
    ///
    /// `port_path`: serial port to open (e.g. `/dev/ttyACM0`, `COM3`).
    pub fn new(port_path: impl Into<String>) -> Self {
        Self {
            inner: Mutex::new(Inner { port: None, seq: 0, initialized: false }),
            port_path: port_path.into(),
        }
    }

    fn lock(&self) -> HsmResult<std::sync::MutexGuard<'_, Inner>> {
        self.inner.lock().map_err(|_| HsmError::UsbError("mutex poisoned".into()))
    }
}

// ── HsmBackend implementation ─────────────────────────────────────────────────

impl HsmBackend for HardwareBackend {
    fn init(&mut self) -> HsmResult<()> {
        let mut g = self.lock()?;
        let port = serialport::new(&self.port_path, 115_200)
            .timeout(Duration::from_secs(5))
            .open_native()
            .map_err(|e| HsmError::UsbError(e.to_string()))?;
        g.port = Some(Box::new(port));
        g.seq  = 0x00;
        let (rsp, _) = g.send_recv(Cmd::Init, &[])?;
        if rsp != Rsp::Ok {
            return Err(HsmError::UsbError("init failed".into()));
        }
        g.initialized = true;
        Ok(())
    }

    fn deinit(&mut self) -> HsmResult<()> {
        let mut g = self.lock()?;
        g.port = None;
        g.initialized = false;
        g.seq = 0x00;
        Ok(())
    }

    fn random(&mut self, out: &mut [u8]) -> HsmResult<()> {
        let len = out.len();
        if len > MAX_PAYLOAD - 2 {
            return Err(HsmError::InvalidParam("random length too large".into()));
        }
        let payload = [(len & 0xFF) as u8, ((len >> 8) & 0xFF) as u8];
        let mut g = self.lock()?;
        let (_, data) = g.send_recv(Cmd::Random, &payload)?;
        if data.len() != len {
            return Err(HsmError::UsbError("wrong random length in response".into()));
        }
        out.copy_from_slice(&data);
        Ok(())
    }

    fn sha256(&self, data: &[u8]) -> HsmResult<[u8; 32]> {
        if data.len() > MAX_PAYLOAD {
            return Err(HsmError::InvalidParam("data too large".into()));
        }
        let (_, digest) = self.lock()?.send_recv(Cmd::Sha256, data)?;
        digest.try_into().map_err(|_| HsmError::UsbError("bad sha256 response length".into()))
    }

    fn hmac_sha256(&self, handle: KeyHandle, data: &[u8]) -> HsmResult<[u8; 32]> {
        let mut payload = Vec::with_capacity(4 + data.len());
        payload.extend_from_slice(&handle.0.to_le_bytes());
        payload.extend_from_slice(data);
        let (_, mac) = self.lock()?.send_recv(Cmd::HmacSha256, &payload)?;
        mac.try_into().map_err(|_| HsmError::UsbError("bad hmac response length".into()))
    }

    fn aes_gcm_encrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams,
        plaintext: &[u8],
    ) -> HsmResult<(Vec<u8>, [u8; 16])> {
        let aad_len = params.aad.len() as u16;
        let mut payload = Vec::new();
        payload.extend_from_slice(&handle.0.to_le_bytes());
        payload.extend_from_slice(params.iv);
        payload.extend_from_slice(&aad_len.to_le_bytes());
        payload.extend_from_slice(params.aad);
        payload.extend_from_slice(plaintext);
        let (_, ct_tag) = self.lock()?.send_recv(Cmd::AesGcmEnc, &payload)?;
        if ct_tag.len() < 16 {
            return Err(HsmError::UsbError("response too short for ciphertext+tag".into()));
        }
        let (ct, tag_slice) = ct_tag.split_at(ct_tag.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_slice);
        Ok((ct.to_vec(), tag))
    }

    fn aes_gcm_decrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams,
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> HsmResult<Vec<u8>> {
        let aad_len = params.aad.len() as u16;
        let mut payload = Vec::new();
        payload.extend_from_slice(&handle.0.to_le_bytes());
        payload.extend_from_slice(params.iv);
        payload.extend_from_slice(&aad_len.to_le_bytes());
        payload.extend_from_slice(params.aad);
        payload.extend_from_slice(ciphertext);
        payload.extend_from_slice(tag);
        let (_, pt) = self.lock()?.send_recv(Cmd::AesGcmDec, &payload)?;
        Ok(pt)
    }

    fn ecdsa_sign(&self, handle: KeyHandle, digest: &[u8; 32]) -> HsmResult<EcdsaSignature> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&handle.0.to_le_bytes());
        payload.extend_from_slice(digest);
        let (_, rs) = self.lock()?.send_recv(Cmd::EcdsaSign, &payload)?;
        if rs.len() != 64 {
            return Err(HsmError::UsbError("bad ecdsa sign response".into()));
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&rs[..32]);
        s.copy_from_slice(&rs[32..64]);
        Ok(EcdsaSignature { r, s })
    }

    fn ecdsa_verify(
        &self,
        handle: KeyHandle,
        digest: &[u8; 32],
        signature: &EcdsaSignature,
    ) -> HsmResult<bool> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&handle.0.to_le_bytes());
        payload.extend_from_slice(digest);
        payload.extend_from_slice(&signature.r);
        payload.extend_from_slice(&signature.s);
        let (_, valid_byte) = self.lock()?.send_recv(Cmd::EcdsaVerify, &payload)?;
        Ok(valid_byte.first().copied().unwrap_or(0) != 0)
    }

    fn key_generate(&mut self, key_type: KeyType) -> HsmResult<KeyHandle> {
        let kt_byte: u8 = match key_type {
            KeyType::Aes256     => 0x01,
            KeyType::HmacSha256 => 0x02,
            KeyType::EccP256    => 0x03,
        };
        let (_, data) = self.lock()?.send_recv(Cmd::KeyGenerate, &[kt_byte])?;
        if data.len() < 4 {
            return Err(HsmError::UsbError("bad key generate response".into()));
        }
        Ok(KeyHandle(u32::from_le_bytes([data[0], data[1], data[2], data[3]])))
    }

    fn key_delete(&mut self, handle: KeyHandle) -> HsmResult<()> {
        self.lock()?.send_recv(Cmd::KeyDelete, &handle.0.to_le_bytes())?;
        Ok(())
    }

    fn key_import(&mut self, _key_type: KeyType, _wrapped: &[u8]) -> HsmResult<KeyHandle> {
        Err(HsmError::Unsupported)
    }

    fn key_derive(
        &mut self,
        base: KeyHandle,
        info: &[u8],
        out_type: KeyType,
    ) -> HsmResult<KeyHandle> {
        let out_type_byte: u8 = match out_type {
            KeyType::Aes256     => 0x01,
            KeyType::HmacSha256 => 0x02,
            KeyType::EccP256    => 0x03,
        };
        let info_len = info.len() as u16;
        let mut payload = Vec::new();
        payload.extend_from_slice(&base.0.to_le_bytes());
        payload.push(out_type_byte);
        payload.push(32u8); // derived key length in bytes
        payload.extend_from_slice(&info_len.to_le_bytes());
        payload.extend_from_slice(info);
        let (_, data) = self.lock()?.send_recv(Cmd::KeyDerive, &payload)?;
        if data.len() < 4 {
            return Err(HsmError::UsbError("bad key derive response".into()));
        }
        Ok(KeyHandle(u32::from_le_bytes([data[0], data[1], data[2], data[3]])))
    }

    fn ecdh_agree(&self, _handle: KeyHandle, _peer_pub: &[u8; 64]) -> HsmResult<[u8; 32]> {
        // ECDH veneer not yet wired in dispatcher — planned for TZ integration
        Err(HsmError::Unsupported)
    }
}
