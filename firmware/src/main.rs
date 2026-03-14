//! scorehsm-firmware — HSM firmware for STM32L552 Nucleo
//!
//! Architecture: Embassy async, USB CDC, rustcrypto software backend.
//! TrustZone partitioning is prepared (see `trustzone.rs`) and will be
//! activated in a subsequent iteration when HIL testing confirms baseline.
//!
//! USB CDC task: receives frames from the host (Pi), dispatches crypto
//! operations, and sends responses back over the same CDC interface.

#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::{
    bind_interrupts,
    peripherals,
    rng::{self, Rng},
    usb_otg::{self, Driver as UsbDriver, Instance},
};
use embassy_usb::{
    class::cdc_acm::{CdcAcmClass, State},
    Builder, UsbDevice,
};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
use embassy_futures::join::join;
use heapless::Vec;
use rand_core::RngCore;
use {defmt_rtt as _, panic_probe as _};

mod crypto;
mod keystore;
mod protocol;
mod trustzone;

use keystore::{KeyStore, KeyHandle, KeyType};
use protocol::{Cmd, Rsp, Frame, ParseError, FRAME_OVERHEAD, MAX_FRAME, MAX_PAYLOAD};

// ── Embassy interrupt bindings ────────────────────────────────────────────────

bind_interrupts!(struct Irqs {
    OTG_FS => usb_otg::InterruptHandler<peripherals::USB_OTG_FS>;
    RNG    => rng::InterruptHandler<peripherals::RNG>;
});

// ── Key store (static, in SRAM2 ideally — linker section) ────────────────────

static mut KEY_STORE: KeyStore = KeyStore::new();

// ── RNG wrapper (Embassy hardware RNG) ───────────────────────────────────────

struct HwRng<'d>(Rng<'d, peripherals::RNG>);

impl RngCore for HwRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.0.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.0.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for HwRng<'_> {}

// ── USB buffer allocations ────────────────────────────────────────────────────

const USB_EP_BUF_SIZE: usize = 256;

// ── Main entry ────────────────────────────────────────────────────────────────

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_stm32::init(Default::default());

    info!("scorehsm-firmware booting");

    // Initialise hardware RNG
    let rng = Rng::new(p.RNG, Irqs);

    // USB OTG FS
    let mut ep_out_buffer = [0u8; USB_EP_BUF_SIZE];
    let mut config = usb_otg::Config::default();
    config.vbus_detection = true;
    let driver = UsbDriver::new_fs(
        p.USB_OTG_FS, Irqs, p.PA12, p.PA11,
        &mut ep_out_buffer, config,
    );

    // Build USB device with CDC-ACM
    let mut usb_config = embassy_usb::Config::new(0xF055, 0x4853); // "VID=F0SS" "PID=HSM"
    usb_config.manufacturer = Some("Taktflow-Systems");
    usb_config.product      = Some("scoreHSM");
    usb_config.serial_number = Some("0001");
    usb_config.max_power      = 100; // mA
    usb_config.max_packet_size_0 = 64;

    let mut device_descriptor = [0u8; 256];
    let mut config_descriptor  = [0u8; 256];
    let mut bos_descriptor     = [0u8; 256];
    let mut msos_descriptor    = [0u8; 256];
    let mut control_buf        = [0u8; 64];
    let mut state = State::new();

    let mut builder = Builder::new(
        driver,
        usb_config,
        &mut device_descriptor,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut msos_descriptor,
        &mut control_buf,
    );

    let class = CdcAcmClass::new(&mut builder, &mut state, 64);
    let usb = builder.build();

    info!("USB CDC ready");

    join(usb_run(usb), hsm_run(class, rng)).await;
}

// ── USB device driver task ────────────────────────────────────────────────────

async fn usb_run<D: embassy_usb::driver::Driver<'static>>(
    mut usb: UsbDevice<'static, D>,
) -> ! {
    usb.run().await
}

// ── HSM dispatcher task ───────────────────────────────────────────────────────

async fn hsm_run<'d, D: embassy_usb::driver::Driver<'d>>(
    mut class: CdcAcmClass<'d, D>,
    mut hw_rng: Rng<'d, peripherals::RNG>,
) -> ! {
    let mut rx_buf = [0u8; MAX_FRAME];
    let mut tx_buf = [0u8; MAX_FRAME];
    let mut rx_pos: usize = 0;
    let mut initialized = false;
    let mut expected_seq: u8 = 0x00;

    loop {
        // Wait for DTR (host connected)
        class.wait_connection().await;
        info!("Host connected");
        rx_pos = 0;
        initialized = false;
        expected_seq = 0x00;

        'connection: loop {
            // Read bytes into receive buffer
            let n = match class.read_packet(&mut rx_buf[rx_pos..]).await {
                Ok(n) => n,
                Err(_) => break 'connection,
            };
            rx_pos += n;

            // Try to parse a complete frame
            let parse_result = protocol::parse_frame(&rx_buf[..rx_pos]);
            match parse_result {
                Err(ParseError::TooShort) => continue, // need more data
                Err(e) => {
                    warn!("Frame error: {:?}", e);
                    let rsp_code = match e {
                        ParseError::BadMagic | ParseError::BadCrc | ParseError::BadLength => Rsp::ErrBadFrame,
                        ParseError::UnknownCmd => Rsp::ErrUnknownCmd,
                        ParseError::TooShort => unreachable!(),
                    };
                    let n = protocol::build_response(rsp_code, 0x00, &[], &mut tx_buf)
                        .unwrap_or(0);
                    let _ = class.write_packet(&tx_buf[..n]).await;
                    rx_pos = 0;
                    continue;
                }
                Ok(frame) => {
                    let consumed = FRAME_OVERHEAD + frame.payload.len();
                    let cmd = frame.cmd;
                    let seq = frame.seq;

                    // Sequence number check (skip for CMD_INIT)
                    if cmd != Cmd::Init {
                        if seq != expected_seq {
                            warn!("Bad seq: got {} expected {}", seq, expected_seq);
                            let n = protocol::build_response(Rsp::ErrBadFrame, seq, &[], &mut tx_buf)
                                .unwrap_or(0);
                            let _ = class.write_packet(&tx_buf[..n]).await;
                            rx_pos = 0;
                            continue;
                        }
                        if !initialized && cmd != Cmd::Capability {
                            let n = protocol::build_response(Rsp::ErrNotInit, seq, &[], &mut tx_buf)
                                .unwrap_or(0);
                            let _ = class.write_packet(&tx_buf[..n]).await;
                            rx_pos = 0;
                            continue;
                        }
                    }

                    // Copy payload out so we can mutably borrow tx_buf
                    let mut payload_buf = [0u8; MAX_PAYLOAD];
                    let plen = frame.payload.len().min(MAX_PAYLOAD);
                    payload_buf[..plen].copy_from_slice(&frame.payload[..plen]);
                    let payload = &payload_buf[..plen];

                    // Consume bytes from rx_buf
                    rx_buf.copy_within(consumed..rx_pos, 0);
                    rx_pos -= consumed;

                    // Dispatch
                    let (rsp, rsp_payload) = dispatch(
                        cmd, seq, payload,
                        &mut initialized, &mut expected_seq,
                        &mut hw_rng,
                    );

                    let n = protocol::build_response(rsp, seq, &rsp_payload, &mut tx_buf)
                        .unwrap_or(0);
                    if let Err(_) = class.write_packet(&tx_buf[..n]).await {
                        break 'connection;
                    }

                    expected_seq = expected_seq.wrapping_add(1);
                }
            }
        }

        info!("Host disconnected");
    }
}

// ── Command dispatcher ────────────────────────────────────────────────────────

fn dispatch(
    cmd: Cmd,
    _seq: u8,
    payload: &[u8],
    initialized: &mut bool,
    expected_seq: &mut u8,
    rng: &mut Rng<'_, peripherals::RNG>,
) -> (Rsp, heapless::Vec<u8, MAX_PAYLOAD>) {
    let mut out: heapless::Vec<u8, MAX_PAYLOAD> = heapless::Vec::new();

    macro_rules! ok {
        () => { return (Rsp::Ok, out) };
    }
    macro_rules! err {
        ($r:expr) => { return ($r, heapless::Vec::new()) };
    }

    // SAFETY: single-threaded, no re-entrant access to KEY_STORE
    let ks = unsafe { &mut KEY_STORE };

    match cmd {
        // ── Init ─────────────────────────────────────────────────────────────
        Cmd::Init => {
            *initialized = true;
            *expected_seq = 0x01; // next expected after Init at seq=0x00
            info!("HSM initialised");
            ok!();
        }

        // ── Capability ───────────────────────────────────────────────────────
        Cmd::Capability => {
            // version=0x01, algos bitmask (AES-GCM|HMAC|ECDSA|ECDH|HKDF|SHA256)
            let cap = [0x01u8, 0b0011_1111];
            out.extend_from_slice(&cap).ok();
            return (Rsp::Capability, out);
        }

        // ── RNG ──────────────────────────────────────────────────────────────
        Cmd::Random => {
            if payload.len() < 2 { err!(Rsp::ErrBadParam); }
            let len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
            if len > MAX_PAYLOAD { err!(Rsp::ErrBadParam); }
            out.resize(len, 0).ok();
            rng.fill_bytes(&mut out);
            return (Rsp::Random, out);
        }

        // ── SHA-256 ──────────────────────────────────────────────────────────
        Cmd::Sha256 => {
            let digest = crypto::sha256(payload);
            out.extend_from_slice(&digest).ok();
            return (Rsp::Sha256, out);
        }

        // ── HMAC-SHA256 ──────────────────────────────────────────────────────
        Cmd::HmacSha256 => {
            if payload.len() < 4 { err!(Rsp::ErrBadParam); }
            let handle = KeyHandle(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
            let data = &payload[4..];
            match ks.borrow(handle, KeyType::HmacSha256) {
                None => err!(Rsp::ErrBadKey),
                Some(key) => {
                    match crypto::hmac_sha256(key, data) {
                        Err(_) => err!(Rsp::ErrCrypto),
                        Ok(mac) => {
                            out.extend_from_slice(&mac).ok();
                            return (Rsp::Mac, out);
                        }
                    }
                }
            }
        }

        // ── AES-GCM encrypt ──────────────────────────────────────────────────
        Cmd::AesGcmEnc => {
            // Payload: [handle:4][iv:12][aad_len:2][aad...][pt...]
            if payload.len() < 4 + 12 + 2 { err!(Rsp::ErrBadParam); }
            let handle = KeyHandle(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
            let iv: &[u8; 12] = payload[4..16].try_into().unwrap();
            let aad_len = u16::from_le_bytes([payload[16], payload[17]]) as usize;
            if payload.len() < 18 + aad_len { err!(Rsp::ErrBadParam); }
            let aad = &payload[18..18 + aad_len];
            let pt  = &payload[18 + aad_len..];
            match ks.borrow(handle, KeyType::Aes256) {
                None => err!(Rsp::ErrBadKey),
                Some(key) => {
                    match crypto::aes_gcm_encrypt(key, iv, aad, pt) {
                        Err(_) => err!(Rsp::ErrCrypto),
                        Ok(ct) => {
                            out.extend_from_slice(&ct).ok();
                            return (Rsp::AesCipher, out);
                        }
                    }
                }
            }
        }

        // ── AES-GCM decrypt ──────────────────────────────────────────────────
        Cmd::AesGcmDec => {
            if payload.len() < 4 + 12 + 2 { err!(Rsp::ErrBadParam); }
            let handle = KeyHandle(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
            let iv: &[u8; 12] = payload[4..16].try_into().unwrap();
            let aad_len = u16::from_le_bytes([payload[16], payload[17]]) as usize;
            if payload.len() < 18 + aad_len { err!(Rsp::ErrBadParam); }
            let aad = &payload[18..18 + aad_len];
            let ct  = &payload[18 + aad_len..];
            match ks.borrow(handle, KeyType::Aes256) {
                None => err!(Rsp::ErrBadKey),
                Some(key) => {
                    match crypto::aes_gcm_decrypt(key, iv, aad, ct) {
                        Err(_) => err!(Rsp::ErrCrypto),
                        Ok(pt) => {
                            out.extend_from_slice(&pt).ok();
                            return (Rsp::AesPlain, out);
                        }
                    }
                }
            }
        }

        // ── ECDSA sign ───────────────────────────────────────────────────────
        Cmd::EcdsaSign => {
            // Payload: [handle:4][digest:32]
            if payload.len() < 4 + 32 { err!(Rsp::ErrBadParam); }
            let handle = KeyHandle(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
            let digest: &[u8; 32] = payload[4..36].try_into().unwrap();
            match ks.borrow(handle, KeyType::EccP256) {
                None => err!(Rsp::ErrBadKey),
                Some(key) => {
                    let key_bytes: [u8; 32] = key.try_into().unwrap_or([0u8; 32]);
                    match crypto::ecdsa_sign(&key_bytes, digest) {
                        Err(_) => err!(Rsp::ErrCrypto),
                        Ok((r, s)) => {
                            out.extend_from_slice(&r).ok();
                            out.extend_from_slice(&s).ok();
                            return (Rsp::EcdsaSig, out);
                        }
                    }
                }
            }
        }

        // ── ECDSA verify ─────────────────────────────────────────────────────
        Cmd::EcdsaVerify => {
            // Payload: [handle:4][digest:32][r:32][s:32]
            if payload.len() < 4 + 32 + 32 + 32 { err!(Rsp::ErrBadParam); }
            let handle = KeyHandle(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
            let digest: &[u8; 32] = payload[4..36].try_into().unwrap();
            let r:      &[u8; 32] = payload[36..68].try_into().unwrap();
            let s:      &[u8; 32] = payload[68..100].try_into().unwrap();
            match ks.borrow(handle, KeyType::EccP256) {
                None => err!(Rsp::ErrBadKey),
                Some(key) => {
                    let key_bytes: [u8; 32] = key.try_into().unwrap_or([0u8; 32]);
                    match crypto::ecdsa_verify(&key_bytes, digest, r, s) {
                        Err(_) => err!(Rsp::ErrCrypto),
                        Ok(valid) => {
                            out.push(valid as u8).ok();
                            return (Rsp::EcdsaValid, out);
                        }
                    }
                }
            }
        }

        // ── Key generate ─────────────────────────────────────────────────────
        Cmd::KeyGenerate => {
            // Payload: [key_type:1]
            if payload.is_empty() { err!(Rsp::ErrBadParam); }
            let kt = match KeyType::try_from(payload[0]) {
                Ok(t) => t,
                Err(_) => err!(Rsp::ErrBadParam),
            };
            let mut hw_rng = HwRng(unsafe {
                // SAFETY: single call site, non-reentrant
                core::ptr::read(rng as *const Rng<'_, _>)
            });
            let raw_key: heapless::Vec<u8, 32> = match kt {
                KeyType::Aes256 => {
                    let k = crypto::gen_aes256_key(&mut hw_rng);
                    let mut v = heapless::Vec::new();
                    v.extend_from_slice(&k).ok();
                    v
                }
                KeyType::HmacSha256 => {
                    let k = crypto::gen_hmac_key(&mut hw_rng);
                    let mut v = heapless::Vec::new();
                    v.extend_from_slice(&k).ok();
                    v
                }
                KeyType::EccP256 => {
                    let k = crypto::gen_ecc_p256_key(&mut hw_rng);
                    let mut v = heapless::Vec::new();
                    v.extend_from_slice(&k).ok();
                    v
                }
            };
            match ks.store(kt, &raw_key) {
                None => err!(Rsp::ErrCrypto),
                Some(handle) => {
                    out.extend_from_slice(&handle.0.to_le_bytes()).ok();
                    return (Rsp::KeyHandle, out);
                }
            }
        }

        // ── Key delete ───────────────────────────────────────────────────────
        Cmd::KeyDelete => {
            if payload.len() < 4 { err!(Rsp::ErrBadParam); }
            let handle = KeyHandle(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
            if ks.delete(handle) { ok!(); } else { err!(Rsp::ErrBadKey); }
        }

        // ── Key derive (HKDF) ────────────────────────────────────────────────
        Cmd::KeyDerive => {
            // Payload: [base_handle:4][out_type:1][out_len:1][info_len:2][info...]
            if payload.len() < 8 { err!(Rsp::ErrBadParam); }
            let base = KeyHandle(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
            let out_type = payload[4];
            let out_len  = payload[5] as usize;
            let info_len = u16::from_le_bytes([payload[6], payload[7]]) as usize;
            if payload.len() < 8 + info_len { err!(Rsp::ErrBadParam); }
            if out_len > 32 || out_len == 0 { err!(Rsp::ErrBadParam); }
            let info = &payload[8..8 + info_len];
            let kt = match KeyType::try_from(payload[4]) {
                Ok(t) => t,
                Err(_) => err!(Rsp::ErrBadParam),
            };
            let base_kt = match out_type {
                0x01 => KeyType::Aes256,
                0x02 => KeyType::HmacSha256,
                _ => err!(Rsp::ErrBadParam),
            };
            let _ = kt;
            match ks.borrow(base, base_kt) {
                None => err!(Rsp::ErrBadKey),
                Some(key) => {
                    let mut derived = [0u8; 32];
                    if crypto::hkdf_sha256(key, None, info, &mut derived[..out_len]).is_err() {
                        err!(Rsp::ErrCrypto);
                    }
                    // Store derived key in keystore
                    match ks.store(base_kt, &derived[..out_len]) {
                        None => err!(Rsp::ErrCrypto),
                        Some(h) => {
                            out.extend_from_slice(&h.0.to_le_bytes()).ok();
                            return (Rsp::KeyHandle, out);
                        }
                    }
                }
            }
        }

        // ── Key import (wrapped — not yet implemented) ────────────────────────
        Cmd::KeyImport => {
            // Future: AES-GCM-wrapped key import with a KEK
            err!(Rsp::ErrUnknownCmd);
        }
    }
}
