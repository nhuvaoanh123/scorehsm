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
    gpio::{Level, Output, Speed},
    peripherals,
    rng::{self, Rng},
    usb::Driver as UsbDriver,
    wdg::IndependentWatchdog,
};
use embassy_usb::{
    class::cdc_acm::{CdcAcmClass, State},
    Builder, UsbDevice,
};
use embassy_futures::join::join3;
use embassy_time::Timer;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

mod crypto;
mod keystore;
mod protocol;
mod trustzone;

use keystore::{KeyStore, KeyHandle, KeyType};
use protocol::{Cmd, Rsp, ParseError, FRAME_OVERHEAD, MAX_FRAME, MAX_PAYLOAD};

// ── Embassy interrupt bindings ────────────────────────────────────────────────

bind_interrupts!(struct Irqs {
    USB_FS => embassy_stm32::usb::InterruptHandler<peripherals::USB>;
    RNG    => rng::InterruptHandler<peripherals::RNG>;
});

// ── Key store (static, in SRAM2 ideally — linker section) ────────────────────

static mut KEY_STORE: KeyStore = KeyStore::new();

// ── USB buffer allocations ────────────────────────────────────────────────────

// ── Main entry ────────────────────────────────────────────────────────────────

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    // ── RCC config: 80 MHz system + HSI48 for USB (per Embassy L5 example) ──
    let mut config = embassy_stm32::Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.hsi = true;
        config.rcc.sys = Sysclk::PLL1_R;
        config.rcc.pll = Some(Pll {
            source: PllSource::HSI,      // 16 MHz HSI
            prediv: PllPreDiv::DIV1,
            mul: PllMul::MUL10,          // 16 * 10 = 160 MHz VCO
            divp: None,
            divq: None,
            divr: Some(PllRDiv::DIV2),   // 160 / 2 = 80 MHz system clock
        });
        config.rcc.hsi48 = Some(Hsi48Config { sync_from_usb: true });
        config.rcc.mux.clk48sel = mux::Clk48sel::HSI48;
    }
    let p = embassy_stm32::init(config);

    // NUCLEO-L552ZE-Q (Nucleo-144): LED1=PC7(green), LED2=PB7(blue), LED3=PA9(red)
    let mut led = Output::new(p.PC7, Level::High, Speed::Low);
    info!("scorehsm-firmware: phase A OK — Embassy init complete");

    // Blink 3× fast to confirm we're alive
    for _ in 0..3 {
        led.set_low();
        cortex_m::asm::delay(20_000_000); // ~250 ms at 80 MHz
        led.set_high();
        cortex_m::asm::delay(20_000_000);
    }

    // STM32L5: USB transceiver requires VDDUSB supply valid (PWR_CR2.USV)
    {
        let pwr = embassy_stm32::pac::PWR;
        pwr.cr2().modify(|w| w.set_usv(true));
        info!("PWR_CR2.USV set — USB supply valid");
    }

    // ── TrustZone: SAU configuration (before any peripheral init) ────────
    #[cfg(feature = "trustzone")]
    {
        unsafe { trustzone::configure_sau(); }
        if trustzone::verify_tz_active() {
            info!("TrustZone: SAU active, SRAM2 Secure");
        } else {
            error!("TrustZone: SAU enable FAILED — check TZEN option byte");
        }
    }
    #[cfg(not(feature = "trustzone"))]
    {
        info!("TrustZone: disabled (non-TZ build)");
    }

    // Initialise hardware RNG
    let rng = Rng::new(p.RNG, Irqs);

    // USB FS device
    let driver = UsbDriver::new(p.USB, Irqs, p.PA12, p.PA11);

    // Build USB device with CDC-ACM
    let mut usb_config = embassy_usb::Config::new(0xF055, 0x4853);
    usb_config.manufacturer = Some("Taktflow-Systems");
    usb_config.product      = Some("scoreHSM");
    usb_config.serial_number = Some("0001");
    usb_config.max_power      = 100;
    usb_config.max_packet_size_0 = 64;

    static DESC_DEVICE: StaticCell<[u8; 256]> = StaticCell::new();
    static DESC_CONFIG: StaticCell<[u8; 256]> = StaticCell::new();
    static DESC_BOS: StaticCell<[u8; 256]> = StaticCell::new();
    static BUF_CONTROL: StaticCell<[u8; 64]> = StaticCell::new();
    static CDC_STATE: StaticCell<State<'static>> = StaticCell::new();

    let mut builder = Builder::new(
        driver,
        usb_config,
        DESC_DEVICE.init([0; 256]),
        DESC_CONFIG.init([0; 256]),
        DESC_BOS.init([0; 256]),
        BUF_CONTROL.init([0; 64]),
    );

    let class = CdcAcmClass::new(&mut builder, CDC_STATE.init(State::new()), 64);
    let usb = builder.build();
    info!("USB CDC built — starting tasks");

    // IWDG: 2s timeout, pet every 500ms from watchdog task
    let mut wdg = IndependentWatchdog::new(p.IWDG, 2_000_000);
    wdg.unleash();
    info!("IWDG active (2s timeout, 500ms pet)");

    join3(usb_run(usb), hsm_run(class, rng), watchdog_run(wdg)).await;
}

// ── USB device driver task ────────────────────────────────────────────────────

async fn usb_run<D: embassy_usb::driver::Driver<'static>>(
    mut usb: UsbDevice<'static, D>,
) -> ! {
    usb.run().await
}

// ── Watchdog task ─────────────────────────────────────────────────────────────

async fn watchdog_run<'d>(mut wdg: IndependentWatchdog<'d, peripherals::IWDG>) -> ! {
    info!("Watchdog task started");
    loop {
        wdg.pet();
        Timer::after_millis(500).await;
    }
}

// ── HSM dispatcher task ───────────────────────────────────────────────────────

async fn hsm_run<'d, D: embassy_usb::driver::Driver<'d>>(
    mut class: CdcAcmClass<'d, D>,
    mut hw_rng: Rng<'d, peripherals::RNG>,
) -> ! {
    let mut rx_buf = [0u8; MAX_FRAME];
    let mut tx_buf = [0u8; MAX_FRAME];
    let mut rx_pos: usize;
    let mut initialized;
    let mut expected_seq: u32;

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
                        ParseError::TooShort => core::unreachable!(),
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
                    // Send response in 64-byte USB packets (CDC max packet size)
                    let mut sent = 0;
                    while sent < n {
                        let chunk = (n - sent).min(64);
                        if let Err(_) = class.write_packet(&tx_buf[sent..sent + chunk]).await {
                            break 'connection;
                        }
                        sent += chunk;
                    }

                    if expected_seq == u32::MAX {
                        warn!("Sequence overflow — re-init required");
                        break 'connection;
                    }
                    expected_seq += 1;
                }
            }
        }

        info!("Host disconnected");
    }
}

// ── Command dispatcher ────────────────────────────────────────────────────────

fn dispatch(
    cmd: Cmd,
    _seq: u32,
    payload: &[u8],
    initialized: &mut bool,
    expected_seq: &mut u32,
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
    let ks = unsafe { &mut *(&raw mut KEY_STORE) };

    match cmd {
        // ── Init ─────────────────────────────────────────────────────────────
        Cmd::Init => {
            *initialized = true;
            *expected_seq = 0x00; // post-dispatch increment will make this 0x01
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
            let raw_key: heapless::Vec<u8, 32> = match kt {
                KeyType::Aes256 => {
                    let k = crypto::gen_aes256_key(rng);
                    let mut v = heapless::Vec::new();
                    v.extend_from_slice(&k).ok();
                    v
                }
                KeyType::HmacSha256 => {
                    let k = crypto::gen_hmac_key(rng);
                    let mut v = heapless::Vec::new();
                    v.extend_from_slice(&k).ok();
                    v
                }
                KeyType::EccP256 => {
                    let k = crypto::gen_ecc_p256_key(rng);
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
            let base_handle = u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]);
            let out_type = payload[4];
            let out_len  = payload[5] as usize;
            let info_len = u16::from_le_bytes([payload[6], payload[7]]) as usize;
            if payload.len() < 8 + info_len { err!(Rsp::ErrBadParam); }
            if out_len > 32 || out_len == 0 { err!(Rsp::ErrBadParam); }
            let info = &payload[8..8 + info_len];

            // Output key type (what the derived key will be stored as)
            let derived_type = match out_type {
                0x01 => KeyType::Aes256,
                0x02 => KeyType::HmacSha256,
                0x03 => KeyType::EccP256,
                _ => err!(Rsp::ErrBadParam),
            };

            // Look up base key by handle — use key_type() to get actual type
            let base_type = match ks.key_type(KeyHandle(base_handle)) {
                Some(t) => t,
                None => err!(Rsp::ErrBadKey),
            };
            let base_key = match ks.borrow(KeyHandle(base_handle), base_type) {
                Some(k) => k,
                None => err!(Rsp::ErrBadKey),
            };

            // HKDF derive
            let mut derived = [0u8; 32];
            if crypto::hkdf_sha256(base_key, None, info, &mut derived[..out_len]).is_err() {
                err!(Rsp::ErrCrypto);
            }

            // Store derived key with the requested output type
            match ks.store(derived_type, &derived[..out_len]) {
                None => err!(Rsp::ErrCrypto),
                Some(h) => {
                    out.extend_from_slice(&h.0.to_le_bytes()).ok();
                    return (Rsp::KeyHandle, out);
                }
            }
        }

        // ── Key import (plaintext — standalone showcase) ─────────────────────
        // Future: KEK-wrapped import for production use.
        Cmd::KeyImport => {
            // Payload: [key_type:1][key_len:2LE][key_bytes:key_len]
            if payload.len() < 3 { err!(Rsp::ErrBadParam); }
            let kt = match KeyType::try_from(payload[0]) {
                Ok(t) => t,
                Err(_) => err!(Rsp::ErrBadParam),
            };
            let key_len = u16::from_le_bytes([payload[1], payload[2]]) as usize;
            if payload.len() < 3 + key_len { err!(Rsp::ErrBadParam); }
            // All key types currently require exactly 32 bytes
            if key_len != 32 { err!(Rsp::ErrBadParam); }
            let key_bytes = &payload[3..3 + key_len];
            match ks.store(kt, key_bytes) {
                None => err!(Rsp::ErrCrypto), // store full
                Some(handle) => {
                    out.extend_from_slice(&handle.0.to_le_bytes()).ok();
                    info!("KeyImport: type={} handle={}", payload[0], handle.0);
                    return (Rsp::KeyHandle, out);
                }
            }
        }

        // ── ECDH key agreement ──────────────────────────────────────────────
        Cmd::Ecdh => {
            // Payload: [handle:4][peer_pub:65] (0x04 || X:32 || Y:32)
            if payload.len() < 4 + 65 { err!(Rsp::ErrBadParam); }
            let handle = KeyHandle(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
            let peer_pub = &payload[4..4 + 65];
            match ks.borrow(handle, KeyType::EccP256) {
                None => err!(Rsp::ErrBadKey),
                Some(key) => {
                    match crypto::ecdh(key, peer_pub) {
                        Err(_) => err!(Rsp::ErrCrypto),
                        Ok(shared) => {
                            out.extend_from_slice(&shared).ok();
                            return (Rsp::EcdhSecret, out);
                        }
                    }
                }
            }
        }
    }
}
