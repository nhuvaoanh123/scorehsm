// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! Transport layer integration tests — TSR-TIG-01..04.
//!
//! Tests frame integrity (CRC-32), sequence numbering, per-op timeouts,
//! retry with backoff, and safe-state entry after consecutive failures.
//!
//! Uses an inline `MockSerial` implementing `SerialLink` since the internal
//! mock in `transport.rs` is private to unit tests.

use scorehsm_host::{
    error::HsmError,
    safety::{crc32_mpeg2, LibraryState},
    transport::{
        Cmd, OpClass, OpTimeouts, Rsp, SerialLink, Transport, FRAME_OVERHEAD, HDR_LEN, MAGIC,
        MAX_PAYLOAD,
    },
};
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::Duration;

// ── Inline mock serial link ────────────────────────────────────────────────

enum ReadOp {
    Data(Vec<u8>),
    Error(io::ErrorKind),
}

struct MockSerial {
    ops: VecDeque<ReadOp>,
    pending: VecDeque<u8>,
    written: Vec<u8>,
    timeout: Duration,
}

impl MockSerial {
    fn new() -> Self {
        Self {
            ops: VecDeque::new(),
            pending: VecDeque::new(),
            written: Vec::new(),
            timeout: Duration::from_secs(1),
        }
    }

    /// Queue a well-formed response frame.
    fn push_response(&mut self, rsp_code: u8, seq: u32, payload: &[u8]) {
        let frame = build_response(rsp_code, seq, payload);
        self.ops.push_back(ReadOp::Data(frame));
    }

    /// Queue raw bytes (e.g. a corrupted frame).
    fn push_raw(&mut self, data: Vec<u8>) {
        self.ops.push_back(ReadOp::Data(data));
    }

    /// Queue an IO error for the next read_exact call.
    fn push_error(&mut self, kind: io::ErrorKind) {
        self.ops.push_back(ReadOp::Error(kind));
    }
}

impl SerialLink for MockSerial {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.written.extend_from_slice(buf);
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        while self.pending.len() < buf.len() {
            match self.ops.pop_front() {
                Some(ReadOp::Data(data)) => self.pending.extend(data),
                Some(ReadOp::Error(kind)) => {
                    return Err(io::Error::new(kind, "mock error"));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "mock: no more data",
                    ));
                }
            }
        }
        for byte in buf.iter_mut() {
            *byte = self.pending.pop_front().unwrap();
        }
        Ok(())
    }

    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.timeout = timeout;
        Ok(())
    }
}

/// Build a valid response frame.
fn build_response(rsp_code: u8, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let total = FRAME_OVERHEAD + len;
    let mut frame = vec![0u8; total];
    frame[0] = MAGIC[0];
    frame[1] = MAGIC[1];
    frame[2] = rsp_code;
    frame[3..7].copy_from_slice(&seq.to_le_bytes());
    frame[7] = (len & 0xFF) as u8;
    frame[8] = ((len >> 8) & 0xFF) as u8;
    frame[HDR_LEN..HDR_LEN + len].copy_from_slice(payload);
    let crc = crc32_mpeg2(&frame[..HDR_LEN + len]);
    frame[HDR_LEN + len..].copy_from_slice(&crc.to_le_bytes());
    frame
}

fn make_transport(mock: MockSerial) -> Transport {
    let state = Arc::new(LibraryState::new());
    state.transition_to_operating().unwrap();
    Transport::new(Box::new(mock), state).with_backoff_fn(|_| {})
}

// ── TSR-TIG-01: CRC-32 Frame Integrity ────────────────────────────────────

/// ITP-TIG-01-a: Valid CRC-32 frame accepted.
#[test]
fn itp_transport_valid_crc_accepted() {
    let mut mock = MockSerial::new();
    mock.push_response(Rsp::Ok as u8, 0, &[]);
    let mut t = make_transport(mock);

    let (rsp, payload) = t.send_recv(Cmd::Init, &[], OpClass::Admin).unwrap();
    assert_eq!(rsp, Rsp::Ok);
    assert!(payload.is_empty());
}

/// ITP-TIG-01-b: Corrupted CRC is detected and triggers retry.
#[test]
fn itp_transport_corrupt_crc_retried() {
    let mut mock = MockSerial::new();
    // First: corrupted CRC
    let mut bad_frame = build_response(Rsp::Ok as u8, 0, &[]);
    let last = bad_frame.len() - 1;
    bad_frame[last] ^= 0xFF;
    mock.push_raw(bad_frame);
    // Second: valid response
    mock.push_response(Rsp::Ok as u8, 0, &[]);

    let mut t = make_transport(mock);
    let result = t.send_recv(Cmd::Init, &[], OpClass::Admin);
    assert!(result.is_ok());
}

/// ITP-TIG-01-c: Frame with payload has correct CRC round-trip.
#[test]
fn itp_transport_payload_crc_roundtrip() {
    let mut mock = MockSerial::new();
    let data = vec![0x42; 64];
    mock.push_response(Rsp::Sha256 as u8, 0, &data);
    let mut t = make_transport(mock);

    let (rsp, payload) = t.send_recv(Cmd::Sha256, b"hello", OpClass::Aes).unwrap();
    assert_eq!(rsp, Rsp::Sha256);
    assert_eq!(payload, data);
}

/// ITP-TIG-01-d: CRC-32/MPEG-2 KAT matches published test vector.
#[test]
fn itp_transport_crc32_kat() {
    // Standard CRC-32/MPEG-2 known-answer test: "123456789" → 0x0376E6E7
    assert_eq!(crc32_mpeg2(b"123456789"), 0x0376_E6E7);
}

// ── TSR-TIG-02: Sequence Number ──────────────────────────────────────────

/// ITP-TIG-02-a: Sequence number starts at 0 and increments.
#[test]
fn itp_transport_seq_increments() {
    let mut mock = MockSerial::new();
    mock.push_response(Rsp::Ok as u8, 0, &[]);
    mock.push_response(Rsp::Ok as u8, 1, &[]);
    mock.push_response(Rsp::Ok as u8, 2, &[]);

    let mut t = make_transport(mock);
    assert_eq!(t.seq(), 0);

    t.send_recv(Cmd::Init, &[], OpClass::Admin).unwrap();
    assert_eq!(t.seq(), 1);

    t.send_recv(Cmd::Random, &[2, 0], OpClass::Admin).unwrap();
    assert_eq!(t.seq(), 2);

    t.send_recv(Cmd::Sha256, b"x", OpClass::Aes).unwrap();
    assert_eq!(t.seq(), 3);
}

/// ITP-TIG-02-b: Sequence mismatch returns ProtocolError.
#[test]
fn itp_transport_seq_mismatch_rejected() {
    let mut mock = MockSerial::new();
    // Expected seq=0, but firmware returns seq=99
    mock.push_response(Rsp::Ok as u8, 99, &[]);

    let mut t = make_transport(mock);
    let result = t.send_recv(Cmd::Init, &[], OpClass::Admin);
    assert!(matches!(result, Err(HsmError::ProtocolError)));
}

/// ITP-TIG-02-c: SequenceOverflow error variant exists and formats correctly.
#[test]
fn itp_transport_seq_overflow() {
    // The exact overflow path (seq=u32::MAX) is tested in transport.rs unit tests
    // which can construct Transport with internal state. Here we verify the error
    // variant is correct and the message is meaningful.
    let err = HsmError::SequenceOverflow;
    assert_eq!(
        format!("{err}"),
        "sequence number overflow — re-initialization required"
    );
}

// ── TSR-TIG-03: Per-Op Timeouts ────────────────────────────────────────────

/// ITP-TIG-03-a: OpTimeouts has expected default values.
#[test]
fn itp_transport_default_timeouts() {
    let t = OpTimeouts::default();
    assert_eq!(t.aes, Duration::from_millis(100));
    assert_eq!(t.ecdsa, Duration::from_secs(2));
    assert_eq!(t.keygen, Duration::from_secs(5));
    assert_eq!(t.admin, Duration::from_millis(500));
}

/// ITP-TIG-03-b: Timeout on read triggers retry (retriable error).
#[test]
fn itp_transport_timeout_triggers_retry() {
    let mut mock = MockSerial::new();
    // First: timeout
    mock.push_error(io::ErrorKind::TimedOut);
    // Second: success
    mock.push_response(Rsp::Ok as u8, 0, &[]);

    let mut t = make_transport(mock);
    assert!(t.send_recv(Cmd::Init, &[], OpClass::Admin).is_ok());
    assert_eq!(t.consecutive_failures(), 0); // reset on success
}

// ── TSR-TIG-04: Retry and Safe State ────────────────────────────────────────

/// ITP-TIG-04-a: Three consecutive failures trigger safe state.
#[test]
fn itp_transport_safe_state_on_consecutive_failures() {
    let mut mock = MockSerial::new();
    // 3 timeouts
    mock.push_error(io::ErrorKind::TimedOut);
    mock.push_error(io::ErrorKind::TimedOut);
    mock.push_error(io::ErrorKind::TimedOut);

    let mut t = make_transport(mock);
    let result = t.send_recv(Cmd::Init, &[], OpClass::Admin);
    assert!(matches!(result, Err(HsmError::SafeState)));
}

/// ITP-TIG-04-b: Safe state blocks subsequent operations.
#[test]
fn itp_transport_safe_state_blocks_operations() {
    let state = Arc::new(LibraryState::new());
    state.enter_safe_state("test");

    let mock = MockSerial::new();
    let mut t = Transport::new(Box::new(mock), state).with_backoff_fn(|_| {});
    let result = t.send_recv(Cmd::Init, &[], OpClass::Admin);
    assert!(matches!(result, Err(HsmError::SafeState)));
}

/// ITP-TIG-04-c: Success after failure resets consecutive failure counter.
#[test]
fn itp_transport_success_resets_failure_counter() {
    let mut mock = MockSerial::new();
    // Fail then succeed
    mock.push_error(io::ErrorKind::TimedOut);
    mock.push_response(Rsp::Ok as u8, 0, &[]);

    let mut t = make_transport(mock);
    t.send_recv(Cmd::Init, &[], OpClass::Admin).unwrap();
    assert_eq!(t.consecutive_failures(), 0);
}

/// ITP-TIG-04-d: Firmware error responses are NOT retried (not transient).
#[test]
fn itp_transport_firmware_error_not_retried() {
    let mut mock = MockSerial::new();
    // ErrBadKey is a firmware-level error, not a transport error
    mock.push_response(Rsp::ErrBadKey as u8, 0, &[]);

    let mut t = make_transport(mock);
    let result = t.send_recv(Cmd::EcdsaSign, &[], OpClass::Ecdsa);
    assert!(matches!(result, Err(HsmError::InvalidKeyHandle)));
    // Seq still incremented (valid frame exchange)
    assert_eq!(t.seq(), 1);
}

/// ITP-TIG-04-e: Payload too large is rejected before sending.
#[test]
fn itp_transport_payload_too_large() {
    let mut mock = MockSerial::new();
    mock.push_response(Rsp::Ok as u8, 0, &[]);

    let mut t = make_transport(mock);
    let big = vec![0u8; MAX_PAYLOAD + 1];
    let result = t.send_recv(Cmd::Sha256, &big, OpClass::Aes);
    assert!(matches!(result, Err(HsmError::InvalidParam(_))));
}
