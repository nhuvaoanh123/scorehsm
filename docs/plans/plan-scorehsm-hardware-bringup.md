# Plan: scorehsm Full Hardware Bring-Up and ASIL B Showcase

**Date:** 2026-03-14
**Goal:** Bring scorehsm from "docs + partial software" to a fully hardware-verified, timing-proven standalone ASIL B HSM showcase.
**Hardware:** PC (Windows) --SSH--> Raspberry Pi --USB CDC (CN1)--> STM32L552ZE-Q Nucleo; PC --ST-LINK (CN4)--> Nucleo for flashing.

---

## Phase 0 — Make It Compile Clean (~0.5 day)

Nothing else can be tested until the host crate compiles and all existing tests pass.

### 0.1 Fix `UsbError` vs `RateLimitExceeded` bug
- `host/src/session.rs`: 4 sites return `Err(HsmError::UsbError("rate limit exceeded: ..."))` — change to `Err(HsmError::RateLimitExceeded)`
- `host/tests/session_tests.rs`: ~6 assertions match `HsmError::UsbError(_)` — change to `HsmError::RateLimitExceeded`

### 0.2 Verify `boot_status` / `BootStatus` compiles
- `host/src/types.rs` has `BootStatus`; `backend/mod.rs` has default `boot_status()` impl
- Confirm `mock.rs` compiles with trait default — if not, strip the override

### 0.3 Clean unused deps
- `chacha20poly1305`, `sha3`, `rand_chacha` in `host/Cargo.toml` — no HsmBackend method uses them. Leave as-is (reserved for future HSM-REQ-005/014) but document.
- `tls` feature references `tokio`+`rustls` but no `tls.rs` exists — add `#[cfg(feature = "tls")]` stub module or remove feature. Simplest: remove `tls` feature entirely for now.

**Gate:** `cargo test --workspace` passes all ~127 existing tests, `cargo clippy -- -D warnings` clean.

**Files:** `host/src/session.rs`, `host/tests/session_tests.rs`, `host/Cargo.toml`

---

## Phase 1 — Protocol Alignment: CRC-32 + u32 Sequence (~1 day)

**Why:** Firmware uses CRC-16/CCITT + u8 seq. Host uses CRC-32/MPEG-2 + u8 seq. TSR-TIG-01 mandates CRC-32, TSR-TIG-02 mandates u32 seq. The two sides **cannot communicate** today.

### New frame format (both sides)
```
[MAGIC:2][CMD:1][SEQ:4LE][LEN:2LE][PAYLOAD:0..512][CRC32:4LE]
HDR_LEN = 9, FRAME_OVERHEAD = 13, MAX_FRAME = 525
```

### 1.1 Firmware `protocol.rs`
- Replace `crc16()` with `crc32_mpeg2()` (same algo as `host/src/backend/hw.rs`)
- `Frame.seq`: `u8` -> `u32`
- `parse_frame`: read SEQ at `[3..7]`, LEN at `[7..9]`, payload at `[9..9+len]`, CRC at `[9+len..13+len]`
- `build_response`: match new offsets
- Update `FRAME_OVERHEAD=13`, `MAX_FRAME=525`
- Update inline KAT tests

### 1.2 Firmware `main.rs`
- `expected_seq: u8` -> `expected_seq: u32`
- Saturating increment: if `expected_seq == u32::MAX`, refuse frame (close connection)

### 1.3 Host `hw.rs`
- `HDR_LEN=9`, `FRAME_OVERHEAD=13`
- Write SEQ as 4 bytes at `[3..7]`
- LEN at `[7..9]`, payload at `[9..]`
- `Inner.seq`: already `u8` -> `u32`
- At `u32::MAX`: return `HsmError::SequenceOverflow`

### 1.4 Update stale docs
- `docs/architecture/architecture.md` §2.1/2.3: CRC-32, u32 SEQ, overhead=13
- `docs/architecture/architecture.md` §5: keystore = 32 slots x 128B (match code)
- `docs/safety/threat-model.md` D2: 32 slots (not 8)

**Gate:** `cargo test --workspace` green + flash firmware to Nucleo, send Init frame from Pi, get valid CRC-32 response back.

**Files:** `firmware/src/protocol.rs`, `firmware/src/main.rs`, `host/src/backend/hw.rs`, `docs/architecture/architecture.md`, `docs/safety/threat-model.md`

---

## Phase 2 — Timing Verification Infrastructure (~1 day)

**Why:** Without timing proof, the HSM is a demo. This is the showcase differentiator.

### 2.1 Firmware: DWT cycle counter
- `main.rs`: enable `core.DWT.enable_cycle_counter()` before Embassy init
- `crypto.rs`: wrap timing-sensitive ops (`aes_gcm_encrypt`, `ecdsa_sign`) to read `DWT.CYCCNT` before/after, emit delta via `defmt::info!`

### 2.2 Host: criterion benchmarks
- Add `criterion = "0.5"` to `host/Cargo.toml` dev-deps
- Create `host/benches/timing.rs`: benchmark AES-GCM (1/32/128/512B), ECDSA sign, SHA-256 against SW backend
- Create `host/benches/hw_timing.rs` (feature-gated `hw-backend`): same ops against real hardware over USB

### 2.3 Constant-time audit
- Verify `aes-gcm` crate uses `subtle::ConstantTimeEq` for tag comparison (source audit, document finding)
- Verify `p256` crate constant-time scalar ops (document: "software P-256 via `p256` crate; hardware PKA path planned")
- Add statistical timing test: 1000 correct-tag vs 1000 wrong-tag AES-GCM decrypts, assert CV < 5%

**Gate:** `cargo bench` output shows latency distributions. defmt log shows DWT cycle counts. Timing evidence documented.

**Files:** `firmware/src/main.rs`, `firmware/src/crypto.rs`, `host/Cargo.toml`, `host/benches/timing.rs`

---

## Phase 3 — Safety Services Layer (~2 days)

**Why:** All integration tests depend on LibraryState, NonceManager, TokenBucket, and KeyStoreChecksum — none of which exist yet.

### 3.1 Create `host/src/safety.rs`

**LibraryState** (TSR-SSG-01):
- `AtomicU8` with `SeqCst`: `{Initializing=0, Ready=1, Operating=2, SafeState=3}`
- `enter_safe_state(reason)`: any -> SafeState, idempotent
- `check_operating()`: returns `Err(HsmError::SafeState)` if in SafeState
- `reinit()`: SafeState -> Initializing

**TokenBucketRateLimiter** (TSR-RLG-01):
- Per-op-class buckets: ECDSA sign=10/s burst 5, verify=20/s burst 10, keygen=2/s burst 1, ECDH=10/s burst 5, AES=100/s burst 20
- Global (not per-session), `Arc<Mutex<...>>`
- On empty: `Err(HsmError::RateLimitExceeded)` + IDS event

**NonceManager** (TSR-NMG-01/02):
- Add `rusqlite = "0.31"` to `host/Cargo.toml` (optional, behind new `nonce` feature)
- SQLite WAL, `PRAGMA synchronous=FULL`
- `next_iv(key_id, algo_info) -> (u64, [u8; 12])`: pre-increment + HKDF-SHA256
- At `u64::MAX`: `Err(HsmError::NonceExhausted)`

**KeyStoreChecksum** (TSR-SSG-02):
- `AtomicU32` storing CRC-32 of deterministically serialized handle map
- `verify()`: recompute + compare, mismatch -> `Err(HsmError::IntegrityViolation)` + safe state

### 3.2 Integrate into session.rs
- Replace sliding-window `Counter` with reference to global `TokenBucketRateLimiter`
- Add `LibraryState` guard at session entry points
- Wire `KeyStoreChecksum` on handle insert/remove

### 3.3 Add Clock trait for testability
- `pub trait Clock: Send + Sync { fn now(&self) -> Instant; }`
- `SystemClock` (default) + `MockClock` (for tests)
- `HsmSession::with_clock(Arc<dyn Clock>)` builder

**Gate:** New unit tests in `safety.rs` green: state transitions, token bucket refill, nonce increment + overflow, checksum verify/corrupt.

**Files:** `host/src/safety.rs` (new), `host/src/session.rs`, `host/src/lib.rs`, `host/Cargo.toml`

---

## Phase 4 — Transport Hardening (~1.5 days)

**Why:** TSR-TIG-03/04 mandate per-op timeouts and retry with backoff. TSR-IVG-01 mandates startup handshake. HSM-REQ-074-076 mandate POST/KAT.

### 4.1 Extract `host/src/transport.rs` from `hw.rs`
- `Transport` struct: owns `SerialPort`, `seq: u32`, `consecutive_failures: u32`, `PerOpTimeouts`
- `send_recv(cmd, payload, op_class)`: retry loop (max 3 attempts), backoff 10ms/20ms, safe state at 3 consecutive failures
- Per-op timeouts: AES=100ms, ECDSA=2s, KeyGen=5s, Admin=500ms (TSR-TIG-03)

### 4.2 Startup handshake in `HardwareBackend::init()`
- Send `Cmd::Capability` (seq=0)
- Parse response: fw version + capability bitmask
- Read VID/PID from sysfs (`/sys/class/tty/ttyACMx/device/idVendor`)
- Store verified identity; on re-enumeration mismatch -> safe state
- Run POST: AES-GCM KAT (NIST vector) + ECDSA P-256 KAT -> `SelfTestFailed` on failure
- Transition `LibraryState` to `Ready`

### 4.3 Certificate validity check
- `host/src/cert.rs`: add `check_validity(cert) -> HsmResult<()>` using `SystemTime::now()`
- `notBefore`/`notAfter` check, `ClockUnavailable` on clock failure
- Call unconditionally before cert-using operations

**Gate:** Mock transport tests: timeout injection, retry counting, safe-state entry after 3 failures, startup handshake mock.

**Files:** `host/src/transport.rs` (new), `host/src/backend/hw.rs` (simplified), `host/src/cert.rs`

---

## Phase 5 — Integration Test Suite: 52 ITP Tests (~3 days)

All tests run against `MockHardwareBackend` (no hardware required for CI).

| Test file | TSR coverage | Count |
|---|---|---|
| `integration_transport.rs` | TIG-01..04 | 16 |
| `integration_nonce.rs` | NMG-01/02 | 9 |
| `integration_session.rs` | SMG-01/02/03 | 10 |
| `integration_rate_limit.rs` | RLG-01 | 5 |
| `integration_safe_state.rs` | SSG-01/02 | 10 |
| `integration_identity.rs` | IVG-01, CG-01 | 8 |
| `integration_post.rs` | POST/KAT | 4 |
| **Total** | | **52** |

Session timeout tests use `MockClock` (from Phase 3) to avoid 300s real waits.

**Gate:** `cargo test --workspace` — 52/52 integration + ~127 existing = ~179 total, all green.

**Files:** 7 new test files in `host/tests/`

---

## Phase 6 — Qualification Test Suite: 57 QTE Tests (~2 days)

Full-library-level tests verifying FSRs (not TSRs). Run through `hsm_init()` -> `Ready` initialization path.

| FSR | Tests |
|---|---|
| FSR-01..05 | 21 (verify result, constant-time, hash KAT, no export, zeroize) |
| FSR-06..07 | 7 (nonce uniqueness, persistence) |
| FSR-08..09 | 6 (CRC KAT, seq monotonic) |
| FSR-10..11 | 8 (safe state triggers, reinit) |
| FSR-12..14 | 8 (session isolation, timeout, rate limit) |
| FSR-15..16 | 7 (device identity, cert validity) |
| **Total** | **57** |

**Gate:** 57/57 green. `cargo llvm-cov` >= 85% statement / 80% branch.

**Files:** `host/tests/qualification_tests.rs`

---

## Phase 7 — Firmware: Watchdog + KeyImport (~0.5 day)

### 7.1 Watchdog Embassy task
- Add `watchdog_run` async fn: pets IWDG every 500ms (timeout=2000ms)
- `join3(usb_run, hsm_run, watchdog_run)` — aligns with architecture doc's 3-task structure

### 7.2 KeyImport command
- Payload: `[key_type:1][key_len:2LE][key_bytes]`
- Parse, validate, store in KeyStore, return handle
- Note: plaintext import for standalone showcase; document KEK-wrapped import as future

**Gate:** defmt log shows watchdog petting. KeyImport round-trip works from Pi.

**Files:** `firmware/src/main.rs`

---

## Phase 8 — TrustZone Activation (~2 days)

### 8.1 Enable TrustZone
- Set Option Byte `TZEN=1` via STM32CubeProgrammer (one-time)
- Call `configure_sau()` in `main.rs` before Embassy init
- SRAM2 (key store) becomes Secure — hardware-isolated

### 8.2 Single S-world image (simplification)
- Run entire firmware in Secure world — avoids S/NS dual-image complexity
- SAU marks SRAM2 as Secure (key material isolated from debug probes in NS mode)
- Keep software crypto (hardware AES/PKA deferred — document as "pending Embassy HAL support")

**Gate:** TZ active in defmt log. SRAM2 read from NS debug probe returns fault. All HIL functional tests still pass.

**Files:** `firmware/src/main.rs`, `firmware/src/trustzone.rs`

---

## Phase 9 — CI + Project Files (~0.5 day)

- `.github/workflows/ci.yml`: test + clippy + fmt + coverage + firmware check
- `LICENSE` (Apache-2.0), `CONTRIBUTING.md`, `CHANGELOG.md`
- `clippy.toml`, `rustfmt.toml`
- Pin Embassy git deps to specific commit SHA in `firmware/Cargo.toml`
- Remove dangling `tls` feature if not done in Phase 0

**Gate:** CI green on push. Coverage badge shows >= 85%.

**Files:** `.github/workflows/ci.yml`, `LICENSE`, `CONTRIBUTING.md`, `CHANGELOG.md`, `clippy.toml`, `rustfmt.toml`, `firmware/Cargo.toml`

---

## Phase 10 — HIL Tests + Evidence + README (~1 day)

### 4 HIL tests on real hardware
| Test | Method | Pass criteria |
|---|---|---|
| HIL-IVG-01 | Pi reads VID/PID from sysfs | Matches firmware 0xF055/0x4853 |
| HIL-IVG-02 | Replug with different FW | `DeviceIdentityChanged` + SafeState |
| HIL-TIG-05 | 1000 AES-GCM round-trips | 1000/1000 CRC-32 verified |
| HIL-RNG-01 | 1MB TRNG output + `ent` | Entropy ~8.0 bits/byte |

### Evidence artifacts (ISO 26262-6 SS11)
1. `cargo test` full pass log
2. Coverage HTML report (>= 85%/80%)
3. 52/52 integration + 57/57 qualification pass logs
4. HIL execution log
5. DWT timing evidence (cycle counts + CV)
6. Clippy zero-warnings
7. CI green screenshot

### Update docs
- `docs/safety/verification-report.md` — update with real test counts and evidence
- `docs/safety/unit-test-traceability.md` — mark all 52 ITP + 57 QTE as PASSING
- `README.md` — update status from "Phase 0" to actual state with badge

**Gate:** All evidence collected. README reflects reality. Safety case conditions UC-01 (HIL) and UC-02 (coverage) closed.

---

## Phase Summary

| Phase | What | Duration | Cumulative |
|---|---|---|---|
| 0 | Compile clean | 0.5d | 0.5d |
| 1 | Protocol alignment (CRC-32 + u32 seq) | 1d | 1.5d |
| 2 | Timing infrastructure | 1d | 2.5d |
| 3 | Safety services layer | 2d | 4.5d |
| 4 | Transport hardening + POST/KAT | 1.5d | 6d |
| 5 | 52 integration tests | 3d | 9d |
| 6 | 57 qualification tests | 2d | 11d |
| 7 | Firmware: watchdog + KeyImport | 0.5d | 11.5d |
| 8 | TrustZone activation | 2d | 13.5d |
| 9 | CI + project files | 0.5d | 14d |
| 10 | HIL tests + evidence + README | 1d | **15d** |

---

## Key Design Decisions

1. **CRC-32 everywhere** — firmware upgrades to match host and TSR. Frame overhead 8->13 bytes.
2. **u32 saturating seq** — no wrap, refuse at MAX. Matches TSR-TIG-02.
3. **32 keystore slots** — code is authoritative, docs get updated. No code change.
4. **Single S-world TZ image** — avoids dual-image bootloader complexity. SRAM2 isolation is the security property.
5. **Software crypto kept** — hardware AES/PKA deferred. Documented as "pending Embassy HAL."
6. **No full HsmContext rewrite** — global `LibraryState` + enhanced `HsmSession` + `safety.rs` module. Lighter touch.
7. **MockClock trait** — enables session timeout tests without 300s real waits.
8. **Timing claim scoped** — AES-GCM constant-time via `subtle` crate. ECDSA "software P-256, not formally proven." DWT captures cycle counts; CV < 5% is the quantitative claim.
