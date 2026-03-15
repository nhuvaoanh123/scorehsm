# scorehsm — Architecture

Date: 2026-03-14
Status: COMPLETE

---

## 1. System Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  Application layer (KUKSA, OTA verifier, TLS stack, etc.)       │
├─────────────────────────────────────────────────────────────────┤
│  scorehsm-host API  (HsmBackend trait)                          │
│  ┌─────────────────────────┐  ┌──────────────────────────────┐  │
│  │  Software backend       │  │  Hardware backend            │  │
│  │  (rustcrypto)           │  │  (USB CDC → L55)             │  │
│  │  CI / no-hardware path  │  │  Production / isolated path  │  │
│  └─────────────────────────┘  └──────────────┬───────────────┘  │
├───────────────────────────────────────────────┼─────────────────┤
│  USB CDC  /dev/ttyACM0                        │                  │
│  Binary frame protocol (CRC-32/MPEG-2, seq num) │                  │
├───────────────────────────────────────────────┼─────────────────┤
│  STM32L552 — Non-Secure world                 │                  │
│  USB endpoint + command dispatcher            │                  │
│  Frame validation (length, CRC, seq)          │                  │
│  Key handle validation                        │                  │
├───────────────────────────────────────────────┼─────────────────┤
│  TrustZone NSC gateway  (.gnu.sgstubs)        │                  │
│  CMSE veneers — handle + result only          │                  │
├───────────────────────────────────────────────┼─────────────────┤
│  STM32L552 — Secure world                     │                  │
│  AES peripheral driver (GCM/CBC/CCM)          │                  │
│  PKA peripheral driver (ECDSA P-256, ECDH)    │                  │
│  HASH peripheral driver (SHA-256)             │                  │
│  RNG peripheral driver (TRNG)                 │                  │
│  Key store (SRAM2 — security-attributed)      │                  │
│  Key derivation (HKDF-SHA256)                 │                  │
└───────────────────────────────────────────────┘                  │
```

---

## 2. USB Frame Protocol

### 2.1 Frame format

Every command (Pi → L55) and response (L55 → Pi) uses the same frame structure:

```
[MAGIC:2][CMD:1][SEQ:4LE][LEN:2LE][PAYLOAD:LEN][CRC32:4LE]

Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────
0       2     MAGIC  = 0xAB 0xCD  (sync / frame start)
2       1     CMD    = command/response opcode (see §2.2)
3       4     SEQ    = monotonic sequence number (u32, little-endian)
7       2     LEN    = payload length in bytes (little-endian, max 512)
9       LEN   PAYLOAD
9+LEN   4     CRC32  = CRC-32/MPEG-2 over bytes [0 .. 9+LEN-1]
```

Total minimum frame size: 13 bytes (no payload).  FRAME_OVERHEAD = 13.
Maximum frame size: 9 + 512 + 4 = 525 bytes.

### 2.2 Opcodes

**Commands (Pi → L55):**

| Code | Name | Payload |
|---|---|---|
| 0x01 | CMD_INIT | — |
| 0x02 | CMD_RANDOM | `[len: u16]` — bytes requested |
| 0x03 | CMD_SHA256 | `[data...]` |
| 0x04 | CMD_HMAC_SHA256 | `[handle: u32][data...]` |
| 0x05 | CMD_AES_GCM_ENCRYPT | `[handle: u32][iv: 12B][aad_len: u16][aad...][pt...]` |
| 0x06 | CMD_AES_GCM_DECRYPT | `[handle: u32][iv: 12B][aad_len: u16][aad...][tag: 16B][ct...]` |
| 0x07 | CMD_ECDSA_SIGN | `[handle: u32][digest: 32B]` |
| 0x08 | CMD_ECDSA_VERIFY | `[handle: u32][digest: 32B][r: 32B][s: 32B]` |
| 0x09 | CMD_KEY_GENERATE | `[key_type: u8]` |
| 0x0A | CMD_KEY_DELETE | `[handle: u32]` |
| 0x0B | CMD_KEY_DERIVE | `[base: u32][out_type: u8][info_len: u16][info...]` |
| 0x0C | CMD_KEY_IMPORT | `[key_type: u8][wrapped...]` |
| 0x0D | CMD_CAPABILITY | — (device verification handshake) |

**Responses (L55 → Pi):**

| Code | Name | Payload |
|---|---|---|
| 0x80 | RSP_OK | operation-specific result |
| 0x81 | RSP_ERR_INVALID_PARAM | `[error_code: u8]` |
| 0x82 | RSP_ERR_INVALID_HANDLE | — |
| 0x83 | RSP_ERR_SLOT_FULL | — |
| 0x84 | RSP_ERR_CRYPTO_FAIL | — |
| 0x85 | RSP_ERR_TAG_MISMATCH | — |
| 0x86 | RSP_ERR_NOT_INIT | — |
| 0x87 | RSP_ERR_BAD_FRAME | — |
| 0x88 | RSP_ERR_RATE_LIMIT | — |

### 2.3 CRC-32/MPEG-2

Algorithm: CRC-32/MPEG-2 (poly 0x04C11DB7, init 0xFFFFFFFF, no reflection, no final XOR).
Computed over the entire frame excluding the CRC field itself (bytes 0 through 9+LEN-1).

### 2.4 Sequence number

- Pi starts at 0x00000000 on each init, increments per command (u32 saturating, refuses at 0xFFFFFFFF — re-init required).
- L55 echoes the received SEQ in every response.
- If L55 receives SEQ != expected: discard frame, respond RSP_ERR_BAD_FRAME.

---

## 3. Rust API Design

### 3.1 HsmBackend trait (host/src/backend/mod.rs)

```rust
pub trait HsmBackend: Send + Sync {
    fn init(&mut self) -> HsmResult<()>;
    fn deinit(&mut self) -> HsmResult<()>;

    // Entropy
    fn random(&mut self, out: &mut [u8]) -> HsmResult<()>;

    // Hashing
    fn sha256(&self, data: &[u8]) -> HsmResult<[u8; 32]>;

    // MAC
    fn hmac_sha256(&self, handle: KeyHandle, data: &[u8]) -> HsmResult<[u8; 32]>;

    // Symmetric
    fn aes_gcm_encrypt(&self, handle: KeyHandle, params: &AesGcmParams, pt: &[u8])
        -> HsmResult<(Vec<u8>, [u8; 16])>;
    fn aes_gcm_decrypt(&self, handle: KeyHandle, params: &AesGcmParams,
        ct: &[u8], tag: &[u8; 16]) -> HsmResult<Vec<u8>>;

    // Asymmetric
    fn ecdsa_sign(&self, handle: KeyHandle, digest: &[u8; 32]) -> HsmResult<EcdsaSignature>;
    fn ecdsa_verify(&self, handle: KeyHandle, digest: &[u8; 32],
        sig: &EcdsaSignature) -> HsmResult<bool>;
    fn ecdh_agree(&self, handle: KeyHandle, peer_pub: &[u8; 64]) -> HsmResult<[u8; 32]>;

    // Key management
    fn key_generate(&mut self, key_type: KeyType) -> HsmResult<KeyHandle>;
    fn key_import(&mut self, key_type: KeyType, wrapped: &[u8]) -> HsmResult<KeyHandle>;
    fn key_delete(&mut self, handle: KeyHandle) -> HsmResult<()>;
    fn key_derive(&mut self, base: KeyHandle, info: &[u8], out_type: KeyType)
        -> HsmResult<KeyHandle>;
}
```

### 3.2 Error type (host/src/error.rs)

```rust
pub enum HsmError {
    NotInitialized,
    InvalidKeyHandle,
    KeyStoreFull,
    CryptoFail(String),
    TagMismatch,
    UsbError(String),
    InvalidParam(String),
    Unsupported,
    RateLimit,
    BadFrame,
}
```

### 3.3 Access control wrapper

```rust
pub struct HsmSession {
    backend: Box<dyn HsmBackend>,
    owned_handles: HashSet<KeyHandle>,
    ids_hook: Option<Box<dyn IdsHook>>,
    rate_limiter: RateLimiter,
}
```

`HsmSession` wraps any `HsmBackend`. It enforces:
- Handle ownership (session cannot use handles from another session)
- Rate limiting per operation type (HSM-REQ-039)
- IDS event reporting (HSM-REQ-038)

### 3.4 IDS hook

```rust
pub trait IdsHook: Send + Sync {
    fn on_event(&self, event: IdsEvent);
}

pub enum IdsEvent {
    KeyGenerated { handle: KeyHandle, key_type: KeyType },
    KeyDeleted { handle: KeyHandle },
    EcdsaSigned { handle: KeyHandle, digest: [u8; 32] },
    DecryptFailed { handle: KeyHandle },
    RepeatedFailure { count: u32 },
}
```

---

## 4. TrustZone Memory Map (STM32L552ZE)

```
Flash (1 MB total):
  0x0C000000 – 0x0C05FFFF  (384 KB)  Secure alias   — S firmware
  0x0C060000 – 0x0C07FFFF  (128 KB)  NSC region     — CMSE veneers (.gnu.sgstubs)
  0x08080000 – 0x080FFFFF  (512 KB)  Non-Secure     — NS firmware (USB, dispatcher)

SRAM (256 KB total):
  0x30000000 – 0x3000FFFF  (64 KB)   SRAM1 S alias  — S stack, S heap
  0x20010000 – 0x2001FFFF  (64 KB)   SRAM2 S        — Key store (security-attributed)
  0x20000000 – 0x2000FFFF  (64 KB)   SRAM1 NS       — NS stack, USB buffers
  0x20020000 – 0x2003FFFF  (128 KB)  SRAM3 NS       — NS heap, DMA buffers

Peripherals:
  AES    0x420C0000 — Secure
  PKA    0x420C2000 — Secure
  HASH   0x420C0400 — Secure
  RNG    0x420C0800 — Secure
  USB FS 0x40006800 — Non-Secure (USB operates from NS world)
```

SAU regions configured at boot by S firmware before NS execution begins.

---

## 5. Key Store Design (Secure SRAM2)

```
SRAM2 layout (64 KB):
  Offset 0x0000 – 0x007F   Key store header (magic, slot count, version)
  Offset 0x0080 – 0x3FFF   32 key slots × 128 B each

Key slot structure (128 B):
  [0x000]  u32   slot_state  (0 = empty, 1 = active, 0xDEAD = deleted/zeroized)
  [0x004]  u32   key_type    (AES256=1, HMAC=2, ECC_P256=3)
  [0x008]  u32   handle_id   (opaque ID returned to NS/Pi)
  [0x00C]  u32   reserved
  [0x010]  u8[32] key_material  (AES/HMAC) or u8[64] private key (ECC)
  [0x030]  u8[64] public_key   (ECC only)
  [0x070 – 0x7FF]  zeroed padding
```

Zeroize on:
- `key_delete()` — slot_state → 0xDEAD, key bytes → 0x00
- `reset_init()` — all slots zeroized before USB enumeration (HSM-REQ-043)

---

## 6. Firmware Task Structure (Embassy)

```
#[embassy_executor::main]
async fn main(spawner) {
    spawner.spawn(usb_task(usb_driver)).unwrap();
    spawner.spawn(crypto_task(crypto_channel)).unwrap();
    spawner.spawn(watchdog_task(watchdog)).unwrap();
}

usb_task:    receive frame → validate → send to crypto_channel → await result → send response
crypto_task: receive CryptoRequest → dispatch to S-world via NSC veneer → return CryptoResult
watchdog_task: feed TIM watchdog every 500ms
```

USB and crypto run as separate Embassy tasks. Crypto task serializes all S-world calls
(one at a time — PKA is single-instance). USB task enqueues requests and awaits response.

---

## 7. Firmware → S-world Interface (CMSE NSC veneers)

```c
// In S-world (secure partition), exposed as NSC:

__attribute__((cmse_nonsecure_entry))
int32_t NSC_Random(uint8_t *ns_buf, uint32_t len);

__attribute__((cmse_nonsecure_entry))
int32_t NSC_Sha256(const uint8_t *ns_data, uint32_t len, uint8_t *ns_out);

__attribute__((cmse_nonsecure_entry))
int32_t NSC_AesGcmEncrypt(uint32_t handle, const AesGcmParams_NS *ns_params,
                           uint8_t *ns_ct, uint8_t *ns_tag);

__attribute__((cmse_nonsecure_entry))
int32_t NSC_EcdsaSign(uint32_t handle, const uint8_t *ns_digest,
                       uint8_t *ns_r, uint8_t *ns_s);

__attribute__((cmse_nonsecure_entry))
int32_t NSC_KeyGenerate(uint32_t key_type, uint32_t *ns_handle_out);

__attribute__((cmse_nonsecure_entry))
int32_t NSC_KeyDelete(uint32_t handle);
```

All pointer parameters validated with `cmse_check_address_range()` (NS-accessible only)
before dereferencing. Key material is never in any parameter — only handles and operation
results cross the boundary.

Note: In Rust, `#[cmse_nonsecure_entry]` is available on nightly. The S-world gateway
uses nightly Rust for CMSE attributes only. All other firmware is stable Rust.

---

## 8. Requirement → Component Traceability

| Requirement | Component |
|---|---|
| HSM-REQ-001 to 005 | `backend/sw.rs` (SW), `firmware/src/crypto/aes.rs` (HW) |
| HSM-REQ-006 to 010 | `backend/sw.rs` (SW), `firmware/src/crypto/pka.rs` (HW) |
| HSM-REQ-011 | `backend/sw.rs`, `firmware/src/crypto/hash.rs` |
| HSM-REQ-012 to 014 | `backend/sw.rs`, `firmware/src/crypto/hash.rs` |
| HSM-REQ-015 | `backend/sw.rs`, `firmware/src/crypto/kdf.rs` |
| HSM-REQ-016 to 017 | `firmware/src/crypto/rng.rs`, `backend/sw.rs` |
| HSM-REQ-018 | `host/src/cert.rs` |
| HSM-REQ-019 to 023 | `firmware/src/keystore.rs`, `backend/mod.rs` |
| HSM-REQ-024 to 027 | `host/src/types.rs`, `host/src/error.rs` |
| HSM-REQ-028 | `host/benches/` |
| HSM-REQ-029 | `firmware/src/crypto/` (hardware units) |
| HSM-REQ-030 | `host/src/backend/mod.rs` (trait design) |
| HSM-REQ-031 | `firmware/src/secure/` (TrustZone) |
| HSM-REQ-032 | `firmware/src/provision.rs` |
| HSM-REQ-033 | `host/src/pqc.rs` |
| HSM-REQ-034 | `firmware/src/crypto/` |
| HSM-REQ-035 | `host/src/backend/sw.rs` |
| HSM-REQ-036 | `firmware/src/secure/` (TrustZone partition) |
| HSM-REQ-037 | `host/src/session.rs` |
| HSM-REQ-038 | `host/src/ids.rs` |
| HSM-REQ-039 | `host/src/rate_limit.rs` |
| HSM-REQ-040 | `host/src/tls.rs` |
| HSM-REQ-041 | `firmware/src/usb/frame.rs`, `host/src/backend/hw.rs` |
| HSM-REQ-042 | `host/src/backend/hw.rs` (init handshake) |
| HSM-REQ-043 | `firmware/src/main.rs` (reset init) |
| HSM-REQ-044 | `firmware/src/usb/dispatcher.rs` |
| HSM-REQ-045 | `host/src/backend/sw.rs` (compile-time warning) |
