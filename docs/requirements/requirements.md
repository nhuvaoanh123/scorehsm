# scorehsm — Requirements

Date: 2026-03-14
Status: COMPLETE
Backbone: Eclipse SCORE feat_req__sec_crypt__* (43 requirements)
Extensions: threat model security goals SG-01 to SG-10; stkh_req__dependability__security_features gap analysis

Traceability convention:
  HSM-REQ-NNN maps to SCORE ID feat_req__sec_crypt__<name>
  HSM-REQ-NNN with no SCORE mapping = new requirement from threat model

---

## 1. Symmetric Encryption

### HSM-REQ-001 — Symmetric encrypt/decrypt
**SCORE:** feat_req__sec_crypt__sym_symmetric_encrypt
The security component shall provide AES-256 encryption and decryption operations.

### HSM-REQ-002 — AES-256-GCM
**SCORE:** feat_req__sec_crypt__sym_sym_algo_aes_gcm
The security component shall support AES-256-GCM authenticated encryption and decryption.
**Rationale:** GCM provides both confidentiality and integrity in one operation.

### HSM-REQ-003 — AES-256-CBC
**SCORE:** feat_req__sec_crypt__sym_symm_algo_aes_cbc
The security component shall support AES-256-CBC encryption and decryption.

### HSM-REQ-004 — AES-256-CCM
**SCORE:** feat_req__sec_crypt__sym_sym_algo_aes_ccm
The security component shall support AES-256-CCM authenticated encryption and decryption.

### HSM-REQ-005 — ChaCha20-Poly1305
**SCORE:** feat_req__sec_crypt__sym_algo_chacha20
The security component shall support ChaCha20-Poly1305 encryption.
**Backend:** Software fallback only — L55 hardware does not support ChaCha20.

---

## 2. Asymmetric Encryption

### HSM-REQ-006 — Asymmetric encrypt/decrypt
**SCORE:** feat_req__sec_crypt__asym_encryption
The security component shall provide asymmetric encryption and decryption operations.

### HSM-REQ-007 — ECDH P-256
**SCORE:** feat_req__sec_crypt__asym_algo_ecdh
The security component shall support ECDH with P-256 for key exchange.
**Hardware:** L55 PKA peripheral.

---

## 3. Digital Signatures

### HSM-REQ-008 — Signature creation
**SCORE:** feat_req__sec_crypt__sig_creation
The security component shall provide digital signature creation.

### HSM-REQ-009 — Signature verification
**SCORE:** feat_req__sec_crypt__sig_verification
The security component shall provide digital signature verification.

### HSM-REQ-010 — ECDSA P-256
**SCORE:** feat_req__sec_crypt__sig_algo_ecdsa
The security component shall support ECDSA with P-256 for digital signatures.
**Hardware:** L55 PKA peripheral.

---

## 4. Message Authentication Code

### HSM-REQ-011 — MAC
**SCORE:** feat_req__sec_crypt__mac
The security component shall provide HMAC-SHA256 for message authentication.

---

## 5. Hashing

### HSM-REQ-012 — Hashing
**SCORE:** feat_req__sec_crypt__hashing
The security component shall provide hashing operations.

### HSM-REQ-013 — SHA-256
**SCORE:** feat_req__sec_crypt__hashing_algo_sha2
The security component shall support SHA-256.
**Hardware:** L55 HASH peripheral.

### HSM-REQ-014 — SHA-3
**SCORE:** feat_req__sec_crypt__hashing_algo_sha3
The security component shall support SHA-3 (Keccak-256, SHA3-256).
**Backend:** Software fallback only — L55 HASH peripheral does not support SHA-3.

---

## 6. Key Derivation

### HSM-REQ-015 — Key derivation
**SCORE:** feat_req__sec_crypt__kdf
The security component shall provide HKDF-SHA256 key derivation.
A derived key is stored as a new slot. The source key handle is not exported.

---

## 7. Random Number Generation

### HSM-REQ-016 — Entropy source
**SCORE:** feat_req__sec_crypt__rng
The security component shall provide a hardware entropy source.
**Hardware:** L55 TRNG (RNG peripheral). Software fallback: OS CSPRNG (OsRng).

### HSM-REQ-017 — ChaCha20Rng
**SCORE:** feat_req__sec_crypt__rng_algo_chacha20rng
The security component shall use ChaCha20Rng seeded from the hardware entropy source
as the deterministic RNG for key generation.

---

## 8. Certificate Management

### HSM-REQ-018 — Certificate management
**SCORE:** feat_req__sec_crypt__cert_management
The security component shall provide functionality to manage trusted X.509 certificates:
parse, validate chain, store (by handle), retrieve, and delete.

---

## 9. Key Management

### HSM-REQ-019 — Key generation
**SCORE:** feat_req__sec_crypt__key_generation
The security component shall generate key material inside the HSM using the hardware
entropy source. Generated key material shall never leave the HSM.

### HSM-REQ-020 — Key import
**SCORE:** feat_req__sec_crypt__key_import
The security component shall import key material in wrapped (encrypted) form only.
Plaintext key import is prohibited.

### HSM-REQ-021 — Key storage
**SCORE:** feat_req__sec_crypt__key_storage
The security component shall store key material in TrustZone S-world SRAM2
(security-attributed). Key material shall survive USB disconnect but not power-off
unless backed by NvM.

### HSM-REQ-022 — Key deletion
**SCORE:** feat_req__sec_crypt__key_deletion
The security component shall delete key material by zeroizing the key slot.
The handle shall be invalidated after deletion.

### HSM-REQ-023 — Key export prohibition
**SCORE:** feat_req__sec_crypt__no_key_exposure (+ SG-01, SG-04)
The API shall not provide a key export operation. No USB frame shall contain
raw key material. Only opaque handles cross the USB boundary.

---

## 10. API Requirements

### HSM-REQ-024 — Algorithm selection by name
**SCORE:** feat_req__sec_crypt__flexible_api
The API shall allow selection of cryptographic algorithms by a standardized name
(Rust enum variant). The same operation (e.g., sign) shall work for any supported
algorithm via the same function signature.

### HSM-REQ-025 — Algorithm naming
**SCORE:** feat_req__sec_crypt__algo_naming
Algorithm identifiers shall follow a standardized scheme:
`<primitive>_<variant>_<keysize>` — e.g., `Aes256Gcm`, `EcdsaP256`, `Sha256`.

### HSM-REQ-026 — API lifecycle
**SCORE:** feat_req__sec_crypt__api_lifecycle
The API shall provide explicit `init()` and `deinit()` operations.
Operations called before `init()` shall return `HsmError::NotInitialized`.

### HSM-REQ-027 — Error handling
**SCORE:** feat_req__sec_crypt__error_handling
All API functions shall return `Result<T, HsmError>`. Errors shall be typed and
distinguishable. No panics in library code. No `unwrap()`.

---

## 11. Non-Functional Requirements

### HSM-REQ-028 — Performance benchmarks
**SCORE:** feat_req__sec_crypt__performance_tooling
The security component shall include a benchmark suite measuring latency and
throughput for all operations on both backends (hardware and software).
Results shall be documented in `docs/benchmarks/`.

### HSM-REQ-029 — Side-channel mitigation
**SCORE:** feat_req__sec_crypt__side_channel_mitigation
Hardware crypto operations shall use the L55 hardware units which implement
constant-time execution. Timing measurements over USB shall be documented as
residual risk (USB jitter dominates).

### HSM-REQ-030 — Algorithm agility
**SCORE:** feat_req__sec_crypt__algo_updates
The API shall be designed so that algorithms can be added or replaced without
changing the caller interface. Backend implementations are interchangeable.

### HSM-REQ-031 — Reverse engineering protection
**SCORE:** feat_req__sec_crypt__reverse_eng_protection (+ SG-03, SG-05)
Key material shall be isolated in TrustZone S-world. NS-world code and the
Pi application cannot read key material directly. Zeroize on deletion.

### HSM-REQ-032 — Production key provisioning
**SCORE:** feat_req__sec_crypt__production_keys
The security component shall provide a provisioning command that accepts a
wrapped key and installs it into a designated key slot. The wrapping key
(KEK) shall be pre-provisioned during manufacturing.

### HSM-REQ-033 — Post-quantum readiness
**SCORE:** feat_req__sec_crypt__pqc_readiness
The API shall be algorithm-agnostic. PQC algorithms shall be supported in
the software backend: ML-DSA (signatures), SLH-DSA (signatures),
ML-KEM (key encapsulation). Hardware acceleration deferred to future silicon.

### HSM-REQ-034 — Hardware acceleration
**SCORE:** feat_req__sec_crypt__hw_acceleration
The hardware backend shall use L55 hardware peripherals for all supported
operations: AES peripheral (AES-GCM/CBC/CCM), PKA peripheral (ECDSA/ECDH),
HASH peripheral (SHA-256), RNG peripheral (TRNG).

### HSM-REQ-035 — Software fallback
**SCORE:** feat_req__sec_crypt__sw_fallback
A software-only backend using rustcrypto crates shall implement the full
`HsmBackend` trait. It shall be usable without any hardware attached (CI).

### HSM-REQ-036 — OS-level protection
**SCORE:** feat_req__sec_crypt__os_protection (+ SG-03)
The hardware backend shall use TrustZone (S-world) as the security boundary.
The software fallback explicitly does NOT satisfy this requirement.
Both shall be clearly documented.

### HSM-REQ-037 — Access control
**SCORE:** feat_req__sec_crypt__access_control
Key handles shall be session-scoped. The access control layer shall bind
handles to the caller session. A session cannot use another session's handles.

### HSM-REQ-038 — IDS integration
**SCORE:** feat_req__sec_crypt__ids_integration (+ SG-09)
The security component shall call an IDS event hook on: key generation,
key deletion, ECDSA signing, failed decryption (tag mismatch),
and repeated failed command sequences.

### HSM-REQ-039 — DoS mitigation
**SCORE:** feat_req__sec_crypt__dos_mitigation (+ SG-06)
The host library shall enforce a per-operation rate limit for expensive
operations (PKA: max 100/sec, AES: max 10000/sec).
The L55 command queue shall be bounded (max 4 pending commands).

### HSM-REQ-040 — TLS support
**SCORE:** feat_req__sec_crypt__tls_support
The security component shall provide a TLS integration layer enabling
rustls to use HSM-backed keys for TLS 1.3 handshakes.
Private key operations (ECDSA sign) shall be delegated to the HSM backend.

---

## 12. New Requirements (from threat model)

### HSM-REQ-041 — USB frame integrity
**SCORE:** — (SG-02)
Every USB command and response frame shall include a CRC-32/MPEG-2 checksum and a
monotonic u32 sequence number. The receiver shall reject frames with invalid CRC or
out-of-order sequence numbers.

### HSM-REQ-042 — Device verification
**SCORE:** — (SG-01, S1)
On initialization, the host shall verify the connected device responds to
a capability handshake with a valid firmware descriptor. Unknown devices
shall be rejected.

### HSM-REQ-043 — Key slot zeroize on reset
**SCORE:** — (SG-05)
On L55 power-on or reset, all volatile key slots (SRAM2) shall be explicitly
zeroized before any USB enumeration begins.

### HSM-REQ-044 — Frame length validation
**SCORE:** — (SG-07, E3)
The L55 USB dispatcher shall validate the `length` field of every received
frame before reading the payload. Frames with length exceeding the maximum
payload size shall be rejected with an error response.

### HSM-REQ-045 — Software fallback documentation
**SCORE:** — (SG-08, RR2)
The software fallback backend shall emit a compile-time warning when built
without the `hw-backend` feature, noting that key isolation is not enforced.

---

## 13. Platform Security Requirements (stkh_req__dependability__security_features)

SCORE stakeholder requirement `stkh_req__dependability__security_features` lists ten platform
security capabilities. The sub-items below are mapped to our HSM-REQ set; gaps are filled
with new requirements HSM-REQ-046 through HSM-REQ-049. Platform-level items outside the
HSM library boundary are noted explicitly.

| stkh sub-item | Scope | Covered by |
|---|---|---|
| Mandatory access control | HSM library | HSM-REQ-037 |
| Secure boot | Firmware | HSM-REQ-046 (new) |
| Secure onboard communication | HSM library | HSM-REQ-040 (TLS), HSM-REQ-048 (IPSec/MACSec, new) |
| IPSec and MACSec | HSM library | HSM-REQ-048 (new) |
| Firewall | Platform (OS) | Out of scope — Linux netfilter / AUTOSAR firewall |
| Certificate installation and storage in HSM or ARM TrustZone | HSM library | HSM-REQ-018, HSM-REQ-021 |
| Kernel hardening (ASLR, pointer obfuscation) | Platform (OS) | Out of scope — kernel/bootloader config |
| Identity and Access Management | HSM library | HSM-REQ-037 (handle-scoped sessions) |
| Secure Feature Activation | HSM library | HSM-REQ-049 (new) |
| Secure software update | Firmware | HSM-REQ-047 (new) |

### HSM-REQ-046 — Secure boot
**SCORE:** stkh_req__dependability__security_features (Secure boot sub-item)
The STM32L552 firmware shall verify its own image signature at reset before executing
application code. The verification public key shall be provisioned into OTP (option bytes)
during manufacturing. Images failing verification shall halt the boot sequence and assert
a diagnostic fault signal. The HSM library shall expose the boot verification result via
a `boot_status()` query so the host can confirm secure boot succeeded before issuing
cryptographic operations.

### HSM-REQ-047 — Secure software update
**SCORE:** stkh_req__dependability__security_features (Secure software update sub-item)
The firmware shall verify firmware update images against a code-signing certificate
before applying them. The code-signing certificate shall be provisioned via
HSM-REQ-018 (certificate management). Rollback to a version with a lower monotonic
version counter shall be rejected. Failed update verification shall emit an
`IdsEvent::UpdateRejected` event (HSM-REQ-038).

### HSM-REQ-048 — IPSec / MACSec key material provisioning
**SCORE:** stkh_req__dependability__security_features (Secure onboard communication,
IPSec and MACSec sub-items)
The HSM shall provide key generation, ECDH key agreement, and HMAC operations
required by IPSec IKEv2 and MACSec Key Agreement (MKA) protocol stacks.
The protocol stack implementation itself is a platform concern outside the HSM
library boundary. The HSM API shall not expose raw session keys; key handles shall
be passed to the stack which invokes the HSM for each cryptographic operation.

### HSM-REQ-049 — Secure feature activation
**SCORE:** stkh_req__dependability__security_features (Secure Feature Activation sub-item)
The security component shall provide a `feature_activate(token: &[u8]) -> HsmResult<()>`
operation that verifies a signed activation token against the provisioned feature-authority
certificate (stored via HSM-REQ-018) and sets the corresponding feature flag in
authenticated non-volatile storage. Tokens shall include a monotonic counter to prevent
replay. Invalid or replayed tokens shall emit `IdsEvent::ActivationRejected`.

---

## 14. Software Safety Requirements (SSR) — ISO 26262-6 ASIL B

These requirements are derived from the FSR/TSR safety requirement chain (SCORE-FSR →
SCORE-TSR) and govern the `scorehsm-host` library at the implementation level. Each
requirement carries bidirectional traceability to a TSR and is testable in CI via
`MockHardwareBackend` without physical hardware.

**ASIL:** All requirements in this section are ASIL B unless noted otherwise.

### 14a. Transport Integrity

### HSM-REQ-050 — CRC-32/MPEG-2 frame integrity check
**TSR:** TSR-TIG-01 | **FSR:** FSR-08 | **SG:** SG-05
Every USB CDC command frame sent to the L55 and every response frame received from the L55
shall carry a 4-byte CRC-32/MPEG-2 check value (polynomial 0x04C11DB7, init 0xFFFFFFFF)
computed over the entire frame. The receiver shall recompute and compare; a mismatch shall
return `HsmError::CrcMismatch` and the frame payload shall not be used.

### HSM-REQ-051 — 32-bit monotonic sequence numbers
**TSR:** TSR-TIG-02 | **FSR:** FSR-09 | **SG:** SG-05
The host library shall maintain a 32-bit unsigned sequence number initialized to 1 and
incremented by 1 per command. Each response frame shall echo the command's sequence number.
A mismatched echo shall return `HsmError::ProtocolError`. At value `0xFFFF_FFFF` the library
shall refuse further operations with `HsmError::SequenceOverflow` and require re-initialization.

### HSM-REQ-052 — Per-operation command timeout
**TSR:** TSR-TIG-03 | **FSR:** FSR-10 | **SG:** SG-06
The library shall apply per-operation timeouts: AES/hash/HMAC/RNG 100 ms; ECDSA sign/verify
and ECDH 2000 ms; key generation 5000 ms; administrative 500 ms. Timeout shall return
`HsmError::Timeout`. All timeouts shall be configurable via `HsmConfig`.

### HSM-REQ-053 — Retry policy and persistent-failure safe state
**TSR:** TSR-TIG-04 | **FSR:** FSR-08, FSR-10 | **SG:** SG-05, SG-06
On CRC mismatch or timeout, the library shall retry up to 2 times with exponential back-off
(initial 10 ms, factor 2). After 3 consecutive failures on the same operation the library
shall enter safe state (HSM-REQ-063). A single retry success shall reset the consecutive
failure counter.

### 14b. Nonce Management

### HSM-REQ-054 — Per-key nonce counter in persistent storage
**TSR:** TSR-NMG-01 | **FSR:** FSR-06, FSR-07 | **SG:** SG-04
For each key handle used in AEAD encryption the library shall maintain a 64-bit monotonic
nonce counter stored in a local SQLite WAL database (`nonce_counters(key_id, counter)`).
The counter shall be incremented and persisted to disk **before** each AEAD invocation.
On nonce counter overflow (reaching `u64::MAX`) the library shall reject the operation
with `HsmError::NonceExhausted` and require key rotation.

### HSM-REQ-055 — Library-controlled IV derivation
**TSR:** TSR-NMG-01 | **FSR:** FSR-06 | **SG:** SG-04
The 12-byte GCM IV shall be derived by the library as
`HKDF-SHA256(ikm=key_id || counter, info=algo_domain_string, length=12)`.
The library shall reject any caller-supplied IV for AEAD encryption.

### HSM-REQ-056 — HKDF domain separation
**TSR:** TSR-NMG-02 | **FSR:** FSR-06 | **SG:** SG-04
Every HKDF invocation shall use a non-empty algorithm-specific `info` string from the
approved table in SCORE-TSR §3 (TSR-NMG-02). The HKDF API shall return
`HsmError::InvalidArgument` if an empty `info` string is supplied.

### 14c. Session Management

### HSM-REQ-057 — Session-scoped key handle validation
**TSR:** TSR-SMG-01 | **FSR:** FSR-12 | **SG:** SG-07
The library shall maintain a `HashMap<SessionId, HashSet<KeyHandle>>`. Every operation
that accepts a key handle shall look up the handle in the caller's session set only.
A handle present in a different session's set shall be rejected with `HsmError::InvalidHandle`.

### HSM-REQ-058 — Session inactivity timeout
**TSR:** TSR-SMG-02 | **FSR:** FSR-13 | **SG:** SG-06, SG-07
Each session shall record the `std::time::Instant` of its last completed operation.
A background sweep (interval ≤1 s) shall terminate sessions idle longer than the
configured timeout (default 300 s). Termination invalidates all session handles and
emits a `SessionExpired` IDS event.

### HSM-REQ-059 — Maximum concurrent sessions
**TSR:** TSR-SMG-03 | **FSR:** FSR-14 | **SG:** SG-06
The library shall enforce a configurable maximum number of concurrent sessions (default 8,
configurable via `HsmConfig::max_sessions`). Exceeding the limit shall return
`HsmError::ResourceExhausted`.

### 14d. Rate Limiting

### HSM-REQ-060 — Token-bucket rate limiter per operation class
**TSR:** TSR-RLG-01 | **FSR:** FSR-14 | **SG:** SG-06
The library shall implement a token-bucket rate limiter enforced globally across all sessions
with the following defaults: ECDSA sign 10 ops/s burst 5; ECDSA verify 20 ops/s burst 10;
key generation 2 ops/s burst 1; ECDH 10 ops/s burst 5; AES-GCM 100 ops/s burst 20.
Requests exceeding the limit shall return `HsmError::RateLimitExceeded` immediately.
All limits shall be configurable via `HsmConfig::rate_limits`.

### 14e. Safe State

### HSM-REQ-061 — Library state machine
**TSR:** TSR-SSG-01 | **FSR:** FSR-10, FSR-11 | **SG:** SG-06
The library shall implement states `{Initializing, Ready, Operating, SafeState}` using an
`AtomicU8` with `SeqCst` ordering. Transitions are:
`Initializing → Ready` (on successful init);
`Ready/Operating ↔ Operating` (normal ops);
`Any → SafeState` (on any integrity fault listed in TSR-SSG-01).
Re-initialization (`hsm_reinit()`) is the only exit from `SafeState`.

### HSM-REQ-062 — Safe state blocks all operations
**TSR:** TSR-SSG-01 | **FSR:** FSR-11 | **SG:** SG-06
While in `SafeState`, every incoming operation request (crypto, session, key management)
shall return `HsmError::SafeState` immediately without contacting the L55. Active sessions
shall be invalidated on safe state entry.

### HSM-REQ-063 — Safe state triggers
**TSR:** TSR-SSG-01 | **FSR:** FSR-10 | **SG:** SG-06
The following events shall unconditionally trigger safe state entry:
(a) CRC mismatch after max retries; (b) sequence number mismatch; (c) key store integrity
check failure (HSM-REQ-065); (d) L55 fault opcode received; (e) session state
inconsistency detected during handle lookup.

### HSM-REQ-064 — Safe state IDS event
**TSR:** TSR-SSG-01 | **FSR:** FSR-11 | **SG:** SG-06
On safe state entry the library shall emit a `LibrarySafeState` event to the IDS hook
containing the triggering condition code, the sequence number of the failing command, and
the current session count at time of entry.

### HSM-REQ-065 — Key store map integrity checksum
**TSR:** TSR-SSG-02 | **FSR:** FSR-10 | **SG:** SG-06
The session/handle map shall carry a CRC-32 checksum of its serialized content, updated on
every write. On every read access the checksum shall be verified. A mismatch shall trigger
safe state (HSM-REQ-063) with `HsmError::IntegrityViolation`.

### 14f. Key Lifecycle Safety

### HSM-REQ-066 — ZeroizeOnDrop on all key-material types
**TSR:** TSR-KLG-01 | **FSR:** FSR-05 | **SG:** SG-03 | **ASIL:** B(d)
Every Rust type that contains raw key bytes shall derive `ZeroizeOnDrop` from the `zeroize`
crate. A compile-time assertion in each file containing such a type shall verify the
`ZeroizeOnDrop` bound is present. This requirement extends HSM-REQ-023.

### HSM-REQ-067 — No key export opcode
**TSR:** TSR-KLG-02 | **FSR:** FSR-04 | **SG:** SG-03 | **ASIL:** B(d)
The USB CDC opcode table shall contain no opcode that returns raw key material from the L55
to the host. Each firmware release shall be verified against this invariant as part of the
opcode audit documented in the verification report.

### 14g. Hardware Identity Verification

### HSM-REQ-068 — Startup capability handshake
**TSR:** TSR-IVG-01 | **FSR:** FSR-15 | **SG:** SG-01, SG-02, SG-06
During `hsm_init()`, before accepting any crypto operation, the library shall: (1) verify
USB VID/PID; (2) send `CMD_GET_CAPABILITIES` with sequence number 0; (3) verify the
response CRC-32 and sequence number echo; (4) verify firmware version ≥ minimum configured
version; (5) verify the capability bitmask includes all required operations. Any failure
shall return `HsmError::InitializationFailed` and the library shall remain in
`Initializing` state.

### HSM-REQ-069 — VID/PID recheck on re-enumeration
**TSR:** TSR-IVG-01 | **FSR:** FSR-15 | **SG:** SG-01
On USB re-enumeration while the library is in `Ready` or `Operating` state, the library
shall re-verify the VID/PID. If the device identity changes, the library shall enter safe
state with `HsmError::DeviceIdentityChanged`.

### 14h. Certificate Safety

### HSM-REQ-070 — Certificate validity window enforcement
**TSR:** TSR-CG-01 | **FSR:** FSR-16 | **SG:** SG-01
Before any operation that uses a certificate, the library shall check `notBefore ≤ now ≤
notAfter` using `std::time::SystemTime::now()`. An expired certificate shall return
`HsmError::CertificateExpired`. A pre-valid certificate shall return
`HsmError::CertificateNotYetValid`.

### HSM-REQ-071 — Clock unavailability rejects certificate operations
**TSR:** TSR-CG-01 | **FSR:** FSR-16 | **SG:** SG-01
If `SystemTime::now()` returns an error (clock unavailable), all operations requiring
certificate validation shall return `HsmError::ClockUnavailable`. The library shall not
proceed with certificate-based operations using an unverified time source.

### 14i. Verification Safety Properties

### HSM-REQ-072 — Verification returns definitive result only
**TSR:** (direct FSR implementation) | **FSR:** FSR-01 | **SG:** SG-01
`verify()`, `aead_decrypt()`, and `mac_verify()` shall return either a definitive success
(`Ok(data)` or `Ok(true)`) or an error. Partial decryption buffers shall not be exposed
to the caller on error. If AEAD tag verification fails, the output buffer shall be
zeroed before returning `HsmError::AuthenticationFailed`.

### HSM-REQ-073 — Constant-time tag and signature comparison
**TSR:** (direct FSR implementation) | **FSR:** FSR-02 | **SG:** SG-01
All comparison operations that determine the outcome of a cryptographic verification shall
use a constant-time comparison function (e.g., `subtle::ConstantTimeEq`). Conditional
branches dependent on secret comparison state are prohibited.

### 14j. Power-On Self-Test (POST)

### HSM-REQ-074 — AES-GCM known-answer test at initialization
**FSR:** FSR-03 | **SG:** SG-01, SG-02
During `hsm_init()`, the library shall execute a known-answer test (KAT) for AES-256-GCM
using a fixed test vector from NIST SP 800-38D. If the computed ciphertext or tag does not
match the expected value, initialization shall fail with `HsmError::SelfTestFailed`.

### HSM-REQ-075 — ECDSA known-answer test at initialization
**FSR:** FSR-03 | **SG:** SG-01
During `hsm_init()`, the library shall execute a known-answer test for ECDSA P-256 sign
and verify using a fixed test vector. A sign/verify cycle that fails shall cause
initialization to fail with `HsmError::SelfTestFailed`.

### HSM-REQ-076 — POST failure prevents Ready state
**FSR:** FSR-10, FSR-11 | **SG:** SG-06
If any POST (HSM-REQ-074 or HSM-REQ-075) fails, the library shall remain in
`Initializing` state and return `HsmError::SelfTestFailed`. The library shall not
transition to `Ready` until all POST steps pass.

### 14k. Test Infrastructure

### HSM-REQ-077 — MockHardwareBackend for CI coverage
**FSR:** FSR-03, FSR-08, FSR-09, FSR-10, FSR-11 | **SG:** all
A `MockHardwareBackend` shall be provided in the test infrastructure that implements
`HsmBackend` by simulating USB CDC protocol responses in-process. The mock shall support:
injection of CRC errors, sequence number mismatches, timeouts, L55 fault opcodes, and
configurable operation latency. All HSM-REQ-050..076 tests shall pass using this mock
without requiring physical hardware.

---

## Traceability Summary

| HSM-REQ | SCORE req ID | Status |
|---|---|---|
| HSM-REQ-001 | feat_req__sec_crypt__sym_symmetric_encrypt | Derived |
| HSM-REQ-002 | feat_req__sec_crypt__sym_sym_algo_aes_gcm | Derived |
| HSM-REQ-003 | feat_req__sec_crypt__sym_symm_algo_aes_cbc | Derived |
| HSM-REQ-004 | feat_req__sec_crypt__sym_sym_algo_aes_ccm | Derived |
| HSM-REQ-005 | feat_req__sec_crypt__sym_algo_chacha20 | Derived |
| HSM-REQ-006 | feat_req__sec_crypt__asym_encryption | Derived |
| HSM-REQ-007 | feat_req__sec_crypt__asym_algo_ecdh | Derived |
| HSM-REQ-008 | feat_req__sec_crypt__sig_creation | Derived |
| HSM-REQ-009 | feat_req__sec_crypt__sig_verification | Derived |
| HSM-REQ-010 | feat_req__sec_crypt__sig_algo_ecdsa | Derived |
| HSM-REQ-011 | feat_req__sec_crypt__mac | Derived |
| HSM-REQ-012 | feat_req__sec_crypt__hashing | Derived |
| HSM-REQ-013 | feat_req__sec_crypt__hashing_algo_sha2 | Derived |
| HSM-REQ-014 | feat_req__sec_crypt__hashing_algo_sha3 | Derived |
| HSM-REQ-015 | feat_req__sec_crypt__kdf | Derived |
| HSM-REQ-016 | feat_req__sec_crypt__rng | Derived |
| HSM-REQ-017 | feat_req__sec_crypt__rng_algo_chacha20rng | Derived |
| HSM-REQ-018 | feat_req__sec_crypt__cert_management | Derived |
| HSM-REQ-019 | feat_req__sec_crypt__key_generation | Derived |
| HSM-REQ-020 | feat_req__sec_crypt__key_import | Derived |
| HSM-REQ-021 | feat_req__sec_crypt__key_storage | Derived |
| HSM-REQ-022 | feat_req__sec_crypt__key_deletion | Derived |
| HSM-REQ-023 | feat_req__sec_crypt__no_key_exposure | Derived + SG-01/SG-04 |
| HSM-REQ-024 | feat_req__sec_crypt__flexible_api | Derived |
| HSM-REQ-025 | feat_req__sec_crypt__algo_naming | Derived |
| HSM-REQ-026 | feat_req__sec_crypt__api_lifecycle | Derived |
| HSM-REQ-027 | feat_req__sec_crypt__error_handling | Derived |
| HSM-REQ-028 | feat_req__sec_crypt__performance_tooling | Derived |
| HSM-REQ-029 | feat_req__sec_crypt__side_channel_mitigation | Derived |
| HSM-REQ-030 | feat_req__sec_crypt__algo_updates | Derived |
| HSM-REQ-031 | feat_req__sec_crypt__reverse_eng_protection | Derived + SG-03/SG-05 |
| HSM-REQ-032 | feat_req__sec_crypt__production_keys | Derived |
| HSM-REQ-033 | feat_req__sec_crypt__pqc_readiness | Derived |
| HSM-REQ-034 | feat_req__sec_crypt__hw_acceleration | Derived |
| HSM-REQ-035 | feat_req__sec_crypt__sw_fallback | Derived |
| HSM-REQ-036 | feat_req__sec_crypt__os_protection | Derived + SG-03 |
| HSM-REQ-037 | feat_req__sec_crypt__access_control | Derived |
| HSM-REQ-038 | feat_req__sec_crypt__ids_integration | Derived + SG-09 |
| HSM-REQ-039 | feat_req__sec_crypt__dos_mitigation | Derived + SG-06 |
| HSM-REQ-040 | feat_req__sec_crypt__tls_support | Derived |
| HSM-REQ-041 | — (new, SG-02) | New — threat model |
| HSM-REQ-042 | — (new, SG-01) | New — threat model |
| HSM-REQ-043 | — (new, SG-05) | New — threat model |
| HSM-REQ-044 | — (new, SG-07) | New — threat model |
| HSM-REQ-045 | — (new, SG-08) | New — threat model |
| HSM-REQ-046 | stkh_req__dependability__security_features (secure boot) | New — stakeholder req |
| HSM-REQ-047 | stkh_req__dependability__security_features (secure update) | New — stakeholder req |
| HSM-REQ-048 | stkh_req__dependability__security_features (IPSec/MACSec) | New — stakeholder req |
| HSM-REQ-049 | stkh_req__dependability__security_features (feature activation) | New — stakeholder req |
| HSM-REQ-050 | TSR-TIG-01 / FSR-08 / SG-05 | New — SSR (transport CRC-32) |
| HSM-REQ-051 | TSR-TIG-02 / FSR-09 / SG-05 | New — SSR (sequence numbers) |
| HSM-REQ-052 | TSR-TIG-03 / FSR-10 / SG-06 | New — SSR (command timeout) |
| HSM-REQ-053 | TSR-TIG-04 / FSR-08,10 / SG-05,06 | New — SSR (retry + safe state) |
| HSM-REQ-054 | TSR-NMG-01 / FSR-06,07 / SG-04 | New — SSR (nonce counter persistent) |
| HSM-REQ-055 | TSR-NMG-01 / FSR-06 / SG-04 | New — SSR (library IV derivation) |
| HSM-REQ-056 | TSR-NMG-02 / FSR-06 / SG-04 | New — SSR (HKDF domain sep) |
| HSM-REQ-057 | TSR-SMG-01 / FSR-12 / SG-07 | New — SSR (session handle map) |
| HSM-REQ-058 | TSR-SMG-02 / FSR-13 / SG-06,07 | New — SSR (session timeout) |
| HSM-REQ-059 | TSR-SMG-03 / FSR-14 / SG-06 | New — SSR (max sessions) |
| HSM-REQ-060 | TSR-RLG-01 / FSR-14 / SG-06 | New — SSR (rate limiter) |
| HSM-REQ-061 | TSR-SSG-01 / FSR-10,11 / SG-06 | New — SSR (state machine) |
| HSM-REQ-062 | TSR-SSG-01 / FSR-11 / SG-06 | New — SSR (safe state blocks ops) |
| HSM-REQ-063 | TSR-SSG-01 / FSR-10 / SG-06 | New — SSR (safe state triggers) |
| HSM-REQ-064 | TSR-SSG-01 / FSR-11 / SG-06 | New — SSR (safe state IDS event) |
| HSM-REQ-065 | TSR-SSG-02 / FSR-10 / SG-06 | New — SSR (key store checksum) |
| HSM-REQ-066 | TSR-KLG-01 / FSR-05 / SG-03 | New — SSR (ZeroizeOnDrop) |
| HSM-REQ-067 | TSR-KLG-02 / FSR-04 / SG-03 | New — SSR (no key export opcode) |
| HSM-REQ-068 | TSR-IVG-01 / FSR-15 / SG-01,02,06 | New — SSR (startup handshake) |
| HSM-REQ-069 | TSR-IVG-01 / FSR-15 / SG-01 | New — SSR (VID/PID recheck) |
| HSM-REQ-070 | TSR-CG-01 / FSR-16 / SG-01 | New — SSR (cert validity window) |
| HSM-REQ-071 | TSR-CG-01 / FSR-16 / SG-01 | New — SSR (clock unavail rejects cert) |
| HSM-REQ-072 | FSR-01 / SG-01 | New — SSR (definitive verify result) |
| HSM-REQ-073 | FSR-02 / SG-01 | New — SSR (constant-time compare) |
| HSM-REQ-074 | FSR-03 / SG-01,02 | New — SSR (AES-GCM KAT at init) |
| HSM-REQ-075 | FSR-03 / SG-01 | New — SSR (ECDSA KAT at init) |
| HSM-REQ-076 | FSR-10,11 / SG-06 | New — SSR (POST failure blocks Ready) |
| HSM-REQ-077 | FSR-03,08,09,10,11 / all SGs | New — SSR (MockHardwareBackend) |

**Total: 77 requirements**
- 43 SCORE feat_req-derived (HSM-REQ-001..043)
- 6 threat model / stakeholder (HSM-REQ-041..049, excluding duplicates in numbering)
- 28 Software Safety Requirements — ISO 26262-6 ASIL B (HSM-REQ-050..077)

**feat_req__sec_crypt__ coverage: 43/43 (100%)**
**stkh_req__dependability__security_features coverage: 10/10 (100%)**
**ISO 26262-6 FSR coverage: 16/16 FSRs → 28 SSRs (100% FSR allocation)**
**ISO 26262-6 TSR coverage: 16/16 TSRs allocated to SSRs (100%)**
