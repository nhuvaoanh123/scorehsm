# scorehsm — Requirements

Date: 2026-03-14
Status: COMPLETE
Backbone: Eclipse SCORE feat_req__sec_crypt__* (43 requirements)
Extensions: threat model security goals SG-01 to SG-10

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
Every USB command and response frame shall include a CRC-16 and a monotonic
sequence number. The receiver shall reject frames with invalid CRC or
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

**Total: 45 requirements (43 SCORE-derived + 2 new from threat model)**
**SCORE coverage: 43/43 (100%)**
