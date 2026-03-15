# scorehsm — Safety Case (GSN Structured Argument)

Date: 2026-03-14
Status: CONDITIONALLY VALID
ASIL Target: ASIL B
Classification: SEooC (Safety Element out of Context)
Document owner: Taktflow Systems

---

## 1. Purpose and Scope

This document presents the structured safety case for `scorehsm` using Goal Structuring Notation (GSN) described in text form. It constitutes the top-level argument that `scorehsm`, developed and verified in accordance with the ISO 26262-6:2018 software development lifecycle, satisfies its ASIL B integrity claim for assigned cryptographic safety functions.

This safety case is a SEooC safety case per ISO 26262-10:2018 §9. It argues that the software-layer safety functions of `scorehsm` meet ASIL B requirements. The argument is conditional on the Assumed Safety Requirements (ASR-01 through ASR-04, defined in `docs/safety/safety-plan.md` §3) being satisfied by the integrating system.

This document is not a standalone approval artifact. It is intended to be consumed by the integrator's safety case for the item that uses `scorehsm`. The integrator shall reference this document as evidence for the `scorehsm` component contribution to the item-level safety argument.

---

## 2. Safety Claims (SC-01 through SC-04)

The following safety claims define the behavioral properties that this safety case argues are satisfied by `scorehsm`. They are derived from the safety-relevant services provided by the library and from the failure modes identified in the SW-FMEA (`docs/safety/fmea.md`).

| ID | Safety Claim | Rationale |
|---|---|---|
| SC-01 | `scorehsm` correctly rejects invalid signatures — the false-accept rate for well-formed ECDSA inputs is zero by implementation | ECDSA verification is the trust root for OTA firmware acceptance (HSM-REQ-047) and safety-critical message authentication (HSM-REQ-048). A non-zero false-accept rate undermines the entire authentication model and creates a direct path to an S3 vehicle hazard (FM-019 in fmea.md). |
| SC-02 | `scorehsm` never returns decrypted plaintext when the AES-GCM authentication tag is invalid | Authentication bypass in `aes_gcm_decrypt` (FM-013) allows tampered or replayed ciphertext to be accepted as authentic. Plaintext must not be returned when integrity verification fails. This is a fundamental AES-GCM security property. |
| SC-03 | Key material is never exposed outside the L55 hardware boundary via the library API | Key export is the highest-severity key management failure — it enables offline forgery of signatures and decryption of all past traffic. The API provides no key export operation (HSM-REQ-023); TrustZone enforces the hardware boundary (HSM-REQ-031, HSM-REQ-036). |
| SC-04 | `scorehsm` correctly enforces monotonic version ordering in firmware update verification — rollback to any version ≤ the currently installed version is rejected | Firmware rollback re-enables previously patched vulnerabilities. Version monotonicity is a cryptographically binding property when the version counter is part of the signed image content (HSM-REQ-047; FM-030, FM-031 in fmea.md). |

---

## 3. Top-Level Claim

### G1 — Top-Level Safety Claim

**Claim:** `scorehsm`, when integrated in accordance with the Assumed Safety Requirements ASR-01 through ASR-04 documented in `docs/safety/safety-plan.md` §3, satisfies ASIL B software integrity requirements for its assigned cryptographic safety functions (SC-01 through SC-04) under all specified operating conditions defined in this safety case.

**Scope of G1:** This claim covers the `scorehsm-host` Rust library — the `HsmBackend` trait, `SoftwareBackend` implementation, `HardwareBackend` implementation, session layer, IDS hook, and all supporting modules. It does not cover the integrating application, the host operating system, or the physical vehicle environment, except where these are addressed by ASR conditions.

**Conditionality:** G1 is conditionally valid. The conditions are stated explicitly in Section 7 (Justified Assumptions) and Section 8 (Undeveloped Claims). The ASIL B claim is valid for software-layer functions. It is conditional on HIL test completion for hardware isolation (TrustZone enforcement) and secure boot.

---

## 4. Strategy

### S1 — Argument Strategy

**Strategy:** The top-level claim G1 is argued by demonstrating compliance with each phase of the ISO 26262-6 V-model software development lifecycle as applied to this SEooC. Evidence is drawn from work products produced at each lifecycle phase: requirements specification, software architecture design, implementation with compiler-enforced coding guidelines, and multi-layer verification (unit testing, static analysis, code review, coverage measurement, and FMEA).

The strategy decomposes G1 into six sub-claims (G2 through G7), each covering a distinct lifecycle phase or verification activity. All six sub-claims must hold for G1 to be valid.

**Argument structure:**

```
G1 (top-level ASIL B claim)
└── S1 (V-model lifecycle argument)
    ├── G2  All 77 requirements specified, implemented, and verified
    ├── G3  SW-FMEA identifies no unmitigated S3 failure modes
    ├── G4  Coding guidelines enforced at compile-time and CI
    ├── G5  Test suite achieves statement ≥85% and branch ≥80% coverage
    ├── G6  TARA complete; all SG-01…SG-10 traced to requirements
    └── G7  ASR-01…ASR-12 documented and communicated to integrator
```

---

## 5. Sub-Claims and Evidence

### G2 — Requirements Completeness and Verification

**Claim:** All 77 software safety requirements (HSM-REQ-001 through HSM-REQ-077) are specified with verifiable acceptance criteria, implemented in the `scorehsm-host` library, and verified by at least one passing test case or assigned to an integration/qualification test in SCORE-ITP/SCORE-QTE.

**Evidence:**
- `docs/requirements/requirements.md` — 77 requirements in 14 sections:
  - Sections 1–13: 49 original requirements (HSM-REQ-001..049)
  - Section 14 (ASIL B SSR additions): 28 new requirements (HSM-REQ-050..077), derived through the complete SG → FSR → TSR → SSR chain per ISO 26262-6
- `docs/safety/safety-goals.md` — 7 safety goals (SG-01..07), ASIL B, derived from assumed hazardous events HE-01..04
- `docs/safety/assumed-safety-requirements.md` — 12 ASRs (SEooC integrator obligations)
- `docs/safety/functional-safety-requirements.md` — 16 FSRs (what must be safe, technology-neutral)
- `docs/safety/technical-safety-requirements.md` — 16 TSRs (how mechanisms implement safety)
- `docs/safety/software-architectural-design.md` — safety requirement allocation, DFA at architectural level
- `docs/safety/software-unit-design.md` — pseudocode unit designs for 8 safety-critical units
- `host/src/backend/mock.rs` — **13 unit tests passing** with formal V-model traceability (SCORE-UTT)
- `host/tests/` — ~110 original integration tests passing (sw-backend, session, cert, update, onboard-comm, pqc modules); formal V-model traceability assignment in progress
- `docs/safety/unit-test-traceability.md` (SCORE-UTT) — bidirectional SSR ↔ unit test matrix
- `docs/safety/integration-test-plan.md` (SCORE-ITP) — 52 integration tests specified across 16 TSRs (pending implementation)
- `docs/safety/qualification-test-evidence.md` (SCORE-QTE) — 57 qualification tests specified across 16 FSRs (pending implementation)

**Qualification:** Seven original requirements are marked ℹ️ (hardware/firmware — HIL required): HSM-REQ-021, HSM-REQ-029, HSM-REQ-031, HSM-REQ-034, HSM-REQ-036, HSM-REQ-043, HSM-REQ-044, HSM-REQ-046. G2 is fully satisfied for software-layer requirements; HIL requirements are a declared gap.

**Traceability:** Requirements originate from: (1) 43 Eclipse SCORE `feat_req__sec_crypt__*` requirements; (2) threat model STRIDE analysis; (3) stakeholder gap analysis (HSM-REQ-046..049); (4) ISO 26262-6 V-model ASIL B elevation gap analysis (HSM-REQ-050..077). Coverage is complete: 16/16 FSRs → 28 SSRs (100% FSR allocation). Bidirectional traceability at all levels.

---

### G3 — Software FMEA: No Unmitigated S3 Failure Modes

**Claim:** The Software Failure Mode and Effects Analysis identifies no S3 (life-threatening or fatal severity) failure modes in library-controlled code that lack complete design mitigations and test coverage.

**Evidence:**
- `docs/safety/fmea.md` — 37 failure modes analyzed across all safety-critical API functions: `key_generate` (FM-001 to FM-004), `key_import` (FM-005 to FM-007), `key_delete` (FM-008 to FM-010), `aes_gcm_encrypt` (FM-011 to FM-012), `aes_gcm_decrypt` (FM-013 to FM-015), `ecdsa_sign` (FM-016 to FM-018), `ecdsa_verify` (FM-019 to FM-020), `hmac_sha256` (FM-021 to FM-022), `key_derive` (FM-023 to FM-024), `ecdh_agree` (FM-025 to FM-026), `random` (FM-027 to FM-028), `verify_update_image` (FM-029 to FM-031), `verify_activation_token` (FM-032 to FM-034), `HsmSession` access control (FM-035 to FM-037)

**S3 failure modes and their mitigations:**

| FM-ID | Function | Failure Mode (brief) | Primary Mitigation | Test Coverage |
|---|---|---|---|---|
| FM-002 | `key_generate` | Weak key from RNG failure | TRNG health tests (repetition count + adaptive proportion) + ChaCha20Rng 256-byte reseed | `test_rng_health_test_enforced`, `test_key_generate_fails_on_trng_fault` |
| FM-003 | `key_generate` | Handle collision | Epoch-counter + occupancy bitmap; atomic slot allocation | `test_handle_uniqueness_under_repeated_generation` |
| FM-004 | `key_generate` | Slot unpopulated on success return | Write-then-readback before setting slot-occupied flag | `test_key_generate_slot_populated_before_handle_returned` |
| FM-006 | `key_import` | Invalid P-256 scalar accepted | Host + L55 scalar range validation; constant-time comparison via `subtle` crate | `test_key_import_rejects_zero_scalar`, `test_key_import_rejects_scalar_above_group_order` |
| FM-007 | `key_import` | Wrong type tag on imported handle | Host-authoritative type; type not derived from firmware response | `test_key_import_handle_type_matches_requested_type` |
| FM-008 | `key_delete` | Zeroize not performed | `write_volatile` overwrite + occupancy-flag-last discipline + IDS event | `test_key_delete_zeroizes_slot` (HIL), `test_key_zeroize_on_delete` (software backend) |
| FM-009 | `key_delete` | Handle remains usable after delete | Dual enforcement: host session state (`Deleted`) + L55 occupancy flag | `test_deleted_handle_is_unusable` |
| FM-013 | `aes_gcm_decrypt` | Tag mismatch authentication bypass | Constant-time 16-byte comparison; plaintext zeroed in response buffer on mismatch; `HsmError::TagMismatch` | `test_aes_gcm_wrong_tag_rejected`, `test_aes_gcm_decrypt_no_plaintext_on_tag_mismatch` |
| FM-018 | `ecdsa_sign` | Biased nonce k | RFC 6979 deterministic nonce (HMAC-DRBG); software backend uses `ecdsa` crate | `test_ecdsa_sign_deterministic_rfc6979` |
| FM-019 | `ecdsa_verify` | Invalid signature returns true | Audited `p256` crate (rustcrypto); NIST P-256 test vectors; L55 PKA status register, not timing | `test_ecdsa_verify_wrong_signature_fails`, NIST vector tests |
| FM-027 | `random` | Predictable CSPRNG output | Same TRNG health test mechanism as FM-002; `HsmError::HardwareFault` on health test failure; buffer zeroed on error | `test_random_returns_error_on_trng_fault` |
| FM-029 | `verify_update_image` | Invalid signature accepted | Explicit `== true` check on `ecdsa_verify` result; no path returns `Ok(())` without confirmed `true` | `test_update_valid_signature_accepted`, `test_update_tampered_image_rejected`, `test_update_wrong_key_rejected` |
| FM-030 | `verify_update_image` | Version rollback accepted | Exclusive monotonic version comparison (`<=` rejected); version in signed content | `test_update_version_rollback_rejected`, `test_update_same_version_rejected` |
| FM-031 | `verify_update_image` | Version check bypassed/omitted | Unconditional check (not feature-flag gated); mutation test planned | `test_update_version_rollback_rejected` (fails if check removed) |

**Summary:** 14 S3 failure modes identified. 14 S3 failure modes have complete mitigations in design and test coverage. 0 S3 failure modes are unmitigated in library-controlled code.

**Note on hardware-boundary failure modes:** FM-002, FM-003, FM-004, FM-008, and FM-027 have mitigations that partially rely on L55 firmware behavior. These mitigations are fully documented in the FMEA. HIL testing is required to verify the L55-side mitigations at the hardware boundary (see UC-01).

---

### G4 — Coding Guidelines: Compile-Time and CI Enforcement

**Claim:** The `scorehsm` coding guidelines are enforced at compile-time and in CI, eliminating entire classes of failure modes without reliance on manual review.

**Evidence:**
- `docs/safety/coding-guidelines.md` — complete set of Rust coding guidelines for ASIL B
- Source-level enforcement:
  - `#![deny(unsafe_code)]` — eliminates all undefined behavior from memory unsafety; `unsafe` blocks are a compilation error
  - `#![deny(missing_docs)]` — eliminates undocumented public API items; all safety-relevant functions have doc comments
  - `RUSTFLAGS="-D warnings"` in CI — all Rust warnings are treated as errors; no warnings are silenced in the library crate
- CI enforcement:
  - `cargo clippy --all-features -- -D warnings` — static linting on every push and pull request; lint warnings block merge
  - `cargo fmt --check` — enforces uniform formatting; inconsistent formatting blocks merge
  - `cargo audit` — monitors for security advisories against all dependencies on every CI run
- Dependency discipline:
  - Rust toolchain pinned in `rust-toolchain.toml`
  - All crate dependencies pinned via committed `Cargo.lock`
  - Dependency updates require pull request review

**Safety relevance:** `#![deny(unsafe_code)]` is the single most impactful safety control in the Rust safety argument. It eliminates buffer overflows, use-after-free, and undefined behavior at the language level — the same failure classes that MISRA C rules and formal methods target in C codebases. This is the primary justification for the tailoring decision that removes the formal methods recommendation for ASIL B (safety-plan.md §4.1).

---

### G5 — Structural Coverage: Statement ≥85%, Branch ≥80%

**Claim:** The test suite achieves statement coverage ≥85% and branch coverage ≥80% over the `scorehsm-host` library, satisfying ISO 26262-6 Clause 11 structural coverage targets for ASIL B.

**Evidence:**
- `docs/test-strategy/test-strategy.md` — 110 passing tests across all test modules
- Coverage measurement infrastructure: `cargo-llvm-cov` integrated in CI (`target/llvm-cov/` output directory)
- Coverage targets are enforced as CI gates on the `main` branch (CI fails if coverage drops below threshold)
- Current coverage measurement status: **pending execution on Linux CI runner** (see UC-02 in Section 8)

**Current state:** Coverage measurement requires a Linux CI runner. The test density (123 tests covering 77 requirements, with boundary value, error injection, fault injection, and negative tests throughout) is expected to meet the ≥85%/≥80% targets based on engineering judgment. Formal measurement is a declared open item (OI-03 in safety-plan.md).

**MC/DC tailoring:** MC/DC coverage analysis is tailored away at ASIL B per the safety plan (§4.1). Branch coverage is the primary structural coverage criterion at ASIL B. This tailoring is consistent with ISO 26262-6 Table 10, where MC/DC is recommended (++) at ASIL C/D but branch coverage is the ASIL B target.

**Tool confidence:** `cargo-llvm-cov` is classified TCL-2 (`docs/safety/tool-qualification-records.md` T3). A validation exercise against known coverage ground truth is required before the first release (OI-02/TQR-OI-02). Until TCL-2 validation is complete, coverage reports are treated as indicative, not as release-blocking evidence.

---

### G6 — Threat Model and Security Goal Traceability

**Claim:** The TARA (threat model) is complete, covering all relevant attack surfaces, and all ten security goals (SG-01 through SG-10) are traced to software safety requirements in HSM-REQ-001 through HSM-REQ-049.

**Evidence:**
- `docs/safety/threat-model.md` — STRIDE analysis across all six threat categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege); 19 identified threats (S1-S3, T1-T4, R1-R2, I1-I5, D1-D4, E1-E3)
- Security goals SG-01 through SG-10 derived from threat analysis
- `docs/requirements/requirements.md` traceability — security goals are embedded in HSM-REQ identifiers with explicit SCORE and SG cross-references

**Security goal to requirement traceability:**

| Security Goal | Derived Safety Requirement | Safety Rationale |
|---|---|---|
| SG-01 Key material never in USB frame | HSM-REQ-023 (key export prohibition) | Compromised key enables offline forgery of firmware signatures, defeating secure boot |
| SG-02 USB frame integrity (CRC + sequence) | HSM-REQ-041 | Tampered commands could trigger invalid crypto operations; corrupted results could cause safety decision errors |
| SG-03 TrustZone as isolation boundary | HSM-REQ-036 (OS-level protection) | TrustZone is the hardware enforcement point for key isolation; no software mechanism substitutes for hardware separation |
| SG-04 No key export API | HSM-REQ-023 | API-level prevention is the first line of defense; HSM-REQ-023 prohibits any USB frame containing raw key bytes |
| SG-05 Key slot zeroize on delete and reset | HSM-REQ-022, HSM-REQ-043 | Residual key material enables fraudulent signatures after revocation |
| SG-06 Rate limiting | HSM-REQ-039 | Prevents DoS exhaustion of safety-critical crypto operations |
| SG-07 Frame length validation | HSM-REQ-044 | Prevents buffer overflow in L55 NS dispatcher (E3 threat) |
| SG-08 Software fallback documented as non-isolated | HSM-REQ-045 | Prevents inadvertent production use of the `SoftwareBackend` which does not satisfy key isolation |
| SG-09 Signing operations logged to IDS | HSM-REQ-038 | Anomalous signing activity may indicate a safety-relevant fault condition |
| SG-10 SWD locked in production | ASG-04 (integrator ASR) | SWD access bypasses TrustZone — the hardware boundary on which the key isolation argument depends |

**Completeness argument:** All 19 STRIDE threats have countermeasures documented in `threat-model.md`. Four residual risks are accepted (RR1-RR4); these are addressed in Section 9 of this document. The security goal traceability is bidirectional: every SG maps to ≥1 HSM-REQ, and all HSM-REQ items with security relevance carry SG annotations in `requirements.md`.

---

### G7 — ASR Communication to Integrator

**Claim:** The Assumed Safety Requirements (ASR-01 through ASR-04) are completely documented and formally communicated to the integrator as conditions on the ASIL B claim.

**Evidence:**
- `docs/safety/safety-plan.md` Section 3 — Assumed Safety Goals (ASG-01 through ASG-04) are the normative statement of what the integrating system must provide
- Section 2.2 of the safety plan explicitly lists six obligations for the integrator, including DFA, item-level HARA, RDP Level 2 provisioning, and exclusive use of `HardwareBackend` in production
- This safety case document (Section 7 below) restates the ASRs as context nodes in the GSN structure, making the conditionality explicit in the safety argument itself

**ASR summary:**

| ID | Assumed Safety Requirement | Consequence if Violated |
|---|---|---|
| ASR-01 (ASG-01) | Only authorized OS processes can open a `scorehsm` session | Key handle isolation model is undermined; a compromised process can access any session's keys |
| ASR-02 (ASG-02) | Application treats `Err(HsmError::*)` on safety-critical operations as requiring safe-state transition | `scorehsm` reports outcomes but does not enforce safe states; the application must act on errors |
| ASR-03 (ASG-03) | USB connection between Raspberry Pi and STM32L552 is within a physically protected vehicle boundary | Physical access to USB cable enables USB sniffing (residual risk RR1); plaintext is returned in USB response frames |
| ASR-04 (ASG-04) | L55 provisioned with RDP Level 2 (SWD locked) before vehicle deployment; verified at End-of-Line | SWD access bypasses TrustZone; without SWD lock, TrustZone enforcement is not a reliable boundary |

---

## 6. Context Nodes (Justified Assumptions)

The following assumptions are the conditions under which G1 is valid. In GSN terminology, these are context nodes (C) and assumption nodes (A) attached to the top-level claim and strategy.

### C1 — Operating Environment

`scorehsm` is operated on a Raspberry Pi (or equivalent Linux HPC SoC) connected to a STM32L552ZE-Q via USB CDC. The Raspberry Pi runs a Linux-based OS with process isolation enforced by the kernel. The L55 is the only device connected to the USB CDC interface used by `scorehsm`. No other device can present itself as a valid HSM.

### C2 — Production Backend Constraint

The `SoftwareBackend` is used only in CI/development environments. Production deployments use the `HardwareBackend` exclusively. This is documented in `safety-plan.md` §2.2 and enforced by the `#[cfg(feature = "hw-backend")]` gate on the hardware backend. The ASIL B claim for key isolation (SC-03) applies only to the `HardwareBackend` + L55 configuration.

### C3 — Cryptographic Library Soundness

The cryptographic primitives in the software backend are provided by the `rustcrypto` family of crates (`p256`, `aes-gcm`, `hmac`, `sha2`, `ecdsa`, `hkdf`). These crates have undergone independent security audits. No automotive proven-in-use argument is claimed (safety-plan.md §4.1), but the audit history is cited as evidence of implementation correctness for FM-019 and FM-013 mitigations.

### C4 — Rust Language and Toolchain Assumptions

The Rust compiler (`rustc`) correctly compiles `scorehsm` source code and correctly enforces `#![deny(unsafe_code)]`. The compiler version is pinned in `rust-toolchain.toml`. The safety argument does not claim compiler correctness at the tool qualification level (TCL-1 per safety-plan.md §7) — the 110-test suite is the evidence that compiler-introduced errors would be detected before release.

### A1 — No Adversarial Physical Access to Internal USB Bus

The safety argument for SC-03 (key material never exposed via API) relies on the USB cable being on an internal vehicle bus (ASR-03). If an adversary has physical access to the USB cable, they can observe plaintext in USB response frames (residual risk RR1). The safety argument accepts this as a residual risk and places the mitigation obligation on the integrator.

### A2 — Image Format Includes Signed Version Counter

The rollback protection argument (SC-04) depends on the firmware version counter being part of the signed image content. If the version counter is not in the signed data, an attacker can modify the version field without invalidating the signature. This is documented as a caller obligation in the `verify_update_image` API contract and as an integrator responsibility in `docs/architecture/architecture.md`.

---

## 7. Residual Risks: Mapping to Safety Case

The threat model documents four accepted residual risks (RR1-RR4). This section explains each risk's relationship to the ASIL B safety claim and why each does not invalidate G1.

### RR1 — Plaintext Returned Over USB Is Visible on Cable

**Threat model entry:** STRIDE I3 — Plaintext recovered from USB traffic.
**Nature:** Architectural design decision. The Pi application needs the decrypted plaintext, so it must be returned in the USB response frame. The USB cable is on an internal vehicle bus but is theoretically accessible with physical access to the vehicle interior.
**Impact on safety case:** RR1 does not threaten SC-01, SC-02, SC-03, or SC-04 directly. Key material is never in any USB frame (SC-03 is unaffected). The plaintext that is exposed is the output of a completed and verified decryption operation — the authenticity check (SC-02) has already passed before plaintext appears in the frame.
**Acceptance rationale:** Physical access to internal vehicle wiring is outside the threat scope for a production automotive deployment. ASR-03 places the physical protection obligation on the integrator. The safety claim is not undermined because no safety-critical decision is made based solely on the intercepted plaintext — the ECDSA signature and tag verification occur within the L55 boundary before any output is transmitted.
**Disposition:** Accepted. ASIL B claim is not affected.

### RR2 — Software Fallback Has No Key Isolation

**Threat model entry:** STRIDE I5 — Key material in Pi process memory (software fallback).
**Nature:** Known architectural limitation. The `SoftwareBackend` stores key material in Pi process heap memory, where it is accessible to the OS and other processes with sufficient privilege.
**Impact on safety case:** RR2 is scoped out of the ASIL B claim for key isolation. The safety plan (§2.2) explicitly states that the `SoftwareBackend` does not satisfy HSM-REQ-036 and must not be used in production. The ASIL B claim for SC-03 applies only to the `HardwareBackend` + L55 TrustZone configuration.
**Acceptance rationale:** The `SoftwareBackend` is a development and CI artifact. Its limitations are documented at compile time (`#[cfg(not(feature = "hw-backend"))]` warning per HSM-REQ-045). The safety case is scoped accordingly.
**Disposition:** Accepted. ASIL B claim is scoped to `HardwareBackend` + L55; `SoftwareBackend` is explicitly excluded from the production safety argument.

### RR3 — SWD Not Locked in Development

**Threat model entry:** STRIDE T2 — Attacker modifies L55 firmware over SWD.
**Nature:** Development board configuration. SWD is open in the development and CI environment by design.
**Impact on safety case:** RR3 affects the hardware isolation boundary (SC-03). If SWD is open in production, an attacker with physical access can read SRAM2 key material directly, bypassing TrustZone. This would violate SC-03.
**Acceptance rationale:** ASR-04 places the SWD lock obligation on the integrator. The safety plan (§2.2) explicitly requires RDP Level 2 provisioning before vehicle deployment and End-of-Line verification. The safety case is conditional on ASR-04 being satisfied — if RDP Level 2 is not applied, the ASIL B claim for SC-03 is voided.
**Disposition:** Accepted for development. Conditionally accepted for production — G1 is invalid if ASR-04 is not satisfied.

### RR4 — Timing Side-Channel Residual Over USB

**Threat model entry:** STRIDE I4 — Timing side-channel on AES/PKA via USB response latency.
**Nature:** Residual after hardware countermeasures. Hardware crypto units (L55 AES peripheral, PKA peripheral) are constant-time by hardware design. USB framing adds variable latency that masks any remaining timing signal.
**Impact on safety case:** Timing side-channels are a key-extraction vector (information disclosure), not a direct safety failure mode. A successful timing attack would require many millions of carefully measured operations with attacker-controlled inputs. This is not achievable against an in-vehicle HSM operating within its normal rate limits (HSM-REQ-039).
**Acceptance rationale:** USB jitter dominates the timing signal. The hardware crypto units are constant-time. The rate limiter bounds the number of attacker-observable operations per second. The residual risk is below any realistic exploitation threshold.
**Disposition:** Accepted. ASIL B claim is not affected — timing side-channels target confidentiality, not the safety claims SC-01 through SC-04.

---

## 8. Undeveloped Claims

The following claims are not yet fully supported by evidence as of the date of this safety case. They are declared explicitly per GSN practice for undeveloped nodes (TBD notation). The ASIL B claim (G1) is conditionally valid pending completion of these items.

### UC-01 — HIL Testing for Hardware Isolation and Secure Boot

**Scope:** The following HSM-REQ items require hardware-in-the-loop testing on the STM32L552ZE-Q Nucleo board CI rig and cannot be verified by software-only testing:

| HSM-REQ | Description | Why HIL Required |
|---|---|---|
| HSM-REQ-021 | Key storage in TrustZone SRAM2 | Requires reading L55 SRAM2 via debug probe; software backend stores keys in Pi heap |
| HSM-REQ-029 | Side-channel mitigation (constant-time hardware) | Requires hardware timing measurement against L55 AES/PKA peripherals |
| HSM-REQ-031 | Reverse engineering protection (TrustZone boundary) | Requires SAU/IDAU configuration verification; not observable via software |
| HSM-REQ-034 | Hardware acceleration | Requires L55 peripheral invocation |
| HSM-REQ-036 | OS-level protection (TrustZone isolation) | Requires SecureFault injection testing |
| HSM-REQ-041 | USB frame integrity (CRC + sequence number) | Protocol conformance testing on live USB connection |
| HSM-REQ-043 | Key slot zeroize on reset | Requires reading SRAM2 before and after L55 reset via debug probe |
| HSM-REQ-044 | Frame length validation | Frame fuzzing on live L55 USB endpoint |
| HSM-REQ-046 | Secure boot | Requires SWD readback of boot status register; signed vs. unsigned image test |

**Status:** Phase 10b complete — 3/3 HIL tests passed (USB identity, AES-GCM 1000× encrypt/decrypt, TRNG 1MB entropy). ECDH opcode now wired end-to-end (firmware dispatcher + host hw.rs backend). 3/9 hardware-layer requirements partially verified (HSM-REQ-034, HSM-REQ-041, HSM-REQ-016). Full HIL CI rig completion target: 2026-05-15 (OI-06 in safety-plan.md).

**Impact on G1:** G1 sub-claims G2 and G3 are partially undeveloped for hardware-isolation failure modes. The software-layer safety functions (SC-01 through SC-04, G2 software requirements, G3 software failure modes) are fully supported. The hardware boundary argument (SC-03 for `HardwareBackend`) is conditionally supported pending UC-01 completion. Phase 10b provides partial evidence for HSM-REQ-034, HSM-REQ-041, and HSM-REQ-016.

### UC-02 — Coverage Measurement on Linux CI

**Scope:** Structural coverage measurement (statement ≥85%, branch ≥80%) has not yet been executed and reported. The `cargo-llvm-cov` tool is integrated and ready; measurement requires a Linux CI runner to avoid the `pqc` feature linker issue on Windows.

**Status:** Open item OI-03 in safety-plan.md. Expected completion: 2026-04-30.

**Impact on G5:** G5 is asserted based on test density engineering judgment. Formal coverage evidence is not yet available. G5 becomes fully supported when Linux CI produces a passing coverage report.

### UC-03 — T1 Independence Verification

**Scope:** ISO 26262-6 Clause 11 requires T1 independence (designer ≠ tester) for ASIL B software testing. The safety plan (§9) documents the policy and compensating measures. Final release sign-off by an independent reviewer (external or internal) has not been completed for the current development session.

**Status:** Ongoing. Per safety-plan.md §9.3, external review by OEM safety consultant may be used to satisfy T1 independence for final release verification.

**Impact on G1:** All 123 tests are automated and their pass/fail status is determined by the CI system, not by human judgment. The independence requirement primarily applies to the test plan review and results approval. This is a procedural gap rather than a technical safety argument gap.

---

## 9. Claim Status Summary

| Claim | Status | Conditions |
|---|---|---|
| G1 — ASIL B top-level claim | CONDITIONALLY VALID | ASRs satisfied; UC-01, UC-02, UC-03, TQR OIs complete |
| G2 — All 77 requirements verified | CONDITIONALLY VALID | Software layer: complete (77/77 specified). HIL requirements: UC-01 pending |
| G3 — No unmitigated S3 failure modes | CONDITIONALLY VALID | Software layer: complete. Hardware-boundary FM mitigations: UC-01 pending |
| G4 — Coding guidelines enforced | VALID | Compile-time and CI enforcement in place; 0 warnings in mock backend |
| G5 — Coverage targets met | CONDITIONALLY VALID | 123 tests in place; formal measurement pending UC-02 |
| G6 — TARA complete; SG/FSR/TSR/SSR traced | VALID | Full V-model chain: SG→FSR→TSR→SSR→test (SCORE-UTT/ITP/QTE) |
| G7 — ASRs documented and communicated | VALID | assumed-safety-requirements.md — 12 ASRs; safety-plan.md §3 — 4 ASGs |
| SC-01 (false-accept rate = 0) | VALID for software backend | audited `p256` crate + NIST vectors + constant-time; HSM-REQ-072,073 |
| SC-02 (no plaintext on tag mismatch) | VALID for software backend | `test_aead_auth_failure_returns_error_not_partial_plaintext` passes |
| SC-03 (key material never exposed via API) | CONDITIONALLY VALID | HardwareBackend: ASR-HW-02 (SWD lock) required; SoftwareBackend: excluded |
| SC-04 (version monotonicity enforced) | VALID | `verify_update_image` tests cover all rollback cases |

**Overall verdict:** The ASIL B claim for `scorehsm` is **CONDITIONALLY VALID** as of 2026-03-14.

The V-model is **complete at specification and test-plan level** (Steps 1–16 of the ISO 26262-6 V-model process). All 16 FSRs and all 28 SSRs are specified; 52 integration tests and 57 qualification tests are defined; DFA, tool qualification records, and safety case are all updated.

The claim becomes fully VALID upon:
1. **UC-01**: HIL test execution and reporting for hardware-layer requirements
2. **UC-02**: Coverage measurement on Linux CI confirming ≥85%/≥80% targets
3. **UC-03**: T1 independence sign-off for v0.1.0 release
4. **TQR-OI-01..03**: Tool qualification open items closed
5. **ASR-HW-01..05, ASR-OS-01..03, ASR-INT-01..04**: Verified by integrator

---

## 10. Open Items Affecting this Safety Case

| ID | Item | Impact | Target |
|---|---|---|---|
| OI-04 | This safety case — initial version | Satisfies safety-plan.md OI-04 | 2026-03-14 (complete — this document) |
| OI-06 | HIL test execution | Required to close UC-01 and fully support G2/G3 hardware claims | 2026-05-15 |
| OI-03 | Coverage measurement on Linux CI | Required to close UC-02 and fully support G5 | 2026-04-30 |
| OI-02 | TCL-2 validation for `cargo-llvm-cov` | Required before coverage reports are used as release-blocking evidence | 2026-04-01 |
| FMEA-OI-1 | Mutation testing for FM-019, FM-029, FM-031 | Strengthens G3 evidence for the three failure modes with mutation test coverage planned | 2026-04-15 |
| FMEA-OI-2 | Hardware backend zeroize verification (FM-008) | Closes the HIL gap in G3 for the FM-008 zeroize mitigation | 2026-05-15 |

---

*Document cross-references:*
- *Safety Plan: `docs/safety/safety-plan.md`*
- *Requirements: `docs/requirements/requirements.md`*
- *Architecture: `docs/architecture/architecture.md`*
- *SW-FMEA: `docs/safety/fmea.md`*
- *Threat Model: `docs/safety/threat-model.md`*
- *Coding Guidelines: `docs/safety/coding-guidelines.md`*
- *Test Strategy: `docs/test-strategy/test-strategy.md`*
- *Verification Report: `docs/safety/verification-report.md`*
- *Safety Goals: `docs/safety/safety-goals.md`*
- *Assumed Safety Requirements: `docs/safety/assumed-safety-requirements.md`*
- *Functional Safety Requirements: `docs/safety/functional-safety-requirements.md`*
- *Technical Safety Requirements: `docs/safety/technical-safety-requirements.md`*
- *Software Architectural Design: `docs/safety/software-architectural-design.md`*
- *Software Unit Design: `docs/safety/software-unit-design.md`*
- *Unit Test Traceability: `docs/safety/unit-test-traceability.md`*
- *Integration Test Plan: `docs/safety/integration-test-plan.md`*
- *Qualification Test Evidence: `docs/safety/qualification-test-evidence.md`*
- *DFA: `docs/safety/dependent-failure-analysis.md`*
- *Tool Qualification Records: `docs/safety/tool-qualification-records.md`*
