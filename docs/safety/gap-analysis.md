# SCORE-HSM Gap Analysis

| Field | Value |
|-------|-------|
| Document ID | SCORE-GAP |
| Date | 2026-03-26 |
| Revision | 1.0 |
| Status | RELEASED |
| Scope | Audit of scorehsm safety, verification, and test artefacts against ASIL B release criteria |

---

## 1  Release-Blocking Gaps

Items that **must** close before v0.1.0 can move from *conditional pass* to *full pass*.

| ID | Gap | Source | Owner | Target | Status |
|----|-----|--------|-------|--------|--------|
| RB-01 | HIL test execution — 6 of 9 hardware-layer requirements still pending: HSM-REQ-021 (TrustZone key storage), HSM-REQ-029 (constant-time HW), HSM-REQ-031 (TrustZone isolation), HSM-REQ-036 (OS-level protection), HSM-REQ-043 (SRAM2 zeroize), HSM-REQ-046 (secure boot) | SCORE-VER OVI-01 | Embedded Developer | 2026-05-15 | In progress |
| RB-02 | Coverage extraction — lcov.info generated in CI but statement (>=85%) and branch (>=80%) percentages not yet extracted | SCORE-VER OVI-02 | Host Library Developer | 2026-04-30 | Infrastructure ready |
| RB-03 | cargo-llvm-cov TCL-2 validation — KAT not executed; coverage reports remain indicative only, not admissible as release evidence | SCORE-TQR T3, SCORE-VER OVI-06 | Tester | 2026-04-01 | Open |
| RB-04 | T1 independence review sign-off — required for ASIL B procedural compliance (ISO 26262-6 Table 10) | SCORE-VER OVI-05, SCORE-TRM UC-03 | Safety Engineer | Before v0.1.0 | Open |
| RB-05 | Mutation testing for FM-019 (version check), FM-029 (auth bypass), FM-031 (rollback) | SCORE-FMEA §3.4, SCORE-VER OVI-07 | Software Safety Engineer | 2026-04-15 | Open |

---

## 2  High-Priority Gaps

Items that affect verification evidence quality or hardware readiness.

| ID | Gap | Source | Owner | Target | Status |
|----|-----|--------|-------|--------|--------|
| HP-01 | Product ID (PID) TBD in TSR §8 IVG-01 — must be assigned before hardware deployment | SCORE-TSR line 277 | Configuration Manager | Before HW flash | Open |
| HP-02 | PQC tests excluded from Windows CI (linker issue) — HSM-REQ-033 coverage unconfirmed on Linux | SCORE-VER OVI-04 | Host Library Developer | Linux CI runner available | Open |
| HP-03 | Firmware timing audit — DWT cycle counter instrumentation planned but blocked on hardware availability | timing-evidence.md §4 | Embedded Developer | After HIL setup | Blocked |
| HP-04 | TRNG health test validation report (FM-002, FM-027) | SCORE-FMEA §3.4 | Embedded Developer | 2026-04-30 | Open |
| HP-05 | `verify_activation_token` counter-update test coverage (FM-034) | SCORE-FMEA §3.4 | Host Library Developer | 2026-04-15 | Open |

---

## 3  Untested Crypto Requirements

Algorithms defined in the requirement set but lacking any test coverage.

| ID | Requirement | Algorithm | Issue |
|----|-------------|-----------|-------|
| CR-01 | HSM-REQ-003 | AES-256-CBC | Enum variant defined in types; zero test coverage |
| CR-02 | HSM-REQ-004 | AES-256-CCM | Enum variant defined in types; zero test coverage |
| CR-03 | HSM-REQ-005 | ChaCha20-Poly1305 | Not implemented in any backend |
| CR-04 | HSM-REQ-014 | SHA-3 | No test suite; L552 HASH peripheral does not support SHA-3 — software-only path required |
| CR-05 | HSM-REQ-017 | ChaCha20Rng seeding | Deterministic seeding approach not verified |

---

## 4  Missing Test Cases

Tests that are planned in test-strategy.md but not yet written.

### 4.1  Update module edge cases

| Test | Purpose |
|------|---------|
| `test_update_ids_event_on_rollback` | IDS event fires on version rollback attempt |
| `test_update_ids_event_on_bad_sig` | IDS event fires on invalid signature |
| `test_update_truncated_signature_rejected` | Truncated DER signature rejected cleanly |
| `test_update_corrupted_der_rejected` | Corrupted DER payload rejected cleanly |

### 4.2  Onboard communication edge cases

| Test | Purpose |
|------|---------|
| `test_ikev2_nonce_domain_separation` | IKEv2 nonce does not collide with other domains |
| `test_ikev2_ecdh_invalid_handle` | Invalid key handle rejected in ECDH exchange |
| `test_macsec_wrong_key_type_rejected` | MACsec operation rejects non-MACsec key type |

### 4.3  Property-based tests (proptest)

| Test | Purpose |
|------|---------|
| Update sign-verify roundtrip | Arbitrary payloads survive sign then verify |
| Activation token roundtrip | Arbitrary tokens survive issue then verify |

### 4.4  Performance evidence

| Test | Purpose |
|------|---------|
| HSM-REQ-028 bench harness | Criterion benchmarks for all crypto primitives |

---

## 5  Safety Documentation Gaps

| ID | Document / Artefact | Gap | Target |
|----|---------------------|-----|--------|
| SD-01 | Safety Case (GSN) | Not authored — `docs/safety/safety-case.md` is a placeholder | 2026-05-15 |
| SD-02 | SW-FMEA | USB protocol layer and key management sections still in progress | 2026-04-15 |
| SD-03 | HW-level zeroize evidence (FM-008) | Requires debug probe + SRAM2 read on L552 | 2026-05-15 |
| SD-04 | Tool qualification (Clippy CI) | Conflicting status — TQR §2 T4 says CLOSED, §3 summary says OPEN | Clarify |
| SD-05 | HSM-REQ-044 frame-length validation | Requires oversized-frame injection test on hardware | 2026-05-15 |

---

## 6  Integrator Obligations (ASR Evidence)

12 Assumed Safety Requirements are defined with integrator verification checklists.
Zero integrator evidence has been collected. These are not blocking the SEooC release
but will block any ASIL B vehicle integration.

| ASR | Obligation | Evidence Required |
|-----|-----------|-------------------|
| ASR-HW-01 | TrustZone enforcement | SAU configuration evidence |
| ASR-HW-02 | SWD locked (RDP Level 2) | Production flashing procedure |
| ASR-HW-03 | Genuine L552 device | Device verification test evidence |
| ASR-HW-04 | USB physical protection or encryption | Physical routing statement |
| ASR-HW-05 | Trusted time source | Clock source specification |
| ASR-OS-01 | Process isolation | OS hardening evidence |
| ASR-OS-02 | Supply chain integrity | Binary hash and build evidence |
| ASR-OS-03 | Single active instance | Singleton enforcement test |
| ASR-INT-01 | ASIL B integration context | HARA extract |
| ASR-INT-02 | Caller error handling | Integration layer code review |
| ASR-INT-03 | Rate limiter not bypassed | Configuration review |
| ASR-INT-04 | Key provisioning integrity | KMS documentation |

---

## 7  Accepted Residual Risks

Risks reviewed and accepted with documented rationale.

| ID | Risk | Rationale |
|----|------|-----------|
| RR-01 | Plaintext visible on USB cable | Physical access required; in-vehicle USB physically protected. Future: USB encryption. |
| RR-02 | Software fallback has no key isolation | CI / development only. Production must use hardware backend. |
| RR-03 | SWD not locked in development | Development board. Production deployment guide mandates RDP Level 2. |
| RR-04 | Timing side-channel residual over USB | USB jitter dominates. Hardware crypto is constant-time. |

---

## 8  Summary

| Category | Count |
|----------|-------|
| Release blockers | 5 |
| High-priority gaps | 5 |
| Untested crypto requirements | 5 |
| Missing test cases | 10+ |
| Safety documentation gaps | 5 |
| Integrator ASR evidence items | 12 (zero collected) |
| Accepted residual risks | 4 |

**Software-layer verdict:** CONDITIONALLY PASSED (274/274 tests green).
**Hardware-layer verdict:** NOT YET VERIFIED (HIL pending).
**Full ASIL B sign-off:** Blocked by RB-01 through RB-05.
