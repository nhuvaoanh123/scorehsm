# scorehsm — ISO 26262 Part 6 Software Safety Plan

Date: 2026-03-14
Status: ACTIVE
ASIL Target: ASIL B
Classification: SEooC (Safety Element out of Context)
Document owner: Taktflow Systems

---

## 1. Purpose and Scope

### 1.1 Purpose

This document is the software safety plan for `scorehsm`, a hardware-backed cryptographic library for automotive Software Defined Vehicle (SDV) platforms. It defines the safety activities, work products, roles, verification strategy, and tailoring decisions required to achieve and maintain an ASIL B software safety integrity claim in accordance with ISO 26262-6:2018.

This plan is the top-level safety governance document for the `scorehsm-host` Rust library and its interaction with the STM32L552ZE-Q (L55) hardware security module firmware. It governs the full software development lifecycle from requirements through verification.

### 1.2 Scope

**In scope:**
- `scorehsm-host` Rust library — the `HsmBackend` trait, `SoftwareBackend` implementation, `HardwareBackend` implementation, and all supporting modules (key management, session layer, IDS hook, USB CDC frame protocol, TLS integration)
- L55 firmware — the Non-Secure USB command dispatcher, TrustZone NSC gateway (CMSE veneers), and Secure-world cryptographic driver layer (AES, PKA, HASH, RNG, key store)
- The USB CDC binary frame protocol (CRC-16, sequence number, opcode definitions) as an internal interface

**Out of scope:**
- The Linux OS on the Raspberry Pi HPC proxy (assumed correct and appropriately hardened by the integrator)
- Application software consuming the `HsmBackend` trait (KUKSA, OTA verifier, TLS stack) — these are the responsibility of the item integrator
- Production provisioning infrastructure (KEK pre-provisioning during manufacturing)
- Post-quantum algorithm hardware acceleration (deferred to future silicon; software backend only)

### 1.3 Lifecycle Phases Covered

This plan covers phases 5 through 9 of the ISO 26262 software development V-model as applied to this SEooC:

| Phase | ISO 26262-6 Clause | Activity |
|---|---|---|
| Software Safety Requirements | Clause 6 | Derivation and allocation of software-level safety requirements from safety goals and assumed safety requirements |
| Software Architecture Design | Clause 7 | Design of the dual-backend architecture, USB protocol, TrustZone partitioning |
| Unit Design | Clause 8 | Module-level design for each backend, protocol layer, and hardware driver |
| Unit Implementation and Testing | Clause 9 | Rust implementation with language enforcement (`deny(unsafe_code)`, `deny(missing_docs)`), unit test execution |
| Integration and Integration Testing | Clause 10 | Software integration across backends, USB protocol conformance testing, session layer integration |
| Software Testing | Clause 11 | Requirements-based testing against all 49 HSM-REQ items, error-path coverage, mutation testing |
| Software Safety Requirements Verification | Clause 12 | Traceability matrix, coverage analysis, review records |

---

## 2. SEooC Classification

### 2.1 Rationale for SEooC

`scorehsm` is developed as a Safety Element out of Context (SEooC) per ISO 26262-10:2018 §9 because:

1. **No single item context at development time.** The library is intended to be integrated into multiple SDV platforms (automotive Linux HPC, zonal ECUs, HIL test environments) by one or more Tier-1 integrators. The specific vehicle-level hazard analysis, safety goals, and HARA that use this element's safety contribution are performed by the integrator for each item.

2. **Assumed Safety Requirements (ASRs) are defined a priori.** This document defines the ASRs (see §3) that the integrator must verify are satisfied. The ASIL B integrity claim for `scorehsm` is conditional on these ASRs being met.

3. **The element provides a safety-relevant service.** `scorehsm` performs signature verification of OTA firmware images, enables secure boot attestation, and authenticates safety-critical inter-ECU communication. Failure to perform these functions correctly can contribute to safety goal violations (e.g., installation of corrupted firmware, acceptance of spoofed safety messages). These contributions to safety make an ASIL B treatment necessary.

### 2.2 What the Integrator Must Provide

The integrator shall:

1. **Perform a system-level HARA** covering the item that uses `scorehsm`. The integrator shall identify which vehicle-level safety goals are supported by `scorehsm`'s cryptographic services and assign the appropriate ASIL decomposition or allocation.

2. **Verify the Assumed Safety Requirements** (§3) are satisfied in the integration context.

3. **Provide a Dependency Failure Analysis (DFA)** per ISO 26262-9 §7.4, covering common-cause failures between `scorehsm` and the application layer using it.

4. **Classify the integration-level safety case** and reference this SEooC safety plan as evidence for the `scorehsm` component.

5. **Lock the production L55 firmware** with SWD disabled (RDP Level 2) before vehicle deployment, satisfying security goal SG-10 and residual risk RR3.

6. **Configure the production deployment** to use the `HardwareBackend` exclusively. The `SoftwareBackend` does not satisfy key isolation (HSM-REQ-036) and must not be used in production safety contexts.

---

## 3. Assumed Safety Goals (ASGs)

The following Assumed Safety Goals state what the integrating system must satisfy for the ASIL B integrity claim of this SEooC to hold. If any ASG is violated at integration time, the ASIL B claim for `scorehsm` is voided and must be re-evaluated.

| ID | Assumed Safety Goal | Rationale |
|---|---|---|
| ASG-01 | The integrating system shall ensure that only authorized software processes on the Raspberry Pi can open a `scorehsm` session. No unauthenticated OS process shall be able to call `HsmBackend::init()` in a production deployment. | Key handles are session-scoped but process isolation is enforced by the OS, not by `scorehsm`. A compromised process with session access undermines the key isolation model (HSM-REQ-037). |
| ASG-02 | The integrating system shall ensure that a response from `scorehsm` indicating `Err(HsmError::*)` on a safety-critical operation (e.g., signature verification failure) causes the item to take a safe state. `scorehsm` is not responsible for safe-state enforcement; it only reports outcomes. | `scorehsm` returns typed errors per HSM-REQ-027. The application's error handler, not `scorehsm`, must transition to a safe state (e.g., abort OTA, refuse to boot). |
| ASG-03 | The integrating system shall ensure the USB connection between the Raspberry Pi and the STM32L552 is within a physically protected vehicle boundary (no externally accessible USB port). | USB plaintext is returned in USB response frames (residual risk RR1, STRIDE I3). Physical access to the cable is the attack vector. In-vehicle USB wiring must not be externally accessible in production. |
| ASG-04 | The integrating system shall provision the L55 with RDP Level 2 (SWD debug port locked) before vehicle deployment, and shall verify this during End-of-Line testing. | SWD access in development is a documented residual risk (RR3, STRIDE T2). Production deployment without SWD lock removes the TrustZone enforcement boundary, invalidating the key isolation security argument which underpins the ASIL B safety argument. |

---

## 4. Safety Lifecycle Tailoring

This section documents tailoring decisions relative to ISO 26262-6:2018 Table 1 (software development methods) and the method recommendation tables for ASIL B. Tailoring is permitted under ISO 26262-6 §5.4.7 when documented and justified.

### 4.1 Applied Tailoring

| ISO 26262-6 Work Product / Method | ASIL B Recommendation | Tailoring Decision | Justification |
|---|---|---|---|
| Formal methods (Table 7) | Recommended (++) | Not applied | Rust's type system and borrow checker provide compile-time memory safety guarantees that address the failure modes formal methods would target. `#![deny(unsafe_code)]` eliminates the entire class of undefined behavior that formal methods are typically applied to detect. This satisfies the intent with a language-level mechanism. |
| Source code coverage — MC/DC (Clause 11, Table 10) | Recommended (++) | Branch coverage (≥80%) applied; MC/DC not required | MC/DC is recommended at ASIL C/D. At ASIL B, branch coverage is the primary structural coverage criterion. The unit count and conditional complexity of `scorehsm` make branch coverage tractable and sufficient. |
| Dynamic analysis — memory testing tools (Clause 9, Table 9) | Recommended (+) | Applied via `cargo test` with Rust's built-in bounds checking | Rust's memory model eliminates buffer overflows and use-after-free at compile time. Runtime bounds checking (`panic` on out-of-bounds) replaces valgrind/sanitizer-class tools as the detection mechanism. `cargo-llvm-cov` is used for coverage instrumented builds. |
| Hardware-software integration test on target (Clause 10) | Recommended (+) | Deferred to HIL test environment | Full hardware-software integration testing is performed in the HIL environment (Raspberry Pi + STM32L552 Nucleo board). Software-only integration tests use the `SoftwareBackend`. Target integration evidence is documented in the HIL test report. |
| Proven-in-use argument (ISO 26262-8 §14) | Not applicable | Not claimed | The rustcrypto crates have extensive public use but have not been assessed under an automotive proven-in-use regime. No proven-in-use credit is claimed. Standard ASIL B verification applies. |

### 4.2 Retained Requirements

The following ISO 26262-6 methods are applied without tailoring at ASIL B:

- Design and coding guidelines (Clause 8) — enforced via `clippy`, `deny(warnings)`, `deny(unsafe_code)`, `deny(missing_docs)`, and `rustfmt`
- Requirements-based testing (Clause 11, Table 10 — highly recommended ++) — all 49 HSM-REQ items have ≥1 test; see `docs/test-strategy/test-strategy.md`
- Structural coverage ≥ statement 85%, branch 80% (Clause 11) — measured by `cargo-llvm-cov`
- Static analysis (Clause 9) — `cargo clippy -- -D warnings` run on every CI build
- Software integration testing (Clause 10) — layer-by-layer: unit → software integration → HIL hardware integration
- Independence of testing (Clause 11) — T1 independence for safety-critical functions (see §9)
- Software safety requirements verification (Clause 12) — traceability matrix maintained in `docs/requirements/requirements.md`

---

## 5. Work Product Status Matrix

| Work Product | ISO 26262-6 Clause | Required at ASIL B | Status | Location |
|---|---|---|---|---|
| Software Safety Requirements | Clause 6 | Mandatory | Complete (49 items, HSM-REQ-001…049) | `docs/requirements/requirements.md` |
| SW Architecture Design | Clause 7 | Mandatory | Complete | `docs/architecture/architecture.md` |
| Unit Design (module-level) | Clause 8 | Mandatory | Complete (inline Rust doc — `deny(missing_docs)`) | Source: `host/src/**/*.rs`, `firmware/src/**/*.rs` |
| Coding Guidelines | Clause 8 | Mandatory | Complete (compiler-enforced) | `deny(unsafe_code)`, `deny(missing_docs)`, `clippy`, `rustfmt.toml` |
| Unit Tests | Clause 9 | Mandatory | Complete (110 passing tests) | `host/tests/`, `host/src/lib.rs` `#[cfg(test)]` |
| Software Integration Tests | Clause 10 | Mandatory | Complete (software backend); HIL tests in progress | `host/tests/sw_backend_tests.rs`, HIL test plan |
| FMEA (SW-FMEA) | Clause 7 / Annex A | Recommended (++) | In progress — USB protocol layer and key management covered | `docs/safety/sw-fmea.md` (target) |
| Statement Coverage Analysis (≥85%) | Clause 11 | Mandatory | Pending — measurement infrastructure ready (`cargo-llvm-cov`) | CI report: `target/llvm-cov/` |
| Branch Coverage Analysis (≥80%) | Clause 11 | Mandatory | Pending — measurement infrastructure ready | CI report: `target/llvm-cov/` |
| Safety Case (GSN/structured argument) | Clause 12 | Mandatory | Planned — architecture in this plan | `docs/safety/safety-case.md` (target) |
| Threat Model / TARA | ISO 21434 §15 (interface) | Not mandated by 26262 — included as complementary evidence | Complete | `docs/safety/threat-model.md` |
| Verification Report | Clause 12 | Mandatory | Planned — generated from CI artifacts per release | `docs/safety/verification-report.md` (target) |
| Configuration Management Plan | ISO 26262-8 §7 | Mandatory | Complete (git, semver, branch policy) | §11 of this document |
| Tool Classification Record | ISO 26262-8 §11 | Mandatory | Complete | §7 of this document |

**FMEA note:** SW-FMEA is in progress. Coverage of the USB protocol layer (frame parsing, CRC verification, sequence number enforcement) and key management (slot allocation, handle validation, zeroization) is the first priority, as these contain the highest density of safety-relevant failure modes.

---

## 6. Roles and Responsibilities

| Role | Individual / Team | Responsibilities |
|---|---|---|
| Safety Manager | Taktflow Systems lead | Approves this safety plan; maintains compliance posture; manages deviations from plan; interfaces with OEM safety auditor |
| Software Safety Engineer | Taktflow Systems embedded team | Authors safety requirements (HSM-REQ), maintains traceability matrix, writes SW-FMEA, authors safety case arguments, reviews verification reports |
| Software Architect | Taktflow Systems embedded team | Authors and maintains architecture.md; owns dual-backend design decisions; reviews unit design for safety-relevant modules |
| Embedded Developer (L55 firmware) | Taktflow Systems embedded team | Implements and maintains L55 Non-Secure dispatcher, TrustZone NSC gateway, and Secure-world drivers; responsible for coding guideline compliance on firmware side |
| Host Library Developer | Taktflow Systems embedded team | Implements and maintains `scorehsm-host` Rust crate; owns `HsmBackend` trait; responsible for coding guideline compliance |
| Tester (Safety-Critical Functions) | Independent of designer per T1 requirement (§9) | Executes or reviews tests for safety-critical functions: signature verification, key isolation, error propagation, replay protection. Must not be the same person who designed the function under test |
| Cybersecurity Engineer | Taktflow Systems | Maintains threat-model.md (STRIDE/TARA); maps security goals (SG-01…SG-10) to safety requirements; participates in SW-FMEA for attack-path failure modes |
| Configuration Manager | Taktflow Systems embedded team | Maintains git branch policy, semver tags, submodule pointer discipline; controls release artifacts |

**Note on small-team independence:** Taktflow Systems acknowledges that T1 independence (designer ≠ tester) requires organizational discipline when team size is small. The policy is: for each safety-critical module, the primary reviewer (who creates the test plan and reviews test results) shall be a team member who did not write the implementation. Test plans shall be authored before implementation is complete to prevent confirmation bias. All safety-critical test reviews shall be documented with reviewer name and date.

---

## 7. Tool Classification

Tool classification follows ISO 26262-8:2018 §11, which requires determining a Tool Confidence Level (TCL) for each tool used in development. TCL is derived from Tool Impact (TI) and Tool Error Detection (TD).

All tools in the `scorehsm` build and verification chain fall into one of two categories: they either produce the deliverable artifact (the compiled library) or they measure and verify properties of that artifact. Because none of these tools' outputs are embedded in the production binary without further human review, the tool impact is bounded.

| Tool | Version Policy | TI | TD | TCL | Qualification Required | Rationale |
|---|---|---|---|---|---|---|
| `rustc` (Rust compiler) | Pinned via `rust-toolchain.toml` | TI1 | TD3 | TCL-1 | No | Well-established tool with extensive public use, active LLVM backend validation suite, and published errata. Compiler output is validated by the unit and integration test suite — any compiler-introduced error that affects behavior would be caught by the 110-test suite before release. |
| `cargo` (build system + package manager) | Pinned with `rustc` | TI1 | TD3 | TCL-1 | No | Orchestrates compilation and test execution; does not produce safety-relevant output beyond invoking `rustc`. Well-established in the Rust ecosystem. CI enforces reproducible builds via `Cargo.lock`. |
| `cargo-llvm-cov` (coverage measurement) | Locked in `Cargo.toml` | TI2 | TD2 | TCL-2 | Validation required | Measures structural coverage and influences the pass/fail decision for release. An incorrect coverage measurement could mask insufficient test coverage. Validation strategy: cross-check coverage on a known test case where the covered lines are known by inspection; validate that deliberately uncovered branches register as uncovered. |
| GitHub Actions CI | Pinned action SHAs | TI1 | TD3 | TCL-1 | No | Orchestrates the build and test pipeline. Does not transform source code. CI failures are visible and block merges. The CI configuration itself is version-controlled and peer-reviewed. |
| `cargo clippy` | Pinned with `rustc` | TI1 | TD3 | TCL-1 | No | Static linter. Lint warnings treated as errors (`-D warnings`). Findings reviewed by developer; does not produce safety output autonomously. |

**TCL-2 validation plan for `cargo-llvm-cov`:** Before the first release, a validation test shall be executed: a module with a known set of covered and uncovered branches shall be measured; the coverage report output shall be manually compared against the known ground truth. The validation test and its results shall be recorded in `docs/safety/tool-validation-llvm-cov.md`.

---

## 8. Verification Strategy

### 8.1 Requirements-Based Testing

Every software safety requirement (HSM-REQ-001 through HSM-REQ-049) is mapped to at least one test case. This mapping is maintained in `docs/requirements/requirements.md` and in the test source files (`host/tests/`). Tests are identified by requirement ID in comments using the convention `// HSM-REQ-NNN`.

Safety-critical requirement groups and their corresponding test categories:

| Requirement Group | Safety Relevance | Test Category | Example Tests |
|---|---|---|---|
| HSM-REQ-019, 022, 023 | Key generation, deletion, no-export | Key management tests | `test_key_generate_aes256_returns_handle`, `test_no_key_export_in_api`, `test_deleted_handle_is_unusable` |
| HSM-REQ-041 | USB frame integrity (CRC + sequence) | Protocol tests | Frame mutation, CRC fault injection, sequence number out-of-order |
| HSM-REQ-027 | Error propagation — no panics, typed errors | Error-path tests | Every `HsmError` variant exercised; no `unwrap()` in library |
| HSM-REQ-038 | IDS event emission | IDS tests | Every `IdsEvent` variant emitted in ≥1 test |
| HSM-REQ-039 | DoS rate limiting | Rate limiter tests | Burst above threshold returns `HsmError::RateLimitExceeded` |
| HSM-REQ-043 | Key slot zeroize on reset | Reset/init sequence | Slot state after simulated power cycle |

### 8.2 Static Analysis

`cargo clippy -- -D warnings` is run on every CI build. All clippy warnings are treated as errors and block merge. The following clippy lint groups are enabled:

- `clippy::all` (default)
- `clippy::pedantic` (selectively enabled; exceptions documented in `clippy.toml`)
- `clippy::cargo` (dependency hygiene)

Additionally, `#![deny(unsafe_code)]` ensures that no `unsafe` block can be introduced without a compilation failure, eliminating an entire class of memory-safety defects without requiring dynamic analysis tooling.

### 8.3 Code Review

All changes to safety-critical modules require a pull request review by a team member who did not author the change. Safety-critical modules are identified in `docs/architecture/architecture.md` and include:

- Key management layer (`host/src/key_management.rs`)
- Session and access control layer (`host/src/session.rs`)
- USB CDC frame protocol encoder/decoder (`host/src/protocol/`)
- TrustZone NSC gateway (`firmware/src/secure/gateway.rs`)
- L55 Secure-world cryptographic drivers (`firmware/src/secure/crypto/`)

Review records are maintained as GitHub pull request review threads, which are preserved in the repository history.

### 8.4 Structural Coverage Targets

| Coverage Metric | Target | Tool | Measurement Trigger |
|---|---|---|---|
| Statement coverage | ≥ 85% | `cargo-llvm-cov` | Every CI run on `main` branch |
| Branch coverage | ≥ 80% | `cargo-llvm-cov` | Every CI run on `main` branch |

Coverage is measured over the `scorehsm-host` library and its integration tests. CI fails if coverage drops below threshold. Coverage reports are archived as CI artifacts for each release tag.

The `SoftwareBackend` path is the primary coverage target, as it runs in CI without hardware. `HardwareBackend`-specific paths are covered in the HIL test environment and reported separately.

### 8.5 Regression

All 110 tests run on every push to a feature branch and on every pull request to `main`. Zero test failures is a merge gate. The test count is documented in CI and is expected to grow monotonically — any decrease in test count triggers a review.

---

## 9. Independence Requirements

### 9.1 Requirement

ISO 26262-6:2018 Clause 11 requires independence level T1 for software testing at ASIL B. T1 independence means: the person who designs and implements a safety-critical function shall not be the person who solely performs and approves testing of that function.

### 9.2 Application to scorehsm

The following policy is in effect:

1. **Test plan authoring:** The test plan for each safety-critical module (listed in §8.3) shall be authored or reviewed by a team member who did not implement the module. The test plan shall specify the expected behavior, input partitions, and error conditions. This is documented in `docs/test-strategy/test-strategy.md`.

2. **Test review:** The test results (CI pass/fail records and coverage reports) for a release shall be formally reviewed by a person other than the primary implementer of the covered module. Review sign-off is recorded as a GitHub pull request review or a sign-off entry in the verification report.

3. **Safety-critical function identification:** The following functions are classified as safety-critical for the purpose of independence requirements:
   - `ecdsa_verify` — verification of firmware/message signatures
   - `aes_gcm_decrypt` — authenticated decryption with tag verification
   - `hmac_sha256` — MAC verification used for integrity checking
   - Key handle validation in the access control layer
   - Frame CRC validation and sequence number enforcement in the USB protocol layer

4. **Developer–tester assignment tracking:** A table mapping safety-critical functions to their implementer and designated independent reviewer is maintained in the verification report (`docs/safety/verification-report.md`).

### 9.3 Limitations at Current Team Size

Where team size prevents strict personnel independence, the following compensating measures are applied:

- Automated testing is relied upon as the primary verification mechanism for well-defined behavioral requirements, reducing dependence on human review for pass/fail determination.
- Self-review of test plans is prohibited for safety-critical functions; a second person must approve the test plan before implementation begins.
- External review by the safety consultant engaged by the OEM may be used to provide independence for final release verification.

---

## 10. Interface to ISO 21434 (Cybersecurity)

### 10.1 Relationship Between Safety Plan and TARA

`scorehsm` operates at the intersection of ISO 26262 (safety) and ISO 21434:2021 (cybersecurity). The threat model (`docs/safety/threat-model.md`) is the primary cybersecurity artifact, produced using STRIDE analysis and aligned with the TARA methodology of ISO 21434 §15.

The two standards are complementary, not redundant:

| Aspect | ISO 26262 (this plan) | ISO 21434 (threat-model.md) |
|---|---|---|
| Primary concern | Random hardware faults, systematic software faults | Deliberate adversarial attacks |
| Failure model | Unintentional — electrical noise, software bugs, transient faults | Intentional — spoofing, tampering, replay, key extraction |
| Evidence produced | FMEA, coverage reports, design verification | STRIDE analysis, security goals (SG-01…SG-10), attack path analysis |
| Residual risk treatment | Safe state, error detection and recovery | Accepted residual risks (RR1…RR4) with documented rationale |

### 10.2 Security Goals Feeding Safety Requirements

Ten security goals (SG-01 through SG-10) were derived from the STRIDE analysis and are directly traceable to software safety requirements in `docs/requirements/requirements.md`. This traceability ensures that security countermeasures are implemented as requirements, tested, and verified under the same ASIL B rigor as functional safety requirements.

Key traceability examples:

| Security Goal | Derived Safety Requirement | Safety Rationale |
|---|---|---|
| SG-01 (Key material never in USB frame) | HSM-REQ-023 (key export prohibition) | A compromised key enables fabrication of valid firmware signatures, defeating secure boot |
| SG-02 (USB frame integrity — CRC + sequence) | HSM-REQ-041 | Tampered commands could trigger invalid crypto operations; corrupted results could cause safety decision errors |
| SG-05 (Key slot zeroize on deletion/reset) | HSM-REQ-022, HSM-REQ-043 | Residual key material could be used to generate fraudulent signatures after the original key was deleted (revocation failure) |
| SG-09 (Signing operations logged to IDS) | HSM-REQ-038 | Anomalous signing activity may indicate a safety-relevant fault condition (firmware rollback attack) |
| SG-10 (SWD locked in production) | ASG-04 | SWD access bypasses TrustZone — the architectural boundary on which the key isolation safety argument depends |

### 10.3 Shared Review Process

The cybersecurity engineer participates in the SW-FMEA review. Failure modes identified in the FMEA that correspond to known attack vectors in the TARA are cross-referenced. Residual risks accepted in the TARA (RR1…RR4) are documented in this safety plan as known limitations, with the integrator's Assumed Safety Goals addressing the residual risk attribution.

---

## 11. Configuration Management

### 11.1 Version Control

All `scorehsm` source code, documentation, test code, and build configuration are managed in a git repository with the following policy:

- **Main branch (`main`):** Protected. No direct commits. All changes via pull request with ≥1 reviewer approval and passing CI.
- **Feature branches:** Named `feat/<description>`. Created from `main`. Merged via pull request.
- **Fix branches:** Named `fix/<description>` or `hotfix/<description>` for urgent safety-relevant fixes.
- **Release tags:** Semver format `vX.Y.Z`. Annotated tags created only on `main` after all CI checks pass and verification report is updated.

### 11.2 Submodule Discipline

`scorehsm` uses a git submodule for the `taktflow-embedded` firmware. The following invariants are maintained:

1. The submodule pointer in the parent repository always references a commit that exists on the remote submodule repository. A commit that does not exist on remote will break downstream consumers.
2. Submodule commits are made first; the parent repository pointer is updated second — never the reverse.
3. A feature branch exists in both repositories for any change that spans the host library and firmware. The parent pull request references the submodule pull request for reviewer traceability.
4. At session start: `git pull && git submodule update --init` is the required pull routine.

### 11.3 Dependency Pinning

- Rust toolchain version is pinned in `rust-toolchain.toml`.
- All Rust crate dependencies are pinned via `Cargo.lock`, which is committed to the repository.
- `Cargo.lock` changes require pull request review; dependency updates are not automated without review.
- Security advisories against dependencies are monitored via `cargo audit` on every CI run.

### 11.4 Build Reproducibility

A production release build shall be reproducible from the tagged commit using only the pinned toolchain and `Cargo.lock`. The CI artifact for each release tag includes the full build log, test results, and coverage report. These artifacts are retained for the duration of the project safety lifecycle.

### 11.5 Change Impact Assessment

For any change to a safety-critical module (§8.3), the pull request description shall include a change impact assessment addressing:

- Which HSM-REQ items are affected
- Whether any new failure modes are introduced (SW-FMEA impact)
- Whether test coverage for affected functions is maintained above threshold
- Whether the safety case argument is affected

---

## 12. Open Items and Action Log

| ID | Item | Owner | Target Date | Status |
|---|---|---|---|---|
| OI-01 | Complete SW-FMEA for USB protocol layer and key management module | Software Safety Engineer | 2026-04-15 | In progress |
| OI-02 | Validate `cargo-llvm-cov` against known ground truth (TCL-2 validation, §7) | Tester | 2026-04-01 | Open |
| OI-03 | Achieve ≥85% statement / ≥80% branch coverage with CI gate enforced | Host Library Developer | 2026-04-30 | In progress — `cargo-llvm-cov` integrated |
| OI-04 | Author safety case (GSN) in `docs/safety/safety-case.md` | Software Safety Engineer | 2026-05-15 | Open |
| OI-05 | Produce first verification report for v0.1.0 release | Software Safety Engineer + Tester | 2026-05-30 | Open |
| OI-06 | HIL test execution and documentation — `HardwareBackend` coverage | Embedded Developer | 2026-05-15 | In progress |
| OI-07 | Confirm `cargo audit` clean for all v0.1.0 dependencies | Configuration Manager | Per release | Ongoing |
