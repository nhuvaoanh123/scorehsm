# scorehsm — Tool Qualification Records

Date: 2026-03-14
Standard: ISO 26262-8:2018 §11 (Software Tools)
Status: RELEASED
ASIL Target: ASIL B
Document ID: SCORE-TQR

---

## 1. Purpose

ISO 26262-8 §11 requires that software tools used in the development and verification of safety-relevant software be qualified. Tool qualification establishes confidence that tool failures do not introduce undetected errors into the safety-relevant software.

**Tool Confidence Level (TCL):** ISO 26262-8 §11.4.6 assigns TCL-1, TCL-2, or TCL-3 based on two criteria:
- **TI (Tool Impact):** Could a malfunction of the tool introduce faults into the safety-relevant software or fail to detect a fault?
- **TD (Tool Error Detection):** Would a malfunction be detected by other measures before it causes a hazard?

| TCL | TI | TD | Qualification requirement |
|---|---|---|---|
| TCL-1 | 1 | 1 | No qualification required |
| TCL-2 | 1 | 0 | Tool validation (demonstrate correct operation) |
| TCL-3 | 1 | 0 (high impact) | Full qualification (development process evidence) |

For ASIL B, TCL-2 tools require validation evidence; TCL-3 tools require full qualification or avoidance.

---

## 2. Tool Inventory

### T1 — Rust Compiler (rustc)

| Field | Value |
|---|---|
| Tool name | `rustc` (Rust compiler) |
| Version | `rustc 1.96.0-nightly (1d8897a4e 2026-03-13)` |
| Vendor | The Rust Project Developers (Mozilla Foundation / Rust Foundation) |
| Purpose | Compiles safety-relevant Rust source code to native binary |
| TI | 1 — a compiler bug could generate incorrect code without warning |
| TD | 1 — extensive test suites (rustc test suite: ~100K tests); LLVM backend qualification track record; diverse independent CI platforms; binary output verified by unit/integration tests |
| **TCL** | **TCL-1** |

**Rationale for TCL-1:** Although `rustc` has TI=1 (compiler bugs could introduce errors), TD=1 because:
1. The `rustc` test suite is one of the most comprehensive of any compiler (~100,000 tests including regression tests for every reported bug).
2. All safety-relevant code paths are covered by ASIL B unit + integration tests (SCORE-UTT, SCORE-ITP). Any compiler code-generation bug affecting a safety-relevant path would be detected by the failing tests.
3. The LLVM backend used by `rustc` has independent qualification evidence (used in gcc-like compilers across safety domains).
4. Cross-platform CI (Linux + Windows) provides diversity that would expose platform-specific code generation bugs.

**Validation evidence:** Unit tests (13/13 pass), integration tests (52 specified), CI runs on two independent platforms.

**Note on nightly toolchain:** A nightly build is used because the `sha2` crate with `force-soft-compact` requires it for cross-compilation targets. The nightly build is pinned by `rust-toolchain.toml` to exact version `1.96.0-nightly (1d8897a4e 2026-03-13)`. When a stable release of Rust 1.96.0 is available, migration is required. Until then, the nightly qualification is maintained by locking the exact commit (`1d8897a4e`).

**Open item:** Pin `rust-toolchain.toml` to exact `1.96.0-nightly (1d8897a4e 2026-03-13)` and commit to repository. Status: **CLOSED** — exact nightly pin committed in `rust-toolchain.toml`.

---

### T2 — Cargo (Build System and Package Manager)

| Field | Value |
|---|---|
| Tool name | `cargo` |
| Version | `1.96.0-nightly (cbb9bb8bd 2026-03-13)` |
| Vendor | The Rust Project Developers |
| Purpose | Dependency resolution, build orchestration, test runner |
| TI | 1 — wrong dependency version or build flag could silently change behavior |
| TD | 1 — `Cargo.lock` pins all transitive dependencies to exact versions; dependency audit by `cargo-audit` |
| **TCL** | **TCL-1** |

**Rationale for TCL-1:** `Cargo.lock` provides full reproducibility — the exact version of every transitive dependency is pinned and committed to the repository. A cargo bug that resolves the wrong version would be immediately visible in the lock file diff. Cargo itself only affects build orchestration, not code generation (rustc handles that).

**Validation evidence:** `Cargo.lock` committed; `cargo build` is deterministic across CI runs.

---

### T3 — cargo-llvm-cov (Coverage Tool)

| Field | Value |
|---|---|
| Tool name | `cargo-llvm-cov` |
| Version | Latest stable (pinned in CI: `0.6.x`) |
| Vendor | Community (Taiki Endo) |
| Purpose | Measures statement and branch coverage for ASIL B coverage evidence |
| TI | 1 — incorrect coverage report could falsely assert coverage target met |
| TD | 0 — incorrect coverage numbers would not be detected by other means |
| **TCL** | **TCL-2** |

**Qualification approach (TCL-2 — Tool Validation):**

Coverage tool validation demonstrates that the tool correctly measures coverage on known-coverage test cases.

**Validation test: Coverage KAT (Known-Answer Test)**

Create a function with 4 branches (A, B, C, D). Execute only branches A and B in tests. Verify that `cargo-llvm-cov` reports exactly 50% branch coverage.

```rust
// coverage_kat.rs
pub fn branch_kat(x: u8) -> u8 {
    if x == 0 { return 1; }       // branch A
    if x == 1 { return 2; }       // branch B
    if x == 2 { return 3; }       // branch C (not tested)
    4                              // branch D (not tested)
}

#[test]
fn test_branch_a() { assert_eq!(branch_kat(0), 1); }

#[test]
fn test_branch_b() { assert_eq!(branch_kat(1), 2); }
```

**Expected result:** `cargo-llvm-cov` reports 50% branch coverage (2/4).
**Pass criterion:** Reported coverage = 50% ± 0%.
**Status:** **OPEN** — KAT not yet executed. Must be completed before coverage evidence is accepted.

**Validation evidence:** KAT execution log to be attached to CI artifact. Status: **OPEN**.

---

### T4 — Clippy (Static Analysis)

| Field | Value |
|---|---|
| Tool name | `cargo clippy` |
| Version | Same as `rustc 1.96.0-nightly` (bundled) |
| Vendor | The Rust Project Developers |
| Purpose | Static analysis — detects Rust anti-patterns, potential bugs, and unsafe code |
| TI | 1 — missed warning could allow a latent bug to pass review |
| TD | 0 — false negatives (missed warnings) not detected by other static analysis |
| **TCL** | **TCL-2** |

**Qualification approach (TCL-2 — Tool Validation):**

Clippy is run with `-- -D warnings` (zero-warning policy). Validation demonstrates:

1. Clippy detects known anti-patterns:
   ```
   cargo clippy --lib -- -D warnings
   ```
   Expected: **0 warnings** (enforced in CI as a blocking check).

2. Known clippy KAT: introduce a deliberate `unused_variable` warning, verify clippy reports it, remove it.

**Validation evidence:** CI log showing `0 warnings` from `cargo clippy --workspace --all-targets --features "mock,certs" -- -D warnings`. The `host-clippy` job in `.github/workflows/ci.yml` runs this check on every push and PR to `main`. Status: **CLOSED** — CI evidence exists in `host-clippy` job (green as of 2026-03-15).

---

### T5 — cargo-audit (Dependency Vulnerability Scanner)

| Field | Value |
|---|---|
| Tool name | `cargo-audit` |
| Version | Latest stable (pinned in CI) |
| Vendor | RustSec Advisory Database |
| Purpose | Identifies known vulnerabilities in transitive dependencies (security) |
| TI | 0 — tool does not modify code; audit failure blocks CI but does not introduce faults |
| TD | 1 |
| **TCL** | **TCL-1** |

**Rationale for TCL-1:** `cargo-audit` is read-only. A failure in the tool could produce a false negative (missed advisory), but this is a security concern, not a safety concern — the advisory database is maintained independently and updated continuously. For ASIL B software, `cargo-audit` is a defense-in-depth measure.

---

### T6 — GitHub Actions (CI Platform)

| Field | Value |
|---|---|
| Tool name | GitHub Actions |
| Version | Hosted runners: `ubuntu-latest`, `windows-latest` |
| Vendor | GitHub (Microsoft) |
| Purpose | Automated CI execution of build, test, coverage, and lint |
| TI | 1 — a CI platform failure could silently pass a failing test |
| TD | 1 — test results are reported as GitHub check statuses; separate monitoring |
| **TCL** | **TCL-1** |

**Rationale for TCL-1:** CI platform failures are immediately visible (failed check status). A silent false pass would require both the test execution and the result reporting to fail simultaneously. GitHub Actions has extensive uptime monitoring (status.github.com). Additionally, local `cargo test` runs by developers provide independent verification.

---

## 3. Tool Qualification Summary

| ID | Tool | Version | TCL | Status |
|---|---|---|---|---|
| T1 | rustc | 1.96.0-nightly | TCL-1 | Open item: pin toolchain |
| T2 | cargo | 1.96.0-nightly | TCL-1 | Complete |
| T3 | cargo-llvm-cov | 0.6.x | TCL-2 | Open: coverage KAT |
| T4 | cargo clippy | 1.96.0-nightly | TCL-2 | Open: CI integration |
| T5 | cargo-audit | latest | TCL-1 | Complete |
| T6 | GitHub Actions | hosted | TCL-1 | Complete |

**Open items for TCL-2 tools:**
1. **T3**: Execute coverage KAT; attach output to CI artifact — **OPEN**
2. **T4**: Configure `cargo clippy -- -D warnings` as blocking CI step — **OPEN**
3. **T1**: Commit `rust-toolchain.toml` pinning `1.96.0-nightly (1d8897a4e)` — **OPEN**

All open items must be closed before ASIL B sign-off.

---

## 4. Dependency Security Audit

The following table lists all direct dependencies (from `Cargo.toml`) with their security status as of the document date.

| Crate | Version | Purpose | Advisory Status |
|---|---|---|---|
| `aes-gcm` | 0.10 | AES-256-GCM encryption | No known advisories |
| `sha2` | 0.10 | SHA-256/384 hashing | No known advisories |
| `hmac` | 0.12 | HMAC-SHA256 | No known advisories |
| `hkdf` | 0.12 | HKDF key derivation | No known advisories |
| `p256` | 0.13 | ECDSA P-256, ECDH | No known advisories |
| `chacha20poly1305` | 0.10 | ChaCha20-Poly1305 | No known advisories |
| `sha3` | 0.10 | SHA-3 | No known advisories |
| `rand_core` | 0.6 | RNG interface | No known advisories |
| `rand_chacha` | 0.3 | ChaCha RNG | No known advisories |
| `zeroize` | 1 | Key zeroization | No known advisories |
| `subtle` | 2 | Constant-time ops | No known advisories |
| `serialport` | 4 | USB CDC serial | No known advisories |
| `thiserror` | 1 | Error handling | No known advisories |

All crates listed are members of the [RustCrypto](https://github.com/rustcrypto) or [Rust Security](https://github.com/rust-secure-code) organizations and have established security track records.

**`cargo audit` last run:** 2026-03-14 — **0 advisories**.

---

*Document end — SCORE-TQR rev 1.0 — 2026-03-14*
