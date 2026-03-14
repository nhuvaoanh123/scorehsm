# scorehsm — Coding Guidelines

Date: 2026-03-14
Status: COMPLETE
ASIL Target: ASIL B
Classification: SEooC (Safety Element out of Context)
Document owner: Taktflow Systems

---

## 1. Purpose and Scope

### 1.1 Purpose

This document defines the coding guidelines for the `scorehsm` Rust cryptographic library. It is required by ISO 26262-6:2018 §8.4.5 (software unit design and implementation — design and coding guidelines) and maps to the principles of ISO 26262-6:2018 Table D.1, which specifies language and coding notation guidelines for safety-relevant software at ASIL B.

The guidelines in this document are Rust-specific adaptations of the classes of rules that ISO 26262-6 Table D.1 addresses: memory safety, numeric handling, control flow, error handling, documentation, and code structure. A core advantage of Rust as the implementation language for an ASIL B safety element is that many rules which require runtime checks or static analysis tools in C/C++ are enforced at compile time by the Rust compiler and ownership type system. This document makes those compile-time enforcements explicit and documents their corresponding rule IDs for traceability.

Rules are identified by `RG-XXX-NN` (Rule Group — sequential number). Each rule states:
- The **enforcement level** (compile-time, clippy lint, CI check, or manual review)
- The **rationale** connecting the rule to functional safety
- The **specific mechanism** by which the rule is enforced or verified

### 1.2 Scope

These guidelines apply to:
- All Rust source files in `scorehsm-host` (`host/src/**/*.rs`, `host/tests/**/*.rs`)
- All Rust source files in L55 Non-Secure firmware (`firmware/src/nonsecure/**/*.rs`)

The L55 Secure-world firmware (`firmware/src/secure/**/*.rs`) is implemented in C and governed by a separate C coding guideline document (`docs/safety/coding-guidelines-c.md`). Where the Secure-world firmware interfaces with Rust via CMSE NSC veneers, the interface contract is defined in `docs/architecture/architecture.md` and the Rust side of that interface follows these guidelines.

**Test code** (`host/tests/`, `#[cfg(test)]` blocks) is exempt from the stricter rules where noted (e.g., `unwrap()` is permitted in test code). Exemptions are noted per rule.

### 1.3 Relationship to ISO 26262-6 Table D.1

ISO 26262-6:2018 Annex D Table D.1 specifies notation and language guidelines for programming languages used in safety-relevant software. The table is language-agnostic; the following mapping shows how each category is addressed by this document:

| ISO 26262-6 Table D.1 Category | Addressed by |
|---|---|
| Use of a language subset | §2 (deny(unsafe_code), no unwrap, no global mutable state) |
| Enforcement of strong typing | §2 (Rust's type system — no implicit conversions, no void*) |
| Use of defensive implementation techniques | §2, §3, §4 (ZeroizeOnDrop, checked arithmetic, typed errors) |
| Use of well-established design principles | §6 (single responsibility, no recursion, exhaustive match) |
| Use of code analysis tools | §8 (clippy, cargo audit, llvm-cov) |
| Documentation of interfaces and assumptions | §5 (missing_docs, Safety/Errors sections, HSM-REQ traceability) |

---

## 2. Rules — Memory Safety

### RG-MEM-01: No Unsafe Code

**Rule:** No `unsafe` block, `unsafe fn`, or `unsafe trait impl` shall appear in production source code.

**Enforcement:** Compile-time. `#![deny(unsafe_code)]` is declared in `host/src/lib.rs` and in all firmware Rust crates. Any introduction of `unsafe` causes a compilation error and blocks CI.

**Rationale:** Rust's safety guarantees — no use-after-free, no dangling pointers, no data races, no undefined behavior from memory misuse — hold unconditionally only in safe Rust. `unsafe` code can violate these invariants. Undefined behavior is incompatible with ISO 26262 functional safety requirements because its effects are by definition unpredictable and unanalyzable. Eliminating `unsafe` from the codebase is the strongest available guarantee that this class of failure mode does not exist. This satisfies the spirit of ISO 26262-6 Table D.1's requirement for a language subset that excludes features with unpredictable behavior.

**Exception:** Third-party crates (e.g., `p256`, `aes-gcm`, `zeroize`) may contain `unsafe` internally. These crates are assessed under the tool and dependency classification in `docs/safety/safety-plan.md` §7. Their `unsafe` usage is justified by crate-level audits and is not within the `scorehsm` codebase boundary for this rule.

**Test code exemption:** None — `unsafe` is not needed in test code for this project. The rule applies equally to `#[cfg(test)]` blocks.

---

### RG-MEM-02: No `unwrap()` or `expect()` in Library Code

**Rule:** `unwrap()` and `expect()` shall not appear in any non-test source file. The `?` operator or explicit `match`/`if let` shall be used instead.

**Enforcement:** clippy lint `clippy::unwrap_used` declared as `#[deny]` in `host/src/lib.rs`. CI fails on any `unwrap()` or `expect()` in production code.

```toml
# In Cargo.toml or .cargo/config.toml:
[target.'cfg(not(test))'.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
```

**Rationale:** `unwrap()` and `expect()` call `panic!()` on `None` or `Err(_)`. A panic in library code is unacceptable in a safety library for two reasons: (1) it terminates the calling thread with a stack unwind, giving the integrating application no opportunity to handle the failure gracefully or transition to a safe state; (2) the panic message may leak internal state to log outputs. ISO 26262 requires that failure modes be detectable and handled; panic is an uncontrolled failure mode. `Result<T, HsmError>` propagation via `?` gives the caller the typed error and the ability to take a safe action.

**Test code exemption:** `unwrap()` is permitted in `#[cfg(test)]` blocks where the intent is to fail the test on unexpected `None`/`Err`. Test panics are acceptable; library panics are not.

---

### RG-MEM-03: Heap Allocation Policy

**Rule:** Heap allocation (`Vec<T>`, `Box<T>`, `String`) is permitted only for variable-length outputs where the output size is not known at compile time. The primary permitted use case is `Vec<u8>` for ciphertext output from `aes_gcm_encrypt`, where the output length equals the input length and is not a compile-time constant. Fixed-size buffers shall use stack arrays (see RG-MEM-04).

**Enforcement:** Manual review. Clippy lint `clippy::vec_init_then_push` is enabled to discourage inefficient heap patterns. New heap allocations in hot paths require justification in the PR description.

**Rationale:** Rust's ownership model guarantees that heap-allocated memory has a single owner; when the owner is dropped, the memory is freed exactly once (no use-after-free, no double-free). This makes heap allocation safe in Rust in the memory-correctness sense. However, heap allocation introduces runtime allocation failure risk (OOM) on resource-constrained embedded targets. The policy limits heap use to cases where it is genuinely necessary, making the memory footprint more predictable and OOM conditions easier to reason about. For an ASIL B library targeting automotive Linux, OOM on the Raspberry Pi host is not a realistic scenario for the data sizes involved (ciphertext output is bounded by the OTA image size, which is handled at the application layer), but the policy is maintained for architectural discipline.

---

### RG-MEM-04: Stack Arrays for Fixed-Size Cryptographic Outputs

**Rule:** Fixed-size cryptographic outputs shall be represented as stack arrays:

| Type | Array Type |
|---|---|
| SHA-256 digest | `[u8; 32]` |
| AES-GCM authentication tag | `[u8; 16]` |
| HMAC-SHA256 output | `[u8; 32]` |
| P-256 ECDH shared secret | `[u8; 32]` |
| AES-256 key material (in transit) | `[u8; 32]` |
| ECDSA signature (r, s) | `EcdsaSignature` struct wrapping `[u8; 32]` each |

No heap allocation shall be used for any of these types.

**Enforcement:** Compile-time (Rust type system enforces array sizes). Manual review verifies that new cryptographic output types use this convention.

**Rationale:** Stack arrays have deterministic lifetime (stack frame), are automatically dropped at end of scope, and avoid heap fragmentation. For secret values (key material in transit, shared secrets), stack allocation combined with ZeroizeOnDrop (RG-MEM-05) provides the strongest available guarantee that secret bytes are cleared before memory is reused. Heap-allocated secret buffers that are dropped without zeroization may persist in heap memory until overwritten by a future allocation.

---

### RG-MEM-05: ZeroizeOnDrop for All Key Material Structs

**Rule:** Any struct that holds cryptographic key material (raw key bytes, private key scalars, shared secrets in transit) shall derive or implement `ZeroizeOnDrop` from the `zeroize` crate. This ensures key bytes are overwritten with zeros when the struct is dropped, regardless of the code path that causes the drop.

**Enforcement:** Compile-time assertion pattern. Each key material struct shall include:

```rust
// HSM-REQ-031
#[derive(ZeroizeOnDrop)]
struct KeySlot {
    key_bytes: [u8; 32],
    key_type: KeyType,
}

// Compile-time assertion that ZeroizeOnDrop is implemented:
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<KeySlot>();
};
```

New key material types that do not implement `ZeroizeOnDrop` will fail the assertion at compile time.

**Rationale:** In Rust, stack frames and heap allocations are not automatically zeroed when freed. Without explicit zeroization, key material persists in memory as "dead bytes" until overwritten by a future allocation. Physical memory inspection (cold-boot attack, DMA attack) or OS core dump could expose these bytes. ISO 26262 and ISO 21434 both require that key material be protected at rest and in transit; zeroize-on-drop is the software-layer enforcement of this requirement (HSM-REQ-022, HSM-REQ-031, SG-05).

---

### RG-MEM-06: No Global Mutable State

**Rule:** `static mut` variables shall not appear in production source code. All mutable state required by the library shall be encapsulated in `&mut self` method receivers or in thread-safe wrappers (`Arc<Mutex<T>>`, see RG-CON-01). Compile-time constants (`static` without `mut`, `const`) are permitted.

**Enforcement:** Compile-time. Any `static mut` is `unsafe` in Rust, so `#![deny(unsafe_code)]` (RG-MEM-01) also prohibits `static mut` without an additional lint. The no-global-mutable-state rule is therefore a corollary of RG-MEM-01.

**Rationale:** Global mutable state creates implicit coupling between functions (a function can observe or modify state that is not visible in its signature), makes reasoning about state transitions difficult, and in multi-threaded contexts introduces data races unless protected. ISO 26262-6 requires that function interfaces be clearly defined and that side effects be documented. Encapsulating state in `&mut self` makes the state ownership explicit and the borrow checker enforces that no two callers hold mutable access simultaneously.

---

## 3. Rules — Integer and Arithmetic Safety

### RG-INT-01: No Unchecked Arithmetic on Safety-Relevant Values

**Rule:** Arithmetic operations (`+`, `-`, `*`, `/`) on values that have safety relevance (counters, indices, lengths, version numbers) shall use checked, saturating, or explicitly justified wrapping arithmetic. Specifically:

- Prefer `checked_add(n).ok_or(HsmError::Overflow)?` for counter increments
- Prefer `saturating_add` for rate limiter bucket arithmetic (overflow is safe in this context — it saturates at max)
- Plain `+` is acceptable for non-safety-relevant values (e.g., string formatting, log message construction)
- Wrapping arithmetic (`wrapping_add`) shall only be used where wrap-around is correct by design (e.g., cryptographic nonce increment in CTR mode), and shall be commented to document the intent

**Enforcement:** Manual review with clippy lint `clippy::integer_arithmetic` enabled in pedantic mode for safety-critical modules. CI will report instances; developer must justify or fix before merge.

**Rationale:** Integer overflow in Rust in debug builds panics (which is bad in a library — see RG-MEM-02); in release builds it wraps silently. For safety-relevant values, silent wrap produces logically incorrect values: a version counter that wraps from `u32::MAX` to 0 would defeat rollback protection; a length that overflows would produce a short buffer. Explicit checked arithmetic turns overflow into a detectable error condition.

---

### RG-INT-02: Use `u64` for Sequence Numbers and Counters

**Rule:** Monotonic sequence numbers (USB frame sequence numbers), replay-protection counters (activation token counter, OTA version number if promoted to u64), and rate limiter counters shall be declared as `u64`. Narrower types (`u32`, `u16`) shall not be used for these values unless a documented analysis shows the narrower type is sufficient for the operational lifetime of the system.

**Enforcement:** Manual review. New counter types are reviewed at PR time.

**Rationale:** A `u32` counter incrementing once per second wraps in approximately 136 years — adequate for most embedded systems. However, a `u32` USB frame sequence number incrementing at 1000 frames/second wraps in approximately 49 days, which is within a plausible vehicle uptime for long-haul commercial vehicles. A `u64` counter incrementing at 1 billion increments/second would take approximately 585 years to wrap. Using `u64` eliminates the counter-wrap failure mode for all realistic automotive operational scenarios without meaningful cost on a 64-bit host processor.

---

### RG-INT-03: Cryptographic Length Validation at API Boundary

**Rule:** Every function that accepts a `&[u8]` or `Vec<u8>` input with a cryptographic constraint on its length (key material, IV, AAD, digest, signature) shall validate the length at the entry point of the public API function, before any computation or USB command is sent. Validation failures shall return `Err(HsmError::InvalidParam)` with a variant that identifies the specific invalid parameter. Silent truncation or silent extension of input buffers is prohibited.

**Enforcement:** CI test: each public API function has at least one test that passes a buffer of the wrong length and asserts `Err(HsmError::InvalidParam(_))` is returned. `clippy::indexing_slicing` is enabled to flag unchecked slice indexing.

**Rationale:** Silent truncation is a classic source of cryptographic weakness (e.g., accepting a 16-byte key for an AES-256 slot results in a 128-bit effective key strength). Explicit validation at the API boundary provides a clear error to the caller and prevents incorrect inputs from reaching the cryptographic computation layer. Detecting the error at the API boundary is also more efficient — no USB round-trip is initiated for an invalid input.

---

### RG-INT-04: No Float Arithmetic in Cryptographic Code

**Rule:** Floating-point types (`f32`, `f64`) and floating-point arithmetic shall not be used in any cryptographic computation, key management, or safety-relevant error handling code. Float arithmetic is permitted only in benchmark reporting and diagnostic tooling.

**Enforcement:** clippy lint `clippy::float_arithmetic` enabled for safety-critical modules. Manual review.

**Rationale:** Floating-point arithmetic is non-associative, subject to rounding, and platform-dependent in edge cases (NaN, infinity, denormals). These properties are incompatible with cryptographic algorithms which require exact, reproducible integer arithmetic. Additionally, float-to-integer conversion (`as` cast) in Rust can produce implementation-defined values on overflow (rounds to `i64::MAX` — not a panic, not an error). Using integer types exclusively eliminates this category of subtle arithmetic error from the safety-relevant code paths.

---

## 4. Rules — Error Handling

### RG-ERR-01: All Functions Return `Result<T, HsmError>`

**Rule:** Every function in the public API and in any internal module that performs a fallible operation shall return `Result<T, HsmError>`. Functions that cannot fail may return `T` directly. A function shall not return a raw `bool` to indicate success or failure of a fallible operation (e.g., a function named `verify_something` shall not return `bool` — it shall return `Result<bool, HsmError>` if the verification operation itself can fail, or `bool` only if the verification is infallible, which is not the case for cryptographic operations involving I/O to the L55).

**Enforcement:** Manual review. API functions are reviewed at design time for correct return type.

**Rationale:** `bool` return values for fallible operations have two failure modes: (1) the caller ignores the `false` return value (the compiler does not require checking a `bool`); (2) error information is lost — the caller cannot distinguish "signature invalid" from "USB communication failure". `Result<T, HsmError>` forces the compiler to require the caller to handle both `Ok` and `Err` cases (via `must_use`), and preserves error type information for safe-state decision making. ISO 26262 requires that error conditions be distinguishable (HSM-REQ-027).

---

### RG-ERR-02: Every `HsmError` Variant Is Distinguishable

**Rule:** The `HsmError` enum shall have no generic "catch-all" variant (e.g., no `HsmError::Generic(String)`, no `HsmError::Other`). Each failure mode that the library can encounter shall have its own named variant with any additional context encoded in the variant's data. The current set of variants is:

```rust
pub enum HsmError {
    NotInitialized,
    InvalidHandle,
    InvalidParam(InvalidParamKind),
    TagMismatch,
    SignatureInvalid,
    VersionRollback,
    ReplayDetected,
    KeySlotFull,
    KeyTypeMismatch,
    RateLimitExceeded,
    HardwareFault,
    StorageFault,
    ShortRead,
    FrameError(FrameErrorKind),
    UsbDisconnected,
    Overflow,
}
```

Adding a new error variant requires a PR with: (1) the new variant, (2) at least one test that triggers the new variant, (3) documentation of which failure mode the variant represents.

**Enforcement:** Manual review at PR time. The absence of a catch-all variant is verified by code review and by the exhaustive `match` requirement (RG-STR-04 — any code that matches on `HsmError` must handle all variants).

**Rationale:** A catch-all error variant conceals root cause from the integrating system. ISO 26262 requires that errors be distinguishable so that appropriate safe-state actions can be taken. A `TagMismatch` error has a different safety implication than a `UsbDisconnected` error — the former indicates a potential attack or data corruption; the latter indicates a transient hardware fault. The integrator's safe-state handler must be able to distinguish these.

---

### RG-ERR-03: All Errors Must Be Propagated

**Rule:** The result of a fallible operation shall never be silently discarded with `let _ = result;` or by calling a function without binding its `Result` return. All `Result` values shall be either propagated with `?`, explicitly matched, or explicitly acknowledged with a documented rationale comment if discarding is intentional (e.g., best-effort IDS event emission where delivery failure is acceptable).

**Enforcement:** clippy lint `clippy::let_underscore_must_use` enabled. The `#[must_use]` attribute is applied to `Result<T, HsmError>` (inherited from the standard library) and to all custom types where ignoring the value would be a bug.

**Rationale:** Silently discarding a `Result` is the functional equivalent of ignoring an error return code in C. If the discarded operation was the tag comparison in `aes_gcm_decrypt`, ignoring its result produces an authentication bypass (FM-013). The Rust type system's `#[must_use]` machinery provides compile-time detection of most cases; the clippy lint catches remaining cases.

**Intentional discard pattern:** Where discarding is genuinely correct (e.g., IDS hook delivery), use:

```rust
// IDS event delivery is best-effort; delivery failure does not affect crypto correctness.
// HSM-REQ-038
let _ = ids_hook.emit(IdsEvent::DecryptAuthFail { session_id });
```

The comment must document why the discard is acceptable.

---

### RG-ERR-04: No `abort`, `exit`, or `process::exit` in Library Code

**Rule:** `std::process::abort()`, `std::process::exit()`, and any equivalent that terminates the calling process shall not be called from library code. Fatal conditions (protocol violations, unrecoverable hardware faults) shall be returned to the caller as `Err(HsmError::HardwareFault)` or an appropriate variant. The caller decides whether to terminate the process.

**Enforcement:** clippy lint `clippy::exit` is enabled. Manual review.

**Rationale:** A library that calls `process::exit()` removes the integrating application's ability to take a safe state before termination (e.g., logging the event, notifying the vehicle bus, engaging a fallback mode). ISO 26262 requires that the integrating system control safe-state transitions; the `scorehsm` library is only responsible for reporting error conditions. An unexpected `exit()` from within a library call is indistinguishable from a crash from the integrator's perspective.

---

## 5. Rules — Documentation

### RG-DOC-01: All Public Items Must Have Doc Comments

**Rule:** Every `pub` function, struct, enum, enum variant, trait, and type alias shall have a Rust doc comment (`///`). The doc comment shall at minimum describe: what the item does, what the parameters represent, and what the return value represents.

**Enforcement:** Compile-time. `#![deny(missing_docs)]` is declared in `host/src/lib.rs`. Any public item without a doc comment causes a compilation error.

**Rationale:** ISO 26262-6 §8.4.4 requires that software unit design is documented. In Rust, `///` doc comments serve as the unit-level design documentation — they are embedded in the source, cannot become out-of-date with the implementation without deliberate effort, and are verified by `rustdoc` to have correct example code (if examples are included). `deny(missing_docs)` is the strongest available enforcement mechanism for documentation completeness.

---

### RG-DOC-02: Safety-Relevant Pre/Post-Conditions in Doc Comments

**Rule:** Functions that have non-obvious preconditions, postconditions, or error conditions that are safety-relevant shall document them in dedicated `# Errors` or `# Safety` sections in the doc comment. The format follows Rust API guidelines:

```rust
/// Verifies an OTA firmware image against a code-signing certificate.
///
/// # Errors
///
/// Returns `Err(HsmError::SignatureInvalid)` if the ECDSA signature does not
/// verify against the certificate's public key.
///
/// Returns `Err(HsmError::VersionRollback)` if `version <= installed_version`.
/// This check is cryptographically binding only if `version` is included in the
/// signed content of the image. See image format specification in
/// `docs/architecture/architecture.md §5.3`.
///
/// # Panics
///
/// Does not panic. See RG-MEM-02.
// HSM-REQ-047
pub fn verify_update_image(
    cert: &Certificate,
    image: &[u8],
    sig: &EcdsaSignature,
    version: u32,
    installed_version: u32,
) -> Result<(), HsmError> { ... }
```

**Enforcement:** Manual review. Safety review checklist includes: "Does every safety-relevant function have an `# Errors` section listing all possible error variants?"

**Rationale:** Undocumented preconditions are a common source of integration defects. If the integrator does not know that `verify_update_image` requires the version to be part of the signed content, the rollback protection can be silently defeated by a caller that passes an unsigned version field. Explicit documentation of this assumption in the API makes the ASR visible to the integrator at the point of use.

---

### RG-DOC-03: Requirement Traceability Comments

**Rule:** Every `impl` block, function, or code section that implements a specific `HSM-REQ-NNN` requirement shall carry a traceability comment in the format:

```rust
// HSM-REQ-022 — key deletion and zeroize
impl HsmBackend for HardwareBackend {
    fn key_delete(&mut self, handle: KeyHandle) -> Result<(), HsmError> {
        // HSM-REQ-022: zeroize before invalidating handle
        // HSM-REQ-038: emit IDS event on deletion
        ...
    }
}
```

The traceability comment shall reference the exact `HSM-REQ-NNN` identifier as it appears in `docs/requirements/requirements.md`.

**Enforcement:** Manual review. The requirements-to-code traceability matrix in `docs/requirements/requirements.md` is maintained by cross-referencing these comments. CI tooling may be added to verify all HSM-REQ IDs referenced in source code exist in the requirements document.

**Rationale:** ISO 26262-6 §12.4.2 requires that software safety requirements be traceable to their implementation. Without explicit traceability comments, the traceability matrix must be maintained as a separate artifact that can become stale. Embedding requirement IDs in source comments makes the traceability self-maintaining — the code is the evidence. Reviewers can verify that the implementation covers all aspects of the cited requirement at PR time.

---

## 6. Rules — Code Structure

### RG-STR-01: No Recursion

**Rule:** Recursive function calls (direct or mutual recursion) shall not appear in production source code. All repetition shall use iterative constructs (`for`, `while`, `loop`, iterator adapters).

**Enforcement:** Manual review. Rust does not prevent recursion at compile time. Reviewers shall check for recursive calls during PR review. Clippy lint `clippy::only_used_in_recursion` is enabled (detects trivially recursive patterns). Stack depth analysis is required for any function that is identified as a candidate for recursion (e.g., recursive data structure traversal).

**Rationale:** Recursion's stack consumption is not bounded at compile time in Rust. In an embedded or safety-relevant context, unbounded stack growth can cause stack overflow, which in Rust causes an abort (not a panic, not a recoverable error). ISO 26262 requires that the worst-case stack usage be analyzable (WCSA). Eliminating recursion makes stack usage statically bounded — each function's stack frame is fixed and analyzable. This is particularly important on the L55 firmware side where the Cortex-M stack is small (typically 4–8 KB).

---

### RG-STR-02: Single Responsibility per Module

**Rule:** Each Rust module (`mod`) shall have a single, clearly stated responsibility. The following module boundaries are mandatory and shall not be merged:

| Module | Responsibility |
|---|---|
| `host/src/crypto/` | Cryptographic operation implementations (aes_gcm, ecdsa, hmac, kdf) |
| `host/src/key_management.rs` | Key slot allocation, handle management, zeroization |
| `host/src/session.rs` | Session lifecycle, access control, rate limiting |
| `host/src/ids.rs` | IDS event types and hook dispatch |
| `host/src/protocol/` | USB CDC frame encoding, CRC, sequence numbers |
| `host/src/error.rs` | `HsmError` type definition |
| `host/src/backend/` | `HsmBackend` trait definition and backend implementations |

Cross-module dependencies shall flow in a directed acyclic graph (no circular imports). The dependency direction is: `backend → crypto, key_management, session, ids, protocol → error`.

**Enforcement:** Compile-time (Rust module system enforces that circular `use` dependencies cause compilation errors if they create circular type dependencies). Manual review verifies that new code is added to the correct module.

**Rationale:** Single-responsibility modules reduce the scope of changes required for any given modification, making impact assessment (required for change management under ISO 26262-8 §8) tractable. A change to the USB protocol should not require re-verification of the cryptographic operation implementations. Clear module boundaries make the SW-FMEA more precise (failure modes are localized to modules) and make code review more effective (reviewers can focus on one responsibility at a time).

---

### RG-STR-03: No Placeholder Code in Production

**Rule:** `todo!()`, `unimplemented!()`, and empty function bodies in trait implementations (stubs that return `Err(HsmError::NotInitialized)` without implementing the function) shall not appear in production source code on the `main` branch. Feature branches may contain `todo!()` temporarily during development.

**Enforcement:** CI check: `grep -r 'todo!\|unimplemented!' host/src/ firmware/src/nonsecure/` fails the build if any match is found on the `main` branch. This is enforced by a CI job that runs only on pushes to `main`.

**Rationale:** `todo!()` and `unimplemented!()` panic at runtime. Their presence in production code means the safety analysis (FMEA, test strategy) is based on an incomplete implementation. ISO 26262-6 §8.4.5 requires that implementation be complete before integration testing. A library shipped with stub implementations cannot meet its safety requirements and cannot be validly covered by a requirements-based test suite (the tests for stub functions would trivially fail).

---

### RG-STR-04: Exhaustive Match Statements on Enums

**Rule:** `match` statements on `HsmError`, `KeyType`, `IdsEvent`, and any other safety-relevant enum shall be exhaustive — they shall list all variants explicitly. The catch-all pattern `_ => { ... }` shall not be used as a substitute for listing variants, unless the catch-all is documented to be intentionally handling future variants (open enum extension point), in which case a `// DEVIATION: RG-STR-04` comment with justification is required.

`_ => unreachable!()` is specifically prohibited as this panics if a new variant is added and this arm is reached.

**Enforcement:** Compile-time. Rust's exhaustiveness checker requires all match arms to cover all enum variants. If a new variant is added to `HsmError`, all match statements on `HsmError` that do not have a `_` catch-all will produce a compilation error, forcing the developer to handle the new variant. This is the desired behavior.

**Rationale:** Non-exhaustive match statements are a common source of "forgotten case" bugs. In safety software, an unhandled variant of a status enum (e.g., a new `HsmError` variant added without updating the caller's match) defaults to whatever behavior the catch-all specifies — which may be incorrect for the new variant. Exhaustive match statements guarantee at compile time that all cases are explicitly handled. Adding a new `HsmError` variant without updating all match sites is a compile-time error, not a runtime defect.

---

## 7. Rules — Concurrency

### RG-CON-01: Thread Safety via `Arc<Mutex<T>>`

**Rule:** `HsmBackend` implementations shall implement `Send + Sync`. Any shared mutable state required across async task boundaries (e.g., the session handle registry, the rate limiter token bucket) shall be wrapped in `Arc<Mutex<T>>` or `Arc<RwLock<T>>`. Raw shared mutable state (including `static mut` — already prohibited by RG-MEM-01 and RG-MEM-06) is prohibited.

```rust
// HSM-REQ-037
pub struct HsmSession {
    backend: Arc<Mutex<dyn HsmBackend + Send>>,
    owned_handles: HashSet<HandleId>,
    rate_limiter: Arc<Mutex<TokenBucket>>,
}
```

**Enforcement:** Compile-time. Rust's `Send` and `Sync` auto-traits propagate through type composition; any type containing a non-Send or non-Sync field will not implement `Send + Sync`. The trait bounds `T: Send + Sync` on function signatures that accept `HsmBackend` implementations enforce this at the call site.

**Rationale:** The `scorehsm` library is used from an async Rust application (Embassy on firmware, Tokio on the Pi host). Async runtimes may move futures across threads; any state accessed across `.await` points must be `Send`. Without explicit thread-safety requirements on shared state, data races are possible in multi-threaded async contexts. Rust's `Send`/`Sync` type system mechanically prevents data races for all types that correctly implement these traits. ISO 26262-6 requires that data consistency be maintained; `Mutex<T>` provides this guarantee.

---

### RG-CON-02: Single-Task Key Slot Access in Firmware

**Rule:** In the L55 firmware, key slot read and write operations (all operations on the SRAM2 key store) shall be performed from a single Embassy task — the USB command dispatcher task. Key slot access shall not be shared across multiple concurrent tasks without an explicit synchronization primitive. No task other than the command dispatcher shall write to or read from key slots.

**Enforcement:** Manual review. The firmware architecture (`docs/architecture/architecture.md`) documents the single-task key store access policy. The SRAM2 key store module shall not be made `Send` or `Sync` — it is a `!Send` type that can only be owned by the dispatcher task.

**Rationale:** The L55 Secure world operates with a cooperative task scheduler (Embassy). Concurrent access to the key store from multiple tasks — even without a hardware data race — can produce logical data races (task A reads a slot while task B is in the middle of writing it). Making the key store `!Send` prevents it from being moved to another task accidentally. Combined with the single-dispatcher-task architecture, this eliminates the class of concurrent key store corruption bugs without requiring explicit locking, which would introduce deadlock risk on a resource-constrained embedded target.

---

## 8. Enforcement Matrix

The following table summarizes the enforcement level for each rule:

| Rule ID | Rule Summary | Compile-time | clippy | CI Script | Manual Review |
|---|---|---|---|---|---|
| RG-MEM-01 | No unsafe code | Yes (`deny(unsafe_code)`) | — | — | — |
| RG-MEM-02 | No unwrap/expect in library | Partial (must_use) | Yes (`unwrap_used`, `expect_used`) | — | PR checklist |
| RG-MEM-03 | Heap allocation policy | — | Yes (`vec_init_then_push`) | — | PR review |
| RG-MEM-04 | Stack arrays for fixed-size outputs | Yes (array type sizes) | — | — | PR review |
| RG-MEM-05 | ZeroizeOnDrop for key structs | Yes (const assertion) | — | — | PR checklist |
| RG-MEM-06 | No global mutable state | Yes (via RG-MEM-01) | — | — | — |
| RG-INT-01 | Checked arithmetic for safety values | — | Yes (`integer_arithmetic` pedantic) | — | PR review |
| RG-INT-02 | u64 for counters | — | — | — | PR review |
| RG-INT-03 | Length validation at API boundary | — | Yes (`indexing_slicing`) | Length test per function | PR review |
| RG-INT-04 | No floats in crypto code | — | Yes (`float_arithmetic`) | — | PR review |
| RG-ERR-01 | All functions return Result | — | — | — | PR design review |
| RG-ERR-02 | Distinguishable error variants | — | — | — | PR review |
| RG-ERR-03 | No silent error discard | Partial (must_use) | Yes (`let_underscore_must_use`) | — | PR review |
| RG-ERR-04 | No abort/exit in library | — | Yes (`exit`) | — | PR review |
| RG-DOC-01 | All public items have doc comments | Yes (`deny(missing_docs)`) | — | — | — |
| RG-DOC-02 | Safety pre/post-conditions documented | — | — | — | Safety review checklist |
| RG-DOC-03 | HSM-REQ traceability comments | — | — | Grep for HSM-REQ IDs (planned) | PR review |
| RG-STR-01 | No recursion | — | Yes (`only_used_in_recursion`) | — | PR review |
| RG-STR-02 | Single responsibility per module | Partial (no circular imports) | — | — | Architecture review |
| RG-STR-03 | No todo!/unimplemented! in main | — | — | Yes (grep on main branch) | — |
| RG-STR-04 | Exhaustive match statements | Yes (Rust exhaustiveness) | — | — | — |
| RG-CON-01 | Arc<Mutex> for shared state | Yes (Send + Sync bounds) | — | — | PR review |
| RG-CON-02 | Single-task key slot access | Yes (!Send on key store type) | — | — | Architecture review |

**Key:** "Yes" indicates the mechanism provides primary enforcement. "Partial" indicates the mechanism enforces some but not all aspects of the rule.

---

## 9. Deviations

### 9.1 Deviation Process

A deviation from any rule in this document shall be approved before the non-conforming code is merged to `main`. The deviation process is:

1. **Identify the deviation.** The developer identifies which rule is violated and why a violation is necessary (e.g., a third-party crate requires `unsafe` in a wrapper function).

2. **Document the deviation.** A deviation record shall be created in `docs/safety/deviations/DEV-NNN.md` with the following fields:
   - **DEV-ID:** Sequential deviation identifier (DEV-001, DEV-002, …)
   - **Rule:** The rule ID being deviated from (e.g., RG-MEM-01)
   - **Location:** File path and function name of the non-conforming code
   - **Reason:** Why the rule cannot be followed in this specific case
   - **Alternative Mitigation:** What replaces the rule's normal enforcement mechanism to achieve equivalent safety confidence (e.g., if unsafe is required: a safety comment block documenting the invariants that must hold, a unit test that would fail if the invariant is violated, and a code review by a second developer)
   - **Residual Risk:** The remaining risk after the alternative mitigation is applied
   - **Approval:** Name and date of Safety Manager approval

3. **Reference the deviation in code.** The non-conforming code shall carry a comment:
   ```rust
   // DEVIATION: RG-MEM-01 — see docs/safety/deviations/DEV-001.md
   unsafe { ... }
   ```

4. **Approval authority.** Deviations from RG-MEM-01 (unsafe code) and RG-MEM-02 (unwrap in library code) require Safety Manager approval. Deviations from other rules require Architecture review approval. No rule may be deviated from without documented approval.

### 9.2 Known Deviations

At the time of this document (2026-03-14), there are no approved deviations from any rule in this document. All production source code in `scorehsm-host` and the L55 Rust firmware is conformant.

---

## 10. Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-03-14 | Taktflow Systems | Initial release — all 22 rules defined; enforcement matrix complete |
