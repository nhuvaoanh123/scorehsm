# Timing Evidence — scorehsm Constant-Time Audit

**Date:** 2026-03-14
**Scope:** AES-256-GCM tag comparison, P-256 ECDSA/ECDH scalar operations
**Crate versions:** `aes-gcm 0.10.3`, `p256 0.13.2`, `subtle 2.6.1`

---

## 1. AES-GCM Tag Comparison

**Claim:** AES-GCM tag comparison uses `subtle::ConstantTimeEq` — no early-exit on first mismatched byte.

**Source evidence** (`aes-gcm-0.10.3/src/lib.rs`, lines 304–310):
```rust
fn decrypt_in_place_detached(...) -> Result<(), Error> {
    let expected_tag = self.compute_tag(mask, associated_data, buffer);
    use subtle::ConstantTimeEq;
    if expected_tag[..TagSize::to_usize()].ct_eq(tag).into() {
        ctr.apply_keystream_partial(buffer.into());
        Ok(())
    } else {
        Err(Error)
    }
}
```

The GHASH-based expected tag is compared against the provided tag using `ct_eq` (constant-time equality). Ciphertext decryption only occurs after tag verification passes (authenticate-then-decrypt ordering).

**Statistical test** (`host/tests/constant_time_tests.rs`):
- 2000 iterations each of: first-byte-wrong, last-byte-wrong, all-bytes-wrong tags
- A non-CT byte-by-byte comparison would show first_mean << last_mean
- Result: first↔last drift < 20% (within system noise)

**Note:** Total decrypt time DOES differ between correct-tag and wrong-tag operations. This is expected: correct-tag includes CTR decryption, wrong-tag returns immediately. This is not a timing leak — the result (success/failure) is already visible to the caller.

---

## 2. P-256 Scalar Operations

**Claim:** P-256 scalar arithmetic uses `subtle` primitives for constant-time operation.

**Source evidence:**

### 2a. Scalar type (`p256-0.13.2/src/arithmetic/scalar.rs`)
- Lines 20–23: imports `subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess, CtOption}`
- `PartialEq` delegates to `ct_eq` (lines 441–444)
- `ConditionallySelectable` implemented for branchless selection (lines 712–716)

### 2b. Point multiplication (`primeorder-0.13.6/src/projective.rs`)
- Lines 130–137: windowed scalar multiplication uses `conditional_assign` with `Choice`
- No data-dependent branches on secret scalar bits

### 2c. RFC 6979 nonce generation (`rfc6979-0.4.0/src/ct_cmp.rs`)
- Candidate k values compared against curve order using `subtle::ConstantTimeEq` and `ct_lt`

### 2d. Field elements (`p256-0.13.2/src/arithmetic/field.rs`)
- Uses `subtle::{Choice, ConstantTimeEq, CtOption}`

---

## 3. Caveats

| Caveat | Impact | Mitigation |
|--------|--------|------------|
| `Ord::cmp` on `Scalar` is variable-time | Leaks if scalars used as sort keys | ECDSA/ECDH paths never sort scalars |
| `invert_vartime` exists | Leaks if called on secret scalars | Normal `invert()` uses constant-time Fermat path |
| `subtle` is best-effort | Compiler may defeat volatile barrier | Use `--release` builds; hardware audit pending |
| Debug builds have `debug_assert` branches | Data-dependent branches in debug | Only release builds for production/testing |
| AES hardware acceleration (AES-NI) | CT properties of AES block cipher depend on hardware | AES-NI provides CT by design |

---

## 4. Firmware Timing (Pending Hardware)

DWT cycle counter instrumentation is planned for firmware `crypto.rs`. When hardware is available:

1. Enable `DWT.CYCCNT` before Embassy init
2. Measure AES-GCM encrypt/decrypt and ECDSA sign cycle counts
3. Collect 1000+ samples, compute CV
4. Target: CV < 5% for timing-sensitive operations

---

## 5. Benchmark Infrastructure

Host-side criterion benchmarks (`host/benches/timing.rs`):
- AES-256-GCM encrypt/decrypt at 1B, 32B, 128B, 512B payloads
- ECDSA P-256 sign/verify
- SHA-256 at 32B, 256B, 1KB, 4KB
- HMAC-SHA256 at 256B

Run: `cargo bench --bench timing`

---

## 6. Conclusion

The scorehsm software backend uses constant-time primitives for all security-sensitive comparisons:
- **AES-GCM tag verification:** `subtle::ConstantTimeEq::ct_eq` — verified by source audit and statistical test
- **P-256 scalar operations:** `subtle::ConditionallySelectable` and `ConstantTimeEq` throughout — verified by source audit
- **Limitation:** Software P-256 via `p256` crate; hardware PKA path planned but not yet implemented
