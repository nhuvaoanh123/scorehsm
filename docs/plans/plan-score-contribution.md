# SCORE Security Crypto Contribution Plan

Date: 2026-03-14
Status: DRAFT
Author: Taktflow Systems
Target: Eclipse SCORE `baselibs/score/crypto/` component
License: Apache-2.0 (SPDX: Apache-2.0)

---

## 1. Ground Truth — What Exists in the SCORE Repo

Cloned at: `C:\Users\andao\AppData\Local\Temp\eclipse-contrib\baselibs\`

```
score/crypto/
├── include/score/crypto/
│   └── hsm_types.h          ← ONLY file that exists (types + error codes)
└── src/
    ├── posix/               ← EMPTY (Linux/QNX software implementation)
    └── stm32l5/
        ├── linker/          ← EMPTY
        ├── nonsecure/       ← EMPTY (USB CDC host side)
        └── secure/          ← EMPTY (TrustZone Secure world firmware)
```

**The crypto component is a stub.** Our job is to implement it.

---

## 2. Interface Contract — What `hsm_types.h` Specifies

The SCORE team has defined the canonical C types. Every function we write must use
exactly these types — no divergence.

### 2.1 Error Codes (`HsmStatus_t = int32_t`)

| SCORE constant | Value | Maps to `HsmError` variant |
|---|---|---|
| `HSM_OK` | 0 | `Ok(...)` |
| `HSM_ERR_INVALID_PARAM` | −1 | `InvalidParam`, `InvalidArgument` |
| `HSM_ERR_INVALID_KEY_ID` | −2 | `InvalidKeyHandle` |
| `HSM_ERR_KEY_SLOT_FULL` | −3 | `KeyStoreFull` |
| `HSM_ERR_CRYPTO_FAIL` | −4 | `CryptoFail`, `HardwareFault` |
| `HSM_ERR_NOT_INITIALIZED` | −5 | `NotInitialized` |
| `HSM_ERR_TAG_MISMATCH` | −6 | `TagMismatch`, `AuthenticationFailed` |
| `HSM_ERR_BUFFER_TOO_SMALL` | −7 | *(new — no equivalent yet in HsmError)* |
| `HSM_ERR_UNSUPPORTED` | −8 | `Unsupported` |

**Gap:** `HSM_ERR_BUFFER_TOO_SMALL` has no Rust counterpart. Add to `HsmError` before FFI work.

**Safety-specific error codes to propose adding to `hsm_types.h`:**

| Proposed constant | Value | ASIL B reason |
|---|---|---|
| `HSM_ERR_SAFE_STATE` | −9 | Library entered `SafeState` — all ops blocked |
| `HSM_ERR_RATE_LIMIT` | −10 | Token-bucket exhausted (DoS mitigation) |
| `HSM_ERR_SEQUENCE_OVERFLOW` | −11 | Sequence counter at `u32::MAX` |
| `HSM_ERR_NONCE_EXHAUSTED` | −12 | Per-key AEAD nonce counter exhausted |
| `HSM_ERR_CERT_EXPIRED` | −13 | X.509 certificate past `notAfter` |
| `HSM_ERR_CERT_NOT_YET_VALID` | −14 | X.509 certificate before `notBefore` |

These map directly to TSR-RLG-01, TSR-SSG-01, TSR-TIG-02, TSR-NMG-01, TSR-CG-01.
Must propose them to the SCORE safety WG as part of the PR.

### 2.2 Key Types (`HsmKeyType_t = uint32_t`)

| SCORE constant | Value | Maps to `KeyType` |
|---|---|---|
| `HSM_KEY_TYPE_AES_256` | 0x0001 | `KeyType::Aes256` |
| `HSM_KEY_TYPE_HMAC_SHA256` | 0x0002 | `KeyType::HmacSha256` |
| `HSM_KEY_TYPE_ECC_P256` | 0x0003 | `KeyType::EccP256` |

✓ **Full match.** No gaps.

### 2.3 Algorithm Identifiers (`HsmAlgorithm_t = uint32_t`)

| SCORE constant | Value | Maps to `Algorithm` |
|---|---|---|
| `HSM_ALG_AES_256_GCM` | 0x0001 | `Algorithm::Aes256Gcm` |
| `HSM_ALG_HMAC_SHA256` | 0x0002 | `Algorithm::HmacSha256` |
| `HSM_ALG_ECDSA_P256` | 0x0003 | `Algorithm::EcdsaP256` |

**Gap — missing from `hsm_types.h`:**

| Proposed constant | Value | Maps to |
|---|---|---|
| `HSM_ALG_SHA256` | 0x0004 | `Algorithm::Sha256` |
| `HSM_ALG_ECDH_P256` | 0x0005 | `Algorithm::EcdhP256` |
| `HSM_ALG_HKDF_SHA256` | 0x0006 | `Algorithm::HkdfSha256` |

Must propose these additions in the PR. ECDH and HKDF are required by HSM-REQ-007
(`feat_req__sec_crypt__asym_algo_ecdh`) and HSM-REQ-015 (`feat_req__sec_crypt__key_derivation`).

### 2.4 Data Structures

These already exist in `hsm_types.h` and match our Rust types exactly:

| C struct | Rust equivalent | Match? |
|---|---|---|
| `HsmAesGcmEncryptReq_t` | `(KeyHandle, &AesGcmParams, &[u8])` | ✓ equivalent (flatter in C) |
| `HsmAesGcmDecryptReq_t` | `(KeyHandle, &AesGcmParams, &[u8], &[u8; 16])` | ✓ |
| `HsmEcdsaSignature_t { r[32], s[32] }` | `EcdsaSignature { r: [u8; 32], s: [u8; 32] }` | ✓ exact |

**Missing structs to add to `hsm_types.h`:**

```c
/* ECDSA verify request */
typedef struct {
    HsmKeyHandle_t       key_handle;
    const uint8_t       *digest;          /* [HSM_SHA256_DIGEST_SIZE] */
    const HsmEcdsaSignature_t *signature;
    bool                *result_out;      /* true = valid, false = invalid */
} HsmEcdsaVerifyReq_t;

/* ECDH P-256 key agreement */
typedef struct {
    HsmKeyHandle_t   key_handle;          /* ECC_P256 private key */
    const uint8_t   *peer_pub;            /* [64] uncompressed X||Y */
    uint8_t         *shared_secret_out;   /* [32] */
} HsmEcdhReq_t;

/* HKDF-SHA256 key derivation */
typedef struct {
    HsmKeyHandle_t   base_handle;
    const uint8_t   *info;
    size_t           info_len;
    HsmKeyType_t     out_type;
    HsmKeyHandle_t  *derived_handle_out;
} HsmHkdfReq_t;

/* Secure boot status */
typedef struct {
    bool     verified;
    uint32_t firmware_version;
} HsmBootStatus_t;
```

### 2.5 Size Constants (all in `hsm_types.h`)

All present: `HSM_AES_256_KEY_SIZE` (32), `HSM_AES_GCM_IV_SIZE` (12), `HSM_AES_GCM_TAG_SIZE` (16),
`HSM_SHA256_DIGEST_SIZE` (32), `HSM_HMAC_SHA256_SIZE` (32), `HSM_ECC_P256_KEY_SIZE` (32),
`HSM_ECC_P256_SIG_R_SIZE` / `_S_SIZE` (32).

**Missing:**

```c
#define HSM_ECDH_SHARED_SECRET_SIZE  (32U)
#define HSM_ECC_P256_PUBKEY_SIZE     (64U)   /* uncompressed X||Y */
#define HSM_MAX_KEY_SLOTS            (32U)   /* matches firmware keystore capacity */
```

---

## 3. C API Header to Create — `hsm.h`

Location: `score/crypto/include/score/crypto/hsm.h`

This is the primary contribution artifact — it does not exist yet. All SCORE callers
include this header. It declares every function that the `posix` and `stm32l5`
implementations must provide.

```c
/* Apache-2.0 license header */
#ifndef SCORE_LIB_CRYPTO_HSM_H
#define SCORE_LIB_CRYPTO_HSM_H

#include "score/crypto/hsm_types.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Lifecycle ─────────────────────────────────────────────────────────── */

/** Initialize the HSM backend. Must be called before any other function.
 *  feat_req__sec_crypt__api_lifecycle (HSM-REQ-026) */
HsmStatus_t HSM_Init(void);

/** Release resources. After this, HSM_Init() must be called again.
 *  feat_req__sec_crypt__api_lifecycle (HSM-REQ-026) */
HsmStatus_t HSM_Deinit(void);

/** Re-initialize after a safe-state entry (ASIL B: TSR-SSG-01).
 *  Clears SafeState and resets transport sequence counters. */
HsmStatus_t HSM_Reinit(void);

/** Query secure boot verification result (HSM-REQ-046). */
HsmStatus_t HSM_BootStatus(HsmBootStatus_t *status_out);

/* ── Key management ────────────────────────────────────────────────────── */

/** Generate a new key. Returns an opaque handle.
 *  feat_req__sec_crypt__key_generation (HSM-REQ-019) */
HsmStatus_t HSM_KeyGenerate(HsmKeyType_t key_type, HsmKeyHandle_t *handle_out);

/** Import wrapped key material. Returns an opaque handle.
 *  Hardware backend: material must be KEK-wrapped.
 *  Software backend: raw bytes accepted (dev/CI only).
 *  feat_req__sec_crypt__key_import (HSM-REQ-022) */
HsmStatus_t HSM_KeyImport(HsmKeyType_t key_type,
                           const uint8_t *material, size_t material_len,
                           HsmKeyHandle_t *handle_out);

/** Delete a key and zeroize its slot.
 *  feat_req__sec_crypt__key_deletion, feat_req__sec_crypt__no_key_exposure
 *  (HSM-REQ-043, HSM-REQ-066) */
HsmStatus_t HSM_KeyDelete(HsmKeyHandle_t handle);

/** Derive a child key via HKDF-SHA256.
 *  feat_req__sec_crypt__key_derivation (HSM-REQ-015) */
HsmStatus_t HSM_KeyDerive(const HsmHkdfReq_t *req);

/* ── Entropy ────────────────────────────────────────────────────────────── */

/** Fill `len` bytes with cryptographically secure random data.
 *  feat_req__sec_crypt__rng (HSM-REQ-016) */
HsmStatus_t HSM_Random(uint8_t *out, size_t len);

/* ── Hashing ────────────────────────────────────────────────────────────── */

/** SHA-256.
 *  feat_req__sec_crypt__hashing_algo_sha2 (HSM-REQ-013) */
HsmStatus_t HSM_Sha256(const uint8_t *data, size_t len,
                        uint8_t digest_out[HSM_SHA256_DIGEST_SIZE]);

/* ── MAC ────────────────────────────────────────────────────────────────── */

/** HMAC-SHA256.
 *  feat_req__sec_crypt__mac (HSM-REQ-011) */
HsmStatus_t HSM_HmacSha256(HsmKeyHandle_t handle,
                             const uint8_t *data, size_t len,
                             uint8_t mac_out[HSM_HMAC_SHA256_SIZE]);

/* ── Symmetric AEAD ─────────────────────────────────────────────────────── */

/** AES-256-GCM encrypt. Ciphertext length equals plaintext length.
 *  feat_req__sec_crypt__sym_symmetric_encrypt,
 *  feat_req__sec_crypt__sym_algo_aes_gcm (HSM-REQ-001, HSM-REQ-002) */
HsmStatus_t HSM_AesGcmEncrypt(const HsmAesGcmEncryptReq_t *req);

/** AES-256-GCM decrypt and verify. Returns HSM_ERR_TAG_MISMATCH if auth fails.
 *  Result: no partial plaintext on tag failure (ASIL B: TSR-POST-01, HSM-REQ-072) */
HsmStatus_t HSM_AesGcmDecrypt(const HsmAesGcmDecryptReq_t *req);

/* ── Asymmetric ─────────────────────────────────────────────────────────── */

/** ECDSA P-256 sign. Signs a pre-computed SHA-256 digest.
 *  feat_req__sec_crypt__sig_creation (HSM-REQ-008) */
HsmStatus_t HSM_EcdsaSign(HsmKeyHandle_t handle,
                            const uint8_t digest[HSM_SHA256_DIGEST_SIZE],
                            HsmEcdsaSignature_t *sig_out);

/** ECDSA P-256 verify. Result is definitive true/false — never ambiguous.
 *  Uses constant-time comparison (ASIL B: HSM-REQ-073).
 *  feat_req__sec_crypt__sig_verification (HSM-REQ-009) */
HsmStatus_t HSM_EcdsaVerify(const HsmEcdsaVerifyReq_t *req);

/** ECDH P-256 key agreement. Returns 32-byte shared secret.
 *  feat_req__sec_crypt__asym_algo_ecdh (HSM-REQ-007) */
HsmStatus_t HSM_EcdhAgree(const HsmEcdhReq_t *req);

#ifdef __cplusplus
}
#endif

#endif /* SCORE_LIB_CRYPTO_HSM_H */
```

**Function count: 15.** Each maps 1-to-1 to an `HsmBackend` trait method.

---

## 4. Rust FFI Layer

### 4.1 New file: `host/src/ffi.rs`

Add a C-compatible wrapper over `HsmBackend`. Exposes the 15 `HSM_*` functions as
`#[no_mangle] pub extern "C"` Rust functions.

```rust
// host/src/ffi.rs
//! C FFI bridge — implements the SCORE HSM C API using scorehsm-host.
//!
//! Compiled into a static library (`libscoreHsm.a`) for linking by C/C++ code.
//! Generated header: `score/crypto/include/score/crypto/hsm.h` (hand-maintained
//! to stay in sync — do NOT use cbindgen; the SCORE header is authoritative).

use crate::backend::sw::SoftwareBackend;   // posix target
use crate::backend::HsmBackend;
use crate::error::HsmError;
use crate::types::{AesGcmParams, EcdsaSignature, KeyHandle, KeyType};
use std::sync::Mutex;

// ...global singleton backend...
// ...error mapping fn map_err(e: HsmError) -> i32...
// ...15 #[no_mangle] extern "C" functions...
```

Key design decisions for `ffi.rs`:
- **Global singleton** `Mutex<Option<Box<dyn HsmBackend>>>` — C callers have no
  session concept; `HSM_Init` creates it, `HSM_Deinit` drops it.
- **No heap allocation in hot path** — all output is written to caller-supplied buffers
  (matching `HsmAesGcmEncryptReq_t` pattern).
- **Null-pointer check** on every pointer argument before dereferencing — return
  `HSM_ERR_INVALID_PARAM` immediately. This is the C boundary safety invariant.
- **No `unsafe` in business logic** — only in the FFI wrappers themselves, which are
  explicitly `unsafe fn` internally with documented safety preconditions.

### 4.2 `host/Cargo.toml` additions

```toml
[lib]
name = "scoreHsm"
crate-type = ["staticlib", "rlib"]   # staticlib for C linking; rlib for Rust tests

[features]
ffi = []       # enables ffi.rs module — compile with --features ffi
```

Gate `ffi.rs` under `#[cfg(feature = "ffi")]` to avoid polluting pure-Rust builds.

### 4.3 Why NOT cbindgen

The SCORE `hsm.h` is the authoritative interface — it lives in the SCORE repo and
is reviewed by the SCORE safety WG. cbindgen generates headers from Rust signatures,
which would invert the ownership: SCORE would be locked to our Rust API shape.
Instead, we keep `hsm.h` hand-maintained (only 15 functions) and test that Rust FFI
signatures match it via a compile-time `static_assert` equivalent (`assert_type!`
or just CI build).

---

## 5. Build System Integration

### 5.1 Bazel BUILD file pattern (from SCORE OS component)

```python
# score/crypto/BUILD  (Apache-2.0 header)
load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_rust//rust:defs.bzl", "rust_static_library")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl",
     "COMPILER_WARNING_FEATURES")

# ── Types header (already exists) ──────────────────────────────────────────

cc_library(
    name = "hsm_types",
    hdrs = ["include/score/crypto/hsm_types.h"],
    strip_include_prefix = "include",
    visibility = ["//visibility:public"],
)

# ── Public API header ───────────────────────────────────────────────────────

cc_library(
    name = "hsm_api",
    hdrs = ["include/score/crypto/hsm.h"],
    strip_include_prefix = "include",
    visibility = ["//visibility:public"],
    deps = [":hsm_types"],
)

# ── Platform-selected implementation ───────────────────────────────────────

alias(
    name = "hsm",
    actual = select({
        "@platforms//os:linux":  ":hsm_posix",
        "@platforms//os:qnx":    ":hsm_posix",
        # stm32l5 selected by custom platform config
        "@score_bazel_platforms//:stm32l5": ":hsm_stm32l5_nonsecure",
        "//conditions:default":  ":hsm_posix",
    }),
    visibility = ["//visibility:public"],
)

# ── Posix backend (wraps scorehsm SoftwareBackend via Rust FFI) ────────────

rust_static_library(
    name = "scoreHsm_rust_posix",
    srcs = ["//scorehsm/host:srcs"],
    rustc_flags = ["--cfg=feature=\"ffi\"", "--cfg=feature=\"sw-backend\""],
    edition = "2021",
)

cc_library(
    name = "hsm_posix",
    hdrs = ["include/score/crypto/hsm.h"],
    deps = [
        ":hsm_types",
        ":scoreHsm_rust_posix",
    ],
    strip_include_prefix = "include",
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//visibility:private"],
)

# ── STM32L5 non-secure backend (USB CDC to TrustZone) ─────────────────────

rust_static_library(
    name = "scoreHsm_rust_stm32l5_ns",
    srcs = ["//scorehsm/host:srcs"],
    rustc_flags = ["--cfg=feature=\"ffi\"", "--cfg=feature=\"hw-backend\""],
    edition = "2021",
)

cc_library(
    name = "hsm_stm32l5_nonsecure",
    hdrs = ["include/score/crypto/hsm.h"],
    deps = [
        ":hsm_types",
        ":scoreHsm_rust_stm32l5_ns",
    ],
    strip_include_prefix = "include",
    features = COMPILER_WARNING_FEATURES,
    target_compatible_with = ["@score_bazel_platforms//:stm32l5"],
    visibility = ["//visibility:private"],
)
```

**Open question:** Does SCORE use `rules_rust` in `MODULE.bazel`? Must check and add
the dep if not present. Alternative: compile the Rust static lib separately and
check it in as a pre-built artifact (less clean but avoids the Rust toolchain dep).

### 5.2 Test BUILD target

```python
cc_test(
    name = "hsm_test",
    srcs = ["test/hsm_test.cpp"],
    deps = [
        ":hsm",
        "@googletest//:gtest_main",
    ],
    features = COMPILER_WARNING_FEATURES,
)
```

---

## 6. License Compliance

**SCORE license: Apache-2.0.** Our current codebase has no license header on any file.

Every file contributed to SCORE must have the SCORE-standard Apache-2.0 header:

```c
/******************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 *****************************************************************************/
```

**Action items:**
- All files going into the SCORE PR must carry this header.
- `scorehsm-host` Rust files that are contributed must also be dual-licensed or
  contributed under Apache-2.0. The current scorehsm repo has no `LICENSE` file —
  decide: Apache-2.0, MIT, or dual? Recommend Apache-2.0 to match SCORE.
- Add `LICENSE` and `NOTICE` files to the scorehsm repo before the PR.

---

## 7. GoogleTest Wrappers

SCORE uses GoogleTest for all C++ tests. Create `score/crypto/test/hsm_test.cpp`
covering the SCORE qualification test cases (mapped from SCORE-QTE).

Key tests:

```cpp
// Smoke: init / deinit
TEST(HsmTest, InitDeinit) {
    EXPECT_EQ(HSM_OK, HSM_Init());
    EXPECT_EQ(HSM_OK, HSM_Deinit());
}

// Key lifecycle: generate, use, delete
TEST(HsmTest, KeyGenerateDeleteCycle) { /* ... */ }

// AES-GCM round-trip
TEST(HsmTest, AesGcmEncryptDecryptRoundTrip) { /* ... */ }

// ECDSA sign / verify definitive result (FSR-01 / QT-FSR-01-b)
TEST(HsmTest, EcdsaVerifyTamperedSigReturnsFalseNotError) { /* ... */ }

// No key material in output (FSR-04)
TEST(HsmTest, KeyImportReturnsHandleNotBytes) { /* ... */ }

// ASIL B: safe state after faults (FSR-10 / QT-FSR-10-a)
// Hardware backend only — skip on posix with GTEST_SKIP()
TEST(HsmTest, SafeStateBlocksAllOps) { /* ... */ }
```

---

## 8. Requirement ID Embedding in Code

SCORE enforces traceability via comments in source. Every `HSM_*` function body must
reference the `feat_req__sec_crypt__*` ID in a Doxygen `@reqref` tag or comment:

```c
/**
 * @brief AES-256-GCM encrypt.
 * @reqref feat_req__sec_crypt__sym_symmetric_encrypt
 * @reqref feat_req__sec_crypt__sym_algo_aes_gcm
 * @safety ASIL-B HSM-REQ-001 HSM-REQ-002 FSR-08
 */
HsmStatus_t HSM_AesGcmEncrypt(const HsmAesGcmEncryptReq_t *req) { ... }
```

This is how the SCORE traceability tooling (which parses source) links requirements
to implementation.

---

## 9. Implementation Work Summary

### Files to create in the SCORE repo

| File | Content | Effort |
|---|---|---|
| `score/crypto/include/score/crypto/hsm.h` | 15 C function declarations | Small |
| `score/crypto/include/score/crypto/hsm_types.h` | Extend with missing types/constants | Small |
| `score/crypto/src/posix/hsm_posix.c` | Thin shim calling Rust FFI | Medium |
| `score/crypto/src/stm32l5/nonsecure/hsm_ns.c` | USB CDC shim calling Rust FFI | Medium |
| `score/crypto/BUILD` | Bazel cc_library + rust_static_library | Medium |
| `score/crypto/test/hsm_test.cpp` | GoogleTest cases (15+) | Medium |
| `score/crypto/test/BUILD` | Bazel cc_test | Small |
| `NOTICE` | Eclipse Foundation NOTICE file | Small |

### Files to create/modify in scorehsm repo

| File | Change | Effort |
|---|---|---|
| `host/src/ffi.rs` | 15 `extern "C"` wrappers + global singleton | Large |
| `host/src/error.rs` | Add `BufferTooSmall` variant | Trivial |
| `host/Cargo.toml` | Add `ffi` feature, `crate-type = ["staticlib", "rlib"]` | Trivial |
| `host/src/lib.rs` | `#[cfg(feature = "ffi")] pub mod ffi;` | Trivial |
| `LICENSE` | Add Apache-2.0 | Trivial |
| `NOTICE` | Add Eclipse Foundation NOTICE | Trivial |

---

## 10. PR Sequence

Submit in this order to keep each PR reviewable independently.

### PR 1 — Type extensions to `hsm_types.h` (no implementation)

- Add missing algorithm constants (`HSM_ALG_SHA256`, `HSM_ALG_ECDH_P256`, `HSM_ALG_HKDF_SHA256`)
- Add missing request structs (`HsmEcdsaVerifyReq_t`, `HsmEcdhReq_t`, `HsmHkdfReq_t`, `HsmBootStatus_t`)
- Add missing size constants (`HSM_ECDH_SHARED_SECRET_SIZE`, `HSM_ECC_P256_PUBKEY_SIZE`)
- Propose safety-specific error codes (`HSM_ERR_SAFE_STATE`, etc.) — mark as
  `[RFC]` for SCORE safety WG discussion
- **No implementation changes.** Easy to review, unblocks everything else.

### PR 2 — `hsm.h` public API header

- Create `include/score/crypto/hsm.h` with all 15 function declarations
- Apache-2.0 header, `@reqref` annotations for all `feat_req__sec_crypt__*` IDs
- Add BUILD target `hsm_api` exposing the header
- **Still no implementation.** Agree on the API surface before writing code.

### PR 3 — Posix implementation (software backend, Linux/QNX CI)

- `scorehsm-host` static library with `ffi` + `sw-backend` features compiled into
  `scoreHsm_rust_posix.a`
- `src/posix/hsm_posix.c` (or eliminate the C file entirely — Rust FFI is the impl)
- BUILD targets for posix
- Full GoogleTest suite passing on Linux CI

### PR 4 — STM32L5 non-secure implementation (hardware backend)

- `scoreHsm_rust_stm32l5_ns.a` compiled with `ffi` + `hw-backend` features
- BUILD targets for stm32l5 (requires `rules_rust` + ARM cross-compilation)
- HIL test results attached as CI artifact

### PR 5 — Safety documentation package

- Safety plan, safety case, TSRs, FSRs, DFA, TQR — formatted for SCORE safety WG
- Traceability matrix linking SCORE `feat_req__sec_crypt__*` IDs to our
  FSR/TSR/SSR evidence
- Submit for SCORE safety WG review, not merge — starts the acceptance process

---

## 11. Prerequisites Before PR 1

These must be done in the scorehsm repo first:

| Item | Status | Target |
|---|---|---|
| Add `LICENSE` (Apache-2.0) to scorehsm repo | OPEN | Before PR 1 |
| Add `NOTICE` file | OPEN | Before PR 1 |
| Add `BufferTooSmall` to `HsmError` | OPEN | Before `ffi.rs` work |
| Implement `ffi.rs` skeleton (compiles, all fns return `HSM_ERR_NOT_INITIALIZED`) | OPEN | Before PR 3 |
| Close TQR-OI-01 (pin toolchain) | OPEN | 2026-03-21 |
| Close TQR-OI-03 (clippy CI) | OPEN | 2026-03-21 |
| Close UC-02 (coverage ≥85%) | OPEN | 2026-04-30 |
| Close UC-01 (HIL tests) | OPEN | 2026-05-15 |
| `cargo test --lib --features sw-backend,mock,certs` — all green | ✓ Done | 2026-03-14 |

---

## 12. Open Questions for SCORE Safety WG

These require upstream discussion before PR 2 can be merged:

1. **Safety-specific error codes** — Are `HSM_ERR_SAFE_STATE`, `HSM_ERR_RATE_LIMIT`,
   `HSM_ERR_NONCE_EXHAUSTED` in scope for the baselibs interface, or are they
   implementation-internal?

2. **Session concept** — scorehsm has `HsmSession` with handle-scoping and inactivity
   timeout. Should SCORE expose this in the C API, or keep it hidden behind `HSM_*`
   stateless calls? (Recommendation: hide it — C callers don't need session lifecycle.)

3. **Async operations** — HSM-REQ-030 requires async support for TLS. Should the C API
   include async variants (`HSM_AesGcmEncryptAsync`), or leave async to the Rust layer?

4. **Algorithm agility** — The current `HSM_*` functions are algorithm-specific
   (`HSM_AesGcmEncrypt`, `HSM_EcdsaSign`). SCORE may prefer a unified
   `HSM_Cipher(HsmAlgorithm_t, ...)` dispatch API. Trade-off: type safety vs. agility.

5. **rules_rust dependency** — Adding Rust to the SCORE Bazel build requires SCORE to
   accept `rules_rust` as a MODULE.bazel dependency. Is the SCORE infra team OK with
   this? If not, we provide a pre-compiled static archive instead.

---

*Document end — plan-score-contribution.md — 2026-03-14*
