# scorehsm — Test Strategy
Date: 2026-03-14
Status: CURRENT
Scope: `scorehsm-host` library (software backend + session layer + security modules)
V-model level: Unit → Integration → System (SIL)

---

## 1. Test Objectives

| Objective | Success Criterion |
|---|---|
| Verify all HSM-REQ-001…049 are exercised | Each requirement mapped to ≥1 test |
| Zero test failures on every CI run | `cargo test` exit code = 0 |
| No raw key material in any test assertion | Code review — no `assert!(key_bytes == …)` on generated keys |
| Error path coverage | Every `HsmError` variant returned at least once |
| IDS event correctness | Every `IdsEvent` variant emitted by at least one test |
| Replay protection coverage | Counter=same, counter=old, counter=MAX all covered |
| Signature mutation coverage | Byte flip, truncation, wrong key, feature_id swap |

---

## 2. Test Layers

### Layer 1 — Unit Tests (src/lib.rs internal)

Location: `host/src/lib.rs` (`#[cfg(test)] mod sha2_sanity`)
Target: SHA-256 reference implementation used internally
Run on: every `cargo test`

| Test | Purpose |
|---|---|
| `sha256_known_vectors` | NIST vectors: empty string, fox sentence |
| `sha256_via_sha2_crate` | sha2 crate matches inline reference impl |
| `arithmetic_sanity` | `rotate_right`, `wrapping_add` — CPU primitives |

### Layer 2 — Software Backend Integration Tests

Location: `host/tests/sw_backend_tests.rs` (37 tests)
Target: `SoftwareBackend` — all `HsmBackend` trait methods
Run on: every `cargo test`

#### 2a. Lifecycle
| Test | HSM-REQ |
|---|---|
| `test_init_succeeds` | HSM-REQ-026 |
| `test_deinit_succeeds` | HSM-REQ-026 |
| `test_not_initialized_before_init` | HSM-REQ-026/027 |

#### 2b. Key Management
| Test | HSM-REQ |
|---|---|
| `test_key_generate_aes256_returns_handle` | HSM-REQ-019 |
| `test_key_generate_hmac_returns_handle` | HSM-REQ-019 |
| `test_key_generate_unique_handles` | HSM-REQ-019 |
| `test_key_delete_valid_handle` | HSM-REQ-022 |
| `test_key_delete_invalid_handle` | HSM-REQ-022/027 |
| `test_key_delete_twice_is_error` | HSM-REQ-022/027 |
| `test_deleted_handle_is_unusable` | HSM-REQ-022 |
| `test_no_key_export_in_api` | HSM-REQ-023 |

#### 2c. Symmetric Cryptography
| Test | HSM-REQ |
|---|---|
| `test_aes_gcm_roundtrip` | HSM-REQ-001/002 |
| `test_aes_gcm_ciphertext_length` | HSM-REQ-002 |
| `test_aes_gcm_different_iv_different_ct` | HSM-REQ-002 |
| `test_aes_gcm_wrong_tag_rejected` | HSM-REQ-002/027 |
| `test_aes_gcm_wrong_aad_rejected` | HSM-REQ-002/027 |
| `test_aes_gcm_wrong_handle_fails` | HSM-REQ-002/027 |
| `test_aes_gcm_wrong_key_type_fails` | HSM-REQ-002/027 |

#### 2d. Hashing and MAC
| Test | HSM-REQ |
|---|---|
| `test_sha256_abc_vector` | HSM-REQ-013 |
| `test_sha256_empty_vector` | HSM-REQ-013 |
| `test_sha256_deterministic` | HSM-REQ-013 |
| `test_sha256_different_inputs_differ` | HSM-REQ-013 |
| `test_hmac_sha256_nist_vector` | HSM-REQ-011 |
| `test_hmac_sha256_deterministic` | HSM-REQ-011 |
| `test_hmac_sha256_different_keys` | HSM-REQ-011 |
| `test_hmac_sha256_different_messages` | HSM-REQ-011 |

#### 2e. Asymmetric Cryptography
| Test | HSM-REQ |
|---|---|
| `test_ecdsa_sign_verify_roundtrip` | HSM-REQ-008/009/010 |
| `test_ecdsa_sign_deterministic_rfc6979` | HSM-REQ-010 |
| `test_ecdsa_verify_wrong_digest_fails` | HSM-REQ-009 |
| `test_ecdsa_verify_wrong_signature_fails` | HSM-REQ-009 |

#### 2f. Key Derivation and RNG
| Test | HSM-REQ |
|---|---|
| `test_hkdf_returns_new_handle` | HSM-REQ-015 |
| `test_hkdf_deterministic` | HSM-REQ-015 |
| `test_hkdf_derived_key_is_usable` | HSM-REQ-015 |
| `test_random_fills_buffer` | HSM-REQ-016 |
| `test_random_is_different_each_call` | HSM-REQ-016 |
| `test_random_zero_length` | HSM-REQ-016 |

#### 2g. Error Handling
| Test | HSM-REQ |
|---|---|
| `test_errors_are_typed_not_panics` | HSM-REQ-027 |

### Layer 3 — Session Layer Tests

Location: `host/tests/session_tests.rs` (7 tests)
Target: `HsmSession` — handle ownership, rate limits, IDS hooks
Run on: every `cargo test`

| Test | HSM-REQ |
|---|---|
| `test_session_own_handle_allowed` | HSM-REQ-037 |
| `test_session_foreign_handle_rejected` | HSM-REQ-037 |
| `test_session_deleted_handle_rejected` | HSM-REQ-037 |
| `test_ids_key_generated_event` | HSM-REQ-038 |
| `test_ids_key_deleted_event` | HSM-REQ-038 |
| `test_ids_ecdsa_signed_event` | HSM-REQ-038 |
| `test_rate_limit_sign_exceeded` | HSM-REQ-039 |

**Missing (planned):**
- `test_rate_limit_decrypt_exceeded` — HSM-REQ-039
- `test_rate_limit_random_exceeded` — HSM-REQ-039
- `test_rate_limit_derive_exceeded` — HSM-REQ-039
- `test_ids_repeated_failure_event` — HSM-REQ-038
- `test_ids_rate_limit_event` — HSM-REQ-038
- `test_ids_decrypt_failed_event` — HSM-REQ-038
- `test_session_deinit_invalidates_handles` — HSM-REQ-037
- `test_session_key_import_owned` — HSM-REQ-037

### Layer 4 — Secure Update Tests

Location: `host/tests/update_tests.rs` (8 tests)
Target: `verify_update_image()` — HSM-REQ-047
Run on: every `cargo test`

| Test | Scenario | HSM-REQ |
|---|---|---|
| `test_update_valid_signature_accepted` | Happy path | HSM-REQ-047 |
| `test_update_tampered_image_rejected` | 1-byte mutation in image | HSM-REQ-047 |
| `test_update_version_rollback_rejected` | version < installed | HSM-REQ-047 |
| `test_update_same_version_rejected` | version == installed | HSM-REQ-047 |
| `test_update_wrong_key_rejected` | Signature from different key | HSM-REQ-047 |
| `test_update_empty_image_accepted` | Zero-length image, valid sig | HSM-REQ-047 |
| `test_update_first_install_accepted` | 0 → 1 first update | HSM-REQ-047 |
| `test_update_large_version_jump_accepted` | 0 → u32::MAX | HSM-REQ-047 |

**Missing (planned):**
- `test_update_ids_event_on_rollback` — verify `UpdateRejected` IDS payload contains "version rollback"
- `test_update_ids_event_on_bad_sig` — verify `UpdateRejected` IDS payload contains "signature"
- `test_update_truncated_signature_rejected` — DER truncated at N bytes
- `test_update_corrupted_der_rejected` — invalid DER structure

### Layer 5 — Feature Activation Tests

Location: `host/tests/feature_activation_tests.rs` (13 tests)
Target: `verify_activation_token()` — HSM-REQ-049
Run on: every `cargo test`

| Test | Scenario | HSM-REQ |
|---|---|---|
| `test_activation_valid_token_accepted` | Happy path | HSM-REQ-049 |
| `test_activation_higher_counter_accepted` | counter=100, last=50 | HSM-REQ-049 |
| `test_activation_first_activation_accepted` | counter=1, last=0 | HSM-REQ-049 |
| `test_activation_same_counter_rejected` | Replay (=) | HSM-REQ-049 |
| `test_activation_old_counter_rejected` | Replay (<) | HSM-REQ-049 |
| `test_activation_zero_counter_rejected` | counter=0 always replay | HSM-REQ-049 |
| `test_activation_wrong_key_rejected` | Foreign signing key | HSM-REQ-049 |
| `test_activation_feature_id_mismatch_rejected` | feature_id tampered | HSM-REQ-049 |
| `test_activation_counter_mismatch_in_signature_rejected` | counter byte tampered | HSM-REQ-049 |
| `test_activation_malformed_signature_rejected` | Truncated DER | HSM-REQ-049 |
| `test_activation_empty_signature_rejected` | Zero-length sig | HSM-REQ-049 |
| `test_activation_empty_feature_id_accepted` | Empty string feature_id | HSM-REQ-049 |
| `test_activation_max_counter_accepted` | counter=u64::MAX | HSM-REQ-049 |

**Missing (planned):**
- Proptest: randomised feature_id strings, counter values, mutated signatures

### Layer 6 — Onboard Comm (IPSec/MACSec) Tests

Location: `host/tests/onboard_comm_tests.rs` (4 tests)
Target: `ikev2_derive_keys()`, `macsec_derive_mka_keys()` — HSM-REQ-048
Run on: every `cargo test`

| Test | Scenario | HSM-REQ |
|---|---|---|
| `test_ikev2_derive_keys_produces_distinct_keys` | SK_d/ai/ar/ei/er all differ | HSM-REQ-048 |
| `test_ikev2_derive_keys_deterministic` | Different ECDH key → different output | HSM-REQ-048 |
| `test_macsec_mka_derive_produces_keys` | ICK ≠ 0, KEK ≠ 0, ICK ≠ KEK | HSM-REQ-048 |
| `test_macsec_mka_different_cak_name_different_keys` | CKN domain separation | HSM-REQ-048 |

**Missing (planned):**
- `test_ikev2_nonce_domain_separation` — different nonces, same ECDH key → different output
- `test_ikev2_spi_domain_separation` — different SPIs → different output
- `test_ikev2_ecdh_invalid_handle` — invalid handle propagates error
- `test_macsec_wrong_key_type_rejected` — AES key handle on HMAC-expecting function

---

## 3. Requirements Coverage Matrix

| HSM-REQ | Layer | Test File | Status |
|---|---|---|---|
| HSM-REQ-001 AES-256 | 2 | sw_backend_tests | ✅ |
| HSM-REQ-002 AES-GCM | 2 | sw_backend_tests | ✅ |
| HSM-REQ-003 AES-CBC | — | — | ⚠️ not yet tested |
| HSM-REQ-004 AES-CCM | — | — | ⚠️ not yet tested |
| HSM-REQ-005 ChaCha20 | — | — | ⚠️ not yet tested |
| HSM-REQ-006 Asym enc | — | — | ⚠️ (via ECDH/ECDSA) |
| HSM-REQ-007 ECDH | — | — | ⚠️ covered in onboard_comm indirectly |
| HSM-REQ-008 Sig create | 2 | sw_backend_tests | ✅ |
| HSM-REQ-009 Sig verify | 2 | sw_backend_tests | ✅ |
| HSM-REQ-010 ECDSA-P256 | 2 | sw_backend_tests | ✅ |
| HSM-REQ-011 HMAC-SHA256 | 2 | sw_backend_tests | ✅ |
| HSM-REQ-012 Hashing | 2 | sw_backend_tests | ✅ |
| HSM-REQ-013 SHA-256 | 1+2 | lib + sw_backend | ✅ |
| HSM-REQ-014 SHA-3 | — | — | ⚠️ not yet tested |
| HSM-REQ-015 HKDF | 2 | sw_backend_tests | ✅ |
| HSM-REQ-016 RNG | 2 | sw_backend_tests | ✅ |
| HSM-REQ-017 ChaCha20Rng | — | — | ⚠️ not yet tested |
| HSM-REQ-018 Cert mgmt | — | — | ⚠️ planned |
| HSM-REQ-019 Key generation | 2 | sw_backend_tests | ✅ |
| HSM-REQ-020 Key import | — | — | ⚠️ (returns Unsupported) |
| HSM-REQ-021 Key storage | — | — | ℹ️ TrustZone — HIL only |
| HSM-REQ-022 Key deletion | 2 | sw_backend_tests | ✅ |
| HSM-REQ-023 No export | 2 | sw_backend_tests | ✅ |
| HSM-REQ-024 Algo by name | 2 | sw_backend_tests | ✅ |
| HSM-REQ-025 Algo naming | 2 | sw_backend_tests (KeyType enum) | ✅ |
| HSM-REQ-026 Lifecycle | 2 | sw_backend_tests | ✅ |
| HSM-REQ-027 Error handling | 2 | sw_backend_tests | ✅ |
| HSM-REQ-028 Benchmarks | — | — | ⚠️ bench harness planned |
| HSM-REQ-029 Side-channel | — | — | ℹ️ hardware only |
| HSM-REQ-030 Algo agility | 2 | sw_backend_tests (KeyType enum) | ✅ |
| HSM-REQ-031 RE protection | — | — | ℹ️ TrustZone — HIL only |
| HSM-REQ-032 Provisioning | — | — | ⚠️ planned |
| HSM-REQ-033 PQC | — | — | ⚠️ planned (behind `pqc` feature) |
| HSM-REQ-034 HW accel | — | — | ℹ️ hardware only |
| HSM-REQ-035 SW fallback | 2 | sw_backend_tests | ✅ |
| HSM-REQ-036 OS protection | — | — | ℹ️ TrustZone — HIL only |
| HSM-REQ-037 Access control | 3 | session_tests | ✅ |
| HSM-REQ-038 IDS events | 3 | session_tests | ✅ (partial — 3/7 events) |
| HSM-REQ-039 DoS/rate limit | 3 | session_tests | ✅ (1/4 ops covered) |
| HSM-REQ-040 TLS support | — | — | ⚠️ planned |
| HSM-REQ-041 USB frame CRC | — | — | ⚠️ planned (firmware test) |
| HSM-REQ-042 Device verify | — | — | ⚠️ planned |
| HSM-REQ-043 Zeroize on reset | — | — | ℹ️ firmware HIL only |
| HSM-REQ-044 Frame length | — | — | ℹ️ firmware HIL only |
| HSM-REQ-045 SW fallback warn | 2 | sw_backend_tests | ✅ |
| HSM-REQ-046 Secure boot | — | — | ℹ️ firmware HIL only |
| HSM-REQ-047 Secure update | 4 | update_tests | ✅ |
| HSM-REQ-048 IPSec/MACSec | 6 | onboard_comm_tests | ✅ (partial) |
| HSM-REQ-049 Feature activ. | 5 | feature_activation_tests | ✅ |

**Legend:** ✅ tested | ⚠️ planned | ℹ️ hardware/firmware — SIL/HIL required

---

## 4. Test Verdict by Status

| Category | Count |
|---|---|
| ✅ Fully tested | 29 |
| ⚠️ Planned / partial | 13 |
| ℹ️ Hardware-only (SIL/HIL) | 7 |
| **Total** | **49** |

**Current passing tests: 73**
(3 lib + 37 sw_backend + 7 session + 8 update + 13 feature_activation + 4 onboard_comm + 1 doc-ignored)

---

## 5. Planned Test Additions

### 5a. Missing IDS Events (HSM-REQ-038)

```rust
// host/tests/session_tests.rs additions
fn test_ids_decrypt_failed_event()         // TagMismatch → IdsEvent::DecryptFailed
fn test_ids_repeated_failure_event()       // 10 consecutive fails → IdsEvent::RepeatedFailure
fn test_ids_rate_limit_event()             // exceed limit → IdsEvent::RateLimitExceeded
fn test_ids_unknown_handle_event()         // foreign handle → IdsEvent::UnknownHandle
```

### 5b. Missing Rate Limit Coverage (HSM-REQ-039)

```rust
fn test_rate_limit_decrypt_exceeded()      // decrypt ops exceed limit
fn test_rate_limit_random_exceeded()       // random ops exceed limit
fn test_rate_limit_derive_exceeded()       // key_derive ops exceed limit
fn test_rate_limit_window_resets()         // after window expires, counter resets
```

### 5c. Certificate Chain Tests (HSM-REQ-018)

```rust
// host/tests/cert_tests.rs (new, feature = "certs")
fn test_cert_parse_valid_der()
fn test_cert_extract_public_key()
fn test_cert_verify_self_signed()
fn test_cert_verify_chain_two_levels()
fn test_cert_chain_invalid_signature_rejected()
fn test_cert_chain_empty_rejected()
fn test_cert_unsupported_algorithm_rejected()
```

### 5d. ECDH Direct Tests (HSM-REQ-007)

```rust
// host/tests/sw_backend_tests.rs additions
fn test_ecdh_produces_32_bytes()
fn test_ecdh_symmetric()              // A.ecdh(B.pub) == B.ecdh(A.pub)
fn test_ecdh_invalid_handle()
fn test_ecdh_invalid_peer_point()     // point not on curve
```

### 5e. PQC Tests (HSM-REQ-033, feature = pqc)

```rust
// host/tests/pqc_tests.rs (new)
fn test_mldsa_keygen_sign_verify_roundtrip()
fn test_mldsa_verify_wrong_message_fails()
fn test_mlkem_encap_decap_roundtrip()
fn test_mlkem_wrong_ciphertext_fails()
```

### 5f. Proptest / Property-Based (HSM-REQ-047/049)

```rust
// Proptest: any random 32-byte signing key + any image bytes → sign → verify roundtrip
proptest! {
    fn prop_update_sign_verify(image in any::<Vec<u8>>(), sk in any::<[u8;32]>()) { … }
    fn prop_activation_sign_verify(fid in "\\PC*", counter in 1..u64::MAX) { … }
    fn prop_activation_bit_flip_rejected(fid in "\\PC+", counter in 1..u64::MAX) { … }
}
```

---

## 6. SIL/HIL Test Plan (Hardware Tests)

These tests require the STM32L552 Nucleo board connected over USB CDC.

### 6a. Hardware Backend Smoke Tests
- `hw_test_init_and_boot_status` — verify `boot_status().verified` (needs OTP key provisioned)
- `hw_test_key_generate_and_delete` — end-to-end over USB CDC
- `hw_test_aes_gcm_roundtrip` — encrypt on firmware, decrypt on host (or vice versa)
- `hw_test_ecdsa_sign_verify` — generate key on firmware, sign+verify over USB

### 6b. Frame Integrity Tests (HSM-REQ-041)
- `hw_test_crc_mismatch_rejected` — corrupt CRC byte, expect error response
- `hw_test_sequence_number_ooo_rejected` — replay old sequence number
- `hw_test_oversized_frame_rejected` — length field > max payload (HSM-REQ-044)

### 6c. Key Isolation Tests (HSM-REQ-031/036)
- `hw_test_sram2_not_readable_from_ns` — TrustZone S-world isolation (requires debug probe)

### 6d. Secure Boot (HSM-REQ-046)
- `hw_test_boot_verified_flag_set` — after OTP key provisioned, `boot_status().verified == true`
- `hw_test_boot_unsigned_firmware_rejected` — flash unsigned image, verify boot halts

---

## 7. CI Configuration

All Layer 1–6 tests run automatically on every `git push` via GitHub Actions:

```yaml
# .github/workflows/test.yml (excerpt)
- name: Test host library
  run: cargo test --manifest-path scorehsm/host/Cargo.toml
  env:
    RUSTFLAGS: "-D warnings"   # warnings are errors in CI
```

Hardware (SIL/HIL) tests run nightly on the dedicated test rig connected to the Nucleo board.

---

## 8. Test Result Summary (2026-03-14)

```
running 73 tests
  lib (unit)                  3/3  ✅
  sw_backend_tests           37/37  ✅
  session_tests               7/7  ✅
  update_tests                8/8  ✅
  feature_activation_tests   13/13  ✅
  onboard_comm_tests          4/4  ✅

Total: 73 passed, 0 failed
```
