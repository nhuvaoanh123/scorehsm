# scorehsm — Safety Goals

Date: 2026-03-14
Standard: ISO 26262-6:2018 §5 / ISO 26262-10:2018 §9 (SEooC)
Status: RELEASED
ASIL Target: ASIL B
Document ID: SCORE-SG

---

## 1. Purpose

This document defines the Safety Goals (SGs) for the `scorehsm` Safety Element out of Context (SEooC). Safety Goals are the top-level safety claims that bound all safety activities downstream in the V-model. They represent the element-level contribution to preventing hazardous events in the integrated item.

Because `scorehsm` is a SEooC, Safety Goals are defined from assumed operational hazards rather than a full vehicle-level HARA. Each safety goal is expressed as a harm prevention obligation on the element. The integrator maps these to their vehicle-level safety goals during item integration.

---

## 2. Assumed Operational Context

`scorehsm` is assumed to be deployed in safety-relevant operational roles including but not limited to:

| Role | Safety relevance |
|---|---|
| OTA firmware signature verification | Prevents installation of unsigned or tampered vehicle software |
| Secure boot attestation | Prevents execution of corrupted boot images |
| Safety-critical inter-ECU MAC authentication | Prevents acceptance of spoofed actuator commands |
| TLS session key establishment | Prevents man-in-middle interception of safety data |

**Assumed vehicle-level hazardous events:**

| HE-ID | Hazardous event | Assumed ASIL |
|---|---|---|
| HE-01 | Vehicle installs corrupted or unauthorized firmware, leading to uncontrolled vehicle behavior | ASIL B |
| HE-02 | Safety-critical inter-ECU command accepted based on invalid or forged authentication, leading to unintended actuation | ASIL B |
| HE-03 | Cryptographic operation returns silently incorrect result (wrong plaintext, false-positive verification), causing downstream system to act on corrupt data | ASIL B |
| HE-04 | HSM element enters undefined state after hardware fault, causing indeterminate behavior in safety-critical application | ASIL B |

---

## 3. Safety Goal Definitions

### SG-01 — No False Verification Success

**Statement:** The `scorehsm` element shall never return a "verification success" result for a signature, MAC, or AEAD authentication tag that does not cryptographically correspond to the input message and the stored key.

**Rationale:** A false-positive verification result is the direct enabler of HE-01 (corrupted firmware accepted) and HE-02 (forged command accepted). This is the most safety-critical functional property of the element.

**ASIL:** B

**Derived from:** HE-01, HE-02

**Failure mode:** `verify()`, `aead_decrypt()`, or `mac_verify()` returns `Ok(true)` or `Ok(decrypted_data)` when the input is invalid or tampered.

---

### SG-02 — No Silent Output Corruption

**Statement:** The `scorehsm` element shall not return plaintext, ciphertext, or signature data that has been silently modified due to a hardware communication fault, memory error, or transport error. All detected faults shall result in an error return, never in a value return.

**Rationale:** An undetected bit-flip in an output buffer — e.g., in returned decrypted plaintext or a computed ECDSA signature — could cause a downstream system to act on corrupted data (HE-03). A detected fault that produces an error return allows the caller to handle the situation safely.

**ASIL:** B

**Derived from:** HE-03

**Failure mode:** A USB frame CRC error, SRAM parity fault, or DMA error causes a modified value to be returned to the caller without any error indication.

---

### SG-03 — No Key Material Disclosure

**Statement:** The `scorehsm` element shall not disclose raw cryptographic key material through any programmatic interface, log output, or error message. Key material shall be confined to the hardware security module and shall not appear in any USB frame, host-side memory region accessible to other processes, or diagnostic output.

**Rationale:** Key material disclosure enables an attacker to forge signatures, decrypt protected data, and break authentication — enabling all of HE-01, HE-02, HE-03 without needing to compromise the HSM hardware.

**ASIL:** B (decomposed: ASIL B(d) for software; hardware isolation provides complementary ASIL B(d))

**Derived from:** HE-01, HE-02

**Failure mode:** A key export API, a debug log statement, or an error message embeds raw key bytes.

---

### SG-04 — Nonce Uniqueness for AEAD Operations

**Statement:** For every AEAD encryption operation performed with a given key, the `scorehsm` element shall ensure that the nonce (IV) is unique across all invocations with that key. Nonce reuse with the same key shall be detected and rejected before the encryption operation is performed.

**Rationale:** AES-GCM nonce reuse with the same key catastrophically destroys both confidentiality and authentication. An attacker who observes two ciphertexts encrypted with the same (key, nonce) pair can recover the plaintext XOR and forge authentication tags. This enables HE-02 by allowing forged commands to pass MAC verification.

**ASIL:** B

**Derived from:** HE-02, HE-03

**Failure mode:** `aead_encrypt()` is called twice with the same key handle and the same IV value. Both calls succeed, producing two ciphertexts with the same (key, IV) pair.

---

### SG-05 — Transport Fault Detection

**Statement:** The `scorehsm` element shall detect corruption of any USB CDC command or response frame with a diagnostic coverage of at least 99% for single-bit errors and at least 95% for multi-bit burst errors up to 16 bits. Detected frame errors shall return an error to the caller; the corrupted data shall not be used.

**Rationale:** The USB cable connecting the host to the L55 HSM is physically accessible to an attacker and can experience electromagnetic interference in an automotive environment. Silent frame corruption maps directly to SG-02 (HE-03).

**ASIL:** B

**Derived from:** HE-03, HE-04

**Failure mode:** A USB frame arrives with a corrupted payload. The host library accepts and processes the corrupted frame, returning corrupted data to the caller.

---

### SG-06 — Safe State on Integrity Fault

**Statement:** Upon detection of an internal integrity violation — including key store inconsistency, session state corruption, unexpected sequence number, or unrecoverable hardware fault — the `scorehsm` element shall enter a defined safe state. In safe state: all pending operations shall be aborted, all active sessions shall be invalidated, no new operations shall be accepted, and the caller shall receive an unambiguous error return.

**Rationale:** An element in an undefined state after a hardware fault may return arbitrary results — this is more dangerous than a known-error state (HE-04). A defined safe state allows the integrator's functional safety mechanism (e.g., a supervisor task) to detect the condition and initiate a safe system response.

**ASIL:** B

**Derived from:** HE-04

**Failure mode:** After a hardware fault (USB disconnect, L55 watchdog reset, power glitch), the host library continues to process requests using stale or invalid state, returning incorrect results to the caller.

---

### SG-07 — No Privilege Escalation Between Sessions

**Statement:** The `scorehsm` element shall ensure that a caller holding a key handle for one session cannot use that handle to perform operations on behalf of, or access the state of, a different active session.

**Rationale:** If session isolation fails, a compromised application could leverage another application's valid key handles to forge signatures or decrypt data — enabling HE-01 and HE-02 without needing to extract key material.

**ASIL:** B

**Derived from:** HE-01, HE-02

**Failure mode:** Session A's key handle is valid and usable in Session B's operation context.

---

## 4. Safety Goal Summary

| ID | ASIL | Hazardous Event | Short Title |
|---|---|---|---|
| SG-01 | B | HE-01, HE-02 | No false verification success |
| SG-02 | B | HE-03 | No silent output corruption |
| SG-03 | B(d) | HE-01, HE-02 | No key material disclosure |
| SG-04 | B | HE-02, HE-03 | Nonce uniqueness for AEAD |
| SG-05 | B | HE-03, HE-04 | Transport fault detection ≥99% single-bit |
| SG-06 | B | HE-04 | Safe state on integrity fault |
| SG-07 | B | HE-01, HE-02 | Session isolation |

---

## 5. ASIL Assignment Rationale

All seven safety goals are assigned ASIL B. The assignment is based on the assumed hazardous events at the vehicle level (HE-01 through HE-04), each of which has severity class S2 (serious injury is conceivable from corrupted vehicle control), exposure class E3 (occurs regularly during normal driving), and controllability class C2 (normally controllable but not reliably).

ASIL = S2 × E3 × C2 = ASIL B (ISO 26262-3 Table 4).

SG-03 is assigned ASIL B(d): the safety claim is decomposed between the software element (must not provide a key export API) and the hardware element (must enforce TrustZone memory separation). Each half carries ASIL B(d).

---

## 6. Relationship to ISO 21434 Security Goals

The threat model (`threat-model.md`) defines Security Goals (cybersecurity goals) under ISO 21434. Several overlap with or complement these Safety Goals:

| Safety Goal | Overlapping Security Goal | Relationship |
|---|---|---|
| SG-01 (no false verification) | I1 (no key export), T1 (frame integrity) | Security enforces correct MAC/sig via key confinement and frame integrity |
| SG-03 (no key disclosure) | I1 (no key export command) | Security = no API; Safety = no leakage via any path |
| SG-04 (nonce uniqueness) | S2 (replay protection via sequence numbers) | Related but distinct: sequence numbers protect frames; nonce uniqueness protects AEAD data |
| SG-05 (transport fault) | T1 (CRC-32/MPEG-2 + AES-GCM tag) | CRC is both a security integrity measure and a safety diagnostic |
| SG-06 (safe state) | D3 (disconnect handling) | Security: return error. Safety: additionally invalidate all sessions and refuse further ops |

Where a mechanism serves both a safety goal and a security goal, the stricter requirement governs. Both safety and security verification evidence is required.

---

## 7. Downstream Derivation

These Safety Goals are the inputs to the following downstream documents in the V-model left side:

```
Safety Goals (this document)
    │
    ├─► Assumed Safety Requirements   [assumed-safety-requirements.md]
    │       (obligations on the integrator)
    │
    └─► Functional Safety Requirements [functional-safety-requirements.md]
            (what the software must do to satisfy each SG)
                │
                └─► Technical Safety Requirements [technical-safety-requirements.md]
                        (how — technology-specific mechanisms)
                            │
                            └─► Software Safety Requirements (SSRs)
                                    [requirements.md §HSM-REQ-050..099]
                                        │
                                        └─► Implementation + Tests
```

---

*Document end — SCORE-SG rev 1.0 — 2026-03-14*
