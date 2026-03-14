# scorehsm — Implementation Plan

Date: 2026-03-14
Status: IN PROGRESS
Phase: Planning

---

## Work Packages

| ID | Work Package | Depends on |
|----|---|---|
| WP1 | Environment setup | — |
| WP2 | Threat model & security concept | — |
| WP3 | Requirements | WP2 |
| WP4 | Architecture | WP3 |
| WP5.1 | Firmware — RNG (TRNG) | WP4 |
| WP5.2 | Firmware — SHA-256 (HASH peripheral) | WP4 |
| WP5.3 | Firmware — AES-256-GCM (AES peripheral) | WP4 |
| WP5.4 | Firmware — ECDSA P-256 / ECDH (PKA peripheral) | WP4 |
| WP5.5 | Firmware — HMAC-SHA256 | WP5.2 |
| WP5.6 | Firmware — Key store (SRAM2) | WP4 |
| WP5.7 | Firmware — Key derivation (HKDF) | WP5.6 |
| WP5.8 | Firmware — USB CDC command dispatcher | WP5.1–WP5.7 |
| WP5.9 | Firmware — TrustZone S/NS partition | WP5.8 |
| WP6.1 | Host — Software fallback backend (rustcrypto) | WP4 |
| WP6.2 | Host — USB CDC hardware backend | WP5.8 |
| WP6.3 | Host — Certificate management (X.509) | WP6.1 |
| WP6.4 | Host — TLS integration layer (rustls) | WP6.2 |
| WP6.5 | Host — Post-quantum crypto (ML-DSA, SLH-DSA, ML-KEM) | WP6.1 |
| WP6.6 | Host — Access control & key handle management | WP6.2 |
| WP6.7 | Host — IDS event reporting hook | WP6.2 |
| WP6.8 | Host — DoS mitigation (rate limiting) | WP6.2 |
| WP7 | Verification — unit tests, integration tests, benchmarks | WP6.2 |
| WP8 | SCORE contribution package | WP7 |

---

## Milestones

| ID | Milestone | Done When |
|----|---|---|
| M1 | Environment ready | L55 blinks, enumerates as /dev/ttyACM0 on Pi, probe-rs flashes |
| M2 | Threat model + requirements | STRIDE complete, all requirements written and traced to SCORE IDs |
| M3 | Architecture locked | USB protocol spec, Rust API traits, TrustZone memory map — all reviewed |
| M4 | First end-to-end | Pi calls RNG → L55 TRNG responds → verified random bytes returned |
| M5 | Symmetric crypto | AES-256-GCM encrypt/decrypt verified end-to-end, test vectors pass |
| M6 | Asymmetric crypto | ECDSA sign/verify + ECDH key exchange verified end-to-end |
| M7 | Full key lifecycle | generate, import (wrapped), store, derive (HKDF), delete — all working |
| M8 | TrustZone | Key material locked in S world, NS can only hold handles, verified |
| M9 | Host library complete | SW fallback + HW backend + certs + TLS + PQC + access control |
| M10 | Verified | Unit tests pass in CI, integration tests pass on bench, benchmarks documented |
| M11 | SCORE ready | Contribution package: code + docs + traceability + benchmark report |

---

## Sequencing

```
WP1 (env) ──────────────────────────────────────────────────────────────────────┐
                                                                                  │
WP2 (threat model) ──► WP3 (requirements) ──► WP4 (architecture) ───────────────┤
                                                                                  │
                                               WP5.1 (RNG) ─────────────────────┤
                                               WP5.2 (SHA) ─────────────────────┤
                                               WP5.3 (AES) ──► M5              │
                                               WP5.4 (PKA) ──► M6              │
                                               WP5.5 (HMAC)                    │
                                               WP5.6 (KeyStore)                │
                                               WP5.7 (HKDF) ──► M7             │
                                               WP5.8 (USB dispatcher) ──► M4   │
                                               WP5.9 (TrustZone) ──► M8        │
                                                                                  │
                                               WP6.1 (SW fallback) ─────────────┤
                                               WP6.2 (HW backend) ──────────────┤
                                               WP6.3 (Certs)                   │
                                               WP6.4 (TLS)                     │
                                               WP6.5 (PQC) ──► M9              │
                                               WP6.6 (Access ctrl)             │
                                               WP6.7 (IDS hook)                │
                                               WP6.8 (DoS)                     │
                                                                                  │
                                               WP7 (verification) ──► M10      │
                                               WP8 (SCORE package) ──► M11 ────┘
```

Note: WP6.1 (software fallback) runs in parallel with WP5 — no hardware dependency,
can be built and tested in CI from day one.

---

## Risks

| ID | Risk | Likelihood | Impact | Mitigation |
|----|---|---|---|---|
| R1 | Embassy PKA not fully implemented for STM32L5 | Medium | High | Verify early (WP1). Fallback: write own PAC-level driver |
| R2 | TrustZone CMSE in nightly Rust — unstable API changes | Medium | Medium | Pin nightly version. Fallback: thin C shim for CMSE gateway only |
| R3 | USB CDC reliability on Pi — endpoint stalls, resets | Low | Medium | Implement retry/reconnect in host library. Test under load |
| R4 | SHA-3 not hardware accelerated on L55 | Certain | Low | Known — software only in fallback. Documented in requirements |
| R5 | PKA ECDSA timing — side-channel exposure | Medium | High | Use Embassy's constant-time wrappers where available. Document residual risk |
| R6 | SCORE maintainers reject architecture | Low | Medium | Come with working code + benchmarks, not a proposal |

---

## Tools & Environment

| Tool | Purpose |
|---|---|
| Rust nightly | TrustZone CMSE attributes (`#[cmse_nonsecure_entry]`) |
| Embassy-STM32 | Async HAL for L55 peripherals |
| probe-rs | Flashing + RTT debug over SWD |
| cargo test | Software fallback unit tests in CI |
| GitHub Actions | CI — software backend tests (no hardware) |
| rustcrypto crates | Software fallback: `aes-gcm`, `p256`, `sha2`, `hmac`, `hkdf` |
| pqcrypto / ml-kem, ml-dsa | Post-quantum software implementation |
| rustls | TLS integration target |
| serialport-rs | USB CDC communication on Pi side |

---

## Cargo Workspace Structure

```
scorehsm/
  Cargo.toml              — workspace root
  firmware/
    Cargo.toml            — Embassy STM32L552 binary crate
    src/
      main.rs             — Embassy entry point
      usb.rs              — USB CDC command dispatcher
      crypto/             — Hardware engine wrappers (aes, pka, hash, rng)
      keystore.rs         — Secure SRAM2 key management
  host/
    Cargo.toml            — Library crate (Pi / Linux)
    src/
      lib.rs              — Public API + Backend trait
      backend/
        hw.rs             — USB CDC hardware backend
        sw.rs             — rustcrypto software fallback
      cert.rs             — Certificate management
      tls.rs              — TLS integration
      pqc.rs              — Post-quantum operations
      access.rs           — Key handles + access control
```

---

## Definition of Done — Per Work Package

- Code compiles with no warnings
- At least one test per public function
- Rustdoc on all public items
- Requirement traceability: each function tagged with SCORE req ID in doc comment
- No `unwrap()` in library code — `Result<T, E>` throughout
