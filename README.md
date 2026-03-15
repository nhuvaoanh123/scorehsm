# scorehsm

Hardware-backed cryptographic module for Linux-based SDV platforms.

STM32L552ZE-Q Nucleo as HSM peripheral over USB to Raspberry Pi. Full V-model — requirements,
architecture, implementation, verification. Rust throughout.

Built as a reference implementation for Eclipse SCORE's Security & Cryptography feature
(`experimental_security_crypto`), which has 43 defined requirements and no implementation.

---

## Architecture

```
Raspberry Pi (HPC proxy)                STM32L552ZE-Q Nucleo (HSM)
┌─────────────────────────┐             ┌────────────────────────────┐
│  host/ Rust library     │             │  firmware/ Embassy Rust    │
│  ┌─────────────────┐   │             │  ┌──────────────────────┐  │
│  │ Hardware backend│◄──┼── USB CDC ──┼─►│  NS: USB gateway     │  │
│  ├─────────────────┤   │             │  ├──────────────────────┤  │
│  │ SW fallback     │   │             │  │  S:  AES/PKA/HASH    │  │
│  │ (rustcrypto)    │   │             │  │      RNG / Key store │  │
│  └─────────────────┘   │             │  └──────────────────────┘  │
│  Common API             │             │  TrustZone boundary        │
└─────────────────────────┘             └────────────────────────────┘
```

Key principle: key material never leaves the L55. Only opaque handles cross the USB boundary.

---

## Hardware

| Component | Role |
|---|---|
| STM32L552ZE-Q NUCLEO-L552ZE-Q | HSM — Cortex-M33 TrustZone, HW AES/PKA/HASH/RNG |
| Raspberry Pi (USB host) | HPC proxy — runs host library |
| USB-A to Micro-USB | Power + data — single cable |

---

## Structure

```
firmware/   — STM32L552 Embassy Rust firmware (HSM device)
host/       — Raspberry Pi Rust library (hardware + software backends)
docs/       — V-model artifacts (requirements, architecture, plans, safety)
```

---

## Test Suite

| Category | Count | Coverage |
|---|---|---|
| Unit tests (host) | 54 | Safety, transport, crypto, mock backend |
| Integration tests (ITP) | 58 | TSR-TIG, NMG, SMG, RLG, SSG, IVG, CG |
| Qualification tests (QTE) | 57 | All 16 FSRs (FSR-01 through FSR-16) |
| Feature tests | 58 | SW backend, session, update, activation, onboard comm |
| **Total** | **227** | |

```bash
# Run all tests
cargo test --workspace --features "mock,certs"

# Clippy
cargo clippy --workspace --all-targets --features "mock,certs" -- -D warnings
```

---

## Status

Phases 0–9 complete. HIL hardware verification (Phase 10) pending.

## License

Apache-2.0 — see [LICENSE](LICENSE).
