# Threat Model — scorehsm

Date: 2026-03-14
Method: STRIDE
Status: COMPLETE

---

## System Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Trust boundary: Raspberry Pi OS process                                     │
│                                                                              │
│  ┌──────────────────────┐          ┌────────────────────────────────────┐   │
│  │  Application         │          │  scorehsm-host library             │   │
│  │  (KUKSA, OTA, etc.)  │─────────►│  HsmBackend trait                  │   │
│  └──────────────────────┘          │  ┌─────────────┐ ┌──────────────┐ │   │
│                                    │  │ SW fallback │ │ HW backend   │ │   │
│                                    │  └─────────────┘ └──────┬───────┘ │   │
│                                    └─────────────────────────┼─────────┘   │
└─────────────────────────────────────────────────────────────┼──────────────┘
                              USB CDC (/dev/ttyACM0)          │
                    Physical cable — accessible to attacker    │
                                                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  STM32L552 — TrustZone boundary                                              │
│                                                                              │
│  ┌────────────────────────────────┐  NSC  ┌──────────────────────────────┐ │
│  │  Non-Secure (NS) world         │───────►│  Secure (S) world            │ │
│  │  USB CDC endpoint              │       │  AES / PKA / HASH / RNG      │ │
│  │  Command dispatcher            │       │  Key store (SRAM2)           │ │
│  │  Key handle validation         │       │  CMSE gateway                │ │
│  └────────────────────────────────┘       └──────────────────────────────┘ │
│                                                                              │
│  SWD debug port — physical access attack surface                             │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Assets

| Asset | Sensitivity | Location |
|---|---|---|
| Key material (AES, HMAC, ECC private) | Critical | L55 S-world SRAM2 only |
| Key handles | Low | Pi process memory, USB frames |
| Plaintext data | High | Pi process memory (transient) |
| Ciphertext + tags | Medium | USB frames, Pi memory |
| L55 firmware | High | L55 flash |
| USB command frames | Low-Medium | USB cable |

---

## STRIDE Analysis

### S — Spoofing

| ID | Threat | Attack vector | Countermeasure |
|----|---|---|---|
| S1 | Attacker replaces L55 with rogue device that returns attacker-controlled "random" bytes | USB — plug different device | Host verifies device VID/PID on init. L55 responds to capability handshake with firmware version. Future: mutual auth via device certificate stored in L55 |
| S2 | Attacker replays a previous USB response to a new command | USB sniffing + replay | Each command includes a monotonic sequence number. L55 rejects out-of-order frames |
| S3 | Malicious Pi process impersonates trusted application to request crypto ops | OS process isolation | Key handles are per-session. Access control layer enforces which process holds which handle |

### T — Tampering

| ID | Threat | Attack vector | Countermeasure |
|----|---|---|---|
| T1 | Attacker flips bits in USB frame (ciphertext, IV, AAD) | USB cable / man-in-middle | CRC-16 on every frame. AES-GCM tag verification catches ciphertext/AAD tampering |
| T2 | Attacker modifies L55 firmware over SWD | Physical access to SWD port | SWD must be locked in production (RDP Level 2). Documented in deployment guide |
| T3 | NS world writes to S-world SRAM2 | TrustZone violation | SAU/IDAU enforces S/NS memory separation in hardware. Violation triggers SecureFault |
| T4 | Attacker modifies Pi-side library to log key handles and correlate with plaintext | Supply chain / OS compromise | Out of scope for this module — OS-level threat |

### R — Repudiation

| ID | Threat | Attack vector | Countermeasure |
|----|---|---|---|
| R1 | Application denies having signed a message | Software audit | ECDSA signing operations log handle ID and digest hash (not key material) to IDS hook |
| R2 | L55 denies having generated a key | Firmware fault | Key generation events written to NvM event log in S-world before returning handle |

### I — Information Disclosure

| ID | Threat | Attack vector | Countermeasure |
|----|---|---|---|
| I1 | Key material extracted via USB (key export command) | Protocol-level request | API has no key export command. Key material never appears in any USB frame. Key handles only |
| I2 | Key material recovered from SRAM2 via cold-boot or power analysis | Physical attack on L55 | SRAM2 is security-attributed (SAU). Key slots zeroized on delete and on power-off (zeroize-on-reset init) |
| I3 | Plaintext recovered from USB traffic (decrypt result in frame) | USB sniffing | Plaintext is returned in the USB response — this is by design (Pi needs the data). USB is on-device bus. Physical access to cable is required. Future: USB-layer encryption |
| I4 | Timing side-channel on AES/PKA via USB response latency | Timing measurement over USB | Hardware crypto units are constant-time by design. USB framing adds jitter. Residual risk documented |
| I5 | Key material in Pi process memory (software fallback) | OS process inspection / core dump | Software fallback explicitly does NOT satisfy os_protection. Documented limitation. Hardware backend required for isolation |

### D — Denial of Service

| ID | Threat | Attack vector | Countermeasure |
|----|---|---|---|
| D1 | Host floods L55 with expensive PKA (ECDSA) operations, starving other operations | USB command flood | Rate limiter in host library. Per-operation throttle. L55 command queue bounded |
| D2 | Attacker exhausts all key slots by generating keys and never deleting | Malicious application | Key slot limit enforced (8 slots). Access control: only authorized handles can generate |
| D3 | USB disconnect/reconnect loop disrupts crypto operations | Physical USB manipulation | Host library detects disconnect, returns error, re-enumerates. In-flight operation result is discarded |
| D4 | L55 watchdog not fed during long PKA operation — resets during signing | Firmware design | Embassy task structure feeds watchdog around blocking PKA operations |

### E — Elevation of Privilege

| ID | Threat | Attack vector | Countermeasure |
|----|---|---|---|
| E1 | NS world calls S-world function directly (not via NSC veneer) | TrustZone violation | CMSE gateway is the only entry point. Direct S-world function calls from NS fault on BLXNS to non-NSC address |
| E2 | Pi application escalates to read another application's key handles | Process-level attack | Key handles are session-scoped. Access control layer binds handles to caller identity |
| E3 | Malformed USB command causes buffer overflow in L55 NS dispatcher | Crafted USB frame | All frame lengths validated before processing. Rust bounds checking. `#![deny(unsafe_code)]` in dispatcher |

---

## Residual Risks

| ID | Risk | Accepted? | Reason |
|----|---|---|---|
| RR1 | Plaintext returned over USB is visible on cable | Yes | Physical access required. In-vehicle USB is physically protected. Future work: USB encryption |
| RR2 | Software fallback has no key isolation | Yes | Documented. Software fallback is for CI/development only. Production must use hardware backend |
| RR3 | SWD not locked in development | Yes | Development board. Production deployment guide mandates RDP Level 2 |
| RR4 | Timing side-channel residual over USB | Yes | USB jitter dominates. Hardware crypto is constant-time. Documented |

---

## Security Goals (derived, feeds requirements)

| ID | Goal |
|----|---|
| SG-01 | Key material shall never leave the L55 in any USB frame |
| SG-02 | USB frames shall be integrity-protected (CRC + sequence number) |
| SG-03 | TrustZone shall be the only enforcement point for key isolation |
| SG-04 | The API shall not expose a key export operation |
| SG-05 | Key slots shall be zeroized on deletion and on device reset |
| SG-06 | Crypto operations shall be rate-limited to prevent DoS |
| SG-07 | All frame lengths shall be validated before use |
| SG-08 | Software fallback shall be clearly documented as non-isolated |
| SG-09 | Signing operations shall be logged to the IDS hook |
| SG-10 | SWD shall be locked in production deployment |
