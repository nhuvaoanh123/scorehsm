//! TrustZone SAU configuration for STM32L552.
//!
//! The STM32L552 supports ARMv8-M TrustZone via the Security Attribution Unit
//! (SAU). This module configures the SAU to partition flash and SRAM between
//! the Secure (S) and Non-Secure (NS) worlds.
//!
//! # Single S-World Architecture (Phase 8)
//!
//! The entire firmware runs in Secure world. No NS image is loaded.
//! SAU regions mark SRAM1 and part of flash as NS for defense-in-depth:
//! if a bug ever transitions to NS mode, SRAM2 (key store) is inaccessible.
//!
//! # Memory layout after TZ activation
//!
//! ```text
//!   S Flash  : 0x0C000000 – 0x0C05FFFF  (384 KB, firmware image)
//!   NSC Gate : 0x0C060000 – 0x0C063FFF  ( 16 KB, veneer table)
//!   NS Flash : 0x08064000 – 0x0807FFFF  (112 KB, reserved for future NS)
//!   S SRAM1  : 0x30000000 – 0x3002FFFF  (192 KB, stack + data)
//!   S SRAM2  : 0x30030000 – 0x3003FFFF  ( 64 KB, key store — HW isolated)
//! ```
//!
//! # Prerequisites (one-time, via STM32CubeProgrammer)
//!
//! ```text
//! # 1. Enable TrustZone
//! STM32_Programmer_CLI -c port=SWD -ob TZEN=1
//!
//! # 2. Set Secure Watermark: pages 0–191 (384 KB Secure flash)
//! STM32_Programmer_CLI -c port=SWD -ob SECWM_PSTRT=0x0 SECWM_PEND=0xBF
//!
//! # 3. Power-cycle the board (mandatory after option byte changes)
//!
//! # 4. Flash the Secure image (S alias address)
//! probe-rs run --chip STM32L552ZETxQ target/thumbv8m.main-none-eabihf/release/scorehsm-firmware
//! ```
//!
//! # Reverting TrustZone
//!
//! ```text
//! # Full regression to non-TZ mode (WARNING: erases flash)
//! STM32_Programmer_CLI -c port=SWD -ob TZEN=0
//! # Then power-cycle and re-flash with non-TZ memory.x build
//! ```

/// Configure the SAU for the TrustZone partition.
///
/// Sets up 3 SAU regions:
/// - Region 0: Flash NS partition (112 KB) — Non-Secure
/// - Region 1: SRAM1 (192 KB) — Non-Secure (defense-in-depth; firmware runs in S-world)
/// - Region 2: NSC gateway (16 KB) — Non-Secure Callable
///
/// Everything else (including SRAM2 key store) remains Secure by default.
///
/// # Safety
///
/// Must be called once at boot with interrupts disabled (guaranteed by
/// cortex-m-rt before main), from Secure Privileged mode, before any
/// NS code runs. Incorrect SAU configuration can lock the device.
#[cfg(feature = "trustzone")]
pub unsafe fn configure_sau() {
    let sau = cortex_m::peripheral::SAU::ptr();

    // Disable SAU before configuring
    (*sau).ctrl.modify(|r| r & !0x1); // ENABLE = 0

    // Helper: write a SAU region
    // RBAR: base address (must be 32-byte aligned)
    // RLAR: limit = end-1, bits[1:0] = {NSC, ENABLE}
    macro_rules! sau_region {
        ($n:expr, $base:expr, $limit:expr, $nsc:expr) => {
            (*sau).rnr.write($n);
            (*sau).rbar.write($base);
            (*sau).rlar.write(($limit & !0x1F) | ($nsc << 1) | 0x1);
        };
    }

    // Region 0: Flash NS partition — Non-Secure, non-callable
    sau_region!(0, 0x0806_4000, 0x0807_FFFF, 0);
    // Region 1: SRAM1 — Non-Secure, non-callable (defense-in-depth)
    sau_region!(1, 0x2000_0000, 0x2002_FFFF, 0);
    // Region 2: NSC gateway — Non-Secure Callable (veneer table)
    sau_region!(2, 0x0C06_0000, 0x0C06_3FFF, 1);

    // Enable SAU: all regions not covered by SAU default to Secure
    (*sau).ctrl.modify(|r| r | 0x1); // ENABLE = 1

    // Note: GTZC MPCBB2 (SRAM2 block-based protection) defaults to all-Secure
    // after reset with TZEN=1. Locking MPCBB2 to prevent runtime modification
    // is deferred until HIL testing confirms baseline. The register address is
    // GTZC1_MPCBB2_CFGLOCK at 0x420C_0010; setting bit 0 (SPLCK0) locks
    // super-block 0, preventing any VCTR modification.
}

/// Verify that TrustZone is active by checking the SAU CTRL.ENABLE bit.
///
/// Returns `true` if the SAU is enabled (confirming our `configure_sau()`
/// call succeeded and wasn't faulted by the hardware).
#[cfg(feature = "trustzone")]
pub fn verify_tz_active() -> bool {
    unsafe {
        let sau = cortex_m::peripheral::SAU::ptr();
        (*sau).ctrl.read() & 0x1 != 0
    }
}

// ── NSC Veneer Table ────────────────────────────────────────────────────────
//
// Functions annotated with `#[cmse_nonsecure_entry]` are placed in the
// `.gnu.sgstubs` section (NSC region) and can be called from NS world.
// Each veneer validates the handle and performs the operation in S context.
//
// These stubs are compiled only when building the Secure firmware image
// with a future NS companion. In the current single-S-world build they
// are not included.

#[cfg(feature = "secure-build")]
pub mod nsc {
    /// NSC veneer: SHA-256 (NS world may compute hashes of NS data).
    #[no_mangle]
    #[cfg_attr(target_arch = "arm", link_section = ".gnu.sgstubs")]
    pub extern "C" fn nsc_sha256(data_ns: *const u8, len: usize, out_ns: *mut u8) -> i32 {
        // Validate NS pointers (TT instruction — target = NS, non-secure accessible)
        // In a real implementation use `cmse_check_address_range` from cortex_m::cmse.
        if data_ns.is_null() || out_ns.is_null() { return -1; }
        unsafe {
            let data = core::slice::from_raw_parts(data_ns, len);
            let digest = crate::crypto::sha256(data);
            core::ptr::copy_nonoverlapping(digest.as_ptr(), out_ns, 32);
        }
        0
    }

    /// NSC veneer: symmetric encrypt (key never leaves S world).
    #[no_mangle]
    #[cfg_attr(target_arch = "arm", link_section = ".gnu.sgstubs")]
    pub extern "C" fn nsc_aes_gcm_encrypt(
        key_handle: u32,
        iv_ns: *const u8,
        aad_ns: *const u8, aad_len: usize,
        pt_ns: *const u8,  pt_len: usize,
        ct_ns: *mut u8,
    ) -> i32 {
        // Pointer validation + dispatch to crypto:: using S keystore
        // Implementation deferred to dual-image phase
        let _ = (key_handle, iv_ns, aad_ns, aad_len, pt_ns, pt_len, ct_ns);
        -1 // not yet implemented
    }
}
