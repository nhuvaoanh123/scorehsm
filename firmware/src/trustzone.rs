//! TrustZone SAU configuration for STM32L552.
//!
//! The STM32L552 supports ARMv8-M TrustZone via the Security Attribution Unit
//! (SAU). This module configures the SAU to partition flash and SRAM between
//! the Secure (S) and Non-Secure (NS) worlds.
//!
//! Memory layout after TZ activation (see architecture.md §4):
//!   Flash S  : 0x0C000000 – 0x0C05FFFF  (384 KB, S alias)
//!   Flash NSC: 0x0C060000 – 0x0C063FFF  ( 16 KB, NSC gateway)
//!   Flash NS : 0x08064000 – 0x0807FFFF  (112 KB, NS firmware)
//!   SRAM1 NS : 0x20000000 – 0x2002FFFF  (192 KB)
//!   SRAM2 S  : 0x20030000 – 0x2003FFFF  ( 64 KB, key store)
//!
//! This module is called from `main.rs` before any NS code runs. The firmware
//! currently runs without TZ enabled (all-NS) and this module provides the
//! setup function for when TZ is activated.

/// Configure the SAU for the TrustZone partition.
///
/// # Safety
/// Must be called with interrupts disabled, from Secure Privileged mode,
/// before any NS code runs. Incorrect configuration can lock the device.
#[allow(dead_code)]
pub unsafe fn configure_sau() {
    // SAU control register — enable SAU, allNS=0 (use region attributes)
    // STM32L552 reference: RM0438 §6 (Security)
    //
    // Region 0: Flash NS — 0x08064000, 112 KB, NS
    // Region 1: SRAM1 NS — 0x20000000, 192 KB, NS
    // Region 2: NSC gateway — 0x0C060000, 16 KB, NSC
    //
    // All other regions default to Secure.

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
    // Region 1: SRAM1 — Non-Secure, non-callable
    sau_region!(1, 0x2000_0000, 0x2002_FFFF, 0);
    // Region 2: NSC gateway — Non-Secure Callable
    sau_region!(2, 0x0C06_0000, 0x0C06_3FFF, 1);

    // Enable SAU
    (*sau).ctrl.modify(|r| r | 0x1); // ENABLE = 1
}

/// CMSE Non-Secure callable veneer table.
///
/// Functions annotated with `#[cmse_nonsecure_entry]` are placed in the
/// `.gnu.sgstubs` section (NSC region) and can be called from NS world.
/// Each veneer validates the handle and performs the operation in S context.
///
/// These stubs are compiled only when building the Secure firmware image
/// (feature "secure-build"). In the current all-NS build they are no-ops.

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
        // Implementation deferred to TZ integration phase
        let _ = (key_handle, iv_ns, aad_ns, aad_len, pt_ns, pt_len, ct_ns);
        -1 // not yet implemented
    }
}
