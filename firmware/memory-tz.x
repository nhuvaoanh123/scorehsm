/* STM32L552ZE — Secure world partition (TrustZone enabled, TZEN=1)
 *
 * Single S-world image: entire firmware runs in Secure mode.
 * SRAM2 is hardware-isolated — inaccessible from NS debug probes.
 *
 * Flash uses the Secure alias (0x0C000000) to ensure all instruction
 * fetches and literal pool loads are marked as Secure transactions.
 * SRAM uses the Secure alias (0x30000000) for stack and .bss/.data.
 *
 * Secure Watermark (SECWM) in FLASH option bytes must cover pages 0–191
 * (384 KB) to match this layout. Remaining 128 KB is reserved for future
 * NS firmware or NSC gateway.
 *
 * Prerequisites (one-time via STM32CubeProgrammer):
 *   1. STM32_Programmer_CLI -c port=SWD -ob TZEN=1
 *   2. STM32_Programmer_CLI -c port=SWD -ob SECWM_PSTRT=0x0 SECWM_PEND=0xBF
 *      (pages 0–191 = 384 KB Secure flash)
 *   3. Power-cycle the board after option byte changes
 *
 * Hardware:
 *   S Flash : 384 KB at 0x0C000000  (Secure alias of 0x08000000)
 *   S SRAM1 : 192 KB at 0x30000000  (Secure alias of 0x20000000)
 *   S SRAM2 :  64 KB at 0x30030000  (Secure alias of 0x20030000, key store)
 */
MEMORY
{
    FLASH  : ORIGIN = 0x0C000000, LENGTH = 384K
    RAM    : ORIGIN = 0x30000000, LENGTH = 192K
    SRAM2  : ORIGIN = 0x30030000, LENGTH = 64K
}

/* Embassy / cortex-m-rt default sections go into FLASH+RAM.
 * Key store is in SRAM2 — referenced from src/keystore.rs via linker symbol. */
_key_store_start = ORIGIN(SRAM2);
_key_store_end   = ORIGIN(SRAM2) + LENGTH(SRAM2);
