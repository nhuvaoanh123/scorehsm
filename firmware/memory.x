/* STM32L552ZE — Non-Secure partition (initial: no TrustZone, full flash/RAM)
 *
 * When TrustZone is enabled (see src/trustzone.rs), the NS image will
 * be relocated to 0x08060000 and the SAU will restrict SRAM1 to NS use.
 * For now the entire device runs in Non-Secure/privileged mode.
 *
 * Hardware:
 *   Flash : 512 KB  at 0x08000000
 *   SRAM1 : 192 KB  at 0x20000000  (NS stack, buffers)
 *   SRAM2 :  64 KB  at 0x20030000  (key store — marked S when TZ active)
 */
MEMORY
{
    FLASH  : ORIGIN = 0x08000000, LENGTH = 512K
    SRAM1  : ORIGIN = 0x20000000, LENGTH = 192K
    SRAM2  : ORIGIN = 0x20030000, LENGTH = 64K
}

/* Embassy / cortex-m-rt default sections go into FLASH+SRAM1.
 * Key store is in SRAM2 — referenced from src/keystore.rs via linker symbol. */
_key_store_start = ORIGIN(SRAM2);
_key_store_end   = ORIGIN(SRAM2) + LENGTH(SRAM2);
