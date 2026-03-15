/* STM32L552ZE — Non-Secure build (no TrustZone, full flash/RAM)
 *
 * Used when building WITHOUT the `trustzone` feature (default).
 * The entire device runs in Non-Secure/privileged mode.
 *
 * For TrustZone builds (cargo build --features trustzone), see memory-tz.x
 * which uses the Secure flash alias at 0x0C000000.
 *
 * Hardware:
 *   Flash : 512 KB  at 0x08000000
 *   SRAM1 : 192 KB  at 0x20000000  (NS stack, buffers)
 *   SRAM2 :  64 KB  at 0x20030000  (key store — marked S when TZ active)
 */
MEMORY
{
    FLASH  : ORIGIN = 0x08000000, LENGTH = 512K
    RAM    : ORIGIN = 0x20000000, LENGTH = 192K
    SRAM2  : ORIGIN = 0x20030000, LENGTH = 64K
}

/* Embassy / cortex-m-rt default sections go into FLASH+SRAM1.
 * Key store is in SRAM2 — referenced from src/keystore.rs via linker symbol. */
_key_store_start = ORIGIN(SRAM2);
_key_store_end   = ORIGIN(SRAM2) + LENGTH(SRAM2);
