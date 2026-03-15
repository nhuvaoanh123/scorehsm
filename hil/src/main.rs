//! scorehsm HIL test suite — runs on Raspberry Pi against physical Nucleo board.
//!
//! Three automated tests exercising real hardware:
//!   HIL-IVG-01  USB device identity (VID/PID via sysfs)
//!   HIL-TIG-05  1000× AES-GCM encrypt+decrypt roundtrip
//!   HIL-RNG-01  1 MB TRNG output, entropy ≥ 7.99 bits/byte (via `ent`)
//!
//! Usage: scorehsm-hil /dev/ttyACM0

use std::env;
use std::fs;
use std::io::Write;
use std::process::{self, Command};
use std::time::Instant;

use scorehsm_host::backend::hw::HardwareBackend;
use scorehsm_host::backend::HsmBackend;
use scorehsm_host::types::{AesGcmParams, KeyType};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: scorehsm-hil <serial-port>");
        eprintln!("  e.g.: scorehsm-hil /dev/ttyACM0");
        process::exit(2);
    }
    let port = &args[1];

    println!("scorehsm HIL test suite");
    println!("=======================");
    println!("Device: {}", port);
    println!();

    let mut passed = 0u32;
    let mut failed = 0u32;

    // ── HIL-IVG-01: USB device identity ──────────────────────────────────────
    print!("[HIL-IVG-01] USB device identity (VID=f055 PID=4853) ... ");
    match test_ivg_01() {
        Ok(msg) => {
            println!("PASSED  {}", msg);
            passed += 1;
        }
        Err(e) => {
            println!("FAILED  {}", e);
            failed += 1;
        }
    }

    // ── Init hardware backend ────────────────────────────────────────────────
    let mut backend = HardwareBackend::new(port);
    if let Err(e) = backend.init() {
        eprintln!("FATAL: cannot initialise HardwareBackend: {}", e);
        process::exit(2);
    }
    println!("[init] HardwareBackend ready\n");

    // ── HIL-TIG-05: 1000× AES-GCM roundtrip ─────────────────────────────────
    print!("[HIL-TIG-05] 1000x AES-GCM encrypt+decrypt ... ");
    match test_tig_05(&mut backend) {
        Ok(msg) => {
            println!("PASSED  {}", msg);
            passed += 1;
        }
        Err(e) => {
            println!("FAILED  {}", e);
            failed += 1;
        }
    }

    // ── HIL-RNG-01: 1 MB TRNG + ent ─────────────────────────────────────────
    print!("[HIL-RNG-01] 1 MB TRNG entropy (>= 7.99 bits/byte) ... ");
    match test_rng_01(&mut backend) {
        Ok(msg) => {
            println!("PASSED  {}", msg);
            passed += 1;
        }
        Err(e) => {
            println!("FAILED  {}", e);
            failed += 1;
        }
    }

    // ── Cleanup ──────────────────────────────────────────────────────────────
    let _ = backend.deinit();

    println!();
    println!("Result: {}/{} passed", passed, passed + failed);
    process::exit(if failed > 0 { 1 } else { 0 });
}

// ── HIL-IVG-01: USB device identity via sysfs ───────────────────────────────
//
// Walk /sys/bus/usb/devices/*/idVendor and idProduct looking for
// VID=f055 PID=4853 (scoreHSM).

fn test_ivg_01() -> Result<String, String> {
    let usb_dir = "/sys/bus/usb/devices";
    let entries =
        fs::read_dir(usb_dir).map_err(|e| format!("cannot read {}: {}", usb_dir, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("readdir: {}", e))?;
        let path = entry.path();

        let vid_path = path.join("idVendor");
        let pid_path = path.join("idProduct");

        if let (Ok(vid), Ok(pid)) = (fs::read_to_string(&vid_path), fs::read_to_string(&pid_path))
        {
            let vid = vid.trim();
            let pid = pid.trim();
            if vid == "f055" && pid == "4853" {
                return Ok(format!("(found at {})", path.display()));
            }
        }
    }

    Err("scoreHSM USB device (VID=f055 PID=4853) not found in sysfs".into())
}

// ── HIL-TIG-05: 1000× AES-GCM encrypt+decrypt ──────────────────────────────
//
// Generate one AES-256 key on hardware, then for 1000 iterations:
//   1. Build deterministic plaintext (32 bytes) and counter-based IV
//   2. Encrypt via hardware
//   3. Decrypt via hardware
//   4. Verify decrypted == original (byte-exact)
// Pass criteria: 1000/1000 verified.

fn test_tig_05(backend: &mut HardwareBackend) -> Result<String, String> {
    const ITERATIONS: u32 = 1000;

    // Generate AES-256 key on hardware
    let handle = backend
        .key_generate(KeyType::Aes256)
        .map_err(|e| format!("key_generate: {}", e))?;

    let start = Instant::now();
    let mut verified = 0u32;

    for i in 0..ITERATIONS {
        // Deterministic plaintext: 32 bytes derived from iteration index
        let pt: Vec<u8> = (0..32u8)
            .map(|b| (i as u8).wrapping_add(b).wrapping_mul(0x37))
            .collect();

        // Counter-based IV (unique per iteration)
        let mut iv = [0u8; 12];
        iv[..4].copy_from_slice(&i.to_le_bytes());

        let params = AesGcmParams {
            iv: &iv,
            aad: &[],
        };

        // Encrypt on hardware
        let (ct, tag) = backend
            .aes_gcm_encrypt(handle, &params, &pt)
            .map_err(|e| format!("encrypt #{}: {}", i, e))?;

        // Decrypt on hardware
        let dec = backend
            .aes_gcm_decrypt(handle, &params, &ct, &tag)
            .map_err(|e| format!("decrypt #{}: {}", i, e))?;

        // Verify byte-exact match
        if dec != pt {
            return Err(format!(
                "mismatch at iteration {} (pt_len={}, dec_len={})",
                i,
                pt.len(),
                dec.len()
            ));
        }
        verified += 1;
    }

    let elapsed = start.elapsed();

    // Delete key
    backend
        .key_delete(handle)
        .map_err(|e| format!("key_delete: {}", e))?;

    Ok(format!(
        "({}/{} verified, {:.1}s)",
        verified,
        ITERATIONS,
        elapsed.as_secs_f64()
    ))
}

// ── HIL-RNG-01: 1 MB TRNG entropy test ──────────────────────────────────────
//
// Collect 1 MB of random data from the hardware TRNG (256 bytes per request),
// write to a temp file, run `ent` for entropy analysis.
// Pass criteria: entropy ≥ 7.99 bits per byte.

fn test_rng_01(backend: &mut HardwareBackend) -> Result<String, String> {
    const TOTAL_BYTES: usize = 1_048_576; // 1 MB
    const CHUNK: usize = 256;

    let tmp_path = "/tmp/scorehsm-trng.bin";
    let mut file =
        fs::File::create(tmp_path).map_err(|e| format!("create {}: {}", tmp_path, e))?;

    let start = Instant::now();
    let mut collected = 0usize;

    while collected < TOTAL_BYTES {
        let want = CHUNK.min(TOTAL_BYTES - collected);
        let mut buf = vec![0u8; want];
        backend
            .random(&mut buf)
            .map_err(|e| format!("random at byte {}: {}", collected, e))?;
        file.write_all(&buf)
            .map_err(|e| format!("write: {}", e))?;
        collected += want;
    }
    drop(file);
    let collect_time = start.elapsed();

    // Run `ent` on the collected data
    let output = Command::new("ent")
        .arg(tmp_path)
        .output()
        .map_err(|e| format!("failed to run ent: {} (is ent installed?)", e))?;

    if !output.status.success() {
        return Err(format!("ent exited with {}", output.status));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse entropy value: "Entropy = X.XXXXXX bits per byte."
    let entropy = parse_entropy(&stdout)?;

    if entropy < 7.99 {
        return Err(format!(
            "entropy {:.6} < 7.99 bits/byte\n{}",
            entropy, stdout
        ));
    }

    // Clean up temp file
    let _ = fs::remove_file(tmp_path);

    Ok(format!(
        "(entropy={:.6} bits/byte, collected in {:.1}s)",
        entropy,
        collect_time.as_secs_f64()
    ))
}

fn parse_entropy(ent_output: &str) -> Result<f64, String> {
    for line in ent_output.lines() {
        if line.starts_with("Entropy") {
            // "Entropy = 7.999825 bits per byte."
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return parts[2]
                    .parse::<f64>()
                    .map_err(|e| format!("parse entropy value '{}': {}", parts[2], e));
            }
        }
    }
    Err("could not find 'Entropy' line in ent output".into())
}
