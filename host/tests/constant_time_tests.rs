//! Statistical constant-time verification for AES-GCM tag comparison.
//!
//! The constant-time property we verify: the tag COMPARISON in `aes-gcm`
//! (via `subtle::ConstantTimeEq::ct_eq`) does not early-exit on the first
//! mismatched byte. Evidence: wrong tags with only the first byte flipped
//! take the same time as wrong tags with only the last byte flipped.
//!
//! NOTE: Total decrypt time differs between correct-tag (includes CTR
//! decryption) and wrong-tag (returns error immediately). This is expected
//! and not a timing leak — the result (success/failure) is already visible
//! to the caller, so the timing delta reveals no additional information.
//!
//! The `subtle` crate warns that debug builds may introduce data-dependent
//! branches. Run with `--release` for definitive evidence.

use scorehsm_host::{
    backend::{sw::SoftwareBackend, HsmBackend},
    types::{AesGcmParams, KeyType},
};
use std::time::Instant;

const ITERATIONS: usize = 2000;
const MAX_DRIFT_PERCENT: f64 = 20.0; // generous for debug builds + CI noise

fn mean(data: &[f64]) -> f64 {
    data.iter().sum::<f64>() / data.len() as f64
}

fn stddev(data: &[f64], m: f64) -> f64 {
    let var = data.iter().map(|x| (x - m).powi(2)).sum::<f64>() / data.len() as f64;
    var.sqrt()
}

/// Measure N decrypt attempts with a specific bad tag, return timing vector.
fn measure_wrong_tag(
    backend: &SoftwareBackend,
    handle: scorehsm_host::types::KeyHandle,
    params: &AesGcmParams,
    ciphertext: &[u8],
    tag: &[u8; 16],
    n: usize,
) -> Vec<f64> {
    let mut times = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        let result = backend.aes_gcm_decrypt(handle, params, ciphertext, tag);
        let elapsed = start.elapsed().as_nanos() as f64;
        assert!(result.is_err(), "wrong tag should fail");
        times.push(elapsed);
    }
    times
}

#[test]
fn aes_gcm_tag_comparison_is_constant_time() {
    let mut backend = SoftwareBackend::new();
    backend.init().unwrap();
    let handle = backend.key_generate(KeyType::Aes256).unwrap();

    let iv = [0x42u8; 12];
    let aad = b"constant-time-test";
    let plaintext = vec![0xABu8; 128];
    let params = AesGcmParams { iv: &iv, aad };

    let (ciphertext, correct_tag) = backend
        .aes_gcm_encrypt(handle, &params, &plaintext)
        .unwrap();

    // Three wrong-tag variants to detect byte-by-byte early-exit:
    // A non-CT comparison would make first_byte_wrong faster than last_byte_wrong.
    let mut tag_first_wrong = correct_tag;
    tag_first_wrong[0] ^= 0xFF; // only first byte differs

    let mut tag_last_wrong = correct_tag;
    tag_last_wrong[15] ^= 0xFF; // only last byte differs

    let mut tag_all_wrong = correct_tag;
    for b in tag_all_wrong.iter_mut() {
        *b ^= 0xFF; // all bytes differ
    }

    // ── Warmup ──
    for _ in 0..200 {
        let _ = backend.aes_gcm_decrypt(handle, &params, &ciphertext, &tag_first_wrong);
        let _ = backend.aes_gcm_decrypt(handle, &params, &ciphertext, &tag_last_wrong);
        let _ = backend.aes_gcm_decrypt(handle, &params, &ciphertext, &tag_all_wrong);
    }

    // ── Measure each variant ──
    let first_times = measure_wrong_tag(
        &backend,
        handle,
        &params,
        &ciphertext,
        &tag_first_wrong,
        ITERATIONS,
    );
    let last_times = measure_wrong_tag(
        &backend,
        handle,
        &params,
        &ciphertext,
        &tag_last_wrong,
        ITERATIONS,
    );
    let all_times = measure_wrong_tag(
        &backend,
        handle,
        &params,
        &ciphertext,
        &tag_all_wrong,
        ITERATIONS,
    );

    let first_mean = mean(&first_times);
    let last_mean = mean(&last_times);
    let all_mean = mean(&all_times);

    let first_cv = stddev(&first_times, first_mean) / first_mean * 100.0;
    let last_cv = stddev(&last_times, last_mean) / last_mean * 100.0;
    let all_cv = stddev(&all_times, all_mean) / all_mean * 100.0;

    // Drift between first-byte-wrong and last-byte-wrong
    let max_mean = first_mean.max(last_mean);
    let first_last_drift = (first_mean - last_mean).abs() / max_mean * 100.0;

    // Drift between first-byte-wrong and all-bytes-wrong
    let max_mean2 = first_mean.max(all_mean);
    let first_all_drift = (first_mean - all_mean).abs() / max_mean2 * 100.0;

    eprintln!("── AES-GCM tag comparison constant-time evidence ──");
    eprintln!(
        "  First byte wrong: mean={:.0}ns  CV={:.1}%",
        first_mean, first_cv
    );
    eprintln!(
        "  Last  byte wrong: mean={:.0}ns  CV={:.1}%",
        last_mean, last_cv
    );
    eprintln!(
        "  All  bytes wrong: mean={:.0}ns  CV={:.1}%",
        all_mean, all_cv
    );
    eprintln!("  First↔Last drift: {:.1}%", first_last_drift);
    eprintln!("  First↔All  drift: {:.1}%", first_all_drift);

    // Key assertion: a sequential byte-by-byte comparison would show
    // first_mean << last_mean (early exit on byte 0 vs checking all 16).
    // Constant-time (ct_eq) makes them equal within noise.
    assert!(
        first_last_drift < MAX_DRIFT_PERCENT,
        "First↔Last timing drift {:.1}% exceeds {}% — possible non-CT tag comparison!\n\
         first={:.0}ns last={:.0}ns",
        first_last_drift,
        MAX_DRIFT_PERCENT,
        first_mean,
        last_mean,
    );
    assert!(
        first_all_drift < MAX_DRIFT_PERCENT,
        "First↔All timing drift {:.1}% exceeds {}% — possible non-CT tag comparison!\n\
         first={:.0}ns all={:.0}ns",
        first_all_drift,
        MAX_DRIFT_PERCENT,
        first_mean,
        all_mean,
    );
}
