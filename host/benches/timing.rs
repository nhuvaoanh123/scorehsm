//! Criterion benchmarks for scorehsm software backend.
//!
//! Measures latency distributions for security-sensitive crypto operations:
//! - AES-256-GCM encrypt/decrypt at multiple payload sizes
//! - ECDSA P-256 sign/verify
//! - SHA-256
//! - HMAC-SHA256
//!
//! Run: `cargo bench --bench timing`

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scorehsm_host::{
    backend::{sw::SoftwareBackend, HsmBackend},
    types::{AesGcmParams, KeyType},
};

fn bench_aes_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm");
    let iv = [0x42u8; 12];
    let aad = b"scorehsm-bench";

    for size in [1, 32, 128, 512] {
        let plaintext = vec![0xABu8; size];

        group.throughput(Throughput::Bytes(size as u64));

        // ── encrypt ──
        group.bench_with_input(BenchmarkId::new("encrypt", size), &plaintext, |b, pt| {
            let mut backend = SoftwareBackend::new();
            backend.init().unwrap();
            let handle = backend.key_generate(KeyType::Aes256).unwrap();
            let params = AesGcmParams { iv: &iv, aad };
            b.iter(|| backend.aes_gcm_encrypt(handle, &params, pt).unwrap());
        });

        // ── decrypt ──
        group.bench_with_input(BenchmarkId::new("decrypt", size), &plaintext, |b, pt| {
            let mut backend = SoftwareBackend::new();
            backend.init().unwrap();
            let handle = backend.key_generate(KeyType::Aes256).unwrap();
            let params = AesGcmParams { iv: &iv, aad };
            let (ct, tag) = backend.aes_gcm_encrypt(handle, &params, pt).unwrap();
            b.iter(|| backend.aes_gcm_decrypt(handle, &params, &ct, &tag).unwrap());
        });
    }
    group.finish();
}

fn bench_ecdsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa");
    let digest = [0x55u8; 32];

    // ── sign ──
    group.bench_function("sign", |b| {
        let mut backend = SoftwareBackend::new();
        backend.init().unwrap();
        let handle = backend.key_generate(KeyType::EccP256).unwrap();
        b.iter(|| backend.ecdsa_sign(handle, &digest).unwrap());
    });

    // ── verify ──
    group.bench_function("verify", |b| {
        let mut backend = SoftwareBackend::new();
        backend.init().unwrap();
        let handle = backend.key_generate(KeyType::EccP256).unwrap();
        let sig = backend.ecdsa_sign(handle, &digest).unwrap();
        b.iter(|| backend.ecdsa_verify(handle, &digest, &sig).unwrap());
    });

    group.finish();
}

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    for size in [32, 256, 1024, 4096] {
        let data = vec![0xCDu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            let mut backend = SoftwareBackend::new();
            backend.init().unwrap();
            b.iter(|| backend.sha256(d).unwrap());
        });
    }
    group.finish();
}

fn bench_hmac(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_sha256");
    let data = vec![0xEFu8; 256];

    group.bench_function("256B", |b| {
        let mut backend = SoftwareBackend::new();
        backend.init().unwrap();
        let handle = backend.key_generate(KeyType::HmacSha256).unwrap();
        b.iter(|| backend.hmac_sha256(handle, &data).unwrap());
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_aes_gcm,
    bench_ecdsa,
    bench_sha256,
    bench_hmac
);
criterion_main!(benches);
