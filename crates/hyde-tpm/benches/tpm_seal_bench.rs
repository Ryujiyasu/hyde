//! TPM Seal/Unseal Benchmark
//!
//! Measures the real cost of TPM operations to inform API design decisions.
//! Specifically: whether with_ephemeral_kem() (per-protect TPM.Seal) is practical.
//!
//! Requires swtpm running:
//!   swtpm socket --tpmstate dir=/tmp/swtpm \
//!     --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --tpm2 --daemon

use hyde_core::backend::TeeBackend;
use hyde_tpm::{PcrPolicy, TpmBackend};
use std::time::{Duration, Instant};

fn main() {
    println!("=== TPM Seal/Unseal Benchmark (swtpm) ===\n");

    let iterations = 100;

    // --- Setup ---
    let mut backend =
        TpmBackend::new().expect("Failed to create TpmBackend — is swtpm running on port 2321?");
    backend
        .initialize_primary_key()
        .expect("Failed to initialize primary key");

    let test_data_small = vec![0u8; 64]; // 64 bytes — typical AES key + nonce
    let test_data_1kb = vec![0u8; 1024];
    let test_data_10kb = vec![0u8; 10240];

    // --- Bench: generate_data_key (= TPM.Seal of a fresh key) ---
    println!("--- generate_data_key (TPM.Create + Seal) ---");
    let mut times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let _key = backend
            .generate_data_key()
            .expect("generate_data_key failed");
        times.push(start.elapsed());
    }
    print_stats("generate_data_key", &times);

    // Generate a key for seal/unseal tests
    let key = backend.generate_data_key().expect("key generation failed");

    // --- Bench: seal (= TPM.Unseal dk + AES-GCM encrypt) ---
    for (label, data) in [
        ("seal 64B", &test_data_small),
        ("seal 1KB", &test_data_1kb),
        ("seal 10KB", &test_data_10kb),
    ] {
        println!("\n--- {label} ---");
        let mut times = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _sealed = backend.seal(&key, data).expect("seal failed");
            times.push(start.elapsed());
        }
        print_stats(label, &times);
    }

    // --- Bench: unseal (= TPM.Unseal dk + AES-GCM decrypt) ---
    let sealed_small = backend.seal(&key, &test_data_small).expect("seal failed");
    let sealed_1kb = backend.seal(&key, &test_data_1kb).expect("seal failed");
    let sealed_10kb = backend.seal(&key, &test_data_10kb).expect("seal failed");

    for (label, sealed) in [
        ("unseal 64B", &sealed_small),
        ("unseal 1KB", &sealed_1kb),
        ("unseal 10KB", &sealed_10kb),
    ] {
        println!("\n--- {label} ---");
        let mut times = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _data = backend.unseal(&key, sealed).expect("unseal failed");
            times.push(start.elapsed());
        }
        print_stats(label, &times);
    }

    // --- Bench: ephemeral KEM simulation ---
    // This measures: generate_data_key + seal — the cost of with_ephemeral_kem()
    println!("\n--- ephemeral KEM simulation (keygen + seal 64B) ---");
    let mut times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let ephemeral_key = backend
            .generate_data_key()
            .expect("generate_data_key failed");
        let _sealed = backend
            .seal(&ephemeral_key, &test_data_small)
            .expect("seal failed");
        times.push(start.elapsed());
    }
    print_stats("ephemeral_kem_protect", &times);

    // --- Summary ---
    println!("\n=== Summary ===");
    println!("NOTE: swtpm is software emulation. Real TPM hardware is typically:");
    println!("  - dTPM (discrete): 2-10x SLOWER than swtpm (SPI bus bottleneck)");
    println!("  - fTPM (firmware): ~1-2x of swtpm speed");
    println!("  - Pluton/CRB: ~1x of swtpm speed");
}

fn print_stats(label: &str, times: &[Duration]) {
    let n = times.len();
    let mut sorted: Vec<f64> = times.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let min = sorted[0];
    let max = sorted[n - 1];
    let median = sorted[n / 2];
    let mean: f64 = sorted.iter().sum::<f64>() / n as f64;
    let p99 = sorted[(n as f64 * 0.99) as usize];

    println!(
        "{label:30} | mean: {mean:8.3} ms | median: {median:8.3} ms | min: {min:8.3} ms | max: {max:8.3} ms | p99: {p99:8.3} ms | n={n}"
    );
}
