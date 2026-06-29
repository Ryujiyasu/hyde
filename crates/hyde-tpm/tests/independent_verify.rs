//! Independent FIPS 204 verification of a **real TPM-produced** ML-DSA-44
//! signature, by a separate implementation (RustCrypto `ml-dsa`).
//!
//! This is *evidence*, not attestation: it shows that a signature the TPM
//! emitted over `MSG` is cryptographically valid under an independent FIPS 204
//! implementation. The vectors below were captured from a live firmware-TPM
//! signing run (see `examples/pqc_demo.rs`); the test needs no TPM and runs in
//! CI — the proof travels with the crate.
//!
//! Note: verifying a TPM signature on the host does **not** replace TPM-rooted
//! attestation verification — see the crate README.

#![cfg(feature = "pqc")]

use ml_dsa::{EncodedVerifyingKey, MlDsa44, Signature, VerifyingKey};

/// The exact message the captured signature was produced over.
const MSG: &[u8] = b"Hyde v1.85 PQC: hardware-rooted ML-DSA";
const VK: &[u8] = include_bytes!("vectors/mldsa44_vk.bin"); // out_public.unique, 1312 B
const SIG: &[u8] = include_bytes!("vectors/mldsa44_sig.bin"); // TPMT_SIGNATURE payload, 2420 B

#[test]
fn tpm_mldsa44_signature_is_independently_valid() {
    assert_eq!(VK.len(), 1312, "FIPS 204 ML-DSA-44 verifying key");
    assert_eq!(SIG.len(), 2420, "FIPS 204 ML-DSA-44 signature");

    let evk = EncodedVerifyingKey::<MlDsa44>::try_from(VK).expect("decode verifying key");
    let vk = VerifyingKey::<MlDsa44>::decode(&evk);
    let sig = Signature::<MlDsa44>::try_from(SIG).expect("decode signature");

    // Pure ML-DSA (sig_alg = TPM_ALG_MLDSA 0x00A1) -> empty context.
    assert!(
        vk.verify_with_context(MSG, &[], &sig),
        "independent FIPS 204 impl must accept the TPM-produced signature"
    );
}
