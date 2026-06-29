//! Live pure-Rust TCG TPM 2.0 v1.85 PQC demo against a running TPM.
//!
//! Needs a TPM listening on the mssim command port (e.g. wolfTPM's
//! `fwtpm_server` on 127.0.0.1:2321). Not a CI test.
//!
//! ```text
//! cargo run -p hyde-tpm --no-default-features --features pqc --example pqc_demo
//! ```

use hyde_tpm::pqc::{MlDsa, MlKem, PqcTpm};
use ml_dsa::{EncodedVerifyingKey, MlDsa44, Signature, VerifyingKey};

const MSG: &[u8] = b"Hyde v1.85 PQC: hardware-rooted ML-DSA";

fn main() -> std::io::Result<()> {
    let mut tpm = PqcTpm::connect("127.0.0.1:2321")?;

    // ML-KEM: key gen -> encapsulate -> decapsulate, secrets must match.
    let secret = tpm.ml_kem_roundtrip(MlKem::K512)?;
    println!("ML-KEM-512 round-trip OK: {}-byte shared secret matches", secret.len());

    // ML-DSA: key gen -> hardware-rooted signature.
    let (pubkey, sig) = tpm.ml_dsa_sign(MlDsa::D44, MSG)?;
    println!("ML-DSA-44: pubkey {} B, signature {} B", pubkey.len(), sig.len());

    // Independent FIPS 204 verification (evidence, not attestation verify).
    let evk = EncodedVerifyingKey::<MlDsa44>::try_from(&pubkey[..]).unwrap();
    let vk = VerifyingKey::<MlDsa44>::decode(&evk);
    let signature = Signature::<MlDsa44>::try_from(&sig[..]).unwrap();
    let ok = vk.verify_with_context(MSG, &[], &signature);
    println!("independent ml-dsa verify (ctx=empty): {}", if ok { "VALID" } else { "INVALID" });
    Ok(())
}
