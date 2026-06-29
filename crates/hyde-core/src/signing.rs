//! ML-DSA (FIPS 204) device-bound signatures.
//!
//! ML-DSA is the standardized post-quantum signature algorithm
//! (formerly CRYSTALS-Dilithium). hyde treats the signing key the same
//! way it treats any other secret: the 32-byte master seed is sealed
//! by the active TEE backend's primary key, and recovered only long
//! enough to reconstruct the expanded key for a single signature. The
//! verifying (public) key is kept in the clear so relying parties can
//! verify offline.
//!
//! No TPM currently implements ML-DSA natively, so the signing
//! operation runs in user space using [`ml-dsa`](https://docs.rs/ml-dsa)
//! after the TEE unseals the seed. Device binding still holds — the
//! sealed seed is useless without the TEE that wrapped it — but the
//! signing step itself is not inside the TEE boundary. When TPM 2.0
//! firmware with native ML-DSA ships (SEALSQ sampled one in Q3 2025),
//! [`TeeBackend::sign`] can be overridden per-backend to use the
//! native path and keep the key inside silicon.
//!
//! For a discussion of how this fits the broader Protect / Prove /
//! Compute split, see `hyde-roadmap.md`.

use crate::backend::{BackendType, WrappedKey};
use crate::error::{HydeError, Result};
use getrandom::getrandom;
use ml_dsa::{
    signature::{Keypair, Signer, Verifier},
    B32, EncodedSignature, EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87,
    MlDsaParams, Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Size in bytes of an ML-DSA master seed. See FIPS 204 §3.6.
pub const SEED_LEN: usize = 32;

/// ML-DSA parameter sets as defined in FIPS 204.
///
/// Higher categories mean longer keys, longer signatures, and more
/// conservative security margins. Most applications should start at
/// [`SigningAlgorithm::MlDsa65`] (NIST category 3, ~AES-192-equivalent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    /// FIPS 204 ML-DSA-44 (NIST security category 2, ~AES-128).
    MlDsa44,
    /// FIPS 204 ML-DSA-65 (NIST security category 3, ~AES-192). Recommended default.
    MlDsa65,
    /// FIPS 204 ML-DSA-87 (NIST security category 5, ~AES-256).
    MlDsa87,
}

/// A device-bound ML-DSA signing keypair.
///
/// `sealed_signing_key` is ciphertext produced by the TEE's
/// [`seal`](crate::backend::TeeBackend::seal) operation over the
/// 32-byte master seed. It can only be unsealed by the same backend
/// instance whose primary key wrapped it, which in practice means the
/// same device (and, for PCR-bound TPM backends, the same boot
/// state). `verifying_key` is publishable — hand it to the relying
/// party at enrolment time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedSigningKey {
    pub algorithm: SigningAlgorithm,
    /// Raw verifying key bytes (FIPS 204 encoding).
    pub verifying_key: Vec<u8>,
    /// The TEE-wrapped Data Key that sealed the signing key seed.
    pub wrapping_key: WrappedKey,
    /// AES-GCM ciphertext of the 32-byte ML-DSA master seed.
    pub sealed_signing_key: Vec<u8>,
    /// Which backend produced this — callers should sign with the same.
    pub backend: BackendType,
}

/// Generate a fresh ML-DSA keypair and return `(seed, verifying_key)` as raw bytes.
///
/// The returned `seed` is exactly [`SEED_LEN`] = 32 bytes and is
/// sufficient to reconstruct the signing key via
/// [`ml_dsa::KeyGen::from_seed`]. Typical callers should prefer
/// [`TeeBackend::generate_signing_key`], which seals the seed before
/// it leaves memory.
///
/// [`TeeBackend::generate_signing_key`]: crate::backend::TeeBackend::generate_signing_key
pub fn keygen_raw(algorithm: SigningAlgorithm) -> Result<(Vec<u8>, Vec<u8>)> {
    match algorithm {
        SigningAlgorithm::MlDsa44 => do_keygen::<MlDsa44>(),
        SigningAlgorithm::MlDsa65 => do_keygen::<MlDsa65>(),
        SigningAlgorithm::MlDsa87 => do_keygen::<MlDsa87>(),
    }
}

/// Sign `message` using a raw 32-byte master seed. The seed bytes are
/// zeroised before return.
pub fn sign_raw(
    algorithm: SigningAlgorithm,
    mut signing_seed: Vec<u8>,
    message: &[u8],
) -> Result<Vec<u8>> {
    if signing_seed.len() != SEED_LEN {
        signing_seed.zeroize();
        return Err(HydeError::InvalidKey);
    }
    let mut seed_arr = [0u8; SEED_LEN];
    seed_arr.copy_from_slice(&signing_seed);
    signing_seed.zeroize();

    let seed: B32 = seed_arr.into();
    let result = match algorithm {
        SigningAlgorithm::MlDsa44 => {
            let sk: SigningKey<MlDsa44> = SigningKey::<MlDsa44>::from_seed(&seed);
            let sig: Signature<MlDsa44> = sk.sign(message);
            sig.encode().as_slice().to_vec()
        }
        SigningAlgorithm::MlDsa65 => {
            let sk: SigningKey<MlDsa65> = SigningKey::<MlDsa65>::from_seed(&seed);
            let sig: Signature<MlDsa65> = sk.sign(message);
            sig.encode().as_slice().to_vec()
        }
        SigningAlgorithm::MlDsa87 => {
            let sk: SigningKey<MlDsa87> = SigningKey::<MlDsa87>::from_seed(&seed);
            let sig: Signature<MlDsa87> = sk.sign(message);
            sig.encode().as_slice().to_vec()
        }
    };
    seed_arr.zeroize();
    Ok(result)
}

/// Verify a signature. No TEE needed — relying parties verify anywhere.
pub fn verify(
    algorithm: SigningAlgorithm,
    verifying_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool> {
    match algorithm {
        SigningAlgorithm::MlDsa44 => {
            do_verify::<MlDsa44>(verifying_key_bytes, message, signature_bytes)
        }
        SigningAlgorithm::MlDsa65 => {
            do_verify::<MlDsa65>(verifying_key_bytes, message, signature_bytes)
        }
        SigningAlgorithm::MlDsa87 => {
            do_verify::<MlDsa87>(verifying_key_bytes, message, signature_bytes)
        }
    }
}

// -----------------------------------------------------------------------------
// Generic internals
// -----------------------------------------------------------------------------

fn do_keygen<P: MlDsaParams>() -> Result<(Vec<u8>, Vec<u8>)> {
    // Sidestep the signature/rand_core version skew in the RustCrypto
    // pre-release stack by deriving the key deterministically from 32
    // bytes of OS entropy — equivalent to `P::key_gen(&mut rng)`.
    let mut seed_bytes = [0u8; SEED_LEN];
    getrandom(&mut seed_bytes).map_err(|e| {
        HydeError::Backend(format!("getrandom failed: {e}").into())
    })?;
    let seed: B32 = seed_bytes.into();
    let sk: SigningKey<P> = SigningKey::<P>::from_seed(&seed);
    let vk: VerifyingKey<P> = sk.verifying_key();
    let vk_bytes = vk.encode().as_slice().to_vec();
    let seed_out = sk.to_seed().as_slice().to_vec();
    seed_bytes.zeroize();
    Ok((seed_out, vk_bytes))
}

fn do_verify<P: MlDsaParams>(
    vk_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    let vk_array = match EncodedVerifyingKey::<P>::try_from(vk_bytes) {
        Ok(a) => a,
        Err(_) => return Err(HydeError::InvalidKey),
    };
    let vk = VerifyingKey::<P>::decode(&vk_array);

    let sig_array = match EncodedSignature::<P>::try_from(sig_bytes) {
        Ok(a) => a,
        Err(_) => return Ok(false),
    };
    let sig = match Signature::<P>::decode(&sig_array) {
        Some(s) => s,
        None => return Ok(false),
    };

    Ok(vk.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(algorithm: SigningAlgorithm) {
        let (seed, vk_bytes) = keygen_raw(algorithm).expect("keygen");
        assert_eq!(seed.len(), SEED_LEN);
        assert!(!vk_bytes.is_empty());

        let msg = b"vohu-vote/v1 proposal=demo nullifier=abc ballot-digest=xyz";
        let sig = sign_raw(algorithm, seed.clone(), msg).expect("sign");

        assert!(verify(algorithm, &vk_bytes, msg, &sig).expect("verify"));

        // A different message must not verify.
        assert!(!verify(algorithm, &vk_bytes, b"other", &sig).expect("verify other"));

        // A truncated signature must not verify (returns false, not Err).
        let short = &sig[..sig.len() - 1];
        assert!(!verify(algorithm, &vk_bytes, msg, short).expect("verify short"));
    }

    #[test]
    fn roundtrip_mldsa44() {
        roundtrip(SigningAlgorithm::MlDsa44);
    }

    #[test]
    fn roundtrip_mldsa65() {
        roundtrip(SigningAlgorithm::MlDsa65);
    }

    #[test]
    fn roundtrip_mldsa87() {
        roundtrip(SigningAlgorithm::MlDsa87);
    }

    #[test]
    fn invalid_seed_length_rejected() {
        let r = sign_raw(
            SigningAlgorithm::MlDsa65,
            vec![0u8; 16], // wrong length
            b"msg",
        );
        assert!(matches!(r, Err(HydeError::InvalidKey)));
    }

    /// Recovery and device+person binding re-derive the signing key from a
    /// stored 32-byte seed, so the same seed MUST yield the same verifying key
    /// (FIPS 204 `KeyGen_internal` is deterministic). This is the load-bearing
    /// invariant the `ml-dsa` 0.1.1 call-site fix must preserve — a regression
    /// here means previously-recoverable identities stop recovering. Guards
    /// against silent behavioral drift in the `ml-dsa` dependency.
    #[test]
    fn from_seed_key_derivation_is_deterministic() {
        let seed: B32 = [0x42u8; SEED_LEN].into();
        let vk_a = SigningKey::<MlDsa44>::from_seed(&seed).verifying_key().encode();
        let vk_b = SigningKey::<MlDsa44>::from_seed(&seed).verifying_key().encode();
        assert_eq!(vk_a, vk_b, "same seed must derive the same key (recovery invariant)");

        let other: B32 = [0x43u8; SEED_LEN].into();
        let vk_c = SigningKey::<MlDsa44>::from_seed(&other).verifying_key().encode();
        assert_ne!(vk_a, vk_c, "different seed must derive a different key");
    }
}
