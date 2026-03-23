use crate::error::{HydeError, Result};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    KemCore, MlKem768,
};

// Re-use the same rand_core version that ml-kem depends on (0.6.x)
use aes_gcm::aead::OsRng;

/// ML-KEM-768 encapsulation key (public).
pub type EncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;

/// ML-KEM-768 decapsulation key (secret).
pub type DecapsulationKey = <MlKem768 as KemCore>::DecapsulationKey;

/// ML-KEM-768 ciphertext (1088 bytes).
pub type KemCiphertext = ml_kem::Ciphertext<MlKem768>;

/// PQC keypair for ML-KEM-768 post-quantum key encapsulation.
pub struct PqcKeypair {
    pub(crate) dk: DecapsulationKey,
    pub(crate) ek: EncapsulationKey,
}

impl PqcKeypair {
    /// Generate a fresh ML-KEM-768 keypair.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let (dk, ek) = MlKem768::generate(&mut rng);
        Self { dk, ek }
    }
}

/// Encrypt data with ML-KEM-768 + AES-256-GCM.
///
/// Returns `(kem_ciphertext_bytes, aes_ciphertext)`.
pub(crate) fn pqc_encrypt(ek: &EncapsulationKey, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;
    let (kem_ct, shared_secret) = ek
        .encapsulate(&mut rng)
        .map_err(|_| HydeError::Backend("ML-KEM encapsulation failed".into()))?;

    let ss_bytes: &[u8] = shared_secret.as_ref();
    let ciphertext = crate::passphrase::aes_gcm_encrypt(ss_bytes, data)?;

    let kem_ct_bytes: &[u8] = kem_ct.as_ref();
    Ok((kem_ct_bytes.to_vec(), ciphertext))
}

/// Decrypt data with ML-KEM-768 + AES-256-GCM.
pub(crate) fn pqc_decrypt(
    dk: &DecapsulationKey,
    kem_ct_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let kem_ct = KemCiphertext::try_from(kem_ct_bytes).map_err(|_| HydeError::InvalidKey)?;

    let shared_secret = dk
        .decapsulate(&kem_ct)
        .map_err(|_| HydeError::Backend("ML-KEM decapsulation failed".into()))?;

    let ss_bytes: &[u8] = shared_secret.as_ref();
    crate::passphrase::aes_gcm_decrypt(ss_bytes, ciphertext)
}
