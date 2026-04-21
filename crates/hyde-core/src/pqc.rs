use crate::error::{HydeError, Result};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore, MlKem768,
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

    /// Serialize the encapsulation (public) key to bytes.
    pub fn ek_bytes(&self) -> Vec<u8> {
        self.ek.as_bytes().to_vec()
    }

    /// Serialize the decapsulation (secret) key to bytes.
    pub fn dk_bytes(&self) -> Vec<u8> {
        self.dk.as_bytes().to_vec()
    }

    /// Reconstruct a keypair from its serialized components.
    pub fn from_bytes(ek: &[u8], dk: &[u8]) -> Result<Self> {
        let ek_arr = encoded_from_slice::<EncapsulationKey>(ek)?;
        let dk_arr = encoded_from_slice::<DecapsulationKey>(dk)?;
        Ok(Self {
            ek: EncapsulationKey::from_bytes(&ek_arr),
            dk: DecapsulationKey::from_bytes(&dk_arr),
        })
    }
}

fn encoded_from_slice<K: EncodedSizeUser>(src: &[u8]) -> Result<ml_kem::Encoded<K>> {
    ml_kem::Encoded::<K>::try_from(src).map_err(|_| HydeError::InvalidKey)
}

/// Deserialize an encapsulation (public) key from bytes.
pub fn encapsulation_key_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey> {
    let arr = encoded_from_slice::<EncapsulationKey>(bytes)?;
    Ok(EncapsulationKey::from_bytes(&arr))
}

/// Deserialize a decapsulation (secret) key from bytes.
pub fn decapsulation_key_from_bytes(bytes: &[u8]) -> Result<DecapsulationKey> {
    let arr = encoded_from_slice::<DecapsulationKey>(bytes)?;
    Ok(DecapsulationKey::from_bytes(&arr))
}

/// Encrypt data with ML-KEM-768 + AES-256-GCM.
///
/// Returns `(kem_ciphertext_bytes, aes_ciphertext)`.
pub fn pqc_encrypt(ek: &EncapsulationKey, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
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
pub fn pqc_decrypt(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_bytes_roundtrip() {
        let kp = PqcKeypair::generate();
        let ek_b = kp.ek_bytes();
        let dk_b = kp.dk_bytes();
        let restored = PqcKeypair::from_bytes(&ek_b, &dk_b).unwrap();

        let (kem_ct, aes_ct) = pqc_encrypt(&kp.ek, b"hybrid option Y").unwrap();
        let pt = pqc_decrypt(&restored.dk, &kem_ct, &aes_ct).unwrap();
        assert_eq!(pt, b"hybrid option Y");
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(PqcKeypair::from_bytes(&[0u8; 10], &[0u8; 10]).is_err());
    }
}
