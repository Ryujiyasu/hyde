use crate::error::{HydeError, Result};
use crate::signing::{self, SigningAlgorithm, WrappedSigningKey};
use serde::{Deserialize, Serialize};

/// TEE backend unified interface.
/// TDX/SEV/Secure Enclave backends will implement this same trait in Phase 2+.
pub trait TeeBackend: Send + Sync {
    /// Check if this backend is available on the current system.
    fn is_available() -> bool
    where
        Self: Sized;

    /// Initialize the Primary Key (load if exists, create + persist if not).
    /// Called once per device.
    fn initialize_primary_key(&mut self) -> Result<()>;

    /// Generate a Data Key and wrap it with the Primary Key.
    /// The returned WrappedKey blob cannot be unwrapped without the TEE.
    fn generate_data_key(&mut self) -> Result<WrappedKey>;

    /// Unwrap the Data Key, encrypt data, and seal with PCR policy.
    fn seal(&mut self, key: &WrappedKey, data: &[u8]) -> Result<Vec<u8>>;

    /// Unseal data. Fails if PCR values have changed.
    fn unseal(&mut self, key: &WrappedKey, sealed: &[u8]) -> Result<Vec<u8>>;

    /// Return the backend type identifier.
    fn backend_type(&self) -> BackendType;

    /// Generate an ML-DSA signing keypair bound to this device.
    ///
    /// Default implementation keygens in software, seals the signing
    /// key with this backend's Primary Key, and returns the verifying
    /// key in the clear. Backends with native ML-DSA hardware (not
    /// currently shipping in TPM 2.0 at time of writing) may override
    /// to keep the key inside silicon.
    fn generate_signing_key(
        &mut self,
        algorithm: SigningAlgorithm,
    ) -> Result<WrappedSigningKey> {
        let (signing_bytes, verifying_bytes) = signing::keygen_raw(algorithm)?;
        let wrapping_key = self.generate_data_key()?;
        let sealed_signing_key = self.seal(&wrapping_key, &signing_bytes)?;
        Ok(WrappedSigningKey {
            algorithm,
            verifying_key: verifying_bytes,
            wrapping_key,
            sealed_signing_key,
            backend: self.backend_type(),
        })
    }

    /// Sign a message under a previously-wrapped signing key.
    ///
    /// Default implementation unseals the signing key inside this
    /// backend, runs [`signing::sign_raw`], and zeroises the
    /// recovered bytes before returning.
    fn sign(&mut self, key: &WrappedSigningKey, message: &[u8]) -> Result<Vec<u8>> {
        if key.backend != self.backend_type() {
            return Err(HydeError::Backend(
                "wrapped signing key belongs to a different backend".into(),
            ));
        }
        let signing_bytes = self.unseal(&key.wrapping_key, &key.sealed_signing_key)?;
        signing::sign_raw(key.algorithm, signing_bytes, message)
    }
}

/// A Data Key wrapped by the Primary Key.
/// Safe to persist to disk — cannot be unwrapped without the corresponding TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// Key material wrapped by the Primary Key.
    pub blob: Vec<u8>,
    /// Which backend produced this wrapped key.
    pub backend: BackendType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BackendType {
    Tpm,
    Software,
    // Phase 2+
    // Tdx,
    // Sev,
    // SecureEnclave,
}
