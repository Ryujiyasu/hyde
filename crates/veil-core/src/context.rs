use crate::{
    backend::{TeeBackend, WrappedKey},
    error::Result,
};
use serde::{Deserialize, Serialize};

/// Main entry point for veil operations.
pub struct VeilContext {
    backend: Box<dyn TeeBackend>,
}

#[derive(Debug, Clone)]
pub enum FallbackPolicy {
    /// Error if no TEE hardware is available.
    Deny,
    /// Warn and fall back to software backend.
    Warn,
    /// Silently fall back to software backend.
    Software,
}

impl VeilContext {
    /// Create a VeilContext with a specific backend (for testing or advanced use).
    /// Calls `initialize_primary_key()` on the backend.
    pub fn with_backend(mut backend: Box<dyn TeeBackend>) -> Result<Self> {
        backend.initialize_primary_key()?;
        Ok(Self { backend })
    }

    /// Protect data by generating a Data Key, encrypting, and wrapping.
    /// The returned `ProtectedData` can be serialized and stored anywhere.
    pub fn protect(&mut self, data: &[u8]) -> Result<ProtectedData> {
        let key = self.backend.generate_data_key()?;
        let ciphertext = self.backend.seal(&key, data)?;
        Ok(ProtectedData {
            key,
            ciphertext,
            version: 1,
        })
    }

    /// Decrypt protected data. Requires the same TEE that produced it.
    pub fn unprotect(&mut self, protected: &ProtectedData) -> Result<Vec<u8>> {
        self.backend.unseal(&protected.key, &protected.ciphertext)
    }

    /// Backup protected data with a passphrase (for device migration / recovery).
    pub fn backup(&mut self, protected: &ProtectedData, passphrase: &[u8]) -> Result<Vec<u8>> {
        self.backend.backup(&protected.key, passphrase)
    }

    /// Restore protected data from a passphrase backup.
    pub fn restore(
        &mut self,
        backup: &[u8],
        ciphertext: &[u8],
        passphrase: &[u8],
    ) -> Result<ProtectedData> {
        let key = self.backend.restore(backup, passphrase)?;
        Ok(ProtectedData {
            key,
            ciphertext: ciphertext.to_vec(),
            version: 1,
        })
    }
}

/// TEE-protected data. Serializable for persistence.
/// Cannot be decrypted without the corresponding TEE (or passphrase recovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedData {
    key: WrappedKey,
    ciphertext: Vec<u8>,
    version: u8,
}
