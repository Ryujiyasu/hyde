use crate::{
    backend::{TeeBackend, WrappedKey},
    error::Result,
    recovery::{BackupBundle, RecoveryStrategy},
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

    /// Backup protected data using a chosen recovery strategy.
    ///
    /// `secret` is strategy-specific (e.g., passphrase bytes for `PassphraseRecovery`).
    pub fn backup(
        &self,
        protected: &ProtectedData,
        strategy: &dyn RecoveryStrategy,
        secret: Option<&[u8]>,
    ) -> Result<BackupBundle> {
        strategy.backup(&protected.key, secret)
    }

    /// Restore protected data from a backup using the matching recovery strategy.
    pub fn restore(
        &self,
        bundle: &BackupBundle,
        ciphertext: &[u8],
        strategy: &dyn RecoveryStrategy,
        secret: &[u8],
    ) -> Result<ProtectedData> {
        let key = strategy.restore(bundle, secret)?;
        Ok(ProtectedData {
            key,
            ciphertext: ciphertext.to_vec(),
            version: 1,
        })
    }
}

/// TEE-protected data. Serializable for persistence.
/// Cannot be decrypted without the corresponding TEE (or recovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedData {
    key: WrappedKey,
    pub ciphertext: Vec<u8>,
    version: u8,
}
