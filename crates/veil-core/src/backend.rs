use crate::error::Result;
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

    /// Backup a WrappedKey with a passphrase (for device recovery).
    fn backup(&mut self, key: &WrappedKey, passphrase: &[u8]) -> Result<Vec<u8>>;

    /// Restore a WrappedKey from a passphrase backup.
    fn restore(&mut self, backup: &[u8], passphrase: &[u8]) -> Result<WrappedKey>;

    /// Return the backend type identifier.
    fn backend_type(&self) -> BackendType;
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
