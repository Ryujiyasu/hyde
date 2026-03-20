use veil_core::{
    backend::{BackendType, TeeBackend, WrappedKey},
    error::{Result, VeilError},
};

/// Software-only fallback backend (stub in Phase 1).
///
/// WARNING: Unlike hardware TEE backends, key material in memory is
/// readable by the OS and any privileged process.
pub struct SoftwareBackend;

impl SoftwareBackend {
    pub fn new() -> Self {
        tracing::warn!(
            "SoftwareBackend provides no hardware protection. \
             Secrets are NOT protected from privileged access."
        );
        Self
    }
}

impl TeeBackend for SoftwareBackend {
    fn is_available() -> bool {
        true
    }

    fn initialize_primary_key(&mut self) -> Result<()> {
        Err(VeilError::NoHardware)
    }

    fn generate_data_key(&mut self) -> Result<WrappedKey> {
        Err(VeilError::NoHardware)
    }

    fn seal(&mut self, _key: &WrappedKey, _data: &[u8]) -> Result<Vec<u8>> {
        Err(VeilError::NoHardware)
    }

    fn unseal(&mut self, _key: &WrappedKey, _sealed: &[u8]) -> Result<Vec<u8>> {
        Err(VeilError::NoHardware)
    }

    fn backup(&mut self, _key: &WrappedKey, _passphrase: &[u8]) -> Result<Vec<u8>> {
        Err(VeilError::NoHardware)
    }

    fn restore(&mut self, _backup: &[u8], _passphrase: &[u8]) -> Result<WrappedKey> {
        Err(VeilError::NoHardware)
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Software
    }
}
