use hyde_core::{
    backend::{BackendType, TeeBackend, WrappedKey},
    error::{HydeError, Result},
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
        Err(HydeError::NoHardware)
    }

    fn generate_data_key(&mut self) -> Result<WrappedKey> {
        Err(HydeError::NoHardware)
    }

    fn seal(&mut self, _key: &WrappedKey, _data: &[u8]) -> Result<Vec<u8>> {
        Err(HydeError::NoHardware)
    }

    fn unseal(&mut self, _key: &WrappedKey, _sealed: &[u8]) -> Result<Vec<u8>> {
        Err(HydeError::NoHardware)
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Software
    }
}
