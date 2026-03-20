use tss_esapi::{Context, TctiNameConf};
use veil_core::{
    backend::{BackendType, TeeBackend, WrappedKey},
    error::{Result, VeilError},
};

pub struct TpmBackend {
    context: Context,
    primary_handle: Option<tss_esapi::handles::KeyHandle>,
}

impl TpmBackend {
    pub fn new() -> Result<Self> {
        let tcti = TctiNameConf::from_environment_variable()
            .unwrap_or(TctiNameConf::Device(Default::default()));

        let context =
            Context::new(tcti).map_err(|e| VeilError::Backend(Box::new(e)))?;

        Ok(Self {
            context,
            primary_handle: None,
        })
    }
}

impl TeeBackend for TpmBackend {
    fn is_available() -> bool {
        #[cfg(target_os = "linux")]
        {
            std::path::Path::new("/dev/tpm0").exists()
                || std::path::Path::new("/dev/tpmrm0").exists()
        }
        #[cfg(target_os = "windows")]
        {
            // TODO: Windows TBS API check
            true
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            false
        }
    }

    fn initialize_primary_key(&mut self) -> Result<()> {
        // 1. Try to load from persistent handle (e.g. 0x81000001)
        // 2. If not found, create Primary Key and persist to NV
        todo!("TPM primary key initialization")
    }

    fn generate_data_key(&mut self) -> Result<WrappedKey> {
        // 1. Generate AES-256 key inside TPM (transient)
        // 2. Wrap with Primary Key → blob
        // 3. Discard transient handle (no NV consumption)
        todo!("TPM data key generation")
    }

    fn seal(&mut self, _key: &WrappedKey, _data: &[u8]) -> Result<Vec<u8>> {
        // 1. Unwrap Key Blob with Primary Key → Data Key
        // 2. Seal with PCR 0,7 policy
        // 3. Encrypt data with Data Key
        // 4. Zeroize Data Key
        todo!("TPM sealing")
    }

    fn unseal(&mut self, _key: &WrappedKey, _sealed: &[u8]) -> Result<Vec<u8>> {
        // 1. Verify PCR values
        // 2. Unwrap Key Blob → Data Key
        // 3. Decrypt data
        // 4. Zeroize Data Key
        todo!("TPM unsealing")
    }

    fn backup(&mut self, _key: &WrappedKey, _passphrase: &[u8]) -> Result<Vec<u8>> {
        todo!("Key backup")
    }

    fn restore(&mut self, _backup: &[u8], _passphrase: &[u8]) -> Result<WrappedKey> {
        todo!("Key recovery")
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Tpm
    }
}
