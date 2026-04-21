use aes_gcm::{
    aead::{Aead, KeyInit},
    AeadCore, Aes256Gcm, Key, Nonce,
};
use hyde_core::{
    backend::{BackendType, TeeBackend, WrappedKey},
    error::{HydeError, Result},
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Software-only fallback backend.
///
/// Primary Key is generated on `initialize_primary_key` and held in memory for
/// the lifetime of this backend instance. Data Keys are AES-256-GCM wrapped by
/// the Primary Key.
///
/// WARNING: Unlike hardware TEE backends, key material in memory is readable
/// by the OS and any privileged process. There is no device binding.
pub struct SoftwareBackend {
    primary_key: Option<Zeroizing<[u8; KEY_LEN]>>,
}

impl Default for SoftwareBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftwareBackend {
    pub fn new() -> Self {
        tracing::warn!(
            "SoftwareBackend provides no hardware protection. \
             Secrets are NOT protected from privileged access."
        );
        Self { primary_key: None }
    }

    fn primary_cipher(&self) -> Result<Aes256Gcm> {
        let pk = self
            .primary_key
            .as_ref()
            .ok_or(HydeError::PrimaryKeyNotFound)?;
        Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(pk.as_slice())))
    }

    fn unwrap_data_key(&self, key: &WrappedKey) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        if key.backend != BackendType::Software {
            return Err(HydeError::Backend("wrong backend for wrapped key".into()));
        }
        if key.blob.len() < NONCE_LEN {
            return Err(HydeError::InvalidKey);
        }

        let cipher = self.primary_cipher()?;
        let (nonce, wrapped) = key.blob.split_at(NONCE_LEN);
        let dk_bytes = cipher
            .decrypt(Nonce::from_slice(nonce), wrapped)
            .map_err(|_| HydeError::Backend("data key unwrap failed".into()))?;

        if dk_bytes.len() != KEY_LEN {
            return Err(HydeError::InvalidKey);
        }
        let mut dk = Zeroizing::new([0u8; KEY_LEN]);
        dk.copy_from_slice(&dk_bytes);
        Ok(dk)
    }
}

impl TeeBackend for SoftwareBackend {
    fn is_available() -> bool {
        true
    }

    fn initialize_primary_key(&mut self) -> Result<()> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(key.as_mut_slice());
        self.primary_key = Some(key);
        Ok(())
    }

    fn generate_data_key(&mut self) -> Result<WrappedKey> {
        let mut dk = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(dk.as_mut_slice());

        let cipher = self.primary_cipher()?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let wrapped = cipher
            .encrypt(&nonce, dk.as_slice())
            .map_err(|_| HydeError::Backend("data key wrap failed".into()))?;

        let mut blob = Vec::with_capacity(NONCE_LEN + wrapped.len());
        blob.extend_from_slice(nonce.as_slice());
        blob.extend_from_slice(&wrapped);

        Ok(WrappedKey {
            blob,
            backend: BackendType::Software,
        })
    }

    fn seal(&mut self, key: &WrappedKey, data: &[u8]) -> Result<Vec<u8>> {
        let dk = self.unwrap_data_key(key)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dk.as_slice()));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, data)
            .map_err(|_| HydeError::Backend("seal failed".into()))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unseal(&mut self, key: &WrappedKey, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN {
            return Err(HydeError::InvalidKey);
        }
        let dk = self.unwrap_data_key(key)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dk.as_slice()));
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| HydeError::Backend("unseal failed".into()))
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Software
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seal_unseal() {
        let mut backend = SoftwareBackend::new();
        backend.initialize_primary_key().unwrap();
        let key = backend.generate_data_key().unwrap();

        let plaintext = b"hello vohu";
        let sealed = backend.seal(&key, plaintext).unwrap();
        let unsealed = backend.unseal(&key, &sealed).unwrap();
        assert_eq!(unsealed, plaintext);
    }

    #[test]
    fn distinct_keys_produce_distinct_ciphertexts() {
        let mut backend = SoftwareBackend::new();
        backend.initialize_primary_key().unwrap();
        let k1 = backend.generate_data_key().unwrap();
        let k2 = backend.generate_data_key().unwrap();
        assert_ne!(k1.blob, k2.blob);
    }

    #[test]
    fn unseal_without_initialized_primary_key_fails() {
        let backend = SoftwareBackend::new();
        let fake_key = WrappedKey {
            blob: vec![0u8; NONCE_LEN + 48],
            backend: BackendType::Software,
        };
        assert!(matches!(
            backend.unwrap_data_key(&fake_key),
            Err(HydeError::PrimaryKeyNotFound)
        ));
    }

    #[test]
    fn wrong_backend_type_rejected() {
        let mut backend = SoftwareBackend::new();
        backend.initialize_primary_key().unwrap();
        let tpm_shaped_key = WrappedKey {
            blob: vec![0u8; NONCE_LEN + 48],
            backend: BackendType::Tpm,
        };
        assert!(backend.unwrap_data_key(&tpm_shaped_key).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let mut backend = SoftwareBackend::new();
        backend.initialize_primary_key().unwrap();
        let key = backend.generate_data_key().unwrap();
        let mut sealed = backend.seal(&key, b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(backend.unseal(&key, &sealed).is_err());
    }

    #[test]
    fn hyde_context_protect_unprotect_roundtrip() {
        use hyde_core::HydeContext;

        let backend = Box::new(SoftwareBackend::new());
        let mut ctx = HydeContext::with_backend(backend).unwrap();

        let plaintext = b"Layer 1 PQC + Layer 2 software seal";
        let protected = ctx.protect(plaintext).unwrap();
        let unprotected = ctx.unprotect(&protected).unwrap();
        assert_eq!(unprotected, plaintext);
    }
}
