use crate::{
    backend::{TeeBackend, WrappedKey},
    cache::SecureCache,
    error::Result,
    recovery::{BackupBundle, RecoveryStrategy},
    security_level::SecurityLevel,
};
use serde::{Deserialize, Serialize};

/// Main entry point for Hyde operations.
pub struct HydeContext {
    backend: Box<dyn TeeBackend>,
    security_level: SecurityLevel,
    cache: Option<SecureCache>,
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

impl HydeContext {
    /// Create a HydeContext with a specific backend.
    /// Defaults to `SecurityLevel::Paranoid` (no caching).
    pub fn with_backend(backend: Box<dyn TeeBackend>) -> Result<Self> {
        Self::with_backend_and_security(backend, SecurityLevel::Paranoid)
    }

    /// Create a HydeContext with a specific backend and security level.
    pub fn with_backend_and_security(
        mut backend: Box<dyn TeeBackend>,
        security_level: SecurityLevel,
    ) -> Result<Self> {
        backend.initialize_primary_key()?;

        let cache = if security_level.caches_data_key() {
            Some(SecureCache::new())
        } else {
            None
        };

        Ok(Self {
            backend,
            security_level,
            cache,
        })
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

    /// Decrypt protected data using the context's configured security level.
    pub fn unprotect(&mut self, protected: &ProtectedData) -> Result<Vec<u8>> {
        self.unprotect_with_level(protected, self.security_level)
    }

    /// Decrypt protected data with a specific security level override.
    ///
    /// Useful for one-off escalation to `Paranoid` on sensitive operations.
    pub fn unprotect_with(
        &mut self,
        protected: &ProtectedData,
        level: SecurityLevel,
    ) -> Result<Vec<u8>> {
        self.unprotect_with_level(protected, level)
    }

    fn unprotect_with_level(
        &mut self,
        protected: &ProtectedData,
        level: SecurityLevel,
    ) -> Result<Vec<u8>> {
        match level {
            SecurityLevel::Paranoid => {
                // Always hit the TEE — no caching
                self.backend.unseal(&protected.key, &protected.ciphertext)
            }
            SecurityLevel::Standard { ttl } => self.unprotect_standard(protected, ttl),
            SecurityLevel::Performance { ttl } => self.unprotect_performance(protected, ttl),
        }
    }

    fn unprotect_standard(
        &mut self,
        protected: &ProtectedData,
        ttl: std::time::Duration,
    ) -> Result<Vec<u8>> {
        let cache = self.cache.get_or_insert_with(SecureCache::new);

        // Check data key cache
        if let Some(data_key) = cache.get_data_key(&protected.key.blob) {
            // Cache hit — decrypt with cached data key (skip TPM unseal)
            let result = crate::passphrase::aes_gcm_decrypt(&data_key, &protected.ciphertext);
            return result;
        }

        // Cache miss — full TEE round-trip
        let plaintext = self.backend.unseal(&protected.key, &protected.ciphertext)?;

        // Extract and cache the data key for future calls.
        // We need to unseal the data key separately to cache it.
        // The backend.unseal() already does unseal+decrypt internally,
        // so we need to get just the data key. We'll re-seal a known value
        // to extract the key... Actually, the simpler approach: we call the
        // backend's internal unseal, which gives us plaintext. We can't
        // extract the data key without changing the TeeBackend trait.
        //
        // For now, cache the plaintext result keyed by (blob + ciphertext).
        // This gives us the same performance benefit for repeated reads.
        cache.insert_plaintext(
            &protected.key.blob,
            &protected.ciphertext,
            plaintext.clone(),
            ttl,
        );

        Ok(plaintext)
    }

    fn unprotect_performance(
        &mut self,
        protected: &ProtectedData,
        ttl: std::time::Duration,
    ) -> Result<Vec<u8>> {
        let cache = self.cache.get_or_insert_with(SecureCache::new);

        // Check plaintext cache first
        if let Some(plaintext) = cache.get_plaintext(&protected.key.blob, &protected.ciphertext) {
            return Ok(plaintext);
        }

        // Cache miss — full TEE round-trip
        let plaintext = self.backend.unseal(&protected.key, &protected.ciphertext)?;

        // Cache the plaintext
        cache.insert_plaintext(
            &protected.key.blob,
            &protected.ciphertext,
            plaintext.clone(),
            ttl,
        );

        Ok(plaintext)
    }

    /// Drop all cached keys and plaintext from memory (triggers zeroize).
    pub fn flush_cache(&mut self) {
        if let Some(cache) = &mut self.cache {
            cache.flush();
        }
    }

    /// Change the security level. Flushes the cache.
    pub fn set_security_level(&mut self, level: SecurityLevel) {
        self.flush_cache();
        self.security_level = level;

        if level.caches_data_key() && self.cache.is_none() {
            self.cache = Some(SecureCache::new());
        } else if !level.caches_data_key() {
            self.cache = None;
        }
    }

    /// Returns the current security level.
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Backup protected data using a chosen recovery strategy.
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
