use crate::{
    backend::{TeeBackend, WrappedKey},
    cache::SecureCache,
    error::{HydeError, Result},
    pqc::{self, PqcKeypair},
    recovery::{BackupBundle, RecoveryStrategy},
    security_level::SecurityLevel,
    signing::{self, SigningAlgorithm, WrappedSigningKey},
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

    /// Protect data with TPM + ML-KEM-768 post-quantum encryption.
    ///
    /// The data is first encrypted with ML-KEM (quantum-resistant, chip-independent),
    /// then sealed by the TPM (device-binding). Both layers are always applied.
    pub fn protect(&mut self, data: &[u8]) -> Result<ProtectedData> {
        // Layer 1: PQC encryption (chip-independent, quantum-resistant).
        // The keypair is per-record: its decapsulation key is sealed by the TEE
        // below and travels inside ProtectedData, so the record stays readable
        // after this process exits. (v2 held the keypair in memory only, which
        // made v2 records unreadable by any later context — see
        // `finalize_unprotect`.)
        let keypair = PqcKeypair::generate();
        let (kem_ciphertext, pqc_ciphertext) = pqc::pqc_encrypt(&keypair.ek, data)?;

        // Layer 2: TPM seal (device-binding)
        let key = self.backend.generate_data_key()?;
        let ciphertext = self.backend.seal(&key, &pqc_ciphertext)?;
        // Reusing `key` is safe: seal() draws a fresh nonce on every call.
        let sealed_dk = self.backend.seal(&key, &keypair.dk_bytes())?;

        Ok(ProtectedData {
            key,
            ciphertext,
            kem_ciphertext: Some(kem_ciphertext),
            sealed_dk: Some(sealed_dk),
            version: 3,
            pqc_algorithm: PqcAlgorithm::MlKem768,
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
        let inner = match level {
            SecurityLevel::Paranoid => {
                // Always hit the TEE — no caching
                self.backend.unseal(&protected.key, &protected.ciphertext)?
            }
            SecurityLevel::Standard { ttl } => self.unprotect_cached(protected, ttl)?,
            SecurityLevel::Performance { ttl } => self.unprotect_cached(protected, ttl)?,
        };

        // Apply PQC decryption for v2 data
        self.finalize_unprotect(protected, inner)
    }

    /// Post-process unsealed data: apply PQC decryption for v3, pass through for v1.
    fn finalize_unprotect(&mut self, protected: &ProtectedData, inner: Vec<u8>) -> Result<Vec<u8>> {
        match protected.version {
            3 => {
                let kem_ct = protected
                    .kem_ciphertext
                    .as_ref()
                    .ok_or(HydeError::InvalidKey)?;
                let sealed_dk = protected.sealed_dk.as_ref().ok_or(HydeError::InvalidKey)?;
                let dk_bytes = self.backend.unseal(&protected.key, sealed_dk)?;
                let dk = pqc::decapsulation_key_from_bytes(&dk_bytes)?;
                match protected.pqc_algorithm {
                    PqcAlgorithm::MlKem768 => pqc::pqc_decrypt(&dk, kem_ct, &inner),
                    // Future algorithms would be dispatched here:
                    // PqcAlgorithm::MlKem1024 => pqc_1024::decrypt(...)
                }
            }
            2 => Err(HydeError::Backend(
                "v2 records were encrypted with a keypair that existed only in the \
                 producing HydeContext's memory and was never persisted, so they \
                 cannot be decrypted by any later context. Such data is unrecoverable."
                    .into(),
            )),
            _ => Ok(inner), // v1 legacy: inner is already plaintext
        }
    }

    fn unprotect_cached(
        &mut self,
        protected: &ProtectedData,
        ttl: std::time::Duration,
    ) -> Result<Vec<u8>> {
        let cache = self.cache.get_or_insert_with(SecureCache::new);

        // Check cache (stores TPM-unsealed result, before PQC decryption)
        if let Some(cached) = cache.get_plaintext(&protected.key.blob, &protected.ciphertext) {
            return Ok(cached);
        }

        // Cache miss — full TEE round-trip
        let inner = self.backend.unseal(&protected.key, &protected.ciphertext)?;

        // Cache the TPM-unsealed result
        cache.insert_plaintext(
            &protected.key.blob,
            &protected.ciphertext,
            inner.clone(),
            ttl,
        );

        Ok(inner)
    }

    /// Generate a device-bound ML-DSA signing keypair.
    ///
    /// The signing key's 32-byte master seed is sealed by the active
    /// TEE backend's Primary Key; the verifying key is returned in
    /// the clear and can be published to relying parties. Persist
    /// the whole [`WrappedSigningKey`] and pass it back to
    /// [`HydeContext::sign`] to produce signatures.
    pub fn generate_signing_key(
        &mut self,
        algorithm: SigningAlgorithm,
    ) -> Result<WrappedSigningKey> {
        self.backend.generate_signing_key(algorithm)
    }

    /// Sign `message` under a device-bound signing key.
    ///
    /// Returns [`HydeError::Backend`] if the signing key was wrapped
    /// by a different backend (e.g. sealed on a TPM but presented to
    /// a software context, or vice versa), or if unsealing fails (for
    /// PCR-bound TPM backends, this happens when the boot state has
    /// drifted).
    pub fn sign(&mut self, key: &WrappedSigningKey, message: &[u8]) -> Result<Vec<u8>> {
        self.backend.sign(key, message)
    }

    /// Verify a signature against a published verifying key. Free
    /// function — no TEE needed — exposed as a method for API
    /// symmetry.
    pub fn verify(
        &self,
        key: &WrappedSigningKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        signing::verify(key.algorithm, &key.verifying_key, message, signature)
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
    /// `protected` is the record being recovered: everything except the data
    /// key is carried over from it. Recovering the key alone is not enough —
    /// a v3 record also needs its `kem_ciphertext` and `sealed_dk`, and
    /// synthesising those (as this once did, by hardcoding `version: 1`) makes
    /// `unprotect` skip the PQC layer and hand back ciphertext as if it were
    /// plaintext.
    ///
    /// The recovered key unwraps to the same data key the record was sealed
    /// with, so `sealed_dk` still opens under it.
    pub fn restore(
        &self,
        bundle: &BackupBundle,
        protected: &ProtectedData,
        strategy: &dyn RecoveryStrategy,
        secret: &[u8],
    ) -> Result<ProtectedData> {
        let key = strategy.restore(bundle, secret)?;
        Ok(ProtectedData {
            key,
            ..protected.clone()
        })
    }
}

/// PQC algorithm identifier for forward compatibility.
/// If ML-KEM-768 is ever deprecated, new algorithms can be added here
/// without breaking existing data (old data retains its algorithm tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PqcAlgorithm {
    /// ML-KEM-768 (NIST FIPS 203). Default since v2.
    #[default]
    MlKem768,
    // Future: MlKem1024, ClassicMcEliece, etc.
}

/// TEE-protected data. Serializable for persistence.
/// Cannot be decrypted without the corresponding TEE (or recovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedData {
    key: WrappedKey,
    pub ciphertext: Vec<u8>,
    /// ML-KEM-768 ciphertext for PQC layer (v2+). None for legacy v1 data.
    #[serde(default)]
    kem_ciphertext: Option<Vec<u8>>,
    /// The record's ML-KEM decapsulation key, sealed by the TEE under `key`
    /// (v3+). This is what lets the record outlive the context that made it.
    #[serde(default)]
    sealed_dk: Option<Vec<u8>>,
    version: u8,
    /// PQC algorithm used for this data. Enables future algorithm migration
    /// without breaking existing encrypted data.
    #[serde(default)]
    pqc_algorithm: PqcAlgorithm,
}
