use crate::{
    backend::{BackendType, WrappedKey},
    error::{HydeError, Result},
    recovery::{BackupBundle, RecoveryStrategy, RecoveryType},
};

/// Passphrase-based recovery using Argon2id key derivation + AES-256-GCM.
///
/// # Example
/// ```ignore
/// use hyde::recovery::PassphraseRecovery;
///
/// let strategy = PassphraseRecovery;
/// let backup = ctx.backup(&protected, &strategy, Some(b"my-passphrase"))?;
/// let restored = ctx.restore(&backup, &protected.ciphertext, &strategy, b"my-passphrase")?;
/// ```
pub struct PassphraseRecovery;

impl RecoveryStrategy for PassphraseRecovery {
    fn backup(&self, key: &WrappedKey, secret: Option<&[u8]>) -> Result<BackupBundle> {
        let passphrase = secret.ok_or_else(|| {
            HydeError::RecoveryFailed("passphrase is required for PassphraseRecovery".into())
        })?;

        let mut derived = derive_key_from_passphrase(passphrase)?;
        let encrypted = aes_gcm_encrypt(&derived.key, &key.blob);
        zeroize::Zeroize::zeroize(&mut derived.key);

        let encrypted = encrypted?;

        // Format: [16 bytes salt] [encrypted blob (nonce + ciphertext + tag)]
        let mut data = Vec::with_capacity(16 + encrypted.len());
        data.extend_from_slice(&derived.salt);
        data.extend_from_slice(&encrypted);

        Ok(BackupBundle {
            recovery_type: RecoveryType::Passphrase,
            data,
            user_secret: None,
        })
    }

    fn restore(&self, bundle: &BackupBundle, secret: &[u8]) -> Result<WrappedKey> {
        if bundle.data.len() < 16 + 12 + 16 {
            return Err(HydeError::RecoveryFailed("backup too short".into()));
        }

        let salt = &bundle.data[..16];
        let encrypted = &bundle.data[16..];

        let mut derived = derive_key_with_salt(secret, salt)?;
        let blob = aes_gcm_decrypt(&derived.key, encrypted)
            .map_err(|_| HydeError::RecoveryFailed("wrong passphrase or corrupted backup".into()));
        zeroize::Zeroize::zeroize(&mut derived.key);

        Ok(WrappedKey {
            blob: blob?,
            backend: BackendType::Tpm,
        })
    }

    fn recovery_type(&self) -> RecoveryType {
        RecoveryType::Passphrase
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM helpers
// ---------------------------------------------------------------------------

pub(crate) fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, aead::OsRng, Aes256Gcm, AeadCore, KeyInit};

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| HydeError::Serialization(e.to_string()))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| HydeError::SealMismatch)?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub(crate) fn aes_gcm_decrypt(key: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    if sealed.len() < 12 {
        return Err(HydeError::InvalidKey);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| HydeError::Serialization(e.to_string()))?;

    let nonce = Nonce::from_slice(&sealed[..12]);
    let ciphertext = &sealed[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| HydeError::SealMismatch)
}

// ---------------------------------------------------------------------------
// Argon2id key derivation helpers
// ---------------------------------------------------------------------------

struct DerivedKey {
    key: Vec<u8>,
    salt: [u8; 16],
}

fn derive_key_from_passphrase(passphrase: &[u8]) -> Result<DerivedKey> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)
        .map_err(|e| HydeError::RecoveryFailed(format!("random salt generation failed: {e}")))?;
    derive_key_with_salt(passphrase, &salt)
}

fn derive_key_with_salt(passphrase: &[u8], salt: &[u8]) -> Result<DerivedKey> {
    use argon2::Argon2;

    let mut key = vec![0u8; 32];
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| HydeError::RecoveryFailed(format!("key derivation failed: {e}")))?;

    let mut salt_arr = [0u8; 16];
    salt_arr.copy_from_slice(&salt[..16]);

    Ok(DerivedKey {
        key,
        salt: salt_arr,
    })
}
