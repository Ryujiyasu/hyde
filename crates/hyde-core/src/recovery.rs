use crate::{backend::WrappedKey, error::Result};
use serde::{Deserialize, Serialize};

/// Identifies the recovery method used for a backup.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RecoveryType {
    /// Passphrase-based recovery (Argon2id + AES-256-GCM).
    Passphrase,
    /// One-time recovery key (random key displayed once).
    RecoveryKey,
}

/// Output of a backup operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupBundle {
    /// Which recovery strategy produced this backup.
    pub recovery_type: RecoveryType,
    /// Encrypted backup data (safe to store on disk / cloud).
    pub data: Vec<u8>,
    /// One-time secret to display to the user (e.g., recovery key).
    /// `None` for passphrase-based recovery (user already knows the secret).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_secret: Option<Vec<u8>>,
}

/// Strategy for backing up and restoring a `WrappedKey`.
///
/// Recovery is independent of the TEE backend — any strategy can be used
/// with any backend (TPM, TDX, SEV, etc.).
pub trait RecoveryStrategy: Send + Sync {
    /// Create an encrypted backup of `key`.
    ///
    /// `secret` is strategy-specific input:
    /// - Passphrase: the user's passphrase
    /// - RecoveryKey: ignored (a random key is generated internally)
    fn backup(&self, key: &WrappedKey, secret: Option<&[u8]>) -> Result<BackupBundle>;

    /// Restore a `WrappedKey` from a backup.
    ///
    /// `secret` is strategy-specific input:
    /// - Passphrase: the user's passphrase
    /// - RecoveryKey: the recovery key that was displayed at backup time
    fn restore(&self, bundle: &BackupBundle, secret: &[u8]) -> Result<WrappedKey>;

    /// Return the recovery type identifier.
    fn recovery_type(&self) -> RecoveryType;
}
