use thiserror::Error;

#[derive(Debug, Error)]
pub enum VeilError {
    #[error("Backend error: {0}")]
    Backend(Box<dyn std::error::Error + Send + Sync>),

    #[error("No TEE hardware available")]
    NoHardware,

    #[error("Seal failed: PCR mismatch")]
    SealMismatch,

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("Invalid key material")]
    InvalidKey,

    #[error("Primary key not initialized")]
    PrimaryKeyNotFound,

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, VeilError>;
