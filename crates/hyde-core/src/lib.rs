pub mod backend;
pub(crate) mod cache;
pub mod context;
pub mod error;
pub mod passphrase;
pub mod pqc;
pub mod protected;
pub mod recovery;
pub mod security_level;
pub mod signing;

pub use context::{FallbackPolicy, HydeContext, PqcAlgorithm, ProtectedData};
pub use error::{HydeError, Result};
pub use passphrase::PassphraseRecovery;
pub use protected::Protected;
pub use recovery::{BackupBundle, RecoveryStrategy, RecoveryType};
pub use security_level::SecurityLevel;
pub use signing::{SigningAlgorithm, WrappedSigningKey, verify as verify_signature};
