pub mod backend;
pub mod context;
pub mod error;
pub mod passphrase;
pub mod protected;
pub mod recovery;

pub use context::{FallbackPolicy, ProtectedData, VeilContext};
pub use error::{Result, VeilError};
pub use passphrase::PassphraseRecovery;
pub use protected::Protected;
pub use recovery::{BackupBundle, RecoveryStrategy, RecoveryType};
