use std::marker::PhantomData;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    context::{ProtectedData, VeilContext},
    error::{Result, VeilError},
};

/// A type-safe wrapper around TEE-protected data.
///
/// `Protected<T>` ensures the inner value `T` cannot be accessed without
/// going through the TEE. The encrypted data is serializable for persistence.
///
/// Created by `Protected::new()` or by the `#[veil::protect]` macro.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Protected<T> {
    data: ProtectedData,
    #[serde(skip)]
    _phantom: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> Protected<T> {
    /// Protect a value by serializing it and encrypting with the TEE.
    pub fn new(ctx: &mut VeilContext, value: &T) -> Result<Self> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| VeilError::Serialization(e.to_string()))?;
        let data = ctx.protect(&bytes)?;
        Ok(Self {
            data,
            _phantom: PhantomData,
        })
    }

    /// Decrypt and deserialize the protected value. Requires the same TEE.
    pub fn unprotect(&self, ctx: &mut VeilContext) -> Result<T> {
        let bytes = ctx.unprotect(&self.data)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| VeilError::Serialization(e.to_string()))
    }

    /// Access the underlying `ProtectedData` for backup/restore operations.
    pub fn protected_data(&self) -> &ProtectedData {
        &self.data
    }

    /// Construct from raw `ProtectedData` (e.g., after restore).
    pub fn from_protected_data(data: ProtectedData) -> Self {
        Self {
            data,
            _phantom: PhantomData,
        }
    }
}
