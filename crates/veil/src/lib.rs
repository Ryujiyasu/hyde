//! veil — Unified abstraction layer for hardware-based TEE in Rust.
//!
//! This facade crate handles backend auto-detection and re-exports
//! everything from `veil-core`.

pub use veil_core::*;

use veil_core::backend::TeeBackend;

/// Auto-detect the best available TEE backend and create a `VeilContext`.
pub fn auto_detect(fallback: FallbackPolicy) -> veil_core::Result<VeilContext> {
    #[cfg(feature = "tpm")]
    {
        use veil_tpm::TpmBackend;
        if <TpmBackend as TeeBackend>::is_available() {
            let backend = TpmBackend::new()?;
            return VeilContext::with_backend(Box::new(backend));
        }
    }

    match fallback {
        FallbackPolicy::Deny => Err(VeilError::NoHardware),
        FallbackPolicy::Warn | FallbackPolicy::Software => {
            if matches!(fallback, FallbackPolicy::Warn) {
                tracing::warn!("No TEE hardware available, falling back to software");
            }
            #[cfg(feature = "software")]
            {
                use veil_software::SoftwareBackend;
                return VeilContext::with_backend(Box::new(SoftwareBackend::new()));
            }
            #[cfg(not(feature = "software"))]
            Err(VeilError::NoHardware)
        }
    }
}
