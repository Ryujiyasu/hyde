//! veil — Unified abstraction layer for hardware-based TEE in Rust.
//!
//! This facade crate handles backend auto-detection and re-exports
//! everything from `veil-core`.

pub use veil_core::*;
pub use veil_macros::protect;

use veil_core::backend::TeeBackend;

/// Auto-detect the best available TEE backend and create a `VeilContext`.
///
/// Uses no PCR binding by default. For PCR-bound contexts, use [`auto_detect_with_pcr`].
pub fn auto_detect(fallback: FallbackPolicy) -> veil_core::Result<VeilContext> {
    #[cfg(feature = "tpm")]
    {
        use veil_tpm::TpmBackend;
        if <TpmBackend as TeeBackend>::is_available() {
            let backend = TpmBackend::new()?;
            return VeilContext::with_backend(Box::new(backend));
        }
    }

    fallback_or_deny(fallback)
}

/// Auto-detect the best available TEE backend with PCR policy binding.
///
/// Sealed objects will be bound to the current values of PCR 0 (firmware)
/// and PCR 7 (Secure Boot). Unsealing will fail if these values change.
#[cfg(feature = "tpm")]
pub fn auto_detect_with_pcr(fallback: FallbackPolicy) -> veil_core::Result<VeilContext> {
    use veil_tpm::{PcrPolicy, TpmBackend};
    if <TpmBackend as TeeBackend>::is_available() {
        let backend = TpmBackend::with_pcr_policy(PcrPolicy::default_production())?;
        return VeilContext::with_backend(Box::new(backend));
    }

    fallback_or_deny(fallback)
}

fn fallback_or_deny(fallback: FallbackPolicy) -> veil_core::Result<VeilContext> {
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
