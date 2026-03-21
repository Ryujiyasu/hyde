//! hyde — Unified abstraction layer for hardware-based TEE in Rust.
//!
//! This facade crate handles backend auto-detection and re-exports
//! everything from `hyde-core`.

pub use hyde_core::*;
pub use hyde_macros::protect;

use hyde_core::backend::TeeBackend;

/// Auto-detect the best available TEE backend and create a `HydeContext`.
///
/// Defaults to `SecurityLevel::Paranoid` (no caching).
/// Uses no PCR binding by default. For PCR-bound contexts, use [`auto_detect_with_pcr`].
pub fn auto_detect(fallback: FallbackPolicy) -> hyde_core::Result<HydeContext> {
    auto_detect_with_security(fallback, SecurityLevel::Paranoid)
}

/// Auto-detect the best available TEE backend with a specified security level.
///
/// The security level controls caching behavior:
/// - `Paranoid` — no caching, every call hits the TEE
/// - `Standard { ttl }` — cache data keys in mlock'd memory
/// - `Performance { ttl }` — cache plaintext in mlock'd memory
pub fn auto_detect_with_security(
    fallback: FallbackPolicy,
    security_level: SecurityLevel,
) -> hyde_core::Result<HydeContext> {
    #[cfg(feature = "tpm")]
    {
        use hyde_tpm::TpmBackend;
        if <TpmBackend as TeeBackend>::is_available() {
            let backend = TpmBackend::new()?;
            return HydeContext::with_backend_and_security(Box::new(backend), security_level);
        }
    }

    fallback_or_deny(fallback, security_level)
}

/// Auto-detect the best available TEE backend with PCR policy binding.
///
/// Sealed objects will be bound to the current values of PCR 0 (firmware)
/// and PCR 7 (Secure Boot). Unsealing will fail if these values change.
#[cfg(feature = "tpm")]
pub fn auto_detect_with_pcr(fallback: FallbackPolicy) -> hyde_core::Result<HydeContext> {
    auto_detect_with_pcr_and_security(fallback, SecurityLevel::Paranoid)
}

/// Auto-detect with PCR binding and a specified security level.
#[cfg(feature = "tpm")]
pub fn auto_detect_with_pcr_and_security(
    fallback: FallbackPolicy,
    security_level: SecurityLevel,
) -> hyde_core::Result<HydeContext> {
    use hyde_tpm::{PcrPolicy, TpmBackend};
    if <TpmBackend as TeeBackend>::is_available() {
        let backend = TpmBackend::with_pcr_policy(PcrPolicy::default_production())?;
        return HydeContext::with_backend_and_security(Box::new(backend), security_level);
    }

    fallback_or_deny(fallback, security_level)
}

fn fallback_or_deny(
    fallback: FallbackPolicy,
    #[allow(unused_variables)] security_level: SecurityLevel,
) -> hyde_core::Result<HydeContext> {
    match fallback {
        FallbackPolicy::Deny => Err(HydeError::NoHardware),
        FallbackPolicy::Warn | FallbackPolicy::Software => {
            if matches!(fallback, FallbackPolicy::Warn) {
                tracing::warn!("No TEE hardware available, falling back to software");
            }
            #[cfg(feature = "software")]
            {
                use hyde_software::SoftwareBackend;
                return HydeContext::with_backend_and_security(
                    Box::new(SoftwareBackend::new()),
                    security_level,
                );
            }
            #[cfg(not(feature = "software"))]
            Err(HydeError::NoHardware)
        }
    }
}
