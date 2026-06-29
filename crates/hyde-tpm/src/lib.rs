//! # hyde-tpm — TPM 2.0 backend for Hyde
//!
//! Two independent, feature-gated paths:
//!
//! - **`tss`** (default): classic TPM 2.0 via `tss-esapi` (sealing, device key
//!   wrap, AES-256-GCM). Backward-compatible with 0.1.x.
//! - **`pqc`**: pure-Rust **TCG TPM 2.0 v1.85 post-quantum** (ML-KEM / ML-DSA).
//!   `tss-esapi` has no v1.85 PQC support, so this path marshals the v1.85 PQC
//!   commands directly. See [`pqc`].
//!
//! The `pqc` path builds with no C/`libtss2` dependency:
//! `cargo build -p hyde-tpm --no-default-features --features pqc`.

#[cfg(feature = "tss")]
mod tss;
#[cfg(feature = "tss")]
pub use tss::*;

#[cfg(feature = "pqc")]
pub mod pqc;
