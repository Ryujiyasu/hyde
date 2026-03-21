use std::time::Duration;

/// Controls the trade-off between security and performance when accessing TEE-protected data.
///
/// | Level | Cached | Attack surface | Speed |
/// |-------|--------|---------------|-------|
/// | `Paranoid` | Nothing | Minimal | Slow (TPM every call) |
/// | `Standard` | Data Key only | 32-byte key in memory | Fast (AES-GCM only) |
/// | `Performance` | Data Key + plaintext | Full plaintext in memory | Fastest |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Every `unprotect()` call hits the TEE (TPM unseal + AES decrypt).
    /// No plaintext or data key is ever cached in memory.
    /// Slowest, but smallest attack surface.
    Paranoid,

    /// The unwrapped data key is cached in mlock'd, zeroize-on-drop memory
    /// for a configurable TTL. The plaintext itself is never cached.
    /// Each `unprotect()` still performs AES-GCM decryption, but avoids
    /// the expensive TPM unseal round-trip for repeated accesses.
    Standard {
        /// How long to keep the unwrapped data key in memory.
        ttl: Duration,
    },

    /// Both the unwrapped data key AND the decrypted plaintext are cached
    /// in mlock'd, zeroize-on-drop memory for the TTL period.
    /// Fastest for repeated reads of the same data, but the plaintext
    /// lives in process memory until the TTL expires or the cache is flushed.
    Performance {
        /// How long to keep cached data in memory.
        ttl: Duration,
    },
}

impl SecurityLevel {
    /// Standard level with a default TTL of 30 seconds.
    pub fn standard() -> Self {
        SecurityLevel::Standard {
            ttl: Duration::from_secs(30),
        }
    }

    /// Performance level with a default TTL of 10 seconds.
    pub fn performance() -> Self {
        SecurityLevel::Performance {
            ttl: Duration::from_secs(10),
        }
    }

    /// Returns the TTL if caching is enabled, or `None` for Paranoid.
    pub fn ttl(&self) -> Option<Duration> {
        match self {
            SecurityLevel::Paranoid => None,
            SecurityLevel::Standard { ttl } | SecurityLevel::Performance { ttl } => Some(*ttl),
        }
    }

    /// Returns true if plaintext caching is enabled (Performance level).
    pub fn caches_plaintext(&self) -> bool {
        matches!(self, SecurityLevel::Performance { .. })
    }

    /// Returns true if data key caching is enabled (Standard or Performance).
    pub fn caches_data_key(&self) -> bool {
        !matches!(self, SecurityLevel::Paranoid)
    }
}

impl Default for SecurityLevel {
    /// Defaults to `Paranoid` for maximum security and backward compatibility.
    fn default() -> Self {
        SecurityLevel::Paranoid
    }
}
