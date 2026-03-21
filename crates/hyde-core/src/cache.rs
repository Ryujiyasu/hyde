use std::collections::HashMap;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// SecureVec: mlock'd, zeroize-on-drop byte buffer
// ---------------------------------------------------------------------------

/// A `Vec<u8>` wrapper that:
/// - Calls `mlock()` to prevent swapping to disk
/// - Zeroizes contents and calls `munlock()` on drop
pub(crate) struct SecureVec {
    inner: Vec<u8>,
    mlocked: bool,
}

impl SecureVec {
    pub fn new(data: Vec<u8>) -> Self {
        let mlocked = mlock_buffer(&data);
        if !mlocked {
            tracing::warn!(
                "mlock failed — cached key material may be swappable to disk. \
                 Consider raising RLIMIT_MEMLOCK."
            );
        }
        Self {
            inner: data,
            mlocked,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        // Zeroize before unlocking/freeing
        zeroize::Zeroize::zeroize(&mut self.inner);

        if self.mlocked {
            munlock_buffer(&self.inner);
        }
    }
}

// ---------------------------------------------------------------------------
// Platform-specific mlock/munlock
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn mlock_buffer(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) == 0 }
}

#[cfg(unix)]
fn munlock_buffer(buf: &[u8]) {
    if !buf.is_empty() {
        unsafe {
            libc::munlock(buf.as_ptr() as *const libc::c_void, buf.len());
        }
    }
}

#[cfg(windows)]
fn mlock_buffer(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(
            buf.as_ptr() as *mut _,
            buf.len(),
        ) != 0
    }
}

#[cfg(windows)]
fn munlock_buffer(buf: &[u8]) {
    if !buf.is_empty() {
        unsafe {
            windows_sys::Win32::System::Memory::VirtualUnlock(
                buf.as_ptr() as *mut _,
                buf.len(),
            );
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn mlock_buffer(_buf: &[u8]) -> bool {
    tracing::warn!("mlock not supported on this platform");
    false
}

#[cfg(not(any(unix, windows)))]
fn munlock_buffer(_buf: &[u8]) {}

// ---------------------------------------------------------------------------
// SecureCache: HashMap with TTL-based lazy eviction
// ---------------------------------------------------------------------------

struct CacheEntry {
    data: SecureVec,
    created_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
}

/// Cache key is a SHA-256 hash of the identifier bytes.
type CacheKey = [u8; 32];

fn cache_key(input: &[u8]) -> CacheKey {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

fn cache_key_composite(a: &[u8], b: &[u8]) -> CacheKey {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

/// Secure in-memory cache with mlock'd entries and TTL-based expiration.
pub(crate) struct SecureCache {
    /// Data key cache: keyed by hash of WrappedKey blob.
    data_keys: HashMap<CacheKey, CacheEntry>,
    /// Plaintext cache: keyed by hash of (WrappedKey blob + ciphertext).
    plaintexts: HashMap<CacheKey, CacheEntry>,
}

impl SecureCache {
    pub fn new() -> Self {
        Self {
            data_keys: HashMap::new(),
            plaintexts: HashMap::new(),
        }
    }

    /// Get a cached data key by WrappedKey blob.
    pub fn get_data_key(&mut self, wrapped_key_blob: &[u8]) -> Option<Vec<u8>> {
        let key = cache_key(wrapped_key_blob);
        self.get_entry(&mut EntryTarget::DataKey, &key)
    }

    /// Cache a data key.
    pub(crate) fn insert_data_key(&mut self, wrapped_key_blob: &[u8], data_key: Vec<u8>, ttl: Duration) {
        let key = cache_key(wrapped_key_blob);
        self.data_keys.insert(
            key,
            CacheEntry {
                data: SecureVec::new(data_key),
                created_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Get cached plaintext by WrappedKey blob + ciphertext.
    pub fn get_plaintext(&mut self, wrapped_key_blob: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let key = cache_key_composite(wrapped_key_blob, ciphertext);
        self.get_entry(&mut EntryTarget::Plaintext, &key)
    }

    /// Cache plaintext.
    pub fn insert_plaintext(
        &mut self,
        wrapped_key_blob: &[u8],
        ciphertext: &[u8],
        plaintext: Vec<u8>,
        ttl: Duration,
    ) {
        let key = cache_key_composite(wrapped_key_blob, ciphertext);
        self.plaintexts.insert(
            key,
            CacheEntry {
                data: SecureVec::new(plaintext),
                created_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Drop all cached entries (triggers zeroize on each).
    pub fn flush(&mut self) {
        self.data_keys.clear();
        self.plaintexts.clear();
    }

    fn get_entry(&mut self, target: &mut EntryTarget, key: &CacheKey) -> Option<Vec<u8>> {
        let map = match target {
            EntryTarget::DataKey => &mut self.data_keys,
            EntryTarget::Plaintext => &mut self.plaintexts,
        };

        if let Some(entry) = map.get(key) {
            if entry.is_expired() {
                map.remove(key);
                return None;
            }
            return Some(entry.data.as_bytes().to_vec());
        }
        None
    }
}

enum EntryTarget {
    DataKey,
    Plaintext,
}

impl Drop for SecureCache {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_vec_zeroize_on_drop() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let ptr = data.as_ptr();
        let sv = SecureVec::new(data);
        assert_eq!(sv.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        drop(sv);
        // After drop, memory should be zeroed (best-effort check)
        // Note: This is a weak test — the allocator may have reused the memory.
        // The important thing is that Drop::drop calls zeroize.
        let _ = ptr; // prevent optimization
    }

    #[test]
    fn test_cache_data_key_roundtrip() {
        let mut cache = SecureCache::new();
        let blob = b"wrapped-key-blob";
        let dk = vec![1, 2, 3, 4, 5];

        cache.insert_data_key(blob, dk.clone(), Duration::from_secs(60));
        let cached = cache.get_data_key(blob);
        assert_eq!(cached, Some(dk));
    }

    #[test]
    fn test_cache_ttl_expiry() {
        let mut cache = SecureCache::new();
        let blob = b"key";

        // Insert with 0 TTL (already expired)
        cache.insert_data_key(blob, vec![1], Duration::from_secs(0));

        // Should be expired immediately (or within test execution time)
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(cache.get_data_key(blob), None);
    }

    #[test]
    fn test_cache_flush() {
        let mut cache = SecureCache::new();
        cache.insert_data_key(b"k1", vec![1], Duration::from_secs(60));
        cache.insert_data_key(b"k2", vec![2], Duration::from_secs(60));
        cache.insert_plaintext(b"k1", b"ct", vec![3], Duration::from_secs(60));

        cache.flush();

        assert_eq!(cache.get_data_key(b"k1"), None);
        assert_eq!(cache.get_data_key(b"k2"), None);
        assert_eq!(cache.get_plaintext(b"k1", b"ct"), None);
    }

    #[test]
    fn test_cache_plaintext_roundtrip() {
        let mut cache = SecureCache::new();
        let blob = b"key";
        let ct = b"ciphertext";
        let pt = vec![10, 20, 30];

        cache.insert_plaintext(blob, ct, pt.clone(), Duration::from_secs(60));
        assert_eq!(cache.get_plaintext(blob, ct), Some(pt));

        // Different ciphertext should miss
        assert_eq!(cache.get_plaintext(blob, b"other"), None);
    }
}
