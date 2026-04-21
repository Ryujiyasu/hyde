//! WASM bindings for Hyde.
//!
//! This crate exposes Hyde's protect/unprotect API to JavaScript/TypeScript
//! via wasm-bindgen.
//!
//! # Security model in the browser
//!
//! The `HydeWasm` class wraps a `HydeContext` backed by `SoftwareBackend`. In
//! a browser, the Primary Key lives inside WASM linear memory for the lifetime
//! of the instance. WASM linear memory is readable by the hosting JavaScript
//! (via `WebAssembly.Memory.buffer`), so this does NOT provide
//! non-extractability on its own.
//!
//! For true non-extractability in browsers, the hosting app should:
//! - Use WebCrypto with `extractable: false` for Layer 2 (device-bound key wrap)
//! - Use this crate's PQC primitives (Layer 1) from Rust
//!
//! See the Option Y hybrid pattern: Rust handles PQC, TypeScript handles
//! WebCrypto-based device binding.

use hyde_core::{
    pqc::{
        decapsulation_key_from_bytes, encapsulation_key_from_bytes, pqc_decrypt, pqc_encrypt,
        PqcKeypair,
    },
    HydeContext, ProtectedData,
};
use hyde_software::SoftwareBackend;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// High-level Hyde API for browsers.
///
/// Each instance owns a fresh `SoftwareBackend` and a fresh PQC keypair. Data
/// protected by one instance can only be unprotected by the same instance —
/// there is no cross-session persistence in this minimal build.
#[wasm_bindgen]
pub struct HydeWasm {
    ctx: HydeContext,
}

#[wasm_bindgen]
impl HydeWasm {
    /// Construct a new Hyde instance with a software backend.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<HydeWasm, JsError> {
        let backend = Box::new(SoftwareBackend::new());
        let ctx = HydeContext::with_backend(backend).map_err(to_js_error)?;
        Ok(HydeWasm { ctx })
    }

    /// Protect `data` and return a JSON-serialized `ProtectedData` blob.
    ///
    /// Callers should treat the returned bytes as opaque. The blob includes
    /// both the PQC layer (ML-KEM-768 + AES-GCM) and the software seal layer.
    #[wasm_bindgen]
    pub fn protect(&mut self, data: &[u8]) -> Result<Vec<u8>, JsError> {
        let protected = self.ctx.protect(data).map_err(to_js_error)?;
        serde_json::to_vec(&protected).map_err(to_js_error)
    }

    /// Unprotect a blob produced by `protect`.
    #[wasm_bindgen]
    pub fn unprotect(&mut self, serialized: &[u8]) -> Result<Vec<u8>, JsError> {
        let protected: ProtectedData = serde_json::from_slice(serialized).map_err(to_js_error)?;
        self.ctx.unprotect(&protected).map_err(to_js_error)
    }
}

fn to_js_error<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

// =============================================================================
// Option Y hybrid: low-level PQC primitives
// =============================================================================
//
// These are designed for a pattern where the hosting browser app handles
// Layer 2 (device-bound key wrapping) via WebCrypto with non-extractable
// CryptoKeys, and delegates only Layer 1 (PQC) to this crate.
//
// Typical TypeScript flow:
//   1. const kp = PqcKeypairWasm.generate();
//   2. Store kp.ek_bytes() and kp.dk_bytes() wrapped by a WebCrypto
//      non-extractable AES key (IndexedDB-persisted CryptoKey).
//   3. On protect: ct = pqc_encrypt_bytes(ek_bytes, data); wrap inner key
//      via WebCrypto.
//   4. On unprotect: unwrap key via WebCrypto; pqc_decrypt_bytes(dk_bytes,
//      kem_ct, aes_ct).

/// A serialized ML-KEM-768 keypair. Both keys are opaque byte blobs sized by
/// the spec (ek = 1184 bytes, dk = 2400 bytes for ML-KEM-768).
#[wasm_bindgen]
pub struct PqcKeypairWasm {
    ek: Vec<u8>,
    dk: Vec<u8>,
}

#[wasm_bindgen]
impl PqcKeypairWasm {
    /// Generate a fresh ML-KEM-768 keypair.
    #[wasm_bindgen]
    pub fn generate() -> PqcKeypairWasm {
        let kp = PqcKeypair::generate();
        PqcKeypairWasm {
            ek: kp.ek_bytes(),
            dk: kp.dk_bytes(),
        }
    }

    /// Encapsulation (public) key bytes.
    #[wasm_bindgen(js_name = ekBytes)]
    pub fn ek_bytes(&self) -> Vec<u8> {
        self.ek.clone()
    }

    /// Decapsulation (secret) key bytes. Callers must protect these —
    /// anyone with these bytes can decrypt.
    #[wasm_bindgen(js_name = dkBytes)]
    pub fn dk_bytes(&self) -> Vec<u8> {
        self.dk.clone()
    }
}

#[derive(Serialize)]
struct PqcCiphertext {
    #[serde(rename = "kemCt")]
    kem_ct: Vec<u8>,
    ct: Vec<u8>,
}

/// Encrypt `data` with ML-KEM-768 + AES-256-GCM using the given public key.
///
/// Returns a JSON-serialized `{ kemCt, ct }` blob.
#[wasm_bindgen(js_name = pqcEncrypt)]
pub fn pqc_encrypt_bytes(ek_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>, JsError> {
    let ek = encapsulation_key_from_bytes(ek_bytes).map_err(to_js_error)?;
    let (kem_ct, ct) = pqc_encrypt(&ek, data).map_err(to_js_error)?;
    serde_json::to_vec(&PqcCiphertext { kem_ct, ct }).map_err(to_js_error)
}

/// Decrypt a ciphertext produced by `pqcEncrypt`, using the secret key.
#[wasm_bindgen(js_name = pqcDecrypt)]
pub fn pqc_decrypt_bytes(dk_bytes: &[u8], serialized_ct: &[u8]) -> Result<Vec<u8>, JsError> {
    #[derive(serde::Deserialize)]
    struct Ct {
        #[serde(rename = "kemCt")]
        kem_ct: Vec<u8>,
        ct: Vec<u8>,
    }
    let parsed: Ct = serde_json::from_slice(serialized_ct).map_err(to_js_error)?;
    let dk = decapsulation_key_from_bytes(dk_bytes).map_err(to_js_error)?;
    pqc_decrypt(&dk, &parsed.kem_ct, &parsed.ct).map_err(to_js_error)
}
