//! Classic (tss-esapi) backend integration tests — gated to the `tss` feature.
#![cfg(feature = "tss")]

use hyde_core::backend::TeeBackend;
use hyde_core::recovery::RecoveryStrategy;
use hyde_core::PassphraseRecovery;
use hyde_tpm::{PcrPolicy, TpmBackend};

/// These tests require swtpm running on TCP port 2321:
///   swtpm socket --tpmstate dir=/tmp/swtpm \
///     --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --tpm2 --daemon
///
/// Set env: TPM2TOOLS_TCTI=swtpm  (or TCTI=swtpm)

fn create_backend() -> TpmBackend {
    TpmBackend::new().expect("Failed to create TpmBackend — is swtpm running?")
}

fn create_backend_with_pcr() -> TpmBackend {
    TpmBackend::with_pcr_policy(PcrPolicy::default_production())
        .expect("Failed to create TpmBackend with PCR policy")
}

#[test]
fn test_is_available() {
    // swtpm on TCP 2321 should make this return true
    assert!(TpmBackend::is_available());
}

/// A record must stay readable after the context that wrote it is gone.
///
/// v2 kept the ML-KEM keypair in HydeContext's memory and never persisted it, so
/// every record one context wrote was undecryptable by the next — and quietly,
/// because ML-KEM's implicit rejection turns a wrong decapsulation key into a
/// wrong shared secret instead of an error, surfacing only as a downstream
/// AES-GCM `SealMismatch` that reads like a TPM fault. No test ever protected in
/// one context and unprotected in another, so nothing caught it. This is that
/// test: it needs a durable backend, because a software one loses its own key on
/// drop and would fail before the PQC layer is ever reached.
#[test]
fn protected_data_outlives_the_context_that_wrote_it() {
    use hyde_core::{HydeContext, SecurityLevel};

    let secret = b"a record must outlive its context";

    let mut writer =
        HydeContext::with_backend_and_security(Box::new(create_backend()), SecurityLevel::Paranoid)
            .unwrap();
    let protected = writer.protect(secret).unwrap();
    drop(writer);

    let mut reader =
        HydeContext::with_backend_and_security(Box::new(create_backend()), SecurityLevel::Paranoid)
            .unwrap();
    assert_eq!(reader.unprotect(&protected).unwrap(), secret);
}

#[test]
fn test_initialize_primary_key() {
    let mut backend = create_backend();
    backend
        .initialize_primary_key()
        .expect("Failed to initialize primary key");
}

#[test]
fn test_initialize_primary_key_idempotent() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();
    // Second call should load existing key, not fail
    drop(backend);
    let mut backend2 = create_backend();
    backend2
        .initialize_primary_key()
        .expect("Second init should load existing key");
}

#[test]
fn test_generate_data_key() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();
    let wrapped = backend
        .generate_data_key()
        .expect("Failed to generate data key");
    assert!(!wrapped.blob.is_empty());
}

#[test]
fn test_seal_unseal_roundtrip() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();

    let wrapped = backend.generate_data_key().unwrap();

    let plaintext = b"this is my secret document key!!";
    let sealed = backend.seal(&wrapped, plaintext).expect("Failed to seal");

    // Sealed data should be different from plaintext
    assert_ne!(sealed, plaintext);
    // Should contain nonce (12) + ciphertext + tag (16)
    assert!(sealed.len() > 12 + 16);

    let recovered = backend.unseal(&wrapped, &sealed).expect("Failed to unseal");

    assert_eq!(recovered, plaintext);
}

#[test]
fn test_seal_unseal_large_data() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();

    let wrapped = backend.generate_data_key().unwrap();

    let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let sealed = backend.seal(&wrapped, &plaintext).unwrap();
    let recovered = backend.unseal(&wrapped, &sealed).unwrap();

    assert_eq!(recovered, plaintext);
}

#[test]
fn test_different_keys_cannot_decrypt() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();

    let key1 = backend.generate_data_key().unwrap();
    let key2 = backend.generate_data_key().unwrap();

    let sealed = backend.seal(&key1, b"secret").unwrap();

    // Trying to unseal with a different key should fail
    let result = backend.unseal(&key2, &sealed);
    assert!(result.is_err());
}

#[test]
fn test_tampered_ciphertext_fails() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();

    let wrapped = backend.generate_data_key().unwrap();
    let mut sealed = backend.seal(&wrapped, b"secret").unwrap();

    // Tamper with the ciphertext
    if let Some(byte) = sealed.last_mut() {
        *byte ^= 0xFF;
    }

    let result = backend.unseal(&wrapped, &sealed);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Backup / Restore (via RecoveryStrategy)
// ---------------------------------------------------------------------------

#[test]
fn test_passphrase_backup_restore_roundtrip() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();

    let wrapped = backend.generate_data_key().unwrap();
    let strategy = PassphraseRecovery;
    let passphrase = b"my-recovery-passphrase-2024";

    // Backup the wrapped key
    let bundle = strategy.backup(&wrapped, Some(passphrase)).unwrap();
    assert!(!bundle.data.is_empty());
    assert!(bundle.user_secret.is_none());
    // Should be: 16 salt + 12 nonce + blob + 16 tag
    assert!(bundle.data.len() > 16 + 12 + 16);

    // Restore from backup
    let restored = strategy.restore(&bundle, passphrase).unwrap();

    // The restored key should decrypt data sealed with the original key
    let sealed = backend.seal(&wrapped, b"hello from backup").unwrap();
    let recovered = backend.unseal(&restored, &sealed).unwrap();
    assert_eq!(recovered, b"hello from backup");
}

#[test]
fn test_passphrase_wrong_passphrase_fails() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();

    let wrapped = backend.generate_data_key().unwrap();
    let strategy = PassphraseRecovery;

    let bundle = strategy
        .backup(&wrapped, Some(b"correct-password"))
        .unwrap();

    let result = strategy.restore(&bundle, b"wrong-password");
    assert!(result.is_err());
}

#[test]
fn test_passphrase_tampered_fails() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();

    let wrapped = backend.generate_data_key().unwrap();
    let strategy = PassphraseRecovery;

    let mut bundle = strategy.backup(&wrapped, Some(b"password")).unwrap();

    // Tamper with the encrypted blob (after the salt)
    if bundle.data.len() > 20 {
        bundle.data[20] ^= 0xFF;
    }

    let result = strategy.restore(&bundle, b"password");
    assert!(result.is_err());
}

#[test]
fn test_passphrase_no_secret_fails() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();

    let wrapped = backend.generate_data_key().unwrap();
    let strategy = PassphraseRecovery;

    // Passing None should fail for PassphraseRecovery
    let result = strategy.backup(&wrapped, None);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// PCR Policy Binding
// ---------------------------------------------------------------------------

#[test]
fn test_pcr_seal_unseal_roundtrip() {
    // In swtpm, PCR 0 and 7 are all zeros — but the policy still binds to those values.
    let mut backend = create_backend_with_pcr();
    backend.initialize_primary_key().unwrap();

    let wrapped = backend.generate_data_key().unwrap();

    let plaintext = b"PCR-bound secret data";
    let sealed = backend.seal(&wrapped, plaintext).unwrap();
    let recovered = backend.unseal(&wrapped, &sealed).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn test_pcr_generate_multiple_keys() {
    let mut backend = create_backend_with_pcr();
    backend.initialize_primary_key().unwrap();

    let k1 = backend.generate_data_key().unwrap();
    let k2 = backend.generate_data_key().unwrap();

    let s1 = backend.seal(&k1, b"data-1").unwrap();
    let s2 = backend.seal(&k2, b"data-2").unwrap();

    assert_eq!(backend.unseal(&k1, &s1).unwrap(), b"data-1");
    assert_eq!(backend.unseal(&k2, &s2).unwrap(), b"data-2");
}

#[test]
fn test_pcr_cross_policy_incompatible() {
    // Key created without PCR policy cannot be unsealed by a PCR-policy backend
    // (and vice versa), because the authPolicy digest differs.
    let mut backend_no_pcr = create_backend();
    backend_no_pcr.initialize_primary_key().unwrap();
    let key_no_pcr = backend_no_pcr.generate_data_key().unwrap();
    let _sealed = backend_no_pcr.seal(&key_no_pcr, b"no-pcr-data").unwrap();

    let mut backend_pcr = create_backend_with_pcr();
    backend_pcr.initialize_primary_key().unwrap();

    // Trying to unseal a non-PCR key with a PCR-policy backend should fail
    // because the PCR backend uses a policy session, but the object has user_with_auth.
    // Actually this may succeed since user_with_auth objects accept any session.
    // The real incompatibility is the other way: PCR-bound key without policy session fails.
    let key_pcr = backend_pcr.generate_data_key().unwrap();
    let sealed_pcr = backend_pcr.seal(&key_pcr, b"pcr-data").unwrap();

    // PCR-bound key with no-PCR backend should fail (needs policy session but uses HMAC)
    let result = backend_no_pcr.unseal(&key_pcr, &sealed_pcr);
    assert!(
        result.is_err(),
        "PCR-bound key should not unseal without policy session"
    );
}
