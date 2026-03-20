use veil_core::backend::TeeBackend;
use veil_tpm::TpmBackend;

/// These tests require swtpm running on TCP port 2321:
///   swtpm socket --tpmstate dir=/tmp/swtpm \
///     --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --tpm2 --daemon
///
/// Set env: TPM2TOOLS_TCTI=swtpm  (or TCTI=swtpm)

fn create_backend() -> TpmBackend {
    TpmBackend::new().expect("Failed to create TpmBackend — is swtpm running?")
}

#[test]
fn test_is_available() {
    // swtpm on TCP 2321 should make this return true
    assert!(TpmBackend::is_available());
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
    let sealed = backend
        .seal(&wrapped, plaintext)
        .expect("Failed to seal");

    // Sealed data should be different from plaintext
    assert_ne!(sealed, plaintext);
    // Should contain nonce (12) + ciphertext + tag (16)
    assert!(sealed.len() > 12 + 16);

    let recovered = backend
        .unseal(&wrapped, &sealed)
        .expect("Failed to unseal");

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
// Backup / Restore
// ---------------------------------------------------------------------------

#[test]
fn test_backup_restore_roundtrip() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();

    let wrapped = backend.generate_data_key().unwrap();
    let passphrase = b"my-recovery-passphrase-2024";

    // Backup the wrapped key
    let backup = backend.backup(&wrapped, passphrase).unwrap();
    assert!(!backup.is_empty());
    // Should be: 16 salt + 12 nonce + blob + 16 tag
    assert!(backup.len() > 16 + 12 + 16);

    // Restore from backup
    let restored = backend.restore(&backup, passphrase).unwrap();

    // The restored key should decrypt data sealed with the original key
    let sealed = backend.seal(&wrapped, b"hello from backup").unwrap();
    let recovered = backend.unseal(&restored, &sealed).unwrap();
    assert_eq!(recovered, b"hello from backup");
}

#[test]
fn test_backup_wrong_passphrase_fails() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();

    let wrapped = backend.generate_data_key().unwrap();
    let backup = backend.backup(&wrapped, b"correct-password").unwrap();

    let result = backend.restore(&backup, b"wrong-password");
    assert!(result.is_err());
}

#[test]
fn test_backup_tampered_fails() {
    let mut backend = create_backend();
    backend.initialize_primary_key().unwrap();

    let wrapped = backend.generate_data_key().unwrap();
    let mut backup = backend.backup(&wrapped, b"password").unwrap();

    // Tamper with the encrypted blob (after the salt)
    if backup.len() > 20 {
        backup[20] ^= 0xFF;
    }

    let result = backend.restore(&backup, b"password");
    assert!(result.is_err());
}
