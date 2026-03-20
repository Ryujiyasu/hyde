use veil::{auto_detect, FallbackPolicy, PassphraseRecovery, Protected};

/// These tests require swtpm running.
/// Set env: TCTI="swtpm:host=127.0.0.1,port=2323"

#[test]
fn test_auto_detect_with_tpm() {
    let mut ctx = auto_detect(FallbackPolicy::Deny)
        .expect("auto_detect failed — is swtpm running?");

    let secret = b"auto-detect integration test secret";
    let protected = ctx.protect(secret).unwrap();
    let recovered = ctx.unprotect(&protected).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn test_protected_data_serialize_roundtrip() {
    let mut ctx = auto_detect(FallbackPolicy::Deny).unwrap();

    let secret = b"serialize this secret please";
    let protected = ctx.protect(secret).unwrap();

    // Serialize to JSON
    let json = serde_json::to_string(&protected).unwrap();
    assert!(!json.is_empty());

    // Deserialize back
    let deserialized: veil::ProtectedData = serde_json::from_str(&json).unwrap();

    // Decrypt the deserialized data
    let recovered = ctx.unprotect(&deserialized).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn test_protect_unprotect_multiple() {
    let mut ctx = auto_detect(FallbackPolicy::Deny).unwrap();

    // Each protect() generates a new Data Key
    let p1 = ctx.protect(b"secret-1").unwrap();
    let p2 = ctx.protect(b"secret-2").unwrap();
    let p3 = ctx.protect(b"secret-3").unwrap();

    assert_eq!(ctx.unprotect(&p1).unwrap(), b"secret-1");
    assert_eq!(ctx.unprotect(&p2).unwrap(), b"secret-2");
    assert_eq!(ctx.unprotect(&p3).unwrap(), b"secret-3");
}

#[test]
fn test_backup_restore_via_context() {
    let mut ctx = auto_detect(FallbackPolicy::Deny).unwrap();
    let strategy = PassphraseRecovery;

    let secret = b"backup via context API";
    let protected = ctx.protect(secret).unwrap();

    // Backup
    let passphrase = b"context-level-passphrase";
    let bundle = ctx.backup(&protected, &strategy, Some(passphrase)).unwrap();

    // Restore
    let restored = ctx
        .restore(&bundle, &protected.ciphertext, &strategy, passphrase)
        .unwrap();
    let recovered = ctx.unprotect(&restored).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn test_backup_bundle_serialize_roundtrip() {
    let mut ctx = auto_detect(FallbackPolicy::Deny).unwrap();
    let strategy = PassphraseRecovery;

    let protected = ctx.protect(b"serializable backup").unwrap();
    let bundle = ctx.backup(&protected, &strategy, Some(b"pass")).unwrap();

    // BackupBundle should be serializable
    let json = serde_json::to_string(&bundle).unwrap();
    let deserialized: veil::BackupBundle = serde_json::from_str(&json).unwrap();

    let restored = ctx
        .restore(&deserialized, &protected.ciphertext, &strategy, b"pass")
        .unwrap();
    let recovered = ctx.unprotect(&restored).unwrap();
    assert_eq!(recovered, b"serializable backup");
}

// ---------------------------------------------------------------------------
// #[veil::protect] macro + Protected<T>
// ---------------------------------------------------------------------------

#[veil::protect]
struct DocumentKey {
    key_material: Vec<u8>,
    label: String,
}

#[test]
fn test_protect_macro_roundtrip() {
    let mut ctx = auto_detect(FallbackPolicy::Deny).unwrap();

    let protected = DocumentKey::protect(
        &mut ctx,
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        "my-key".to_string(),
    )
    .unwrap();

    let recovered: DocumentKey = protected.unprotect(&mut ctx).unwrap();
    assert_eq!(recovered.key_material, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(recovered.label, "my-key");
}

#[test]
fn test_protect_macro_serialize_roundtrip() {
    let mut ctx = auto_detect(FallbackPolicy::Deny).unwrap();

    let protected = DocumentKey::protect(
        &mut ctx,
        vec![1, 2, 3],
        "serializable".to_string(),
    )
    .unwrap();

    // Protected<T> is serializable
    let json = serde_json::to_string(&protected).unwrap();
    let deserialized: Protected<DocumentKey> = serde_json::from_str(&json).unwrap();

    let recovered: DocumentKey = deserialized.unprotect(&mut ctx).unwrap();
    assert_eq!(recovered.key_material, vec![1, 2, 3]);
    assert_eq!(recovered.label, "serializable");
}

#[veil::protect(zeroize = false)]
struct NonZeroizedData {
    value: String,
}

#[test]
fn test_protect_macro_no_zeroize() {
    let mut ctx = auto_detect(FallbackPolicy::Deny).unwrap();

    let protected = NonZeroizedData::protect(&mut ctx, "hello".to_string()).unwrap();
    let recovered: NonZeroizedData = protected.unprotect(&mut ctx).unwrap();
    assert_eq!(recovered.value, "hello");
}
