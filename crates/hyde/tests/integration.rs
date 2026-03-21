use hyde::{auto_detect, auto_detect_with_security, FallbackPolicy, PassphraseRecovery, Protected, SecurityLevel};

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
    let deserialized: hyde::ProtectedData = serde_json::from_str(&json).unwrap();

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
    let deserialized: hyde::BackupBundle = serde_json::from_str(&json).unwrap();

    let restored = ctx
        .restore(&deserialized, &protected.ciphertext, &strategy, b"pass")
        .unwrap();
    let recovered = ctx.unprotect(&restored).unwrap();
    assert_eq!(recovered, b"serializable backup");
}

// ---------------------------------------------------------------------------
// #[hyde::protect] macro + Protected<T>
// ---------------------------------------------------------------------------

#[hyde::protect]
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

#[hyde::protect(zeroize = false)]
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

// ---------------------------------------------------------------------------
// SecurityLevel tests
// ---------------------------------------------------------------------------

#[test]
fn test_security_level_paranoid_default() {
    let ctx = auto_detect(FallbackPolicy::Deny).unwrap();
    assert_eq!(ctx.security_level(), SecurityLevel::Paranoid);
}

#[test]
fn test_security_level_standard_cached_unprotect() {
    let mut ctx = auto_detect_with_security(
        FallbackPolicy::Deny,
        SecurityLevel::standard(),
    )
    .unwrap();

    let secret = b"cached-standard-secret";
    let protected = ctx.protect(secret).unwrap();

    // First call: cache miss, hits TPM
    let r1 = ctx.unprotect(&protected).unwrap();
    assert_eq!(r1, secret);

    // Second call: cache hit, no TPM round-trip
    let r2 = ctx.unprotect(&protected).unwrap();
    assert_eq!(r2, secret);
}

#[test]
fn test_security_level_performance_cached_unprotect() {
    let mut ctx = auto_detect_with_security(
        FallbackPolicy::Deny,
        SecurityLevel::performance(),
    )
    .unwrap();

    let secret = b"cached-performance-secret";
    let protected = ctx.protect(secret).unwrap();

    let r1 = ctx.unprotect(&protected).unwrap();
    assert_eq!(r1, secret);

    // Second call: plaintext cache hit
    let r2 = ctx.unprotect(&protected).unwrap();
    assert_eq!(r2, secret);
}

#[test]
fn test_security_level_flush_cache() {
    let mut ctx = auto_detect_with_security(
        FallbackPolicy::Deny,
        SecurityLevel::performance(),
    )
    .unwrap();

    let secret = b"flush-me";
    let protected = ctx.protect(secret).unwrap();

    // Populate cache
    let _ = ctx.unprotect(&protected).unwrap();

    // Flush and verify still works (re-fetches from TPM)
    ctx.flush_cache();
    let recovered = ctx.unprotect(&protected).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn test_security_level_override_with_paranoid() {
    let mut ctx = auto_detect_with_security(
        FallbackPolicy::Deny,
        SecurityLevel::performance(),
    )
    .unwrap();

    let secret = b"override-test";
    let protected = ctx.protect(secret).unwrap();

    // Use paranoid override — skips cache entirely
    let recovered = ctx.unprotect_with(&protected, SecurityLevel::Paranoid).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn test_security_level_change_flushes_cache() {
    let mut ctx = auto_detect_with_security(
        FallbackPolicy::Deny,
        SecurityLevel::performance(),
    )
    .unwrap();

    let secret = b"level-change";
    let protected = ctx.protect(secret).unwrap();
    let _ = ctx.unprotect(&protected).unwrap();

    // Change level — should flush cache
    ctx.set_security_level(SecurityLevel::Paranoid);
    assert_eq!(ctx.security_level(), SecurityLevel::Paranoid);

    // Still works (hits TPM directly)
    let recovered = ctx.unprotect(&protected).unwrap();
    assert_eq!(recovered, secret);
}
