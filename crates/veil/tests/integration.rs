use veil::{auto_detect, FallbackPolicy};

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

    let secret = b"backup via context API";
    let protected = ctx.protect(secret).unwrap();

    // Backup
    let passphrase = b"context-level-passphrase";
    let backup = ctx.backup(&protected, passphrase).unwrap();

    // Serialize the ciphertext (simulating saving to disk)
    let json = serde_json::to_string(&protected).unwrap();
    let saved: veil::ProtectedData = serde_json::from_str(&json).unwrap();

    // Restore on a "new device" (same TPM in this test)
    let ciphertext_json = serde_json::to_value(&saved).unwrap();
    let ciphertext = ciphertext_json["ciphertext"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect::<Vec<u8>>();

    let restored = ctx.restore(&backup, &ciphertext, passphrase).unwrap();
    let recovered = ctx.unprotect(&restored).unwrap();
    assert_eq!(recovered, secret);
}
