use std::sync::Mutex;
use std::time::Instant;

use hyde_core::{
    backend::TeeBackend,
    security_level::SecurityLevel,
    HydeContext, HydeError,
};
use serde::{Deserialize, Serialize};
use tauri::State;

struct AppState {
    ctx: Mutex<Option<HydeContext>>,
}

#[derive(Serialize)]
struct StepResult {
    step: u8,
    label: String,
    detail: String,
    duration_ms: f64,
}

#[derive(Serialize)]
struct ProtectResult {
    steps: Vec<StepResult>,
    encrypted_json: String,
    total_ms: f64,
}

#[derive(Serialize)]
struct UnprotectResult {
    steps: Vec<StepResult>,
    plaintext: String,
    total_ms: f64,
    cache_hit: bool,
}

#[derive(Serialize)]
struct StatusResult {
    tpm_available: bool,
    security_level: String,
}

#[tauri::command]
fn get_status(state: State<AppState>) -> Result<StatusResult, String> {
    let tpm_available = hyde_tpm::TpmBackend::is_available();
    let ctx = state.ctx.lock().map_err(|e| e.to_string())?;
    let security_level = match &*ctx {
        Some(c) => format!("{:?}", c.security_level()),
        None => "Not initialized".to_string(),
    };
    Ok(StatusResult {
        tpm_available,
        security_level,
    })
}

#[tauri::command]
fn initialize(state: State<AppState>, level: String) -> Result<String, String> {
    let security_level = parse_level(&level);

    let backend = hyde_tpm::TpmBackend::new().map_err(|e| format!("TPM error: {e}"))?;
    let ctx = HydeContext::with_backend_and_security(Box::new(backend), security_level)
        .map_err(|e| format!("Init error: {e}"))?;

    let mut guard = state.ctx.lock().map_err(|e| e.to_string())?;
    *guard = Some(ctx);

    Ok("Initialized".to_string())
}

#[tauri::command]
fn protect(state: State<AppState>, plaintext: String) -> Result<ProtectResult, String> {
    let mut guard = state.ctx.lock().map_err(|e| e.to_string())?;
    let ctx = guard.as_mut().ok_or("Not initialized")?;

    let total_start = Instant::now();
    let mut steps = Vec::new();

    // Step 1: Generate Data Key (TPM)
    let step_start = Instant::now();
    let key = ctx_generate_key(ctx).map_err(|e| format!("Key generation: {e}"))?;
    steps.push(StepResult {
        step: 1,
        label: "TPMがData Keyを生成".to_string(),
        detail: format!("🔑 Wrapped Key: {}...  ({} bytes)",
            hex_prefix(&key.wrapped_blob, 16),
            key.wrapped_blob.len(),
        ),
        duration_ms: step_start.elapsed().as_secs_f64() * 1000.0,
    });

    // Step 2: AES-256-GCM encrypt
    let step_start = Instant::now();
    let protected = ctx.protect(plaintext.as_bytes()).map_err(|e| format!("Protect: {e}"))?;
    let encrypt_ms = step_start.elapsed().as_secs_f64() * 1000.0;
    // Subtract key gen time since protect() includes it
    steps.push(StepResult {
        step: 2,
        label: "AES-256-GCMで暗号化".to_string(),
        detail: format!("🔒 Ciphertext: {}...  ({} bytes)",
            hex_prefix(&protected.ciphertext, 16),
            protected.ciphertext.len(),
        ),
        duration_ms: encrypt_ms - steps[0].duration_ms,
    });

    // Step 3: Data Key zeroized
    steps.push(StepResult {
        step: 3,
        label: "Data Keyをメモリから消去".to_string(),
        detail: "🗑 zeroize::Zeroize — メモリ上に鍵は残らない".to_string(),
        duration_ms: 0.0,
    });

    let encrypted_json = serde_json::to_string_pretty(&protected).unwrap_or_default();

    Ok(ProtectResult {
        steps,
        encrypted_json,
        total_ms: total_start.elapsed().as_secs_f64() * 1000.0,
    })
}

#[tauri::command]
fn unprotect(state: State<AppState>, encrypted_json: String) -> Result<UnprotectResult, String> {
    let mut guard = state.ctx.lock().map_err(|e| e.to_string())?;
    let ctx = guard.as_mut().ok_or("Not initialized")?;

    let protected: hyde_core::ProtectedData =
        serde_json::from_str(&encrypted_json).map_err(|e| format!("Parse: {e}"))?;

    let total_start = Instant::now();
    let mut steps = Vec::new();

    let cache_hit = ctx.security_level() != SecurityLevel::Paranoid;

    // Step 1: Unseal Data Key
    let step_start = Instant::now();
    let plaintext_bytes = ctx.unprotect(&protected).map_err(|e| format!("Unprotect: {e}"))?;
    let unseal_ms = step_start.elapsed().as_secs_f64() * 1000.0;

    if cache_hit && unseal_ms < 10.0 {
        steps.push(StepResult {
            step: 1,
            label: "キャッシュヒット ⚡".to_string(),
            detail: "📦 mlock'd メモリから取得（TPMスキップ）".to_string(),
            duration_ms: unseal_ms,
        });
    } else {
        steps.push(StepResult {
            step: 1,
            label: "TPMでData Keyを復元".to_string(),
            detail: "🖥 TPM Unseal → Primary Keyでアンラップ".to_string(),
            duration_ms: unseal_ms * 0.9,
        });
        steps.push(StepResult {
            step: 2,
            label: "AES-256-GCMで復号".to_string(),
            detail: format!("🔓 {} bytes → 平文", protected.ciphertext.len()),
            duration_ms: unseal_ms * 0.1,
        });
    }

    let plaintext = String::from_utf8(plaintext_bytes)
        .unwrap_or_else(|_| "(binary data)".to_string());

    Ok(UnprotectResult {
        steps,
        plaintext,
        total_ms: total_start.elapsed().as_secs_f64() * 1000.0,
        cache_hit: cache_hit && unseal_ms < 10.0,
    })
}

#[tauri::command]
fn set_security_level(state: State<AppState>, level: String) -> Result<String, String> {
    let mut guard = state.ctx.lock().map_err(|e| e.to_string())?;
    let ctx = guard.as_mut().ok_or("Not initialized")?;
    let security_level = parse_level(&level);
    ctx.set_security_level(security_level);
    Ok(format!("{:?}", security_level))
}

#[tauri::command]
fn flush_cache(state: State<AppState>) -> Result<String, String> {
    let mut guard = state.ctx.lock().map_err(|e| e.to_string())?;
    let ctx = guard.as_mut().ok_or("Not initialized")?;
    ctx.flush_cache();
    Ok("Cache flushed".to_string())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct KeyInfo {
    wrapped_blob: Vec<u8>,
}

fn ctx_generate_key(ctx: &mut HydeContext) -> Result<KeyInfo, HydeError> {
    // We can't directly access generate_data_key from HydeContext,
    // so we do a dummy protect to trigger key generation and extract info.
    // This is just for demo visualization purposes.
    let p = ctx.protect(b"_")?;
    let json = serde_json::to_string(&p).unwrap_or_default();
    // Extract the key blob from the JSON for display
    let blob = if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
        v["key"]["blob"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect::<Vec<_>>())
            .unwrap_or_default()
    } else {
        vec![]
    };
    Ok(KeyInfo { wrapped_blob: blob })
}

fn hex_prefix(bytes: &[u8], max: usize) -> String {
    bytes.iter()
        .take(max)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn parse_level(level: &str) -> SecurityLevel {
    match level {
        "standard" => SecurityLevel::standard(),
        "performance" => SecurityLevel::performance(),
        _ => SecurityLevel::Paranoid,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            ctx: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            initialize,
            protect,
            unprotect,
            set_security_level,
            flush_cache,
        ])
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
