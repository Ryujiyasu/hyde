<div align="center">

<img src="docs/hyde-logo-square.png" alt="hyde logo" width="200">

# hyde

Unified abstraction layer for hardware-based Trusted Execution Environments (TEE) in Rust.

ハードウェアTEEの統一抽象化レイヤー（Rust）

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange.svg)](https://www.rust-lang.org)

</div>

---

## Why hyde? / なぜhydeが必要か

Data has three states. Two are solved. One is not.

データには3つの状態がある。2つは解決済み。1つは未解決。

| State / 状態 | Threat / 脅威 | Existing Solution / 既存の解決策 |
|------|------|-------------|
| At rest / 保存時 | Disk theft / ディスク盗難 | BitLocker / FileVault |
| In transit / 通信時 | Interception / 通信傍受 | HTTPS / TLS |
| **In use / 実行時** | **Memory access, cloud admin** | **Unsolved ← hyde** |

hyde binds secrets to **a specific device + a specific person** using TPM (Trusted Platform Module). Even if stored in the cloud, data cannot be decrypted without that person and that device.

hydeはTPMを使い、秘密情報を「特定のデバイス＋特定の人物」に紐付けて保護する。クラウドに保存されても、その人物・そのデバイスなしには復号できない。

---

## Post-Quantum Cryptography (PQC) / ポスト量子暗号

hyde v0.2+ protects all data with **ML-KEM-768** (NIST FIPS 203) post-quantum encryption, always-on by default.

hyde v0.2+は、全データを **ML-KEM-768**（NIST FIPS 203）ポスト量子暗号で保護する。常時有効、デフォルトで最強。

### Why PQC matters / なぜPQCが必要か

**HNDL (Harvest Now, Decrypt Later)** — adversaries capture encrypted data today, decrypt it with quantum computers in the future. For long-lived secrets (medical records, classified documents), this is a real threat.

**HNDL（今収穫、後で復号）** — 暗号化データを今収集し、将来量子コンピュータで解読する攻撃。医療記録や機密文書など長期保存データには現実的な脅威。

### Two-layer architecture / 二層アーキテクチャ

```
┌─────────────────────────────────────────────────┐
│  Layer 2: TPM Seal (device-binding)             │
│  AES-256-GCM with TPM-wrapped Data Key          │
│                                                 │
│  ┌─────────────────────────────────────────────┐│
│  │  Layer 1: PQC Encryption (chip-independent) ││
│  │  ML-KEM-768 + AES-256-GCM                   ││
│  │  Quantum-resistant, portable                 ││
│  └─────────────────────────────────────────────┘│
└─────────────────────────────────────────────────┘
```

- **Layer 1 (PQC)**: Quantum-resistant encryption. Chip-independent — survives hardware migration.
- **Layer 2 (TPM)**: Device-binding. Only this TPM can unseal.
- **Migration**: Only the PQC key needs to be migrated. No re-encryption of data.

開発者はセキュリティレベルを選ぶ必要なし。`ctx.protect()` で常に最強の暗号化が適用される。

---

## The Hyde Ecosystem / Hydeエコシステム

hyde is the foundation of a three-module cryptographic ecosystem:

hydeは3モジュールの暗号エコシステムの基盤：

<div align="center">

| Module | Technology | Purpose / 用途 |
|--------|-----------|----------------|
| **[hyde](https://gitlab.com/Ryujiyasu/hyde)** | TPM + PQC (ML-KEM) | **Protect** data — encrypt, device-bind, quantum-resistant / データを守る |
| **[argo](https://gitlab.com/Ryujiyasu/argo)** | ZKP (Zero-Knowledge Proofs) | **Prove** statements without revealing data / データを見せずに証明する |
| **[plat](https://gitlab.com/Ryujiyasu/plat)** | FHE (Fully Homomorphic Encryption) | **Compute** on encrypted data / 暗号化したまま計算する |

</div>

```
 Protect          Prove           Compute
┌─────────┐    ┌─────────┐    ┌─────────┐
│  hyde    │───▶│  argo   │───▶│  plat   │
│ TPM+PQC │    │  ZKP    │    │  FHE    │
└─────────┘    └─────────┘    └─────────┘
  守る            証明する        計算する
```

All modules share hyde's TPM trust chain as the key management foundation.

全モジュールがhydeのTPM信頼チェーンを鍵管理の基盤として共有。

---

## Quick Start / クイックスタート

```rust
use hyde::{self, FallbackPolicy, PassphraseRecovery};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = hyde::auto_detect(FallbackPolicy::Deny)?;

    // Protect data (ML-KEM-768 PQC + TPM AES-256-GCM — always both layers)
    let secret = b"my document encryption key";
    let protected = ctx.protect(secret)?;

    // Serialize and save anywhere (disk, S3, cloud — HNDL-resistant)
    let json = serde_json::to_string(&protected)?;

    // Decrypt (requires the same TPM + PQC key)
    let deserialized: hyde::ProtectedData = serde_json::from_str(&json)?;
    let recovered = ctx.unprotect(&deserialized)?;
    assert_eq!(recovered, secret);

    // Passphrase backup (for device migration / TPM failure)
    let strategy = PassphraseRecovery;
    let bundle = ctx.backup(&protected, &strategy, Some(b"my-recovery-passphrase"))?;
    let restored = ctx.restore(&bundle, &protected.ciphertext, &strategy, b"my-recovery-passphrase")?;

    Ok(())
}
```

## Architecture / アーキテクチャ

```
┌─────────────────────────────────┐
│       Application               │
│  hyde::auto_detect()            │
│  ctx.protect() / unprotect()    │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│  hyde (facade crate)            │
│  Auto-detects best backend      │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│  hyde-core                      │
│  TeeBackend trait               │
│  PQC layer (ML-KEM-768)         │
│  HydeContext, ProtectedData     │
└────────────┬────────────────────┘
             │
┌────────────▼──────────────────────────┐
│  Backend crates                       │
│  ┌──────────┐  ┌──────────────────┐   │
│  │ hyde-tpm │  │ hyde-software    │   │
│  │ (TPM 2.0)│  │ (fallback stub)  │   │
│  └──────────┘  └──────────────────┘   │
│  ┌────────────────────────────────┐   │
│  │ Phase 2+: hyde-tdx, hyde-sev  │   │
│  └────────────────────────────────┘   │
└───────────────────────────────────────┘
```

## Key Design: Primary Key + Data Key / 鍵管理の設計

hyde uses the **BitLocker pattern** to avoid TPM NV memory exhaustion:

hydeはBitLockerパターンを採用し、TPMのNVメモリ枯渇を防ぐ：

1. **Primary Key** (1 per device) — persisted in TPM NV memory (1 slot)
2. **Data Key** (1 per protect call) — generated by TPM RNG, sealed under Primary Key, stored as blob on disk
3. **PQC Layer** — ML-KEM-768 encapsulation per protect call, quantum-resistant AES-256-GCM encryption
4. **Encryption** — Data is double-encrypted: PQC (inner, chip-independent) + TPM (outer, device-bound)

## Recovery / 回復

Passphrase-based backup uses **Argon2id** key derivation + AES-256-GCM:

パスフレーズベースのバックアップは Argon2id 鍵導出 + AES-256-GCM：

```rust
use hyde::PassphraseRecovery;

let strategy = PassphraseRecovery;

// Backup (before disaster)
let bundle = ctx.backup(&protected, &strategy, Some(b"strong-passphrase"))?;
// → save `bundle` (serializable) somewhere safe

// Restore (on new device)
let restored = ctx.restore(&bundle, &protected.ciphertext, &strategy, b"strong-passphrase")?;
let data = ctx.unprotect(&restored)?;
```

Recovery strategies are pluggable via the `RecoveryStrategy` trait:

回復方式は `RecoveryStrategy` トレイトにより差し替え可能：

| Strategy | Description |
|----------|-------------|
| `PassphraseRecovery` | Argon2id + AES-256-GCM (default) |
| `RecoveryKey` (planned) | One-time random key displayed once |
| `ShamirRecovery` (planned) | N-of-M secret sharing |

## Workspace Structure / ワークスペース構成

```
hyde/
├── Cargo.toml              # Workspace root
├── crates/
│   ├── hyde/               # Facade: auto_detect() + re-exports
│   ├── hyde-core/          # TeeBackend trait, PQC (ML-KEM-768), HydeContext
│   ├── hyde-tpm/           # TPM 2.0 backend (tss-esapi)
│   ├── hyde-software/      # Software fallback (stub)
│   └── hyde-macros/        # #[hyde::protect] proc macro
├── docs/
│   ├── hyde-implementation-guide.md
│   └── hyde-roadmap.md
└── examples/
```

## Prerequisites / 前提条件

```bash
# Linux
sudo apt install libtss2-dev swtpm swtpm-tools

# Start software TPM for development
mkdir /tmp/swtpm && swtpm socket \
  --tpmstate dir=/tmp/swtpm \
  --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 \
  --tpm2 --daemon
swtpm_ioctl --tcp 127.0.0.1:2322 -i

# Windows 11: TPM 2.0 is built-in, no additional install needed
```

## Build & Test / ビルド・テスト

```bash
cargo build --workspace
cargo check --workspace

# Run tests (requires swtpm running)
export TCTI="swtpm:host=127.0.0.1,port=2321"
cargo test --workspace -- --test-threads=1
```

## Roadmap / ロードマップ

| Phase | Target / 対象 | Status / 状態 |
|-------|------|--------|
| **1** | TPM 2.0 (Windows 11 / Linux) | **Complete / 完了** |
| **1.5** | PQC (ML-KEM-768 post-quantum encryption) | **Complete / 完了** |
| 2 | Intel TDX, AMD SEV-SNP (Cloud TEE) | Planned / 計画中 |
| 3 | Apple Secure Enclave, ARM TrustZone (Mobile) | Planned / 計画中 |
| 4 | NVIDIA H100 Confidential Computing (GPU TEE) | Planned / 計画中 |
| 5 | IoT Secure Elements (ATECC608, SE050, TrustZone-M) | Planned / 計画中 |
| 6 | oxi integration, Enterprise SaaS | Planned / 計画中 |

See [docs/hyde-roadmap.md](docs/hyde-roadmap.md) for details.

## Phase 1 Status / Phase 1 進捗

- [x] TPM connection + session
- [x] Primary Key generation + persistence
- [x] Data Key generation + wrapping
- [x] Seal / Unseal (AES-256-GCM)
- [x] ProtectedData serialization (serde)
- [x] Pluggable RecoveryStrategy trait + PassphraseRecovery (Argon2id)
- [x] HydeContext public API
- [x] auto_detect() facade
- [x] SoftwareBackend stub
- [x] 15 integration tests passing (swtpm)
- [x] PCR policy binding (PCR 0 + 7)
- [x] `#[hyde::protect]` macro + `Protected<T>` wrapper
- [x] CI/CD (GitLab CI + swtpm)
- [x] crates.io publish (hyde v0.1.0)
- [x] **ML-KEM-768 PQC encryption (always-on, HNDL-resistant)**
- [x] **Two-layer encryption: PQC (inner) + TPM (outer)**
- [x] **Backward-compatible ProtectedData v2 format**

## Migration from veil-tee / veil-teeからの移行

This project was previously published as `veil-tee-*` on crates.io. The `veil-tee-*` crates are now deprecated. To migrate:

このプロジェクトは以前 `veil-tee-*` としてcrates.ioに公開されていました。`veil-tee-*` は非推奨です。移行方法：

```toml
# Before / 移行前
[dependencies]
veil-tee = "0.1"

# After / 移行後
[dependencies]
hyde = "0.1"
```

```rust
// Before / 移行前
use veil_tee::{auto_detect, VeilContext, VeilError};

// After / 移行後
use hyde::{auto_detect, HydeContext, HydeError};
```

## Contributing / コントリビューション

Contributions welcome! / コントリビューション歓迎！

```bash
git clone https://gitlab.com/Ryujiyasu/hyde.git
cd hyde
cargo build --workspace
cargo test --workspace -- --test-threads=1
```

## License / ライセンス

MIT License

## Author / 著者

Ryuji Yasukochi ([@Ryujiyasu](https://gitlab.com/Ryujiyasu))
