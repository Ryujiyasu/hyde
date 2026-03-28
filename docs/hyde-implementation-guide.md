# veil

> Unified abstraction layer for hardware-based Trusted Execution Environments (TEE) in Rust.

**Phase 1: TPM 2.0 support (Windows 11 / Linux)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)

---

## なぜveilが必要か

データには3つの状態がある：

| 状態 | 脅威 | 既存の解決策 |
|------|------|-------------|
| 保存時（at rest） | ディスク盗難 | BitLocker / FileVault ✅ |
| 通信時（in transit） | 通信傍受 | HTTPS / TLS ✅ |
| **実行時（in use）** | **メモリアクセス・クラウド管理者** | **未解決 ← veil** |

veilはTPM（Trusted Platform Module）を使い、秘密情報を「特定のデバイス＋特定の人物」に紐付けて保護する。
クラウドに保存されても、その人物・そのデバイスなしには復号できない。

---

## Phase 1 スコープ

```
対応ハードウェア：TPM 2.0（Windows 11標準搭載・Linux対応）
対応OS：Windows 11, Linux（Ubuntu 22.04+）
非対応（Phase 2以降）：Intel TDX, AMD SEV, Apple Secure Enclave, ARM TrustZone
```

### Phase 1で実装するもの

- [ ] TPM 2.0への接続・セッション確立
- [ ] Primary Key の生成・永続化（デバイスに1つ）
- [ ] Data Key の生成・Key Blobラップ（データごと）
- [ ] 鍵のシーリング（PCR値に紐付けて封印）
- [ ] 鍵のアンシーリング（PCR値が一致する場合のみ復号）
- [ ] データの暗号化・復号（TPM鍵を使用）
- [ ] `ProtectedData` のシリアライズ・永続化
- [ ] 回復メカニズム（パスフレーズベース）
- [ ] `SoftwareBackend` スタブ（Phase 2で本実装）
- [ ] `#[veil::protect]` アトリビュートマクロの基本実装
- [ ] crates.io への公開

---

## 鍵管理の設計

### 問題：TPMハンドルの永続化

TPMのハンドルには2種類ある：

| 種類 | 保存場所 | ライフサイクル | 制約 |
|------|----------|--------------|------|
| Transient Handle | TPMのRAM | プロセス終了・TPMリセットで消滅 | なし |
| Persistent Handle | TPMのNVメモリ | 再起動後も存在 | 多くのTPMで7スロット程度 |

毎回 `generate_key()` でPersistent Handleを作るとNVメモリが枯渇する。

### 解決：BitLockerパターン（Primary Key + Data Key）

```
┌─────────────────────────────────────────────────┐
│ 初回セットアップ（1回だけ）                         │
│                                                 │
│  TPM NVメモリ                                    │
│  ┌─────────────────────┐                        │
│  │ Primary Key (RSA)    │ ← persistent handle   │
│  │ デバイスに1つだけ      │    NVスロットを1つ使用  │
│  └─────────────────────┘                        │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│ データ保護時（何度でも）                            │
│                                                 │
│  1. Data Key（AES-256）をメモリ上で生成            │
│  2. Data KeyでユーザーデータをAES-GCM暗号化         │
│  3. Primary KeyでData Keyをラップ → Key Blob      │
│  4. Key Blob + Ciphertext をディスクに保存          │
│     （TPMなしでは復号不可）                         │
│  5. メモリ上のData Keyをzeroize                    │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│ データ復号時                                      │
│                                                 │
│  1. ディスクからKey Blob + Ciphertextを読み込み     │
│  2. Key BlobをTPMに渡す                           │
│  3. Primary Keyでアンラップ → Data Keyが復元       │
│  4. Data KeyでCiphertextを復号                    │
│  5. メモリ上のData Keyをzeroize                    │
└─────────────────────────────────────────────────┘
```

この設計により：
- TPMのNVメモリは1スロットのみ使用（Primary Key用）
- データ数に制限なし（Key Blobはディスクに保存）
- プロセス再起動後もPrimary Keyは存続
- `ProtectedData` をシリアライズしてどこにでも保存可能

---

## アーキテクチャ

```
┌─────────────────────────────────┐
│         アプリケーション           │
│  #[veil::protect]               │
│  struct DocumentKey { ... }     │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│     veil（facade crate）        │
│  pub use veil_core::*           │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│     veil-core                   │
│  VeilContext                    │
│  protect() / unprotect()        │
│  backup() / restore()           │
│  TeeBackend trait               │
└────────────┬────────────────────┘
             │
┌────────────▼──────────────────────────────┐
│  バックエンドクレート（feature-gated）        │
│  ┌──────────┐  ┌──────────┐  ┌─────────┐  │
│  │veil-tpm  │  │veil-     │  │(Phase2+)│  │
│  │(Phase 1) │  │software  │  │veil-tdx │  │
│  │          │  │(stub)    │  │veil-sev │  │
│  └──────────┘  └──────────┘  └─────────┘  │
└────────────┬──────────────────────────────┘
             │
┌────────────▼────────────────────┐
│         tss-esapi               │
│  (TPM 2.0 Rust bindings)       │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│         TPM 2.0 ハードウェア      │
└─────────────────────────────────┘
```

---

## ディレクトリ構成（マルチクレートワークスペース）

oxiと同じパターン（`crates/` 配下にドメインごとのクレート）を採用。
Phase 2で `veil-tdx/`, `veil-sev/` を追加する際にコア部分に触らずに済む。

```
veil/
├── Cargo.toml                    # ワークスペースルート
├── README.md
├── docs/
│   ├── veil-implementation-guide.md
│   └── veil-roadmap.md
├── crates/
│   ├── veil/                     # facade crate（pub use + feature gates）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs            # pub use veil_core::*, re-exports
│   ├── veil-core/                # コアロジック
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            # 公開API
│   │       ├── context.rs        # VeilContext（メインエントリポイント）
│   │       ├── backend.rs        # TeeBackend trait, WrappedKey, BackendType
│   │       ├── error.rs          # VeilError型
│   │       ├── protected.rs      # ProtectedData（Serialize/Deserialize）
│   │       └── recovery.rs       # Recovery trait, パスフレーズ回復
│   ├── veil-tpm/                 # TPMバックエンド（Phase 1）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            # TpmBackend実装
│   │       ├── session.rs        # TPMセッション管理
│   │       ├── key.rs            # Primary Key管理・Data Keyラップ
│   │       └── seal.rs           # シーリング・アンシーリング
│   ├── veil-software/            # SoftwareBackend（スタブ）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs            # SoftwareBackend実装
│   └── veil-macros/              # proc macroクレート
│       ├── Cargo.toml
│       └── src/
│           └── lib.rs            # #[veil::protect] マクロ
├── examples/
│   ├── basic_seal.rs             # 基本的なシーリング例
│   ├── document_key.rs           # ドキュメント鍵保護の例
│   └── recovery.rs               # 回復フローの例
└── tests/
    ├── integration/
    │   └── tpm_basic.rs          # TPM統合テスト
    └── mock/
        └── software_tpm.rs       # ソフトウェアTPMを使ったテスト
```

---

## 実装手順

### Step 0: 環境セットアップ

```bash
# Rust（1.70以上）
rustup update stable

# Linux: tss2-esysライブラリのインストール
sudo apt install libtss2-dev

# Windows: TPM 2.0はWindows 11で標準搭載
# 追加インストール不要

# ソフトウェアTPM（開発・テスト用）
# Linux
sudo apt install swtpm swtpm-tools

# ソフトウェアTPMの起動
mkdir /tmp/swtpm && swtpm socket \
  --tpmstate dir=/tmp/swtpm \
  --ctrl type=unixio,path=/tmp/swtpm/ctrl \
  --server type=unixio,path=/tmp/swtpm/tpm \
  --tpm2 --daemon
```

### Step 1: ワークスペースCargo.tomlのセットアップ

```toml
# veil/Cargo.toml（ワークスペースルート）
[workspace]
resolver = "2"
members = [
    "crates/veil",
    "crates/veil-core",
    "crates/veil-tpm",
    "crates/veil-software",
    "crates/veil-macros",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/YOUR_USERNAME/veil"

[workspace.dependencies]
veil-core = { path = "crates/veil-core" }
veil-tpm = { path = "crates/veil-tpm" }
veil-software = { path = "crates/veil-software" }
veil-macros = { path = "crates/veil-macros" }
tss-esapi = "7"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
zeroize = { version = "1", features = ["derive"] }
thiserror = "1"
tracing = "0.1"
```

```toml
# crates/veil/Cargo.toml（facade crate）
[package]
name = "veil"
description = "Unified abstraction layer for hardware-based TEE in Rust"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
veil-core.workspace = true
veil-macros.workspace = true

[dependencies.veil-tpm]
workspace = true
optional = true

[dependencies.veil-software]
workspace = true
optional = true

[features]
default = ["tpm"]
tpm = ["dep:veil-tpm"]
software = ["dep:veil-software"]
```

```toml
# crates/veil-core/Cargo.toml
[package]
name = "veil-core"
description = "Core traits and types for veil TEE abstraction"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
zeroize.workspace = true
thiserror.workspace = true
tracing.workspace = true
```

```toml
# crates/veil-tpm/Cargo.toml
[package]
name = "veil-tpm"
description = "TPM 2.0 backend for veil"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
veil-core.workspace = true
tss-esapi.workspace = true
zeroize.workspace = true
tracing.workspace = true

[dev-dependencies]
tss-esapi = { workspace = true, features = ["integration-tests"] }
```

### Step 2: エラー型の定義（crates/veil-core/src/error.rs）

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VeilError {
    #[error("Backend error: {0}")]
    Backend(Box<dyn std::error::Error + Send + Sync>),

    #[error("No TEE hardware available")]
    NoHardware,

    #[error("Seal failed: PCR mismatch")]
    SealMismatch,

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("Invalid key material")]
    InvalidKey,

    #[error("Primary key not initialized")]
    PrimaryKeyNotFound,

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, VeilError>;
```

> **注意**: `VeilError::Backend` は `Box<dyn Error>` を使い、`veil-core` が
> `tss-esapi` に直接依存しないようにしている。TPM固有のエラーは `veil-tpm` 内で
> `VeilError::Backend` に変換する。

### Step 3: バックエンドtrait定義（crates/veil-core/src/backend.rs）

```rust
use crate::error::Result;
use serde::{Serialize, Deserialize};

/// TEEバックエンドの統一インターフェース
/// Phase 2以降でTDX/SEV/Secure Enclaveも同じtraitを実装する
pub trait TeeBackend: Send + Sync {
    /// バックエンドが利用可能かチェック
    fn is_available() -> bool where Self: Sized;

    /// Primary Keyを初期化（既に存在すればロード、なければ生成・永続化）
    /// デバイスごとに1回だけ呼ばれる
    fn initialize_primary_key(&mut self) -> Result<()>;

    /// Data Keyを生成し、Primary Keyでラップして返す
    /// 返値のKey BlobはTPMなしでは復号できない
    fn generate_data_key(&mut self) -> Result<WrappedKey>;

    /// ラップされたData Keyを復元し、dataを暗号化
    /// PCR値に紐付けてシーリング
    fn seal(&mut self, key: &WrappedKey, data: &[u8]) -> Result<Vec<u8>>;

    /// シーリングされたデータを復号
    /// PCR値が一致しない場合は失敗
    fn unseal(&mut self, key: &WrappedKey, sealed: &[u8]) -> Result<Vec<u8>>;

    /// ProtectedDataをパスフレーズでバックアップ
    /// TPMが壊れた場合の回復用
    fn backup(&mut self, key: &WrappedKey, passphrase: &[u8]) -> Result<Vec<u8>>;

    /// パスフレーズからWrappedKeyを回復
    fn restore(&mut self, backup: &[u8], passphrase: &[u8]) -> Result<WrappedKey>;

    /// バックエンドの種別
    fn backend_type(&self) -> BackendType;
}

/// Primary Keyでラップされた Data Key
/// ディスクに保存可能だが、対応するTPMなしではアンラップ不可
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// TPMのPrimary Keyでラップされた鍵素材
    pub(crate) blob: Vec<u8>,
    /// ラップに使用したバックエンドの種別
    pub(crate) backend: BackendType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BackendType {
    Tpm,
    Software,
    // Phase 2以降
    // Tdx,
    // Sev,
    // SecureEnclave,
}
```

### Step 4: TPMバックエンド実装（crates/veil-tpm/src/lib.rs）

```rust
use tss_esapi::{
    Context, TctiNameConf,
    interface_types::{
        algorithm::HashingAlgorithm,
        resource_handles::Hierarchy,
    },
    structures::{
        Auth, Digest, PcrSelectionListBuilder,
        SymmetricDefinitionObject,
    },
    abstraction::pcr::PcrData,
};
use veil_core::{
    backend::{TeeBackend, WrappedKey, BackendType},
    error::{Result, VeilError},
};

pub mod session;
pub mod key;
pub mod seal;

pub struct TpmBackend {
    context: Context,
    /// Primary Keyの永続ハンドル（初期化後にセット）
    primary_handle: Option<tss_esapi::handles::KeyHandle>,
}

impl TpmBackend {
    pub fn new() -> Result<Self> {
        // 環境変数またはデフォルトのTCTIを使用
        // TPM_TOOLS_TCTI環境変数 or デフォルト（device:/dev/tpm0）
        let tcti = TctiNameConf::from_environment_variable()
            .unwrap_or(TctiNameConf::Device(Default::default()));

        let context = Context::new(tcti)
            .map_err(|e| VeilError::Backend(Box::new(e)))?;
        Ok(Self {
            context,
            primary_handle: None,
        })
    }
}

impl TeeBackend for TpmBackend {
    fn is_available() -> bool {
        #[cfg(target_os = "windows")]
        {
            // TODO: Windows APIによる確認
            true
        }
        #[cfg(target_os = "linux")]
        {
            std::path::Path::new("/dev/tpm0").exists()
                || std::path::Path::new("/dev/tpmrm0").exists()
        }
    }

    fn initialize_primary_key(&mut self) -> Result<()> {
        // 1. まず永続ハンドル(0x81000001等)からロードを試みる
        // 2. なければPrimary Keyを生成してNVに永続化
        // TODO: 実装
        todo!("TPM primary key initialization")
    }

    fn generate_data_key(&mut self) -> Result<WrappedKey> {
        // 1. AES-256鍵をTPM内部で生成（transient）
        // 2. Primary Keyでラップしてblob化
        // 3. Transient handleは破棄（NVメモリを消費しない）
        // TODO: 実装
        todo!("TPM data key generation")
    }

    fn seal(&mut self, key: &WrappedKey, data: &[u8]) -> Result<Vec<u8>> {
        // 1. Key BlobをPrimary Keyでアンラップ → Data Key復元
        // 2. PCR 0,7（ブートおよびセキュアブート状態）に紐付けてシーリング
        // 3. Data Keyでデータを暗号化
        // 4. Data Keyをzeroize
        // TODO: 実装
        todo!("TPM sealing")
    }

    fn unseal(&mut self, key: &WrappedKey, sealed: &[u8]) -> Result<Vec<u8>> {
        // 1. PCR値を確認
        // 2. Key BlobをPrimary Keyでアンラップ → Data Key復元
        // 3. Data Keyでデータを復号
        // 4. Data Keyをzeroize
        // TODO: 実装
        todo!("TPM unsealing")
    }

    fn backup(&mut self, key: &WrappedKey, passphrase: &[u8]) -> Result<Vec<u8>> {
        // パスフレーズで鍵をラップしてバックアップ
        // TODO: 実装
        todo!("Key backup")
    }

    fn restore(&mut self, backup: &[u8], passphrase: &[u8]) -> Result<WrappedKey> {
        // パスフレーズでバックアップから鍵を回復
        // TODO: 実装
        todo!("Key recovery")
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Tpm
    }
}
```

### Step 4.5: SoftwareBackendスタブ（crates/veil-software/src/lib.rs）

```rust
use veil_core::{
    backend::{TeeBackend, WrappedKey, BackendType},
    error::{Result, VeilError},
};

/// ソフトウェアのみで動作するフォールバックバックエンド
/// Phase 1ではスタブ（全メソッドがunimplemented）
/// Phase 2で本実装を行う
///
/// 注意：ハードウェアTEEと異なり、メモリ上の鍵素材は
/// OSやroot権限で読み取り可能。セキュリティレベルは低い。
pub struct SoftwareBackend;

impl SoftwareBackend {
    pub fn new() -> Self {
        tracing::warn!(
            "SoftwareBackend is a stub with no hardware protection. \
             Secrets are NOT protected from privileged access."
        );
        Self
    }
}

impl TeeBackend for SoftwareBackend {
    fn is_available() -> bool {
        true // ソフトウェア実装は常に利用可能
    }

    fn initialize_primary_key(&mut self) -> Result<()> {
        // TODO: Phase 2で実装（ソフトウェア鍵生成）
        Err(VeilError::NoHardware)
    }

    fn generate_data_key(&mut self) -> Result<WrappedKey> {
        Err(VeilError::NoHardware)
    }

    fn seal(&mut self, _key: &WrappedKey, _data: &[u8]) -> Result<Vec<u8>> {
        Err(VeilError::NoHardware)
    }

    fn unseal(&mut self, _key: &WrappedKey, _sealed: &[u8]) -> Result<Vec<u8>> {
        Err(VeilError::NoHardware)
    }

    fn backup(&mut self, _key: &WrappedKey, _passphrase: &[u8]) -> Result<Vec<u8>> {
        Err(VeilError::NoHardware)
    }

    fn restore(&mut self, _backup: &[u8], _passphrase: &[u8]) -> Result<WrappedKey> {
        Err(VeilError::NoHardware)
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Software
    }
}
```

### Step 5: 公開API（crates/veil-core/src/context.rs）

```rust
use crate::{
    backend::{TeeBackend, WrappedKey, BackendType},
    error::{Result, VeilError},
};
use serde::{Serialize, Deserialize};

/// veilのメインエントリポイント
pub struct VeilContext {
    backend: Box<dyn TeeBackend>,
}

#[derive(Debug, Clone)]
pub enum FallbackPolicy {
    /// TEEが利用不可の場合はエラー
    Deny,
    /// TEEが利用不可の場合は警告を出しつつソフトウェア実装で継続
    Warn,
    /// TEEが利用不可の場合はソフトウェア実装で代替（警告なし）
    Software,
}

impl VeilContext {
    /// 利用可能なTEEバックエンドを自動選択して初期化
    pub fn new() -> Result<Self> {
        Self::with_fallback(FallbackPolicy::Deny)
    }

    /// 指定したバックエンドで直接初期化（テスト用・上級者用）
    pub fn with_backend(mut backend: Box<dyn TeeBackend>) -> Result<Self> {
        backend.initialize_primary_key()?;
        Ok(Self { backend })
    }

    pub fn with_fallback(fallback: FallbackPolicy) -> Result<Self> {
        // バックエンドの自動検出は facade crate（crates/veil）で行う。
        // veil-coreはバックエンド実装に依存しない。
        // ここではwith_backend()を使うか、facade crateのnew()を使う。
        match fallback {
            FallbackPolicy::Deny => Err(VeilError::NoHardware),
            FallbackPolicy::Warn => {
                tracing::warn!("No TEE hardware available, falling back to software");
                Err(VeilError::NoHardware)
            }
            FallbackPolicy::Software => {
                Err(VeilError::NoHardware)
            }
        }
    }

    /// データを保護（暗号化）する
    /// 返値はシリアライズしてディスクに保存可能
    /// 対応するTEEなしには復号できない
    pub fn protect(&mut self, data: &[u8]) -> Result<ProtectedData> {
        let key = self.backend.generate_data_key()?;
        let ciphertext = self.backend.seal(&key, data)?;
        Ok(ProtectedData {
            key,
            ciphertext,
            version: 1,
        })
    }

    /// 保護されたデータを復号する
    pub fn unprotect(&mut self, protected: &ProtectedData) -> Result<Vec<u8>> {
        self.backend.unseal(&protected.key, &protected.ciphertext)
    }

    /// 保護されたデータをパスフレーズでバックアップする
    /// TPMが壊れた・デバイスを変更した場合の回復用
    pub fn backup(&mut self, protected: &ProtectedData, passphrase: &[u8]) -> Result<Vec<u8>> {
        self.backend.backup(&protected.key, passphrase)
    }

    /// パスフレーズからProtectedDataを回復する
    /// 別のTPMデバイスでもパスフレーズがあれば復号可能になる
    pub fn restore(
        &mut self,
        backup: &[u8],
        ciphertext: &[u8],
        passphrase: &[u8],
    ) -> Result<ProtectedData> {
        let key = self.backend.restore(backup, passphrase)?;
        Ok(ProtectedData {
            key,
            ciphertext: ciphertext.to_vec(),
            version: 1,
        })
    }
}

/// TEEで保護されたデータ
/// シリアライズしてディスク・クラウドに保存可能
/// 対応するTEE（またはパスフレーズ回復）なしには復号できない
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedData {
    /// Primary Keyでラップされた Data Key
    key: WrappedKey,
    /// Data Keyで暗号化されたデータ
    ciphertext: Vec<u8>,
    /// フォーマットバージョン（将来の互換性のため）
    version: u8,
}
```

### Step 5.5: facade crate（crates/veil/src/lib.rs）

```rust
//! veil — Unified abstraction layer for hardware-based TEE in Rust
//!
//! このcrateはfacadeとして、バックエンドの自動検出と
//! feature-gatedな依存関係の解決を行う。

pub use veil_core::*;

/// 利用可能なバックエンドを自動検出してVeilContextを生成
pub fn auto_detect(fallback: FallbackPolicy) -> veil_core::error::Result<VeilContext> {
    // TPMバックエンドを試行
    #[cfg(feature = "tpm")]
    {
        use veil_tpm::TpmBackend;
        if TpmBackend::is_available() {
            let backend = TpmBackend::new()?;
            return VeilContext::with_backend(Box::new(backend));
        }
    }

    // ソフトウェアフォールバック
    match fallback {
        FallbackPolicy::Deny => Err(veil_core::error::VeilError::NoHardware),
        FallbackPolicy::Warn | FallbackPolicy::Software => {
            if matches!(fallback, FallbackPolicy::Warn) {
                tracing::warn!("No TEE hardware available, falling back to software");
            }
            #[cfg(feature = "software")]
            {
                use veil_software::SoftwareBackend;
                return VeilContext::with_backend(Box::new(SoftwareBackend::new()));
            }
            #[cfg(not(feature = "software"))]
            Err(veil_core::error::VeilError::NoHardware)
        }
    }
}
```

### Step 6: `#[veil::protect]` マクロの仕様（crates/veil-macros/src/lib.rs）

`#[veil::protect]` は構造体に対して以下を自動生成するアトリビュートマクロ：

```rust
/// 使用例：
#[veil::protect(
    fallback = "deny",       // TEE不在時の動作（"deny" | "warn" | "software"）
    recovery = "passphrase", // 回復方式（"passphrase" | "none"）
    zeroize = true,          // Drop時にメモリをゼロクリア（デフォルト: true）
)]
struct DocumentKey {
    key_material: [u8; 32],
}

// ↓ マクロが自動生成するもの：

// 1. コンストラクタ：生の値からの直接構築を禁止、VeilContext経由のみ
impl DocumentKey {
    /// VeilContextを使って保護された状態で構築
    pub fn protect(ctx: &mut VeilContext, key_material: [u8; 32]) -> veil::Result<Protected<DocumentKey>> {
        // key_materialをシリアライズ → ctx.protect() → Protected<T>を返す
        todo!()
    }
}

// 2. Protected<T>ラッパー：内部データへの直接アクセスを禁止
pub struct Protected<T> {
    data: ProtectedData,  // シリアライズ・永続化可能
    _phantom: PhantomData<T>,
}

impl<T> Protected<T> {
    /// 復号して中身を取り出す（TEEが必要）
    pub fn unprotect(&self, ctx: &mut VeilContext) -> veil::Result<T> {
        todo!()
    }

    /// パスフレーズでバックアップ
    pub fn backup(&self, ctx: &mut VeilContext, passphrase: &[u8]) -> veil::Result<Vec<u8>> {
        todo!()
    }
}

// 3. Zeroize: Drop時にメモリをゼロクリア（zeroize = trueの場合）
impl Drop for DocumentKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_material.zeroize();
    }
}

// 4. Serialize/Deserialize: Protected<T>の永続化用に自動derive
```

### Step 7: 基本的な使い方（examples/basic_seal.rs）

```rust
use veil::{self, FallbackPolicy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // バックエンドを自動検出してveilコンテキストを初期化
    // TPMが利用可能な場合はTPMを使用、なければエラー
    let mut ctx = veil::auto_detect(FallbackPolicy::Deny)?;

    // 保護したいデータ（例：ドキュメントの暗号鍵）
    let secret = b"this is my document encryption key 32byte!";

    // TPMで保護（Data Keyを生成 → ラップ → 暗号化）
    let protected = ctx.protect(secret)?;

    // ProtectedDataはシリアライズしてディスクに保存可能
    let json = serde_json::to_string(&protected)?;
    println!("Serialized: {} bytes", json.len());

    // 復号（同じTPM・同じシステム状態でのみ成功）
    let recovered = ctx.unprotect(&protected)?;
    assert_eq!(secret, recovered.as_slice());
    println!("Successfully protected and recovered secret!");

    // パスフレーズでバックアップ（TPM故障時の保険）
    let backup = ctx.backup(&protected, b"my-recovery-passphrase")?;
    println!("Backup: {} bytes", backup.len());

    Ok(())
}
```

---

## テスト戦略

### ソフトウェアTPMを使ったテスト

実機のTPMがない環境でも`swtpm`を使ってテストできる。

```bash
# swtpmの起動（テスト用）
export TPM2TOOLS_TCTI="swtpm:path=/tmp/swtpm/tpm"
export TCTI="swtpm:path=/tmp/swtpm/tpm"

# テスト実行
cargo test --workspace
```

### テストケース

```
基本機能：
- [ ] TPMへの接続・切断
- [ ] Primary Keyの初期化（生成・ロード）
- [ ] Primary Keyの再ロード（再起動後）
- [ ] Data Keyの生成・ラップ
- [ ] シーリング・アンシーリングの往復
- [ ] ProtectedDataのシリアライズ・デシリアライズ往復
- [ ] 異なるTPMではアンシーリング失敗することの確認
- [ ] パスフレーズバックアップ・回復の往復
- [ ] FallbackPolicy::Warn でSoftwareBackendにフォールバック

エラーケース：
- [ ] TPMが存在しない場合のFallbackPolicy::Deny動作
- [ ] PCR不一致時のエラー
- [ ] 不正なシーリングデータのエラー
- [ ] 不正なパスフレーズでの回復失敗
- [ ] Primary Key未初期化での操作試行
```

---

## 既知の課題・TODO

```
Phase 1（現在）：
- Windows APIによるTPM利用可否確認の実装
- Primary Key生成・永続化の具体的な実装
- PCRシーリングの具体的な実装
- パスフレーズ回復の実装（Argon2idによる鍵導出）
- SoftwareBackendの本実装
- #[veil::protect] proc macroの実装
- ソフトウェアTPMを使った自動テストのCI設定

Phase 2（将来）：
- Intel TDX対応（crates/veil-tdx/）
- AMD SEV-SNP対応（crates/veil-sev/）
- Apple Secure Enclave対応（Swiftバインディング）
- ARM TrustZone対応（Kotlinバインディング）
- Windows Helloとの生体認証連携
```

---

## BitLocker設計研究 — 20年の実戦から学んだ設計パターン

hydeの鍵管理設計はBitLockerの20年の歴史から直接学んでいる。BitLockerは数十億台のWindowsデバイスで稼働する、最も実戦検証されたTPMベースの暗号化システムである。

一次資料：
- [MS-FVE仕様](https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc)
- [TPM-based BitLocker Deep Dive](https://itm4n.github.io/tpm-based-bitlocker/)
- [BitLocker SPI Sniffing Attack](https://labs.withsecure.com/publications/sniff-there-leaks-my-bitlocker-key)

### BitLockerの鍵階層

```
[Key Protectors] ── 複数同時に存在可能
  ├── TPM Protector        → VMKをunseal
  ├── Numerical Password   → VMKをunseal  ← リカバリキー（48桁）
  └── Passphrase           → VMKをunseal

        ↓ どれか1つでOK

     VMK (Volume Master Key, 256bit, ディスク上に暗号化保存)
        ↓
     FVEK (Full Volume Encryption Key, 実データ暗号化鍵)
        ↓
     データ本体
```

### hydeとBitLockerの設計対応表

| BitLocker | hyde | 設計意図 |
|---|---|---|
| VMK (Volume Master Key) | dk (decapsulation key) | 重い鍵は1デバイスに1つ。長期保持 |
| FVEK (Full Volume Encryption Key) | DataKey (per protect call) | 軽い鍵は毎回生成。Forward Secrecyをほぼゼロコストで実現 |
| Key Protector (複数共存) | `RecoveryStrategy` trait | 同一マスター鍵を複数の保護手段で守る。差し替え可能 |
| NVRAMに鍵を入れない | 1 NV slot for Primary Key | TPM NVは容量制限あり。BitLockerもディスク上のメタデータに暗号化保存 |
| VMK re-wrap (ローテーション) | dk re-seal (PQCチップ移行) | マスター鍵のre-sealのみ。データの再暗号化は不要 |

### 核心的な学び

#### 1. 鍵はTPM NVに入れない

BitLockerはTPM NVRAMにデータを保存できるが、**実際の鍵はディスク上のFVEメタデータブロックに暗号化された状態で保存される**。hydeのOption A（ディスク+TPMシール）はBitLockerと同じ設計判断。NVに直接入れる選択肢は15年前に否定済み。

- ML-KEM-768のdecap_keyは2400bytes — TPM NVに入れると容量を圧迫
- NV直接保存はTPM故障時にデータ永久喪失のリスク

#### 2. Key Protectorの複数共存がリカバリの本質

BitLockerでは各VMKコピーが異なるアクセス方法で暗号化されており、TPM・テキストパスワード・リカバリキーの**どれか1つ**でデータにアクセスできる。hydeの`RecoveryStrategy`トレイトはこの設計の直接的な模倣。

```rust
// hyde の RecoveryStrategy = BitLocker の Key Protector
let strategy = PassphraseRecovery;           // ← Passphrase Protector相当
let bundle = ctx.backup(&protected, &strategy, Some(b"passphrase"))?;
// 将来: RecoveryKey, ShamirRecovery    // ← Numerical Password, etc.相当
```

#### 3. VMKローテーション = データ再暗号化不要

BitLockerではProtectorが侵害された場合、**新しいVMKを生成してFVEKを再暗号化するだけ**でよく、ボリューム全体の再暗号化は不要。hydeも同じ：

```
dk ローテーション時:
  旧dk → 破棄
  新dk → 既存DataKeyを新dkで再暗号化
  データ本体 → 一切触らない
```

PQCチップ移行時も同様。dkが1個なのでre-seal操作は1回で完了。

#### 4. コスト構造：「重い操作」と「軽い操作」の分離

```
protect() 1回あたりのコスト:

[重い操作 — 初回のみ]
  ML-KEM encapsulate  : 数ms（ソフトウェア）
  TPM seal            : 数十ms〜100ms

[ほぼゼロ — 毎回]
  AES-256 DataKey生成 : マイクロ秒オーダー
  AES-256-GCM暗号化   : ほぼゼロ
```

BitLockerが15年以上この「重い鍵は一度だけ、軽い鍵で毎回」パターンを使い続けている理由がここにある。

#### 5. PCR Policy — PCR 11相当の設計が今後必要

BitLockerのSecure Boot有効時のデフォルト検証プロファイルは**PCR 7とPCR 11**。

- PCR 7: Secure Boot状態
- PCR 11: Windows Boot Managerのみがシールを解除できることを保証

hydeが現在PCR 0+7を使っている場合、PCR 11相当の「アプリケーション固有のシール解除制御」の概念が欠けている可能性がある。Phase 2（TDX/SEV-SNP）ではこの制御が本質的になる。

### PQCチップ移行シナリオ

```
現在（ソフトウェアPQC + TPM）:
  data → [ML-KEM-768(SW)] → [TPM AES-256-GCM] → blob
            Layer1               Layer2

PQCチップ移行後:
  data → [ML-KEM-X(HW)] → [PQCチップ seal] → blob
            Layer1              Layer2

移行プロセス:
  1. 旧TPMでdkをunseal
  2. 新PQCチップでdkをre-seal
  3. データ本体は一切触らない（re-sealは1回で完了）
```

移行後にdkの保護がPQCチップベースになっても、Layer1の旧ML-KEM-768暗号文はそのまま有効。データの「二重PQC」はセキュリティ上むしろ多層防御として機能し、パフォーマンスへの影響もdkのunwrap 1回分のみ。

### 一次資料から学んだ脆弱性と対策

#### 発見: 「鍵はTPMに入っていない」という誤解の修正

> "There is a common misconception that the BitLocker keys are stored in the TPM. Although data can be pushed to the NVRAM of the TPM, the keys are actually stored encrypted in metadata blocks on the BitLocker-protected drive itself."

hydeのOption A（ディスク+TPMシール）はBitLockerと完全に同じ設計判断であり、15年前から正解はこれである。

#### 発見: re-keyingの設計根拠

> "This architecture allows an easy way of re-keying the system if any of the protectors are compromised, since only a new VMK needs to be generated and the FVEK re-encrypted with the new VMK. This mechanism eliminates the requirement to re-encrypt the entire volume."

hydeの`ctx.rotate_key()`設計の根拠がここにある：

```rust
// PQCチップ移行時のre-keying
ctx.rotate_key()?;
// 内部動作：
//   1. 新しいdk生成
//   2. 全DataKeyを新dkでre-seal
//   3. データ本体は一切触らない
```

#### 発見: SPIバス盗聴攻撃 — TPM-onlyの致命的弱点

WithSecureの一次資料がTPM-onlyモードの致命的な弱点を実証している：

```
攻撃に必要なもの：
  - ロジックアナライザー（$300〜$1000）
  - ノートPCの裏蓋を外す物理アクセス（1分以内）

攻撃手順：
  1. SPIバスにプローブを接続
  2. 起動時のTPM通信をキャプチャ
  3. unsealコマンドのレスポンスからVMK（= hydeのdk）が平文で取れる

結果：dkが取れる → 全DataKey復号可能 → 全データ復号
```

**TPM + PINの場合はなぜ安全か：**

```
TPM-only の場合：
  TPMデータ → unseal → VMK (平文) ← SPIバスで取れる

TPM + PIN の場合：
  TPMデータ = AES-CCM暗号化されたKey Protector (KP)
  KPの復号鍵 = SHA256(PIN × 0x100000回 + Salt)
             ↑ PINなしでは計算不可
  KP → 復号 → VMK
```

TPM + PINでは、TPMから出てくるデータ自体がさらにPINで暗号化されている。SPIバスで傍受しても生のVMKは取れない。

#### hydeへの設計示唆: PersonBindingレイヤー

READMEには「特定のデバイス＋**特定の人物**に紐付けて保護する」と記載しているが、TPM-onlyでは「特定の人物」バインディングは実質ゼロである。

```rust
// 現在（TPM-only、人物バインディングなし）
let mut ctx = hyde::auto_detect(FallbackPolicy::Deny)?;
let protected = ctx.protect(secret)?;

// 提案（TPM + PIN、人物バインディングあり）
let mut ctx = hyde::auto_detect(FallbackPolicy::Deny)?
    .with_person_binding(PersonBinding::Pin)?;

let protected = ctx.protect(secret)?;
// → dkはTPMシール + PIN層でラップされる
```

PersonBindingの選択肢：

| 方式 | セキュリティ | UX | 実装難易度 |
|---|---|---|---|
| **PIN** | ◎ SPI傍受耐性あり | △ 毎回入力 | ○ BitLockerと同じパターン |
| **Passphrase** | ◎ | △ | ○ RecoveryStrategyに近い設計がある |
| **FIDO2/Passkey** | ◎◎ | ○ | △ Phase 2以降で価値大 |
| **なし（現在）** | △ SPI傍受で終わり | ◎ | — |

BitLockerはTPM-onlyをデフォルトにしており批判されている。hydeはPersonBinding必須をデフォルトにすることで差別化できる — READMEの「特定の人物」という主張を設計レベルで証明する。

注意: fTPM（CPU内蔵TPM）の場合はSPIバス自体が存在しないため、この攻撃は成立しない。ただしfTPMにはfTPM固有の脆弱性（電圧グリッチ攻撃等）が報告されており、PersonBindingは依然として多層防御として有効。

### 深掘り1: fTPM（CPU内蔵TPM）の攻撃面

#### dTPM vs fTPMのアーキテクチャ

```
dTPM（外付けチップ）:
  CPU ──SPI/LPCバス──→ TPMチップ（外部）
         ↑ここを盗聴できる

fTPM（CPU内蔵）:
  CPU内部でTPM機能が動く
  外部バスが存在しない → SPI傍受が原理的に不可能
```

#### fTPMは完全に安全か？ — faulTPM攻撃

**ノー。** 2023年にTU Berlinが「faulTPM」攻撃を発表。AMDのZen2/Zen3搭載CPUに対して、約$200の機材で電圧フォルト注入攻撃を行い、fTPM内のBitLocker鍵を完全に取得することに成功した。ただし攻撃には**数時間の物理アクセス**が必要。

| TPM種別 | SPI傍受 | faulTPM | 必要な攻撃難易度 |
|---|---|---|---|
| dTPM（外付け） | ✅ 可能・$300・10分 | — | **低** |
| fTPM（CPU内蔵） | ❌ 不可能 | ✅ 可能・$200・数時間 | **中** |
| fTPM + PIN | ❌ | △ PINも破る必要あり | **高** |

#### hydeへの示唆

```rust
// hydeのauto_detect()が将来できるべきこと
auto_detect() → {
    if fTPM → SPI傍受リスクなし、PINなしでも中程度のセキュリティ
    if dTPM → SPI傍受リスクあり、PIN必須と警告を出す
}
```

fTPMはバス盗聴攻撃を回避できるが、それ自体の攻撃面（電圧グリッチ）も持つ。TPM種別を検出してPIN要否を警告する設計が理想。

### 深掘り2: Suspendedモード（Clear Key問題）

#### BitLockerの設計上の「穴」

Suspendedモードはデータを復号するのではなく、**データを復号するための鍵をClear Key（平文）としてディスク上に保存する**。Suspend後に書き込まれる新しいデータは引き続き暗号化されるが、既存データへの鍵が平文でディスクに乗る。

```
通常時：
  VMK → TPMシール → blob（復号にTPM必須）

Suspended時：
  VMK → Clear Key → ディスク上に平文で存在
         ↑ TPMなしで誰でも読める
```

#### いつSuspendedになるか

MicrosoftのWindowsアップデートでは自動的にBitLockerをSuspendしないが、TPMファームウェアの更新やUEFI/BIOSの変更など、サードパーティのソフトウェア更新時は手動でSuspendが必要になる場合がある。2025年10月にも、セキュリティアップデート後にBitLockerリカバリ画面が表示されるケースが報告されている。

#### hydeの構造的優位性

**hydeにはSuspendedモードが構造上存在しない。** これはhydeの設計上の強み。

```
BitLocker：ボリューム全体を暗号化 → 一時的にClear Key必要
hyde：ファイル単位で暗号化 → Suspendの概念がない
      protect()/unprotect()は常にTPM+PQC経由
```

ただしhydeにも類似リスクがある — `unprotect()`後のメモリ上の平文：

```rust
// unprotect()後のメモリ上の平文
let secret = ctx.unprotect(&protected)?;
// この瞬間、secretはRAM上に平文で存在
// → メモリダンプ攻撃に対して無防備

// 対策：zeroize crateでスコープアウト時に即消去
use zeroize::Zeroizing;
let secret = Zeroizing::new(ctx.unprotect(&protected)?);
// スコープを抜けると自動的にゼロ埋め
```

#### 深掘りまとめ

| テーマ | BitLockerの知見 | hydeへの示唆 |
|---|---|---|
| fTPM | dTPMはSPI傍受$300・10分で破れる。fTPMは数時間・$200のfaulTPM攻撃 | `auto_detect()`でTPM種別を検出しPIN要否を警告 |
| Suspendedモード | BIOS更新時などにClear Keyがディスクに平文で乗る | hydeにはSuspendがない→構造的強み。ただし`unprotect()`後のRAM平文は`zeroize`で対処 |

### 論点1の最終結論

```
dk の保管設計 ← 確定

[保管場所]      ディスク + TPMシール        ← BitLockerと同じ、正解
[dk の数]       1デバイス1鍵               ← PQCチップ移行コスト最小
[DataKey]       protect()ごとに生成         ← Forward Secrecy、ゼロコスト
[rotate]        ctx.rotate_key()           ← BitLockerのre-keying模倣
[弱点]          TPM-only = SPI傍受脆弱     ← PersonBindingで緩和
[人物バインド]  PersonBinding::Pin/Passphrase ← READMEの主張を設計で証明
```

---

## 論点2: PCR Policy × クラウドAdmin脅威

### 核心

**PCRポリシーはブート改ざんを検出する仕組みであって、クラウドAdminのメモリアクセスを防ぐ仕組みではない。**

### PCRが守れるもの・守れないもの

```
PCRが守れるもの（ブート整合性）
  ├── ディスクの差し替え
  ├── ブートローダーの改ざん
  └── Secure Boot設定の変更

PCRが守れないもの（実行時攻撃）
  ├── OSが動いている間のメモリダンプ     ← クラウドAdmin
  ├── ハイパーバイザーからのVM停止→スナップショット
  ├── DMA攻撃（PCIe経由のメモリ直読み）
  └── ルートキット（OS起動後に侵入）
```

### クラウドAdminの攻撃を具体的に図解

```
[クラウド環境]

物理サーバー
  └── ハイパーバイザー（クラウドAdmin管理下）
        └── VM（ユーザーのワークロード）
              └── hyde が動いている

攻撃手順：
  1. AdminがVMを一時停止
  2. メモリスナップショットを取得
  3. unprotect()後の平文データがRAMにある場合→取得完了
  4. VMを再開（ユーザーは気づかない）
```

PCRはブート時のハッシュなので、VM起動後にAdminが操作しても値は変わらない。つまり**PCRポリシーはこの攻撃に対して完全に無力**。

### Phase 2のTDX/SEV-SNPが解決する

AzureのドキュメントにはIntel TDXについてこう記載されている：

> ハイパーバイザー、その他のホスト管理コード、および管理者がVMのメモリと状態にアクセスすることを拒否します。

TDX/SEV-SNPはハードウェアレベルでメモリを暗号化し、ハイパーバイザー自身も中身を読めない設計。

```
TDX/SEV-SNPが守れるもの
  ├── ハイパーバイザーからのメモリアクセス ← クラウドAdmin
  ├── 他VMからのアクセス
  └── スナップショット攻撃（暗号化されているので読めない）
```

### hydeのロードマップとの対応

```
Phase 1（現在）: TPM 2.0
  → ブート整合性 ◎
  → クラウドAdmin ✗  ← PCRでは防げない

Phase 2（計画中）: Intel TDX / AMD SEV-SNP
  → ブート整合性 ◎
  → クラウドAdmin ◎  ← ハードウェアメモリ暗号化で防ぐ
```

READMEの「クラウドAdmin」という脅威は、Phase 1では正直に言うと守れていない。Phase 2のTDX/SEV-SNPが入って初めて主張が完全に成立する。

### READMEで修正すべき点

現在の記述：

> hydeはTPMを使い、秘密情報を「特定のデバイス＋特定の人物」に紐付けて保護する。クラウドに保存されても、その人物・そのデバイスなしには復号できない。

より正確な記述：

> - **Phase 1（TPM）**: ディスク盗難・物理攻撃から守る。クラウドAdmin脅威はPhase 2以降。
> - **Phase 2（TDX/SEV-SNP）**: クラウドAdmin含む実行時攻撃から守る。

---

## 全体まとめ

### 論点1（鍵の保管設計）

```
✅ ディスク + TPMシール = BitLockerと同じ正解
✅ DataKeyは毎回生成 = Forward Secrecy
✅ dkは1デバイス1鍵 = PQCチップ移行コスト最小
⚠️  TPM-only = SPI傍受脆弱 → PIN/Passphraseで緩和
⚠️  fTPM = SPI不可だがfaulTPM攻撃あり
```

### 論点2（PCR Policy × クラウドAdmin）

```
✅ PCR = ブート整合性の検出に有効
❌ PCR = クラウドAdminのメモリアクセスには無力
🔮 Phase 2のTDX/SEV-SNPで初めてクラウドAdminを撃退できる
→ READMEのPhase別の守備範囲を明確化すべき
```

### 論点3（#[hyde::protect] マクロと Protected<T> の設計）

```
✅ Deref自動展開は採用しない — 暗黙の復号は設計思想に矛盾
✅ 明示的ctx渡し — 権限の明示化、現在の設計が正しい
✅ Zeroizing統合 — unprotect()の戻り値をZeroizing<T>にして平文寿命を制御
✅ with_unprotected() — スコープ限定APIで平文の寿命をコンパイラが保証
❌ ctxをグローバルシングルトンにしない — テスト困難、マルチスレッドで詰まる
❌ ctxを構造体フィールドに持たない — 「誰がいつ復号できるか」の制御が消える
```

---

## 論点3: #[hyde::protect] マクロと Protected<T> の設計

### 核心の緊張関係

```
Ergonomics（使いやすさ）
  └── Protected<T>をDerefで自動展開したい
        record.diagnosis  // 自動でunprotect

Security（安全性）
  └── unprotectは明示的であるべき
        ctx.unprotect(&record)?  // 意図を持って復号
```

### Derefを実装した場合に何が起きるか

```rust
// Derefありの危険な世界
impl<T> Deref for Protected<T> {
    type Target = T;
    fn deref(&self) -> &T { /* 暗黙のunprotect */ }
}

// 呼び出し側は何も考えなくてよい
println!("{}", record.diagnosis);  // ← TPMアクセスが暗黙に発生
                                   // ← エラーハンドリング不能（Derefは Result を返せない）
                                   // ← いつ復号されたか不明
                                   // ← zeroizeのタイミング制御不能
```

4つの問題が同時に発生する。hydeの設計思想と完全に矛盾するため、**Derefは採用しない**。

### 明示的設計の強化ポイント

#### 強化1: Zeroizingとの統合

```rust
use zeroize::Zeroizing;

impl<T: Zeroize> Protected<T> {
    pub fn unprotect(&self, ctx: &mut HydeContext) -> hyde::Result<Zeroizing<T>> {
        let plain = /* TPM + PQC復号 */;
        Ok(Zeroizing::new(plain))
    }
    //  ↑ スコープを抜けると自動ゼロ埋め
    //    平文がRAMに残るリスクを最小化
}

// 使う側
{
    let plain = record.unprotect(&mut ctx)?;
    process(plain.diagnosis);
}  // ← ここでdiagnosisがゼロ埋め
```

#### 強化2: スコープ限定API（with_unprotected）

```rust
impl<T: Zeroize> Protected<T> {
    /// withブロック内だけ平文にアクセス可能
    pub fn with_unprotected<F, R>(
        &self,
        ctx: &mut HydeContext,
        f: F,
    ) -> hyde::Result<R>
    where
        F: FnOnce(&T) -> R,
    {
        let plain = Zeroizing::new(self.unprotect_inner(ctx)?);
        Ok(f(&plain))
    }
}

// 使う側
record.with_unprotected(&mut ctx, |data| {
    send_to_doctor(data.diagnosis.clone())
})?;
// ← ブロックを抜けると即座にゼロ埋め
// ← 平文の寿命がコンパイラで保証される
```

#### 強化3: HydeContextの取得設計

```rust
// ❌ グローバルシングルトン
static CTX: Mutex<HydeContext> = ...;
// → テスト困難、マルチスレッドで詰まる

// ❌ 構造体フィールドに持つ
struct Service { ctx: HydeContext }
// → Serviceがどこでも復号できてしまう
//   「誰がいつ復号できるか」の制御が消える

// ✅ unprotect時に引数として渡す（現在の設計）
record.unprotect(&mut ctx)?
// → ctxを持っているスコープだけが復号可能
//   権限の明示化

// ✅✅ + with_unprotectedで寿命も制御
record.with_unprotected(&mut ctx, |data| { ... })?
```

### マクロが生成すべきもの

```rust
#[hyde::protect]
struct MedicalRecord {
    patient_id: u64,
    diagnosis: String,
}

// マクロが自動生成するもの:
// 1. impl hyde::Protectable for MedicalRecord {}
// 2. Protected<MedicalRecord> に以下のメソッド:
//    - protect(&self, ctx) -> Protected<MedicalRecord>
//    - unprotect(&self, ctx) -> Zeroizing<MedicalRecord>
//    - with_unprotected(&self, ctx, f) -> R
// 3. Derefは生やさない（コンパイルエラーで守る）
// 4. Drop時にZeroize（平文のメモリ残留を防ぐ）
```

### 論点3 深掘り: HydeContextの生存期間とDecryptPermitパターン

`with_unprotected`を実装したとして、次の問いが出る — TPMセッションの確立は重い操作（数十〜100ms）であり、毎回張るのはパフォーマンス的に問題になりうる。

#### パターンA: リクエストごとに生成

```rust
async fn handle_request(record: Protected<MedicalRecord>) {
    let ctx = hyde::auto_detect(FallbackPolicy::Deny)?;  // 毎回TPMセッション確立
    record.with_unprotected(&mut ctx, |data| {
        process(data)
    })?;
}
// ✅ シンプル、テスト容易
// ❌ パフォーマンス問題（毎回数十〜100ms）
```

#### パターンB: アプリ起動時に1回生成、共有

```rust
// 起動時
let ctx: Arc<Mutex<HydeContext>> = Arc::new(Mutex::new(
    hyde::auto_detect(FallbackPolicy::Deny)?
));

// 各所で
let mut ctx = ctx.lock().unwrap();
record.with_unprotected(&mut ctx, |data| { ... })?;
// ✅ パフォーマンス良好
// ❌ Mutexのロック競合
// ❌ ctxが広いスコープに存在する = 誰でも復号できてしまう
```

#### パターンC: DecryptPermit — Rustの型システムで「復号権限」を表現

```rust
/// 復号権限トークン（一時的に発行される）
/// MutexGuardやRwLockReadGuardと同じ「一時的権限トークン」パターン
pub struct DecryptPermit<'a> {
    ctx: &'a mut HydeContext,
    // lifetime で有効期間をコンパイラが保証
}

impl HydeContext {
    /// permitスコープ内だけ複数のunprotectが可能
    /// TPMセッションは1回、permit発行時のみ
    pub fn with_permit<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(DecryptPermit<'_>) -> R
    {
        f(DecryptPermit { ctx: self })
    }
}

impl<T: Zeroize> Protected<T> {
    pub fn unprotect(&self, permit: &DecryptPermit<'_>) -> hyde::Result<Zeroizing<T>> {
        // permitが存在する = 復号権限がある
        // permitのlifetimeが終わる = 復号権限が消える
        todo!()
    }
}

// 使う側
ctx.with_permit(|permit| {
    let a = record_a.unprotect(&permit)?;
    let b = record_b.unprotect(&permit)?;
    // permitのスコープ内だけ複数のunprotectが可能
    process(&a, &b)
})?;
// ← スコープ外ではunprotect不能
// ← TPMセッションは1回
// ← lifetimeでコンパイラが強制
```

#### パターン比較

| パターン | パフォーマンス | 安全性 | Rust的 |
|---|---|---|---|
| A: 毎回生成 | ❌ 毎回100ms | ✅ スコープ明確 | △ |
| B: Arc\<Mutex\> | ✅ セッション1回 | ❌ 誰でも復号可能 | △ |
| **C: DecryptPermit** | **✅ セッション1回** | **✅ lifetime保証** | **◎ MutexGuardと同じ発想** |

DecryptPermitパターンは、Rustの標準ライブラリが15年かけて洗練させた「一時的権限トークン」パターンをhydeに適用するもの。パフォーマンスと安全性を両立できる唯一の選択肢。

#### なぜパターンBを採用すべきでないか

```rust
// Arc<Mutex<HydeContext>>の問題
let ctx = Arc::clone(&global_ctx);
let mut ctx = ctx.lock().unwrap();

// → ctxが取れれば誰でもどこでも復号できる
// → 権限の境界が消える
// → BitLockerがTPM-onlyで陥った問題と同じ構造
//   「鍵は安全だが、使える人間が多すぎる」
```

### 実装戦略: CをベースにAで始める

**Phase 1（今すぐ・v0.1〜v0.2）: パターンA**

```rust
// シンプルに始める。過剰設計より動くものが優先。
let mut ctx = hyde::auto_detect(FallbackPolicy::Deny)?;
let plain = record.unprotect(&mut ctx)?;
```

**Phase 2（パフォーマンス問題が出たら）: パターンC**

```rust
ctx.with_permit(|permit| {
    let a = record_a.unprotect(&permit)?;
    let b = record_b.unprotect(&permit)?;
    process(a, b)
})?;
```

DecryptPermitの本質的メリット3つ：

1. **TPMセッションが1回で済む** — permit発行=セッション確立（重い・1回）、unprotect=セッション再利用（軽い・n回）、permit消滅=セッション終了
2. **「誰がいつ復号できるか」をコンパイラが強制** — permitを持っていないスコープではunprotect不能=コンパイルエラー
3. **監査ログの挿入点が明確** — `with_permit`のスコープだけ見ればいい

### 論点3の完全な設計図

```
#[hyde::protect] マクロが生成するもの

Protected<T>
  ├── protect(data, ctx) → Protected<T>    // 暗号化
  ├── unprotect(ctx) → Zeroizing<T>        // 復号（明示的）
  ├── with_unprotected(ctx, f) → R         // スコープ限定復号
  └── Derefなし                            // 暗黙の復号を禁止

HydeContext
  └── with_permit(f) → R                  // Phase 2で追加
        └── DecryptPermit<'_>
              └── lifetime でコンパイラが寿命を保証

Zeroizing<T>
  └── スコープアウトで自動ゼロ埋め        // RAMに平文を残さない
```

### 論点3の結論

「安全側に倒した設計を、Rustのコンパイラに強制させる」— これがhydeのマクロが目指すべき方向。BitLockerが15年かけてOSレベルで解いた問題を、Rustの型システムで解く。これがhydeの差別化になる。

---

## 論点4: FallbackPolicyと運用現実

### 問題の構造

```
GitHub Actions / GitLab CI
  └── VM上で動く
        └── TPMなし or vTPM（セキュリティ保証なし）
              └── FallbackPolicy::Deny → エラー
                    └── テストが全部落ちる
```

### テストの3層構造と問題の所在

```
Layer 3: 統合テスト（swtpm必須）
  → 現在動いている ✅
  → --test-threads=1 が必要（TPMはシリアル）
  → CI時間が長い

Layer 2: ユニットテスト（TPM不要なはず）
  → PQC暗号化ロジック
  → シリアライズ/デシリアライズ
  → RecoveryStrategyの計算
  → しかしHydeContextが絡むと全部swtpm必要に ⚠️

Layer 1: プロパティテスト（純粋関数）
  → ML-KEM鍵生成・暗号化・復号
  → Argon2idのKDF計算
  → TPM完全不要 ✅
```

**問題の核心：Layer 2がLayer 3に汚染されている。**

### FallbackPolicyの設計上の欠陥

```rust
// 現在の2択
FallbackPolicy::Deny   // 本番用
FallbackPolicy::Allow  // テスト用？

// Allowの危険性
let ctx = hyde::auto_detect(FallbackPolicy::Allow)?;
// → TPMなし環境でSoftwareBackendが使われる
// → テストは通る
// → しかしSoftwareBackendはセキュリティゼロ
// → 本番でAllowを誤って使ったら？
//   → サイレントにセキュリティが劣化
//   → エラーも警告も出ない
```

これはBitLockerのSuspendedモード問題と同じ構造 — セキュリティが無声で劣化する。

### 解決策：FallbackPolicyに3つ目を追加

```rust
pub enum FallbackPolicy {
    /// 本番用: TPMなし → エラー
    Deny,

    /// テスト用: TPMなし → SoftwareBackend
    /// ただしBackendKindが強制的にSoftwareになる
    /// → ctx.backend_kind()で検出可能
    AllowForTesting,

    /// 廃止予定: Allowは使わせない
    // Allow,  ← 削除
}
```

そして`BackendKind`を公開APIに追加：

```rust
pub enum BackendKind {
    Tpm,            // 本物のTPM
    SoftwareOnly,   // テスト用フォールバック
}

impl HydeContext {
    pub fn backend_kind(&self) -> BackendKind { ... }
}

// 本番コードでの防御
let ctx = hyde::auto_detect(FallbackPolicy::AllowForTesting)?;
assert_eq!(
    ctx.backend_kind(),
    BackendKind::Tpm,
    "本番環境ではTPMが必須です"
);
```

### GitLab CIの構成改善案

現在の構成：

```yaml
test:
  script:
    - swtpm socket ... --daemon
    - export TCTI="swtpm:..."
    - cargo test --workspace -- --test-threads=1
```

改善案 — テストを3層に分離：

```yaml
# Layer 1: 高速・TPM不要（毎PRで走る）
test-unit:
  script:
    - cargo test --workspace --lib -- --test-threads=4
  # swtpm不要・並列実行可能・数秒で終わる

# Layer 2: 中速・swtpm使用（毎PRで走る）
test-integration:
  script:
    - swtpm socket ... --daemon
    - cargo test --workspace --test -- --test-threads=1
  # TPMが絡むテストのみ

# Layer 3: 低速・実TPM（main pushのみ）
test-hardware:
  script:
    - cargo test --workspace -- --test-threads=1
  tags:
    - hardware-tpm  # 実TPM搭載ランナー
  only:
    - main
```

### 論点4の結論

| 問題 | 解決策 |
|---|---|
| Allowのサイレント劣化 | `AllowForTesting`に改名 + `BackendKind`公開 |
| テストが全部swtpm依存 | 3層分離（unit / integration / hardware） |
| `--test-threads=1`で遅い | Layer 1はTPM不要にしてPRで高速フィードバック |
| 本番誤設定の検出 | `backend_kind()`アサーションをドキュメントに明記 |

`AllowForTesting`の追加と`BackendKind`の公開 — この2つがv0.2に入れるべき最優先の運用改善。

---

## 論点5: argo/platのアーキテクチャ設計 — ZKPの社会実装

### エコシステムの全体像と現実

```
hyde  → TPM + PQC     （Phase 1完了）
argo  → ZKP           （計画中）
plat  → FHE           （計画中）
```

これは世界最難関の暗号技術を3つ繋げる計画。現実のパフォーマンスを直視する必要がある。

| 技術 | 用途 | 現実の速度（2025年時点） |
|---|---|---|
| ZKP（Groth16） | 証明生成 | 数秒〜数十秒 |
| ZKP（PLONK） | 証明生成 | 数百ms〜数秒 |
| FHE（TFHE） | AES-128一回 | 約10秒 |
| FHE（CKKS） | 浮動小数演算 | 数ms〜数秒 |

FHEは実用速度に達していない。platは長期ビジョンとして維持し、argoに集中すべき。

### ZKPの社会実装 — なぜ空白地帯なのか

ブロックチェーン領域ではZKPは既に実用段階（2025年時点でZKベースLayer2に$280億ロック、zkSyncは43,000 TPS）。

しかし**政府・公共領域は根本的に違う問題**を抱えている。

```
ブロックチェーンのZKP
  └── 「このトランザクションは正しい」を証明
  └── オンチェーンで検証
  └── 信頼の根拠 = ブロックチェーン

政府・企業のZKP ← ここが空白地帯
  └── 「私は〇〇の条件を満たす」を証明
  └── オフラインで検証
  └── 信頼の根拠 = ??? ← ここにTPMが入る
```

**信頼の根拠がない。** これが政府ZKPの社会実装が進んでいない本当の理由。

NISTの2024年ワークショップでもBBS匿名クレデンシャルのeIDAS 2.0準拠、EUDIウォレットへのZKP適用が議題になっている。政府利用は標準化と規制整備が今まさに進行中の段階。

### argoがhydeと組み合わさると何が起きるか

```
hyde（TPM + PQC）
  └── 「このデバイス・この人物」を証明する信頼の根拠

argo（ZKP）
  └── hydeの信頼チェーンを使って
      「私は〇〇の条件を満たす」を証明

組み合わせると：
  「私（特定の人物）は、
   このデバイス（TPM検証済み）で、
   〇〇の条件を満たす（ZKP）」
   ↑ これを相手に何も見せずに証明できる
```

### 政府ユースケースの具体例

| ユースケース | 証明すること | 見せないこと |
|---|---|---|
| マイナンバー | 日本国民である | 氏名・住所・番号 |
| 年齢確認 | 20歳以上である | 生年月日・氏名 |
| 所得証明 | 年収〇〇万円以上 | 正確な金額 |
| 医療資格 | 医師免許を持つ | 個人情報 |
| 入札資格 | 条件を満たす | 企業財務詳細 |

これらは全部、今の行政では紙か全情報開示で証明しているもの。

### argoの設計方針

```
方針A: ZKPプリミティブをhydeに統合
  → argo = hyde + bellman/arkworks のラッパー
  → 開発者がcircuitを書く必要あり
  → 難易度高い

方針B: 証明テンプレートを用意する ← 推奨
  → argo = よく使うZKP証明を事前定義
  → 「年齢確認」「所得範囲」「資格保有」を一行で
  → 開発者はcircuitを書かなくていい
  → 社会実装に直結
```

方針Bの理想的なAPI：

```rust
use argo::proofs::AgeProof;

// 「20歳以上」を証明（生年月日は見せない）
let proof = AgeProof::prove(
    birth_date,       // 秘密の witness
    threshold: 20,    // 公開条件
    hyde_ctx: &ctx,   // TPMで身元を担保
)?;

// 検証側（生年月日を知らなくても検証できる）
AgeProof::verify(&proof, threshold: 20)?;
```

### platの位置づけ — FHEは遅いが、スピードは問題ではない

#### FHEとは何か

```
通常の計算：
  暗号文 → 復号 → 計算 → 再暗号化
  ↑ 計算する人がデータを見てしまう

FHE（完全準同型暗号）：
  暗号文 → 暗号化したまま計算 → 暗号文
  ↑ 計算する人はデータを一切見ない
```

#### FHEのパフォーマンス現実

```
通常の AES-128 一回：   ナノ秒
FHE で AES-128 一回：   約10秒（1000万倍遅い）
```

しかし**スピードが問題になるかはユースケース次第**。

```
スピードが重要（FHE不可）        スピードが不要（FHE可能）
├── 決済処理（0.1秒以内）        ├── 医療診断（1日待てる）
├── 音声認識（リアルタイム）      ├── 税務計算（月次）
├── 株式取引（ミリ秒）           ├── 統計集計（週次）
                                 └── 機密文書の分析（数時間待てる）
```

#### platの正しいポジショニング

```
❌ 間違い：「高速な暗号計算基盤」
           → FHEは速くないので無理

✅ 正解：「今まで渡せなかったデータを計算させられる基盤」
           → スピードではなく可能性の拡張
```

#### 医療診断 — platの最初のターゲット

医療診断はFHEの最も説得力のあるユースケース。理由が3つ：

1. **データが極めて機密性が高い** — 遺伝子情報・病歴・精神疾患記録、誰にも見せたくない
2. **計算は専門AIに任せたい** — 自分では診断できない、見せずに計算させたい
3. **リアルタイム不要** — 10秒でも数分でも待てる（現状の医療は検査結果に数日〜1週間）

#### hyde + argo + platが揃うと何が起きるか

```rust
// hyde：患者の遺伝子データを暗号化・デバイス紐付け
let encrypted_genome = ctx.protect(&genome_data)?;

// plat：暗号化したまま医療AIに計算させる
let encrypted_result = plat::compute(
    &encrypted_genome,
    ai_model: "cancer_risk_v3",
)?;

// hyde：患者本人だけが復号できる
let diagnosis = ctx.unprotect(&encrypted_result)?;

// argo：「高リスク」という事実だけを保険会社に証明
// （実際の数値は見せない）
let proof = argo::prove_threshold(
    &diagnosis,
    condition: "risk_score < 0.3",
)?;
```

**遺伝子データは誰にも見えていない。医療AIも、保険会社も。**

#### これが「誰も作っていない」理由

```
医療AI企業：計算はできる、でもデータが来ない
患者：診断を受けたい、でもデータを渡したくない
保険会社：リスク評価したい、でも個人情報は要らない

3者の利害が一致しない → 市場が生まれない

hyde + argo + plat：
→ 3者全員がWINする仕組みを技術で実現
→ 市場が生まれる
```

#### platの設計方針

FHEの遅さは問題ではない。問題は「使いやすさ」。開発者がFHEのcircuitを書くのは不可能に近い。argoと同じく**計算テンプレート方式**が正解。

```rust
// 開発者はFHEを意識しない
plat::compute(data, model)
// 内部でFHEが動いているが抽象化されている
```

### 論点5の結論

| 問い | 答え |
|---|---|
| ZKPの社会実装は誰もやっていないか | ブロックチェーン以外はほぼ空白 ✅ |
| なぜ進んでいないか | 信頼の根拠がない → hydeが解決 |
| argoの独自性 | TPM信頼チェーン + ZKP = 世界初の組み合わせ |
| 実装方針 | 方針B（証明テンプレート）で社会実装に直結 |
| 最初のターゲット（argo） | マイナンバー・年齢確認・資格証明 |
| FHEのスピード問題 | ユースケース次第。医療診断なら10秒でも問題なし |
| platの独自性 | 「渡せなかったデータを計算させられる」可能性の拡張 |
| 最初のターゲット（plat） | 医療診断AI（遺伝子データの機密計算） |
| エコシステム全体の意義 | データを一切公開せずに社会的信頼を構築する世界 |

---

## 設計思想の整理（2026-03-27追記）

### hydeの信頼モデル

**hydeが信じるのは、人間が変えられないものだけ — 物理と数学。**

物理法則は遠隔で書き換えられない。数学的証明は交渉で下げられない。それ以外の全て — ポリシー、善意 — hydeは構造で排除する。管理者権限についても、FixedTPMフラグにより鍵の取り出しはハードウェアレベルで拒否される。管理者は「壊す」ことはできるが「盗む」ことはできない。

### 1人1デバイスの理想

hydeは1人1デバイスを信頼モデルの理想とする。マルチユーザーOSは「管理者権限」という概念を生み出した。しかしhydeのFixedTPMフラグにより、管理者権限があってもTPMから鍵を取り出すことは不可能。管理者はサービス妨害（DoS）はできるが、データ窃取はできない。

| Phase | アプローチ |
|---|---|
| Phase 1 | 1人1デバイス環境での完全な保護 |
| Phase 2 | TDX/SEV-SNPで擬似的な1人1環境を実現 |

設計思想の核心：**「完全な安全はない。信頼が必要な範囲を、できる限り小さく・末端にする。」**

この洞察はhydeOSという将来の開発動機となりうる。

### hydeはプライバシーインフラである

hydeはセキュリティツールではなくプライバシーインフラ。

- 「悪い人が入ってこれないか」（セキュリティ）ではなく
- 「正規のアクセス権者を含む第三者にも見せない」（プライバシー）を解く
- セキュリティの向上はその副産物

責任の所在：
- 暗号化されたデータが漏洩してもデータは守られる → hydeの保証
- 鍵（TPM）が盗まれた場合はデバイス所有者の責任
- これがデータの主体権をユーザーに返すことの意味

### スコープ（守備範囲）

Phase 1のスコープはBitLockerと同じ立場：

| 脅威 | Phase 1 | Phase 2 (TDX/SEV-SNP) | 責任 |
|---|---|---|---|
| 管理者権限奪取（RAT・マルウェア） | スコープ外 | **スコープ内** — 隔離VM | OS / エンドポイント |
| 物理攻撃（SPI傍受） | スコープ外（PersonBindingで緩和） | スコープ外 | チップベンダー |
| クラウドAdmin | スコープ外 | **スコープ内** — HWメモリ暗号化 | クラウドTEE |

Phase 2（TDX/SEV-SNP）でBitLockerがスコープに入れていない問題を解く。

### ポジショニング

hydeはBitLockerの代替ではない。比較対象ですらない：

| | BitLocker | hyde |
|---|---|---|
| 守るもの | ディスク全体 | アプリデータ（オブジェクト単位） |
| 暗号化 | AES（古典） | ML-KEM-768 + AES-256-GCM（耐量子） |
| API | なし（OS級） | `ctx.protect(secret)?` — 一行 |
| プラットフォーム | Windows only | Linux, Windows（Phase 3: macOS, mobile） |
| 粒度 | ボリューム | `protect()` 呼び出し単位 |

### 各モジュールの限界

これらの限界は欠陥ではなく、どんな暗号技術も超えられない本質的な制約：

| モジュール | 限界 | 補完 |
|---|---|---|
| hyde | 管理者はDoS（サービス停止）は可能だが、鍵取り出しは不可能（FixedTPM） | Phase 2 (TDX/SEV-SNP) でランタイムメモリ保護を追加 |
| plat | 入力の真正性は保証できない | IoT + TPM (hyde) |
| argo | 現実世界との一致は証明できない | オラクル問題 — 根本的制約 |

### 物理→ブロックチェーン接続（エコシステム完成形）

```
TPMチップ（物理・製造時にEK焼き付け）
  ↓ ハードウェア署名（hyde）
データ・写真・CO2排出量（デジタル）
  ↓ ゼロ知識証明（argo）
ブロックチェーン（改ざん不可能な永続記録）
```

「物理世界の信頼をデジタル世界に接続する橋」

応用：
- CO2排出量の秘匿計算（Scope3算定）
- 写真の真正性証明（C2PA代替）
- 医療カルテの患者主体管理
- 自動車走行データ × 税制
- 年齢確認の秘匿証明

### argoの入力バリデーション層構造

「ゴミを入れればゴミが出る」問題への対処：

```
Layer 0：IoTセンサー + TPM（hyde）
  物理世界の測定値をハードウェアで署名
  → 虚偽値申告を防ぐ

Layer 1：ZKP（argo）+ FHEフォーマット証明
  暗号化時にフォーマットの正しさをZKPで証明
  → ゴミデータを暗号化前に排除
  参考：TFHE-rsのZKP機能・ZHE（IEEE S&P 2025）

Layer 2：plat（FHE）
  暗号化されたまま集計演算

Layer 3：argo（ZKP）
  計算プロセスの正しさを証明
```

| Layer | 防ぐもの | 防げないもの |
|---|---|---|
| 0 (IoT + TPM) | 虚偽申告 | センサー誤差（ベンダー責任） |
| 1 (ZKP format) | 不正フォーマット | 意味的な誤り |
| 2 (FHE) | データ露出 | 入力真正性 |
| 3 (ZKP proof) | 計算不正 | 入力の真実性 |

Layer 0で物理的に防ぐ → Layer 1でフォーマット的に防ぐ → Layer 2・3では計算の正しさのみを担保。

### WitnessRecovery（立会人復元）

N-of-M シャミア秘密分散＋複数デバイスバインド。

```
復元要求
  ↓
立会人デバイスにプッシュ通知
  ↓
承認ボタン（生体認証）
  ↓
N-of-M達成 → 自動復元
  ↓
監査ログ自動生成（誰がいつ承認したか）
```

条件メタデータは公開設計。攻撃者が「誰が持っているか」を知っても、シャードを物理取得しない限り意味がない。

セキュリティグレード設計：
```rust
// Level 1：一般ユーザー
ctx.protect(secret)?;

// Level 2：企業・組織
ctx.protect(secret)
    .with_witness(3, witnesses)?;

// Level 3：政府・防衛
ctx.protect(secret)
    .with_witness(3, witnesses)
    .with_duress_pin()?;
```

解決する問題：
- **物理破壊問題**：復元経路をOR条件で複数層。単一障害点排除。
- **金庫問題（内部犯行）**：N-of-M設計により単独での不正アクセスが構造的に不可能。
- **強制承認問題**：技術ではなくポリシーで解決。ゼロ交渉原則。

### 既知の物理攻撃一覧

hydeはこれらの攻撃を認識している。物理攻撃であり、ソフトウェアでは防げない：

| 攻撃 | 対象 | コスト | hydeの立場 |
|---|---|---|---|
| SPI bus sniffing | dTPM | ~$300, 10min | ソフト緩和: PersonBinding (v0.3) |
| Cold boot attack | DRAM | ~$50, 5min | スコープ外。Phase 2 TDX/SEVで緩和 |
| faulTPM / Voltage glitching | fTPM | ~$200, hours | スコープ外。CPUベンダー責任 |
| Decapping / Microprobing | dTPMチップ | $10K+, days | スコープ外。チップベンダーの耐タンパ |
| EM side-channel | TPM/CPU | $1K+, hours | スコープ外。チップのシールディング |
| Power analysis (DPA/SPA) | TPM | $5K+, hours | スコープ外。チップの対策 |
| JTAG / Debug port | SoC | $100, min | スコープ外。OEMが本番で無効化すべき |
| Evil maid | マザーボード | $500+, min | スコープ外。物理アクセス管理 |
| Rowhammer | DRAM | $0, hours | スコープ外。ECC memoryで緩和 |
| Bus interposer (MitM) | PCIe/SPI | $1K+, hours | スコープ外。物理バス完全性 |

これらはhydeの欠陥ではない。ソフトウェアが終わり、物理が始まる境界。

## 参考資料

- [tss-esapi crate](https://docs.rs/tss-esapi/)
- [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [swtpm - Software TPM Emulator](https://github.com/stefanberger/swtpm)
- [BitLocker Overview — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
- [Azure Confidential Computing — Intel TDX](https://learn.microsoft.com/en-us/azure/confidential-computing/)
- TFHE-rs ZKP features: Zero-knowledge proofs for FHE ciphertext validity
- ZHE (IEEE S&P 2025): Zero-knowledge proofs for homomorphic encryption

---

## ライセンス

MIT License
