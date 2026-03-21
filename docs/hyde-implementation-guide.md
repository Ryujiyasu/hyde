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

## 参考資料

- [tss-esapi crate](https://docs.rs/tss-esapi/)
- [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [swtpm - Software TPM Emulator](https://github.com/stefanberger/swtpm)

---

## ライセンス

MIT License
