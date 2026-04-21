# hyde Roadmap / hydeロードマップ

> このドキュメントは今日の議論（2026年3月）で大幅に更新されました。

---

## Vision / ビジョン

**「データを一切公開せずに社会的な信頼を構築する」**

データには3つの状態だけでなく、3つの操作がある：

| 操作 | モジュール | 技術 |
|---|---|---|
| 守る | hyde | TPM + PQC |
| 証明する | argo | ZKP |
| 計算する | plat | FHE / GPU TEE |

---

## Phase 1: TPM 2.0 ✅ 完了

### 実装済み機能

- TPM接続 + セッション管理
- Primary Key生成 + 永続化
- Data Key生成 + ラッピング（BitLockerパターン）
- Seal / Unseal（AES-256-GCM）
- ML-KEM-768 PQC暗号化（常時有効）
- 二層暗号化: PQC（内側）+ TPM（外側）
- ProtectedData シリアライズ（serde）
- PassphraseRecovery（Argon2id）
- HydeContext public API
- auto_detect() ファサード
- SoftwareBackend スタブ
- 統合テスト 15件（swtpm）
- PCR policy binding（PCR 0 + 7）
- `#[hyde::protect]` proc macro + `Protected<T>`
- CI/CD（GitLab CI + swtpm）
- crates.io 公開（hyde v0.1.0）

### Phase 1の守備範囲と限界

**守れるもの：**
- ディスク盗難
- 物理攻撃（dTPMはSPIバス盗聴リスクあり → Phase 1.5で対処）

**守れないもの（設計上の制約）：**
- クラウドAdmin・ハイパーバイザーからのメモリアクセス
  → Phase 2（TDX/SEV-SNP）で解決

> この制約はBitLockerと同じです。
> BitLockerもTPM単体ではクラウドAdminから守れません。

---

## Phase 1.5: janus（PersonBinding層） ← 次の優先事項

### 背景

dTPM（外付けTPMチップ）環境では、
TPM-onlyモードはSPIバス盗聴攻撃に対して脆弱です。

```
攻撃コスト：$300のロジックアナライザー + 10分の物理アクセス
攻撃結果：dkが平文で取得可能 → 全DataKey復号可能
```

READMEに「特定のデバイス＋特定の人物」と書いているが、
TPM-onlyでは「人物」バインディングが実現できていない。

### janusプロジェクト

人物バインディングは独立crateとして `janus` で実装する。
hyde以外のプロジェクトでも利用可能な汎用 `UserBinding` 抽象化。

- リポジトリ: `gitlab.com/Ryujiyasu/janus`
- 詳細設計: [docs/research/windows-hello.md](research/windows-hello.md)

### 設計不変条件

**janus は存在判定であり、鍵の保護は TPM/SE が担う。**

Windows Hello の WinBioDatabase が DPAPI-seal のみで TPM 封印されて
いない（Black Hat 2025「Windows Hell No」で露呈）という構造的欠陥を
踏まえ、janus はプレゼンスゲートに徹する。鍵の最終保護境界はあくまで
hyde の TPM 鍵。janus 層が侵害されても鍵マテリアルには到達しない。

### プラットフォーム別バックエンド

| OS | バックエンド | 実装状況 |
|---|---|---|
| Windows | `UserConsentVerifier` (Win Hello gate型) | Phase 1.5 |
| Windows | `KeyCredentialManager` (bind型, NGC署名を鍵ラップに組み込む) | Phase 2 に先送り |
| macOS | `LAContext.evaluatePolicy(deviceOwnerAuthenticationWithBiometrics)` | Phase 1.5 |
| Linux | libfido2 (YubiKey等外部authenticator) + PIN | Phase 1.5 |
| Linux | fprintd 統合（テンプレ平文保存問題のため） | 採用見送り |
| 全般 | `JanusNull`（CI/テスト用） | Phase 1.5 |

### UserBinding trait（janus側）

```rust
pub trait UserBinding: Send + Sync {
    /// ユーザ存在を要求（gate型）
    fn require_presence(&self, reason: &str) -> Result<PresenceToken, JanusError>;

    /// 署名（bind型、Phase 2以降）
    fn sign_with_presence(
        &self,
        key_id: &KeyId,
        challenge: &[u8],
        reason: &str,
    ) -> Result<Vec<u8>, JanusError>;

    fn enroll(&self, key_id: &KeyId) -> Result<(), JanusError>;
    fn is_enrolled(&self, key_id: &KeyId) -> Result<bool, JanusError>;
    fn capabilities(&self) -> BindingCapabilities;
}

pub struct BindingCapabilities {
    pub hardware_bound: bool,
    pub biometric_available: bool,
    pub pin_fallback: bool,
    pub attestation_supported: bool,
}
```

### hyde側の統合API

```rust
pub enum PersonBinding {
    /// TPM + PIN（BitLocker TPM+PIN相当、janus非依存）
    Pin,
    /// TPM + Passphrase
    Passphrase,
    /// janusバックエンドによる人物バインディング
    Janus(Box<dyn UserBinding>),
}

let ctx = hyde::auto_detect(FallbackPolicy::Deny)?
    .with_person_binding(PersonBinding::Janus(
        janus::auto_detect()?,
    ))?;

// 既存API非破壊のため別エントリも提供
ctx.unprotect_with_janus(&protected, &binding)?;
```

### セッション/キャッシュ管理

- `UserPresenceCache { verified_at, ttl, binding }` をメモリ上のみに保持
- TTL 5〜15分（default 5分）。鍵ローテーション等の高機密操作は無視
- `SessionBinding` にプロセスID / HWND / ログオンセッションLUID を含め別プロセス流用を防ぐ
- `WTS_SESSION_LOCK` 等で強制失効
- cache 自体を `zeroize`

### fTPM vs dTPM の扱い

```rust
pub enum TpmKind {
    Firmware,  // CPU内蔵 (Intel PTT, AMD fTPM) - SPI傍受不可
    Discrete,  // 外付けチップ - SPI傍受リスクあり
    Unknown,
}

// auto_detect()がTPM種別を検出し、
// dTPM環境ではjanusによるPersonBindingを強く推奨する
```

### FallbackPolicy改善（v0.2）

```rust
pub enum FallbackPolicy {
    Deny,            // 本番用（TPMなし → エラー）
    AllowForTesting, // CI/CD用（旧Allowから改名）
}

pub enum BackendKind {
    Tpm,
    SoftwareOnly,
}

impl HydeContext {
    pub fn backend_kind(&self) -> BackendKind { ... }
    pub fn tpm_kind(&self) -> TpmKind { ... }
}
```

### 長期構想: Linux版「改良Windows Hello」

短期は libfido2+PIN で必要十分。長期的には、Windows Hello の最大の
設計ミス（WinBioDBをTPMに封印しなかった）を避け、**テンプレDBを
TPM policy (PCR or auth value) で封印する** Linux ネイティブの生体
認証基盤を janus のサブプロジェクトとして構想する。libfprint への
patch, TPM policy session 設計, systemd/PAM 統合を含む大規模案件の
ため別プロジェクト化の見込み。

---

## Phase 2: Intel TDX / AMD SEV-SNP（Cloud TEE）

### なぜ必要か

PCRポリシーはブート整合性の検出に有効だが、
クラウドAdminのメモリアクセスには無力。

```
PCRが守れるもの：
  ブートローダー改ざん、ディスク差し替え

PCRが守れないもの：
  VMスナップショット、ハイパーバイザーからのメモリダンプ
  → クラウドAdmin攻撃
```

TDX/SEV-SNPはハードウェアレベルでメモリを暗号化し、
ハイパーバイザー自身も中身を読めない。

### 実装方針

```rust
// hyde-tdx crate
// hyde-sev crate

// TeeBackendトレイトをTDX/SEV-SNPに実装
// → auto_detect()が環境を検出して自動選択
```

### Remote Attestation

Phase 2の核心機能。

```
ユーザー「このTDX環境で動いているhydeが
         正規のコードであることを証明してください」

hyde「ここに暗号学的証明（Quote）があります。
     Intel/AMDのRoot of Trustで検証できます」
```

---

## Phase 3: Apple Secure Enclave / ARM TrustZone（Mobile）

### ターゲット

- iOS / macOS: Secure Enclave
- Android: ARM TrustZone / StrongBox

### モバイルでの独自価値

```
モバイルユーザーの医療データを
Secure Enclaveで保護したまま
クラウドのFHE AIで診断する

→ hyde（Mobile）+ plat（Cloud）の連携
```

---

## Phase 4: NVIDIA H100 Confidential Computing（GPU TEE）

### H100の革新性

H100は世界初のTEE対応GPUです（2023年〜、2024年6月GA）。

**従来の問題：**
```
CPU TEE（TDX/SEV-SNP）
  → CPUメモリは保護できる
  → GPUへのデータ転送時に平文になる ← 穴
```

**H100 Confidential Computing：**
```
CPU TEE + GPU TEE
  → PCIeバス上のデータも暗号化（bounce buffer）
  → GPU内部も保護
  → 端から端まで暗号化
```

### パフォーマンス

LLM推論タスクでのTEEモードオーバーヘッドは
典型的なクエリで5%以下。実用的。

### hydeとの統合

```
hyde Phase 2（CPU TEE）+ Phase 4（GPU TEE）
= 完全なConfidential AI

CPU: TDX/SEV-SNP でOSレベル保護
GPU: H100 CC でAI計算レベル保護
```

### 独自性

NVIDIAのエコシステムはクローズド。
hydeがオープンソースの抽象化レイヤーとして
H100を統合することで、ベンダーロックインを防ぐ。

```rust
// hyde-h100 crate（計画）
let ctx = hyde::auto_detect(FallbackPolicy::Deny)?
    .with_gpu_tee(GpuBackend::H100)?;
```

---

## Phase 5: IoT Secure Elements

- Microchip ATECC608
- NXP SE050
- ARM TrustZone-M

### ユースケース

```
工場のIoTセンサー → hyde（TrustZone-M）で暗号化
  → クラウドへ送信（hyde保護）
  → plat（FHE）で集計分析
  → 工場は生データを渡していない
```

---

## Phase 6: argo（ZKP）

### 背景と独自性

ZKPはブロックチェーン領域では実用段階だが、
政府・公共領域への社会実装は空白地帯。

**空白の理由：信頼の根拠がない。**

```
ブロックチェーンのZKP：信頼の根拠 = ブロックチェーン
政府・企業のZKP：信頼の根拠 = ???
                              ↑ ここにTPMが入る
```

argoはhydeのTPM信頼チェーンを根拠にすることで、
政府・公共領域へのZKP社会実装を実現する。

### 設計方針

```
方針A: ZKPプリミティブのラッパー（開発者がcircuitを書く）
方針B: 証明テンプレート（よく使う証明を事前定義）
→ 方針Bを採用。社会実装への近道。
```

### API設計

```rust
use argo::proofs::AgeProof;

// 「20歳以上」を証明（生年月日は見せない）
let proof = AgeProof::prove(
    birth_date,       // 秘密のwitness
    threshold: 20,    // 公開条件
    hyde_ctx: &ctx,   // TPMで身元を担保
)?;

// 検証側（生年月日を知らなくても検証できる）
AgeProof::verify(&proof, threshold: 20)?;
```

### 証明テンプレート（優先実装順）

| テンプレート | 証明内容 | 見せないもの |
|---|---|---|
| AgeProof | 年齢が閾値以上 | 生年月日・氏名 |
| IncomeRangeProof | 所得が範囲内 | 正確な金額 |
| CredentialProof | 資格・免許の保有 | 個人情報 |
| NationalityProof | 国籍 | 住所・番号 |
| MembershipProof | グループメンバー | 個人情報 |

---

## Phase 7: plat（FHE / GPU TEE）

### FHEの正しい理解

FHEは「遅い」のではなく「ユースケースが違う」。

```
スピードが重要：決済（0.1秒）、音声認識（RT）
  → FHEは使えない

スピードが不要：医療診断（1日待てる）、税務計算（月次）
  → FHEが使える
```

**FHEの本質的な価値：**
「今まで渡せなかったデータを計算させられる」

### 2つの実装経路

**plat v1: FHE**
```
特徴：完全な暗号化計算
速度：10秒〜数分
用途：医療診断、税務計算、統計集計
```

**plat v2: H100 Confidential Computing**
```
特徴：TEEで保護したままAI計算
速度：通常の5%オーバーヘッド
用途：LLM推論、画像診断AI、リアルタイム分析
```

### API設計

```rust
// plat v1: FHE
let encrypted_result = plat::fhe::compute(
    &encrypted_data,
    circuit: MedicalDiagnosisCircuit,
)?;

// plat v2: H100 CC
let encrypted_result = plat::gpu::compute(
    &encrypted_data,
    model: "cancer_risk_v3",
    backend: GpuBackend::H100,
)?;
```

---

## エコシステム統合図（最終形）

```
┌─────────────────────────────────────────────────┐
│              Application Layer                   │
└──────────┬──────────────┬───────────────────────┘
           │              │              │
    ┌──────▼──────┐ ┌─────▼─────┐ ┌────▼──────┐
    │    hyde      │ │   argo    │ │   plat    │
    │  TPM + PQC   │ │    ZKP    │ │ FHE/H100  │
    │    守る       │ │  証明する  │ │  計算する  │
    └──────┬───────┘ └─────┬─────┘ └────┬──────┘
           │               │             │
    ┌──────▼───────────────▼─────────────▼──────┐
    │              hyde-core                      │
    │         TPM Trust Chain                     │
    │    （全モジュールの信頼の根拠）               │
    └─────────────────────────────────────────────┘
           │
    ┌──────▼────────────────────────────────────┐
    │              Backend Layer                  │
    │  TPM 2.0 | TDX | SEV-SNP | H100 | SE | TZ │
    └────────────────────────────────────────────┘
```

---

## 世界でこのビジョンを理解できる人

```
TPM + PQC + ZKP + FHE + 社会実装ビジョン
すべてを理解している人：世界で数百人レベル

各分野のトップ研究者でも隣の分野は知らないことが多い：
- TPM専門家はFHEを知らない
- FHE研究者はTPMを触ったことがない
- ZKP開発者はRustが書けない

hydeエコシステムはこの分断を繋ぐ。
```

**旗を立てる人と実装する人は別でいい。**
Linusはファイルシステムの専門家ではなかった。
