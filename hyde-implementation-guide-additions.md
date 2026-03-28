# hyde Implementation Guide 追記内容

今日の議論で明確になった実装上の知見を追記する。

---

## Section A: 鍵管理設計の根拠

### BitLockerから学んだこと

hydeの鍵管理設計はBitLockerの15年の知見を踏襲している。
以下の一次資料を参照のこと：

- [MS-FVE仕様](https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc)
- [TPM-based BitLocker Deep Dive](https://itm4n.github.io/tpm-based-bitlocker/)
- [BitLocker SPI Sniffing Attack](https://labs.withsecure.com/publications/sniff-there-leaks-my-bitlocker-key)

### 設計上の重要な決定

**決定1: dkはディスク + TPMシール（Option A）**

理由：
- BitLockerも同じ設計（VMKをディスク上のFVEメタデータに保存）
- TPM NV枯渇を防ぐ（ML-KEM-768のdkは2400bytes）
- PQCチップ移行時のre-sealコストが最小

却下した選択肢：
- Option B（TPM NVに直接保存）: NV容量不足、故障リスク
- Option D（1デバイス1鍵再利用）: Forward Secrecyなし

**決定2: DataKeyはprotect()ごとに生成**

理由：
- Forward Secrecy（DataKey_Aが漏れてもBは安全）
- AES-256 DataKey生成はゼロコスト（マイクロ秒）
- TPM操作は不要（軽い）

**決定3: PQCチップ移行時の設計**

```
移行前: dk → TPMシール(AES-256-GCM) → blob
移行後: dk → PQCチップシール → blob

移行手順：
1. ctx.rotate_key()を呼ぶ
2. 新しいdkをPQCチップでre-seal
3. データ本体は一切触らない

dkが1個なのでre-sealは1回で済む。
```

---

## Section B: Protected<T>設計ガイド

### 設計原則

**原則1: Derefを実装しない**

```rust
// ❌ やってはいけない
impl<T> Deref for Protected<T> {
    type Target = T;
    fn deref(&self) -> &T { /* 暗黙のunprotect */ }
}

// 問題：
// - TPMアクセスが暗黙に発生
// - エラーハンドリング不能
// - zeroizeのタイミング制御不能
```

**原則2: Zeroizingで平文の寿命を制御する**

```rust
use zeroize::Zeroizing;

impl<T: Zeroize> Protected<T> {
    pub fn unprotect(
        &self,
        ctx: &mut HydeContext,
    ) -> hyde::Result<Zeroizing<T>> {
        let plain = /* TPM + PQC復号 */;
        Ok(Zeroizing::new(plain))
    }
}

// スコープを抜けると自動ゼロ埋め
{
    let plain = record.unprotect(&mut ctx)?;
    process(&plain);
} // ← ここでRAMからゼロ埋め
```

**原則3: with_unprotectedでスコープ限定復号**

```rust
impl<T: Zeroize> Protected<T> {
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
        // plainはここでゼロ埋め
    }
}

// 使用例
record.with_unprotected(&mut ctx, |data| {
    send_to_doctor(&data.diagnosis)
})?;
```

### HydeContextの取得パターン

**現在（Phase 1）: パターンA**

```rust
// リクエストごとにctxを生成
let mut ctx = hyde::auto_detect(FallbackPolicy::Deny)?;
let plain = record.unprotect(&mut ctx)?;
```

シンプルで今はこれでOK。
TPMセッション確立のコストが問題になったらパターンCへ。

**将来（Phase 2）: パターンC - DecryptPermitトークン**

```rust
pub struct DecryptPermit<'a> {
    ctx: &'a mut HydeContext,
    // lifetimeでコンパイラが有効期間を保証
}

impl HydeContext {
    pub fn with_permit<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(DecryptPermit<'_>) -> R,
    {
        f(DecryptPermit { ctx: self })
    }
}

// 使用例：TPMセッションが1回で複数unprotect可能
ctx.with_permit(|permit| {
    let a = record_a.unprotect(&permit)?;  // セッション再利用
    let b = record_b.unprotect(&permit)?;  // セッション再利用
    audit_log("decrypted", who, when);
    process(a, b)
})?;
// permitスコープ外ではunprotect不能
```

パターンCのメリット：
- TPMセッションが1回で済む（パフォーマンス向上）
- 「誰がいつ復号できるか」をコンパイラが強制
- 監査ログの挿入点が明確

**採用しないパターン: Arc<Mutex<HydeContext>>**

```rust
// ❌ グローバル共有はやらない
static CTX: Mutex<HydeContext> = ...;

// 問題：
// ctxを持っていれば誰でもどこでも復号できる
// 権限の境界が消える
// BitLockerのTPM-onlyが陥った問題と同じ構造
```

---

## Section C: FallbackPolicy運用ガイド

### CI/CDでの推奨構成

テストを3層に分離することで、
swtpm不要のテストを高速で実行できる。

```yaml
# .gitlab-ci.yml

# Layer 1: 高速・TPM不要（毎PRで実行・並列可能）
test-unit:
  script:
    - cargo test --workspace --lib -- --test-threads=4
  # PQC暗号化、シリアライズ、KDF計算など

# Layer 2: swtpm使用（毎PRで実行・シリアル）
test-integration:
  script:
    - mkdir /tmp/swtpm
    - swtpm socket --tpmstate dir=/tmp/swtpm
        --ctrl type=tcp,port=2322
        --server type=tcp,port=2321
        --tpm2 --daemon
    - swtpm_ioctl --tcp 127.0.0.1:2322 -i
    - export TCTI="swtpm:host=127.0.0.1,port=2321"
    - cargo test --workspace --test -- --test-threads=1

# Layer 3: 実TPM（mainブランチのみ）
test-hardware:
  script:
    - cargo test --workspace -- --test-threads=1
  tags:
    - hardware-tpm  # 実TPM搭載のGitLab Runner
  only:
    - main
```

### BackendKindによる本番検証

```rust
// 本番デプロイ時のアサーション
fn initialize_context() -> hyde::Result<HydeContext> {
    let ctx = hyde::auto_detect(FallbackPolicy::Deny)?;

    // 本番環境では必ずTPMバックエンドであることを確認
    match ctx.backend_kind() {
        BackendKind::Tpm => {
            tracing::info!("TPM backend initialized: {:?}", ctx.tpm_kind());
        }
        BackendKind::SoftwareOnly => {
            // 本番でここに来たら即座にパニック
            panic!("SoftwareBackend is not allowed in production");
        }
    }

    Ok(ctx)
}
```

---

## Section D: PCR Policy設計ガイド

### PCRが守るもの・守らないもの

```
PCRが守れるもの（ブート整合性）：
  - ディスクの差し替え
  - ブートローダーの改ざん
  - Secure Boot設定の変更

PCRが守れないもの（実行時攻撃）：
  - OSが動いている間のメモリダンプ
  - ハイパーバイザーからのVMスナップショット
  - DMA攻撃
  ↑ クラウドAdmin攻撃はここに含まれる
```

### BitLockerのPCR選択から学ぶ

Secure Boot有効時のデフォルト: **PCR 7 + PCR 11**

- PCR 7: Secure Boot Policy
- PCR 11: Windows Boot Manager（BitLocker access control用）

**PCR 11の重要性：**
PCR 11はWindows Boot Managerだけがdkをunsealできることを保証する。
これがTPM-onlyモードでも一定のセキュリティを担保している。

hydeでのPCR設計指針：

```rust
// 推奨: Secure Boot環境
PCR_POLICY = [7, 11]  // Secure Boot + アクセス制御

// 代替: Secure Boot非対応環境
PCR_POLICY = [0, 2, 4]  // BIOS + UEFI + BootManager
```

### クラウド環境でのPCR

クラウドVM（TDX/SEV-SNP）では物理PCRではなく
vPCR（仮想PCR）が使われる。

Phase 2（TDX/SEV-SNP）実装時に
Remote Attestationと組み合わせて設計する。

---

## Section E: NVIDIA H100 統合ガイド（Phase 4）

### H100 Confidential Computingの仕組み

```
CPU TEE（TDX/SEV-SNP）
  ↓ encrypted bounce buffer（PCIeバス）
GPU TEE（H100 CC-On mode）
  ↓ GPU内部メモリ（暗号化）
CUDA Kernel実行
```

### 前提条件

- CUDA 12.4以降（r550ドライバー）
- CPU: AMD SEV-SNPまたはIntel TDX対応
- OS: Ubuntu 24.04 LTS + Linux kernel 6.8以降

### Remote Attestation

H100は起動時に暗号学的署名付きの
Attestation Reportを生成する。

```
NVIDIA Root of Trust
  ↓ 証明書チェーン
H100 Identity Key（製造時にfuseに書き込み）
  ↓ 署名
Attestation Report（現在の状態）
```

IntelとNVIDIAは複合Attestationを提供：
「このCPU TEE + このGPUが動いている」を一回で証明できる。

### hydeバックエンドとしての設計

```rust
// hyde-h100 crate（Phase 4）
pub struct H100Backend {
    gpu_device: CudaDevice,
    attestation: GpuAttestation,
}

impl TeeBackend for H100Backend {
    fn protect(&mut self, data: &[u8]) -> Result<ProtectedData> {
        // H100のTEEモードで暗号化
    }

    fn unprotect(&mut self, data: &ProtectedData) -> Result<Vec<u8>> {
        // H100のTEEモードで復号
    }
}
```

---

## Section F: ZKP（argo）統合設計

### 信頼の根拠としてのTPM

```
従来のZKP：
  「私はXという条件を満たす」
  → 信頼の根拠が不明確

hyde + argo：
  「私（TPM検証済みデバイス・人物）は
   Xという条件を満たす」
  → TPMがRoot of Trust
```

### 証明テンプレートの設計方針

開発者がZKPのcircuitを書く必要がない設計にする。

```rust
// argo crate（Phase 6）

// 年齢確認プリミティブ
pub struct AgeProof;
impl AgeProof {
    pub fn prove(
        birth_date: Date,   // 秘密のwitness
        threshold: u32,     // 公開条件
        ctx: &HydeContext,  // TPM信頼チェーン
    ) -> Result<Proof> { ... }

    pub fn verify(
        proof: &Proof,
        threshold: u32,
    ) -> Result<bool> { ... }
}
```

### 日本政府ユースケース（優先ターゲット）

| ユースケース | 既存の方法 | argoによる改善 |
|---|---|---|
| マイナンバー確認 | 番号を開示 | 番号を見せずに日本国民と証明 |
| 年齢確認 | 生年月日を開示 | 年齢だけ証明 |
| 所得証明 | 源泉徴収票を提出 | 範囲内であることだけ証明 |
| 医師資格確認 | 免許証を提示 | 個人情報なしに資格保有を証明 |

---

## Section G: hydeエコシステム実装戦略

### 全体方針

3モジュールすべてMITライセンス・Pure Rustを目標とする。
手段（ゼロから・ラッパー）にはこだわらず、以下3点で判断する：

1. 早く動くものが作れるか
2. MITで公開できるか
3. hydeと統合できるか

### hyde（Phase 1 完成済み）

**方針：ゼロから書く（維持）**

- TPM抽象化層は既存ライブラリがない → Raの競争優位
- crates.io公開済み・テスト通過
- MIT / Pure Rust / クロスプラットフォーム

### argo（Phase 6 未実装 → 次に実装）

**方針：arkworks（MIT/Apache 2.0）をベースにhydeとの統合APIを作る**

- arkworks-rs: Pure Rust / MIT互換 / Groth16・PLONK・Marlin対応
- 2025年も活発に開発中

**platより先に実装する理由：**
- arkworksベースなので早く動くものが作れる
- hyde + argoだけで年齢証明・所得証明が完結する（plat不要）
- 日本政府のマイナンバー文脈で今すぐ刺さる
- platは研究公募の結果待ちがある

argoが提供する価値：
- hydeとの統合（TPM信頼チェーンでZKP）
- platとの統合（FHEフォーマット証明・ZHE参考）← Phase 8で追加
- IoTデバイス署名の検証
- MITで公開可能

argoが作らないもの：
- ZKPプリミティブ / 楕円曲線実装 / SNARK証明システム自体

### plat（Phase 7 未実装 → 研究公募結果後に開始）

**方針：Pure Rust CKKSをゼロから書く（汎用ライブラリとして）**

スコープ：汎用CKKS基本演算
- CKKS Add / Multiply / Relinearize
- Bootstrappingは初期スコープ外
- Scope3 CO2算定はサンプルアプリとして提供（plat本体はScope3に特化しない）

既存ライブラリ（OpenFHE・SEAL）は「教科書として読む」だけ。
コードは取り込まない。

ゼロから書く理由：
- hyde/argo統合を持つCKKS実装は存在しない
- 既存のPure Rust CKKS実装（Poulpy: Apache-2.0、ckks-engine等）は存在するが、
  TPM信頼チェーンやZKP統合を前提とした設計ではない
- TFHE-rs: 特許リスク（BSD-3-Clause-Clear）、CKKS非対応
- OpenFHE: C++依存、Rustバインディング放置（2024年10月以降停止）
- SEAL: C++依存、Rustバインディングはスター2の個人PJ
- C++ FFIはhydeのPure Rust設計哲学に反する

性能要件：
- 想定スケール：1000社 × 1日以内（バッチ処理）
- Scope3算定は月次・四半期ごと。リアルタイム性は不要
- この前提により：パラメータを安全側に振れる、NTT高速化に拘らなくていい

安全性の担保：
- **実装前にSEALとのクロスバリデーション手順を設計する**（テストベクタ生成・比較方法を先に決める）
- Kaniによる形式検証（オーバーフロー・パニック）
- 国の研究公募で監査予算を確保
- 研究期間中：国内大学/OIST暗号研究者によるレビュー
- プロダクション前：Trail of Bits による正式監査（レポート公開）

研究としての価値：
- TPM信頼チェーン（hyde）+ ZKP（argo）+ FHE（plat）の統合は世界初
  （CKKS単体の新規性ではなく、エコシステム統合が新規性）
- Kaniによる形式検証で実装の正しさを証明（バッファオーバーフロー・型不変条件等）
  ※形式検証は暗号スキームの安全性（IND-CPA等）の証明ではない。暗号安全性は別途外部監査で担保
- 「形式検証済みFHE実装 + hyde/argo統合」の組み合わせが論文化の軸

platが提供する価値：
- 汎用CKKS基盤（Scope3に限定しない）
- hydeとの統合（暗号鍵をTPMで管理）
- argoとの統合（FHEフォーマット証明）← Phase 8で追加
- MITで公開可能

platのサンプルアプリ：
- examples/scope3/: CO2算定デモ
- examples/medical/: 医療データ集計デモ

### 実装順序

```
Phase 6: argo（arkworksベース）
  → hyde + argoで年齢証明・所得証明を市場投入

Phase 7: plat（汎用Pure Rust CKKS・ゼロから）
  → 研究公募結果後に開始
  → 1000社×1日のバッチ処理を想定

Phase 8: argo + plat統合
  → FHEフォーマット証明をargoに追加
```

### 5層防御アーキテクチャ

```
Layer 0: IoT + hyde（TPM+PQC）
  → 「誰が測定したか」を証明（虚偽値申告を防ぐ）

Layer 0.5: TSA（RFC 3161）/ ブロックチェーンアンカリング
  → 「いつ測定したか」を証明（タイムスタンプの信頼性）
  → TPM内部時計は信頼できない（リセット可能）ため外部信頼源が必要

Layer 1: argo（ZKP）+ FHEフォーマット証明
  → 「データフォーマットが正しい」を証明（ゴミデータを排除）

Layer 2: plat（FHE）
  → 暗号化されたまま集計演算（プライバシーを守る）

Layer 3: argo（ZKP）
  → 「計算プロセスが正しい」を証明（改ざんを防ぐ）
```

入口から出口まで守る。

### ライセンス戦略

| モジュール | ライセンス | 状態 |
|-----------|-----------|------|
| hyde | MIT | 済 |
| argo | MIT | arkworksがMIT互換 |
| plat | MIT | ゼロから書くことで確保 |

**使わないもの：**
- TFHE-rs（BSD-3-Clause-Clear + 商用有償 → 特許汚染リスク）
- OpenFHE/SEALのコード取り込み（C++依存 → Pure Rust方針に反する）

### 監査戦略

| フェーズ | 監査者 | 目的 |
|---------|--------|------|
| 研究期間中 | 国内大学 / OIST暗号研究者 | 共同研究としてレビュー |
| プロダクション前 | Trail of Bits（米） | 正式監査・レポート公開 |
| 代替候補 | NCC Group（英）/ Cure53（独） | Trail of Bitsが不可の場合 |

---

## Section H: タイムロック暗号設計

### 設計原則

hydeのタイムロックは外部の信頼された時刻サービス（drand / RFC 3161 TSA）と連携することで実現する。

hyde単体では正確な時刻指定はできない。「数学的に不可能」ではなく「信頼された時刻サービスが指定時刻まで復号鍵を公開しない」設計である。

**Timelock puzzles（Rivest-Shamir-Wagner 1996）を採用しない理由：**
- 「N回の逐次計算をしないと解けない」→ 解読時間がハードウェア性能依存
- 2026年のGPUと2030年のGPUで時間が変わる
- 「2026年4月1日に開く」とは指定できない → 「だいたいN年かかる」としか言えない

### 正確な表現（過剰主張の防止）

| よくある主張 | 正しい表現 |
|-------------|-----------|
| 数学的に時間まで開けない | drand連携で指定時刻まで復号鍵を取得できない |
| 管理者でも変更できない | TPM保護された閾値暗号により単一管理者では変更不能 |
| 自動消滅（期限後に復号不可能） | **削除。暗号学的に不可能。** 鍵がコピー・メモリダンプされていたら制御不能。代替表現：「TPM内の鍵消去によりTPM経由の復号を不可能にする」|

### 実装設計

```rust
hyde.protect(
    data,
    policy: {
        // 実現可能（TPM + Shamir秘密分散）
        devices: [pc_tpm, phone_tpm],  // 閾値2-of-2
        biometric: true,                // TPMに格納

        // 実現可能（外部サービス連携）
        time_lock: {
            provider: "drand",          // League of Entropy
            unlock_round: 12345,        // 時刻ではなくラウンド番号
        },

        // 補助条件（信頼の根拠にしない）
        location: office_wifi,          // MACスプーフィング可能
    }
)
```

**locationの扱い：** WiFi/GPSベースの位置情報は偽装可能（MACスプーフィング、GPSスプーフィング）。UX上の利便性として提供するが、セキュリティの根拠にはしない。ドキュメントでも「補助条件」と明記する。

### ユースケース（正確な表現で）

| ユースケース | 実現方法 | 制約 |
|-------------|---------|------|
| M&A極秘文書：開示解禁日まで | drand連携タイムロック + TPM閾値 | drandネットワークへの信頼が前提 |
| 遺言書：条件付き開封 | TPM閾値 + 法的手続きトリガー | 完全自動化は困難、人間の介在が必要 |
| 証拠保全：改ざん不可能 | TSAタイムスタンプ + TPM署名 | 存在証明であり、削除防止ではない |

### ZKP（argo）との組み合わせ

「この文書は特定の時点以降に作成された」をargoで証明できる：
- TSAタイムスタンプをZKPのpublic inputとして使用
- 文書ハッシュとTSA署名の検証をZKP回路内で実行
- → 文書の時系列の真正性を保証（後付け作成の証明が不可能）

---

## Section I: FHE + ZKP Feasibility ベンチマーク結果

### 測定日: 2026-03-27

**環境:** NVIDIA RTX 3090 (24GB) / CUDA 13.0 / HEonGPU v1.1

**シナリオ:** 1000社のCO2データをCKKSで暗号化集計

**パラメータ:**
- poly_modulus_degree: 8192
- coeff_modulus: {60, 30, 30, 30}, P={60}
- scale: 2^30
- slot_count: 4096（SIMD、1000社分を1暗号文にパック）

### 結果

| 操作 | 時間 |
|------|------|
| 暗号化（1000値SIMD） | 2.5 ms |
| 集計（rotate+add ×10） | 0.9 ms |
| 乗算+relin+rescale | 0.2 ms |
| 復号 | 0.4 ms |
| **FHE合計** | **4.0 ms** |
| **FHE+ZKP推定（×30）** | **120 ms** |

精度誤差: 0.0008トン（0.00002%）— Scope3算定には十分。

### 比較

| 実装 | 1000社集計 | 備考 |
|------|-----------|------|
| TFHE-rs（CPU, 整数） | ~175秒 | 1個ずつ逐次加算 |
| HEonGPU（GPU, CKKS） | 0.004秒 | SIMD 4096スロット一括 |
| **差** | **43,000倍** | CKKSのSIMDバッチ処理の威力 |

### 結論

- **FEASIBLE:** 1000社の月次バッチがFHE+ZKP込みで0.12秒
- CKKSのSIMDバッチ処理がTFHEの逐次処理と構造的に異なり、桁違いに速い
- platがCKKSを選ぶ根拠が数字で確認された
- ZHEの30倍オーバーヘッドはCPU実測値であり、GPU上のZKPコストは未測定（次のベンチ対象）

### 注意点（追加検証が必要）

1. ZHEの30倍はCPU前提 — GPU上のZKPオーバーヘッドは未知
2. HEonGPUはC++/CUDA — platはPure Rustなので同等性能は出ない
3. poly_modulus_degree=8192はsec128相当 — より高いセキュリティレベルでは遅くなる
4. rotation keyの生成コスト（422ms）は含めていない（1回生成で再利用可能）

---

## Section J: 場所非依存セキュリティ

### 技術的根拠（指示書用・正確な表現）

**hydeが解いている問題：**

従来のセキュリティは「データの保存場所」が前提になっている。サーバーを守る、ネットワークを守る、DRMで守る — いずれもコピーされた時点で破綻する。

hydeはデータの保存場所をセキュリティの前提にしない。鍵がTPMハードウェアに閉じ込められているため、暗号文はどこにコピーしても復号できない。攻撃コストを物理アクセス+専門機材レベルに引き上げる。

**既存技術との差別化：**

| 既存技術 | アプローチ | hydeとの違い |
|---------|-----------|-------------|
| Microsoft Purview | Azure AD + RMSでファイル暗号化、どこにコピーしてもAzure AD認証が必要 | クラウド依存、TPM必須ではない、PQC未対応 |
| Apple FileVault + Secure Enclave | T2/M1チップに鍵を閉じ込め | デバイス単位でありファイル単位ではない |
| Virtru | メール/ファイル暗号化、鍵はVirtruサーバー管理 | 中央集権、TPMなし |
| BitLocker | TPMでディスク暗号化 | ディスク単位、ファイルコピーには無力 |
| DRM | ファイルフォーマットレベルで保護 | クラック可能、ハードウェア信頼根なし |

hydeの正確なポジション：**TPMハードウェア信頼 + PQC + オフライン動作 + ファイル単位制御を組み合わせた初のOSS実装**

**残存リスク（正直に）：**
- 物理攻撃（SPI sniffing、コールドブート）には追加対策が必要（Section A参照）
- タイムロックはオンライン（drand）必須、オフラインでは無効 — 設計上のトレードオフ
- TPM自体のサプライチェーンリスクは残る

---

## Section K: 労務・情報漏洩対策ユースケース

### ビジネス文脈（README・ピッチ資料用）

**課題：ローカルファイルは管理外**

企業のセキュリティは「サーバー上のデータ」は守れる。しかし社員がローカルにダウンロードした瞬間、管理外になる。

- USBで持ち出す
- 自宅PCにコピーする
- 退職時に持っていく
- 深夜に自宅で作業する

**hydeの解決策：「作業できる」と「持ち出せる」の分離**

| 従来 | hyde |
|------|------|
| ダウンロード = 持ち出し可能 | ダウンロード = 暗号文のコピー |
| ファイルがあれば開ける | TPMが揃った環境でのみ開ける |
| 場所で守る | 鍵で守る |

```
ローカルにコピーしても → 会社のTPMがないと開けない
USBに入れても → 開けない
クラウドにアップしても → 開けない
退職時に持ち出しても → 開けない
```

**タイムロックとの組み合わせ（drand連携時）：**

```
営業時間外 → ローカルにあっても開けない
退職日以降 → TPMポリシーを無効化、全ファイル開けなくなる
契約期間終了 → 取引先に渡したファイルも自動的に開けなくなる
```

### ターゲット顧客

| セグメント | 刺さるポイント |
|-----------|--------------|
| 防衛・官公庁 | JAXA型の持ち出しインシデント防止 |
| 製造業 | 設計図面の競合流出防止 |
| 金融 | インサイダー情報の物理的隔離 |
| 法律事務所 | M&A機密文書の時間制御 |
| 医療 | 患者データの取り扱い制限 |

### 一言で（ピッチ用）

> ファイルがどこにあっても、TPMと時間の条件が揃わないと開けない。
> hydeは「場所を守る」のではなく「鍵を守る」。

---

## Section L: Ephemeral KEM — Forward Secrecy オプション設計

### 背景と設計選択

ML-KEM秘密鍵(dk)は「1デバイスに1つの長期静的鍵」である。dkが漏洩した場合、そのデバイスで保護した全データが危殆化する。

**これは設計選択であり設計ミスではない。**

- BitLockerのVMKと同じ構造的トレードオフ
- dk漏洩にはTPMの物理攻撃（SPI sniffing等）が必要 → hydeの脅威モデルの外
- 脅威モデル内（リモート攻撃・HNDL）ではForward Secrecyは不要

### with_ephemeral_kem() API

高価値データ向けにオプトインで完全なForward Secrecyを提供する。

```rust
// デフォルト：長期dk、速い
ctx.protect(secret)?;

// オプトイン：ephemeral dk、遅いが完全なForward Secrecy
ctx.protect(secret)
    .with_ephemeral_kem()?;
```

動作：
1. `ML-KEM.KeyGen()` → 使い捨ての (ek, dk) を生成（~0.1ms）
2. `TPM.Create()` → dkをTPM-sealした新しいWrappedKeyを作成（dTPM: ~200-500ms）
3. `TPM.Unseal()` → dkを復元してAES-GCM暗号化（dTPM: ~100-300ms）
4. ProtectedData.keyに使い捨てWrappedKeyを格納

### パフォーマンスコスト

| モード | dTPM | fTPM | 備考 |
|--------|------|------|------|
| デフォルト（長期dk） | 100-300ms | 30-80ms | Unsealのみ |
| with_ephemeral_kem() | 300-800ms | 80-180ms | Create + Unseal |

出典: wolfTPMベンチマーク、Chrome TPM signature study (p50: 200ms, p95: 600ms)

1秒未満で完全なForward Secrecy。医療記録、遺言、M&A文書には十分に払う価値がある。

### ProtectedData フォーマット — v2互換

**フォーマット変更不要。** ProtectedData.keyに入るWrappedKeyが長期か使い捨てかの違いだけ。unprotect()側はblobの由来を知る必要がない。

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedData {
    key: WrappedKey,
    pub ciphertext: Vec<u8>,
    #[serde(default)]
    kem_ciphertext: Option<Vec<u8>>,
    version: u8,                      // 2のまま
    #[serde(default)]
    ephemeral: bool,                  // 追加: 監査・UI用、復号には不要
}
```

ephemeralフラグの用途：
- oxiのUI表示：「🔒 Forward Secrecy保護済み」
- 監査ログ：「このデータは使い捨て鍵で保護された」
- 復号には一切不要（`#[serde(default)]`でv2互換）

### ドキュメント修正

README の主張を脅威モデルの範囲に限定した：

```
Before: ctx.protect() で常に最強の暗号化が適用される
After:  ctx.protect() でリモート攻撃・HNDL脅威に対して最強の暗号化が自動的に適用される
```

### 決定事項まとめ

| 項目 | 決定 |
|------|------|
| PQC層のForward Secrecy欠如 | 設計選択（BitLocker方式）、脅威モデル外 |
| with_ephemeral_kem() | オプション実装、dTPM最大~800ms |
| ProtectedDataフォーマット | v2のまま変更不要 |
| ephemeralフラグ | 追加（監査・UI用、復号不要、コストゼロ） |
| ドキュメント修正 | 「常に最強」→「リモート攻撃・HNDL対策として最強」 |

---

## Section M: 三層防御モデル — 攻撃コストの指数関数的増大

### 概要

hydeの防御は3つの層で構成され、各層を突破するコストが指数関数的に増大する。さらに、最も深い層（物理攻撃）が成功しても被害範囲はそのTPM 1台分に限定される。

### 三層構造

```
Layer 1: データを盗む（ネットワーク攻撃）
  攻撃コスト: 低
  結果: 暗号文しか手に入らない → 読めない

Layer 2: PCごと奪う（物理奪取 + 管理者権限）
  攻撃コスト: 中
  結果: FixedTPMが鍵の取り出しを拒否 → 読めない
  ※ 管理者権限でできるのは運用妨害（TPM無効化・プロセス停止・ファイル削除）のみ
  ※ 情報窃取はハードウェアが拒否する

Layer 3: TPMを物理攻撃する（SPI傍受・電子顕微鏡解析）
  攻撃コスト: 超高（国家レベルの設備と専門知識が必要）
  結果: 成功してもそのTPMで暗号化したデータだけが復号される
  → 被害範囲がそのPC 1台分に限定される
```

### 従来のシステムとの比較

```
従来のサーバー集中型:
  サーバーの鍵が1つ盗まれる → 全データが復号される → 被害が全体に及ぶ
  例: JAXA 6.9TB流出 — 1つの侵入で全て

hyde:
  TPM 1台が破られる → そのTPMで暗号化したデータだけ → 被害が局所化
  例: JAXA全PCにhydeがあれば、攻撃者のPCでは読めない。各PCのTPMが個別に必要
```

### 物理分散 × オフライン — 防御の最終形

複数のTPMを物理的に離れた場所に配置し、普段はオフラインにすることで、防御力が飛躍的に向上する。

```
構成例:

東京のPC（TPM-A）:
  普段はオフライン
  データの半分の鍵を持つ

大阪のPC（TPM-B）:
  普段はオフライン
  データの残り半分の鍵を持つ

復号するには:
  両方のPCが必要
  両方がオンラインである必要
  両方の場所に物理的にいる必要
```

### 攻撃シナリオの評価

| 攻撃 | 結果 |
|------|------|
| ネットワーク攻撃 | 両方オフライン → 到達不可能 |
| 東京のPCを盗む | 大阪のTPMがない → 復号不可能 |
| 大阪のPCを盗む | 東京のTPMがない → 復号不可能 |
| 両方同時に盗む | 物理的に離れている → 同時奪取は現実的に不可能 |
| 両方に物理攻撃 | 2台両方に国家レベルの攻撃が必要 → コストが天文学的 |

### オフラインの強さ

オンラインのシステムは常に攻撃にさらされている。オフラインのTPMは攻撃の入口が物理的な接触のみ — ネットワーク経由の攻撃が原理的に不可能。

### 運用例: Scope3月次集計

```
普段:
  東京・大阪のPCはオフライン
  データは暗号化されたまま保存

月末の集計時だけ:
  東京と大阪の担当者が同時にPCを起動
  → 両方のTPMが揃う
  → 復号・集計
  → またオフラインに戻る
```

### 設計原則

**「物理的距離」と「オフライン」がデジタルの最強の防御になる。**

hydeは「デジタルの問題を物理で解決する」設計思想を持つ。TPMというハードウェア信頼基盤が、暗号をネットワーク上の抽象概念から物理世界の制約に変換する。

攻撃コストは層ごとに指数関数的に上がり、成功しても被害範囲はそのTPM 1台分に限定される。これが「盗まれても意味がない」の本当の意味。

### データは無数にコピー、鍵だけを分散 — 設計の逆転

hydeの設計はデータ保護の常識を逆転させる。

```
従来の常識:
  重要なデータは厳重に保管する
  コピーを減らす
  アクセスを制限する
  → でも鍵の管理が甘い
  → セキュリティと可用性がトレードオフ

hydeの世界観:
  データのコピーはどこにあっても構わない → 読めないから
  鍵だけを分散して守る → TPMが唯一の防衛線
  → セキュリティと可用性がトレードオフではなくなる
```

**なぜコピーを増やすべきか：**

暗号文は読めないので、コピーの数はセキュリティに影響しない。むしろコピーを増やすほど可用性が上がる。

- クラウドにコピー → 暗号文しかない → 読めない → でもバックアップになる
- USBにコピー → 暗号文しかない → 読めない → でも持ち運べる
- 各PCにコピー → 暗号文しかない → 読めない → でも冗長性が上がる

**完全な構成：**

```
データ:
  クラウド・USB・各PCに無数のコピーを作る → 消えない

鍵:
  東京のTPM（オフライン） — 鍵の半分
  大阪のTPM（オフライン） — 鍵の残り半分

復号:
  両方のTPMが揃った時だけ → 月次の集計時のみ
```

**一言で：「データはどこにでもある。でも誰にも読めない。」**

---

## Section N: Phase 1 セキュリティの実装状態と残存リスク

### 実装済みの防御（コード確認済み）

| 防御 | 実装箇所 | 効果 |
|------|---------|------|
| FixedTPM=true | `lib.rs:124, :146` | 管理者権限でも鍵取り出し不可。TPMが設計上拒否 |
| zeroize | `lib.rs:431, :438` | seal/unseal後に即座にメモリをゼロ埋め |
| mlock() | `cache.rs:58` | キャッシュされた鍵がスワップに書き出されるのを防止 |
| mlock失敗警告 | `cache.rs:23` | mlockが失敗した場合にログで警告 |

### Phase 1 の残存リスク

| リスク | 内容 | 対策 |
|--------|------|------|
| 実行中RAM上の鍵 | unseal～zeroizeまでの数ミリ秒間、鍵がRAMに展開される | Phase 2 (TDX/SEV-SNP) でハードウェアメモリ暗号化 |
| ハイバネーション | OSがメモリ全体をディスクに書き出す。mlock()では防げない | **ハイバネーション無効化を推奨** |
| CPUキャッシュ残留 | zeroize後もL1/L2に残留する理論上の可能性 | 実用上のリスクは極めて低い |

### 運用推奨事項

hydeを使用する環境では以下を推奨する：

```bash
# Linux: ハイバネーションを無効化
sudo systemctl mask hibernate.target hybrid-sleep.target suspend-then-hibernate.target

# スワップを暗号化（mlock失敗時のフォールバック）
# /etc/crypttab でスワップパーティションを暗号化スワップに設定
```

### Phase 1 セキュリティの正確な評価

```
Phase 1で守れるもの:
  ✅ ディスク盗難 — 暗号化済み
  ✅ ブート改ざん — PCR検証
  ✅ 管理者による鍵取り出し — FixedTPMが拒否
  ✅ スワップへの書き出し — mlock()
  ✅ 使用後のメモリ残留 — zeroize

Phase 1で守れないもの:
  ❌ 実行中のメモリダンプ（数ミリ秒の窓）
  ❌ ハイバネーション（無効化で対策）
  → Phase 2 (TDX/SEV-SNP) で閉じる
```

Phase 1の時点で「環境が信頼できる（ハイバネーション無効・マルウェアなし）」前提であれば、実用上のセキュリティは極めて高い。「完全セキュア」とは言えないが、残存リスクは数ミリ秒のメモリ窓のみであり、これを突くには管理者権限 + 精密なタイミング制御が必要。

---

## Section O: ランサムウェア耐性

### hydeはランサムウェアの3つの脅迫手段を全て無力化する

近年のランサムウェアは単なるファイル暗号化だけでなく、「データを公開する」二重脅迫（Double Extortion）が主流になっている。hydeの設計はこの全パターンに対して構造的な耐性を持つ。

### ランサムウェアの脅迫手段 vs hyde

| 脅迫手段 | 従来のシステム | hydeの世界 |
|---------|-------------|-----------|
| 「ファイルを暗号化した。復元したければ身代金を払え」 | ファイルが使えなくなる → 払うしかない | コピーが他のデバイス・クラウドにある → そこから復元 → **払う理由がない** |
| 「データを盗んだ。公開されたくなければ払え」 | 平文が盗まれている → 公開されたら終わり | 盗めるのは暗号文だけ → 公開しても読めない → **脅迫が成立しない** |
| 「データを削除した。バックアップもない」 | バックアップが同じネットワーク上 → 一緒に消される | コピーが物理分散 + オフライン → **全コピーの同時削除は不可能** |

### なぜ構造的に強いか

```
従来:
  ファイルは平文で保存 → 盗まれたら読める
  バックアップは同じネットワーク上 → 一緒にやられる
  → ランサムウェアのビジネスモデルが成立する

hyde:
  ファイルは最初から暗号化されている → 盗んでも読めない
  コピーは物理分散・オフライン → 全滅は不可能
  鍵はTPMに閉じ込め → ランサムウェアにも取り出せない
  → ランサムウェアのビジネスモデルが成立しない
```

### 攻撃シナリオの詳細

**シナリオ1: ファイル暗号化攻撃**

```
攻撃者: 東京のPCのファイルをランサムウェアで暗号化
結果:  元のファイルはhydeで暗号化された暗号文
       → ランサムウェアが暗号文をさらに暗号化しただけ
       → 大阪のPC・クラウドにコピーがある
       → そこから復元
       → 身代金ゼロ
```

**シナリオ2: データ窃取 + 公開脅迫（二重脅迫）**

```
攻撃者: ネットワーク経由でファイルを盗み出した
       「公開するぞ」と脅迫
結果:  盗んだファイルはhyde暗号文
       → 公開しても誰にも読めない
       → 機密情報は漏洩しない
       → 脅迫が成立しない
```

**シナリオ3: 全削除攻撃**

```
攻撃者: 東京のPCのファイルを全削除
       「バックアップも消した」と主張
結果:  大阪のPC（オフライン）にコピーがある
       クラウドにもコピーがある
       USBにもコピーがある
       → オフラインのデバイスにはランサムウェアが到達できない
       → 復元可能
```

### 一言で

**ランサムウェアのビジネスモデルは「平文を人質にする」こと。hydeの世界には平文の人質が存在しない。**
