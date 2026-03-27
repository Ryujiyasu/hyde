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

| State / 状態 | Threat / 脅威 | Solution / 解決策 |
|---|---|---|
| At rest / 保存時 | Disk theft | BitLocker / FileVault |
| In transit / 通信時 | Interception | HTTPS / TLS |
| In use / 実行時（物理） | Memory sniff, SPI bus attack | **hyde Phase 1 (TPM)** |
| In use / 実行時（クラウド） | Cloud admin, hypervisor | **hyde Phase 2 (TDX/SEV-SNP)** |
| In use / 実行時（AI） | Model theft, prompt leak | **hyde Phase 4 (H100 CC)** |

hyde binds secrets to **a specific device + a specific person** using TPM (Trusted Platform Module). Even if stored in the cloud, data cannot be decrypted without that person and that device.

hydeはTPMを使い、秘密情報を「特定のデバイス＋特定の人物」に紐付けて保護する。クラウドに保存されても、その人物・そのデバイスなしには復号できない。

### Protection scope by phase / フェーズ別の守備範囲

| Phase | Technology | Disk theft / ディスク盗難 | Boot tampering / ブート改ざん | **Cloud admin (memory access)** |
|-------|-----------|:-:|:-:|:-:|
| **1 (current)** | TPM 2.0 + PQC | ✅ | ✅ | ❌ PCR cannot prevent runtime memory access |
| **2 (planned)** | Intel TDX / AMD SEV-SNP | ✅ | ✅ | ✅ Hardware-level memory encryption |

Phase 1 protects **data at rest** (disk theft, boot integrity) and **data in transit** (PQC encryption). Protection against **cloud admin runtime memory access** requires Phase 2's hardware memory encryption (TDX/SEV-SNP), which prevents even the hypervisor from reading VM memory.

Phase 1は**保存時**（ディスク盗難・ブート整合性）と**通信時**（PQC暗号化）を保護する。**クラウド管理者による実行時メモリアクセス**の防御にはPhase 2のハードウェアメモリ暗号化（TDX/SEV-SNP）が必要 — ハイパーバイザー自身もVMメモリを読めない設計。

---

## Design Philosophy / 設計思想

hyde's ideal trust model is **one person, one device**.

hydeは**1人1デバイス**を信頼モデルの理想とする。

Multi-user operating systems introduced the concept of "admin privileges" — a fundamental limit of software-level security. This is not hyde's bug; it is an architectural mismatch with how OSes were designed.

マルチユーザーOSは「管理者権限」という概念を生み出し、ソフトウェアレベルのセキュリティの根本的な限界を作った。これはhydeのバグではなく、OSの設計思想との不整合である。

hyde addresses this reality in phases:

hydeはこの現実にフェーズで対応する：

| Phase | Approach / アプローチ |
|---|---|
| **Phase 1 (current)** | Complete protection in one-person-one-device environments / 1人1デバイス環境での完全な保護 |
| **Phase 2 (planned)** | TDX/SEV-SNP creates a pseudo one-person-one-environment, even on shared infrastructure / 共有インフラ上でも擬似的な1人1環境を実現 |

Ultimately, hyde's design philosophy may motivate the creation of an OS built from the ground up around this trust model — **hydeOS**.

最終的に、hydeの設計思想はこの信頼モデルを前提としたOS — **hydeOS** — の開発動機となりうる。

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
| **[plat](https://gitlab.com/Ryujiyasu/plat)** | FHE / GPU TEE (H100) | **Compute** on encrypted data / 暗号化したまま計算する |

</div>

```
 Protect          Prove           Compute
┌─────────┐    ┌─────────┐    ┌─────────┐
│  hyde    │───▶│  argo   │───▶│  plat   │
│ TPM+PQC │    │  ZKP    │    │FHE/H100 │
└─────────┘    └─────────┘    └─────────┘
  守る            証明する        計算する
```

All modules share hyde's TPM trust chain as the key management foundation.

全モジュールがhydeのTPM信頼チェーンを鍵管理の基盤として共有。

### The Vision / ビジョン

Together, these three modules enable a world where **social trust can be established without ever exposing data**.

3つのモジュールが揃うことで、**データを一切公開せずに社会的な信頼を構築できる**世界を実現する。

```
Example: Medical AI diagnosis without exposing patient data
例：患者データを公開せずに医療AI診断

hyde: Encrypt genome data, bind to patient's device
      遺伝子データを暗号化・患者のデバイスに紐付け

plat: AI diagnoses on encrypted data — never sees raw genome
      暗号化したままAIが診断 — 生の遺伝子データは見えない

argo: Prove "low cancer risk" to insurer — without revealing score
      保険会社に「癌リスク低」を証明 — スコアは見せない
```

### The Endgame / 完成形

**"Mathematically proven digital society infrastructure where no one needs to be trusted."**

**「誰も信頼しなくていい、数学的に証明されたデジタル社会のインフラ」**

```
hyde → Protect (TPM + PQC)     — No one can read your data
       守る                     — 誰もデータを読めない

argo → Prove (ZKP)             — No one needs to see your data
       証明する                 — 誰もデータを見る必要がない

plat → Compute (FHE / H100)    — No one touches your data
       計算する                 — 誰もデータに触れない
```

The logical conclusion of this philosophy: an operating system built from the ground up around hyde's trust model — **hydeOS**. Not a feature request, but an inevitability. When every layer from boot to application assumes "one person, one device, trust only physics and math," the OS itself must be redesigned.

この思想の論理的帰結：hydeの信頼モデルを前提にゼロから構築されたOS — **hydeOS**。機能要望ではなく必然。ブートからアプリケーションまで全レイヤーが「1人1デバイス、信じるのは物理と数学だけ」を前提とするなら、OS自体を再設計するしかない。

---

## Positioning: hyde vs BitLocker / ポジショニング

hyde is **not** a BitLocker replacement. hyde solves problems that BitLocker cannot:

hydeはBitLockerの**代替ではない**。BitLockerが解けない問題を解く：

| Capability | BitLocker | hyde |
|---|---|---|
| Full-disk encryption / ディスク全体暗号化 | ✅ Core purpose | ❌ Not hyde's job |
| **Application-level PQC encryption** / アプリレベルPQC暗号化 | ❌ | ✅ ML-KEM-768, always-on |
| **One-line developer API** / 開発者向け一行API | ❌ | ✅ `ctx.protect(secret)?` |
| **Cross-platform** / クロスプラットフォーム | ❌ Windows only | ✅ Linux, Windows, (Phase 3: macOS, mobile) |
| **Per-file encryption** / ファイル単位の暗号化 | ❌ Volume-level | ✅ Per `protect()` call |
| **Post-quantum resistant** / 耐量子 | ❌ | ✅ ML-KEM-768 (NIST FIPS 203) |
| Admin privilege escalation / 管理者権限奪取 | ❌ Out of scope | ❌ Out of scope (Phase 2) |
| Physical attacks / 物理攻撃 | ❌ Out of scope | ❌ Out of scope (vendor) |

Both BitLocker and hyde share the same honest limitation: neither defends against admin escalation or physical attacks in their current form. The difference is what they **do** protect — BitLocker protects volumes, hyde protects application data with quantum-resistant, device-bound, per-object encryption.

BitLockerとhydeは同じ誠実な限界を共有する：現時点では両者とも管理者権限奪取・物理攻撃は守備範囲外。違いは**何を守るか** — BitLockerはボリュームを、hydeはアプリケーションデータを量子耐性・デバイスバインド・オブジェクト単位で守る。

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

hyde learns from **20 years of BitLocker history** — the most battle-tested full-disk encryption in production. We studied its architecture, key hierarchy, recovery mechanisms, and the real-world failures it solved, then built a modern equivalent for the TEE era.

hydeは**BitLockerの20年の歴史**から学んでいる。プロダクション環境で最も実戦検証されたフルディスク暗号化の設計思想・鍵階層・回復メカニズム・実運用で解決してきた障害を研究し、TEE時代の現代版として再構築した。

hyde uses the **BitLocker pattern** to avoid TPM NV memory exhaustion:

hydeはBitLockerパターンを採用し、TPMのNVメモリ枯渇を防ぐ：

1. **Primary Key** (1 per device) — persisted in TPM NV memory (1 slot)
2. **Data Key** (1 per protect call) — generated by TPM RNG, sealed under Primary Key, stored as blob on disk
3. **PQC Layer** — ML-KEM-768 encapsulation per protect call, quantum-resistant AES-256-GCM encryption
4. **Encryption** — Data is double-encrypted: PQC (inner, chip-independent) + TPM (outer, device-bound)

### What hyde learned from BitLocker / BitLockerから学んだ設計パターン

| BitLocker Concept | hyde Equivalent | Why it matters / なぜ重要か |
|---|---|---|
| VMK → FVEK (2-layer key hierarchy) | dk → DataKey | Heavy key (dk) pays cost once; lightweight DataKey rotates per `protect()` call for Forward Secrecy at near-zero cost / 重い鍵は1回、軽い鍵で毎回Forward Secrecyをほぼゼロコストで実現 |
| Protector (TPM, RecoveryKey, Password) | `RecoveryStrategy` trait | Multiple protection methods guard the same master key — pluggable and extensible / 複数の保護手段で同一マスター鍵を守る。差し替え可能で拡張性あり |
| 1 NV slot for VMK | 1 NV slot for Primary Key | Unlimited data protected from a single TPM slot — no NV exhaustion / TPM 1スロットで無限のデータを保護。NV枯渇なし |
| VMK re-wrap on key rotation | `dk` re-seal on PQC chip migration | Only the master key is re-sealed; data is never re-encrypted / マスター鍵のre-sealだけ。データの再暗号化は不要 |

This design ensures that when dedicated PQC hardware chips arrive, migration is a single re-seal operation — not a re-encryption of all data.

この設計により、将来PQC専用チップが登場した際の移行は、dk の re-seal 1回で完了する。全データの再暗号化は不要。

## Security Model / セキュリティモデル

### Trust Boundary / 信頼境界：ソフトウェアでできることの限界

**hyde trusts only what humans cannot alter: physics and mathematics.**

**hydeが信じるのは、人間が変えられないものだけ — 物理と数学。**

Physical laws cannot be rewritten remotely. Mathematical proofs cannot be negotiated down. Everything else — admin privileges, policies, goodwill — hyde eliminates structurally.

物理法則は遠隔で書き換えられない。数学的証明は交渉で下げられない。それ以外の全て — 管理者権限、ポリシー、善意 — hydeは構造で排除する。

| Layer / レイヤー | Trust / 信頼 | Responsibility / 責任 | Approach / 手段 |
|---|---|---|---|
| Physical chip (TPM, ATECC608) | **Trust** | Chip vendor | Out of scope — hardware tamper resistance |
| OS / Firmware | **Don't trust** | hyde | PCR measurement and verification |
| Cloud provider | **Don't trust** | hyde | Encryption excludes access |
| Admin privileges | **Don't trust** | hyde | Structural exclusion |
| Humans (including witnesses) | **Don't trust** | hyde | N-of-M + audit logs |
| Coercion | **Can't solve with tech** | Policy | Zero Negotiation Principle |

What hyde can do, hyde does. What hyde can't do, hyde says so honestly. A project that states what it **cannot** protect is one whose claims about what it **can** protect are credible.

できることはやる。できないことはできないと言う。「何を守れないか」を明言するプロジェクトは、「何を守れるか」の部分が信用できる。

### Scope / 守備範囲

What hyde does **not** defend against in Phase 1 — and this is the same position as BitLocker:

Phase 1でhydeが守備範囲と**しないもの** — これはBitLockerと同じ立場である：

| Threat / 脅威 | Phase 1 | Phase 2 (TDX/SEV-SNP) | Responsibility / 責任 |
|---|---|---|---|
| Admin privilege escalation (RAT, malware) / 管理者権限奪取 | Out of scope | **In scope** — isolated VM | OS / endpoint security |
| Physical attacks (SPI sniffing) / 物理攻撃 | Out of scope (PersonBinding mitigates) | Out of scope | Chip vendor |
| Cloud admin memory access / クラウド管理者 | Out of scope | **In scope** — hardware memory encryption | Cloud TEE |

Phase 2 (TDX/SEV-SNP) brings admin escalation and cloud admin attacks **into scope** by creating hardware-isolated execution environments. Physical attacks remain the chip vendor's domain across all phases.

Phase 2（TDX/SEV-SNP）は管理者権限奪取とクラウド管理者攻撃をハードウェア隔離環境により**守備範囲に入れる**。物理攻撃は全フェーズを通じてチップベンダーの領域。

---

### Threat: SPI Bus Sniffing / 脅威: SPIバス盗聴

This is a **physical attack** — a logic analyzer is physically attached to the SPI bus between CPU and dTPM. By hyde's trust boundary, this is fundamentally a **chip vendor's responsibility** (unencrypted bus design). hyde provides software-side mitigation as defense-in-depth, not as a claim to solve a physical problem.

これは**物理攻撃**である — CPUとdTPM間のSPIバスにロジックアナライザを物理接続する。hydeの信頼境界に従えば、根本原因は**チップベンダーの責任**（バスの平文通信設計）。hydeはdefense-in-depthとしてソフト側の緩和策を提供するが、物理の問題を解決したとは主張しない。

```
Attack cost / 攻撃コスト: ~$300 logic analyzer + 10 min physical access
Attack result / 攻撃結果: dk recovered in plaintext → all DataKeys compromised
```

| Solution / 解決策 | Layer / レイヤー | Approach / 手段 |
|---|---|---|
| **Root fix** / 根本解決 | Physical (vendor) | Use fTPM — no external bus exists / fTPM使用。バスが存在しない |
| **Software mitigation** / ソフト緩和 | hyde (v0.3) | PersonBinding — sniffed data alone is useless / PIN必須化。盗聴だけでは無意味 |
| ~~Phase 2 (TDX/SEV-SNP)~~ | Cloud memory | Does **not** solve SPI sniffing — different threat layer / SPI盗聴とは別レイヤーの脅威 |

**Mitigation (v0.3 planned): PersonBinding / 対策（v0.3予定）: 人物バインディング**

```rust
// TPM-only (current): device binding only
let ctx = hyde::auto_detect(FallbackPolicy::Deny)?;

// TPM + PIN (v0.3): device + person binding
let ctx = hyde::auto_detect(FallbackPolicy::Deny)?
    .with_person_binding(PersonBinding::Pin)?;
```

### fTPM vs dTPM

| TPM type | SPI sniffing | Attack difficulty |
|---|---|---|
| dTPM (discrete chip) | Possible — $300, 10 min | **Low** |
| fTPM (CPU-integrated: Intel PTT, AMD fTPM) | Impossible | **Medium** (faulTPM attack requires hours) |

**Recommendation**: fTPM environments have medium security even without PIN. dTPM environments should strongly use PersonBinding.

**推奨**: fTPM環境ではPINなしでも中程度のセキュリティ。dTPM環境ではPersonBindingを強く推奨。

### Known Physical Threats / 既知の物理攻撃

hyde is aware of these attacks. They are physical — software cannot prevent them. We list them to be honest about what lies outside our trust boundary.

hydeはこれらの攻撃を認識している。物理攻撃であり、ソフトウェアでは防げない。信頼境界の外にあるものを正直に列挙する。

| Attack / 攻撃 | Target / 対象 | Cost / コスト | Description / 概要 | hyde's stance / hydeの立場 |
|---|---|---|---|---|
| **SPI bus sniffing** | dTPM | ~$300, 10 min | Logic analyzer on TPM bus captures unsealed keys / SPIバス盗聴でTPM通信を傍受 | Software mitigation: PersonBinding (v0.3) |
| **Cold boot attack** | DRAM | ~$50, 5 min | Freeze RAM, extract keys from residual charge / RAMを冷却し残留電荷から鍵抽出 | Out of scope — DRAM physics. Memory encryption (Phase 2 TDX/SEV) mitigates |
| **faulTPM / Voltage glitching** | fTPM | ~$200, hours | Fault injection on CPU to extract fTPM secrets / CPUへの電圧グリッチでfTPM秘密を抽出 | Out of scope — CPU vendor responsibility |
| **Decapping / Microprobing** | dTPM chip | $10K+, days | Physically open chip, probe internal circuits / チップ開封・内部回路の直接読取 | Out of scope — chip vendor's tamper resistance |
| **Electromagnetic side-channel** | TPM / CPU | $1K+, hours | Measure EM emanation during crypto operations / 暗号演算中の電磁放射を計測 | Out of scope — chip vendor's shielding |
| **Power analysis (DPA/SPA)** | TPM | $5K+, hours | Measure power consumption to infer key bits / 消費電力パターンから鍵ビットを推定 | Out of scope — chip vendor's countermeasures |
| **JTAG / Debug port** | SoC | $100, minutes | Access debug interface left enabled / 有効なままのデバッグポートにアクセス | Out of scope — OEM must disable in production |
| **Evil maid (hardware implant)** | Motherboard | $500+, minutes | Physically modify hardware to intercept or inject / ハードウェア改ざんによる傍受・注入 | Out of scope — physical access control |
| **Rowhammer** | DRAM | $0, hours | DRAM bit-flip via repeated memory access / メモリ繰返しアクセスによるビット反転 | Out of scope — DRAM vendor. ECC memory mitigates |
| **Bus interposer (MitM)** | PCIe / SPI | $1K+, hours | Hardware man-in-the-middle on bus / バス上のハードウェアMitM | Out of scope — physical bus integrity |

These are **not hyde's failures**. They are the boundaries where software ends and physics begins. hyde's job is to make the software layer so solid that the only remaining attacks require physical access — and then honestly say "that part is not ours."

これらは**hydeの欠陥ではない**。ソフトウェアが終わり、物理が始まる境界である。hydeの仕事はソフトウェア層を堅固にし、残る攻撃が物理アクセスを必要とする状態にすること — そして「そこから先は我々の領域ではない」と正直に言うこと。

---

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

| Strategy | 日本語 | Description |
|----------|--------|-------------|
| `PassphraseRecovery` | パスフレーズ復元 | Argon2id + AES-256-GCM (default) |
| `RecoveryKey` (planned) | 回復キー復元 | One-time random key displayed once |
| `WitnessRecovery` (planned) | 立会人復元 | N-of-M Shamir, multi-device binding |

### WitnessRecovery / 立会人復元

N-of-M Shamir Secret Sharing with multi-device binding. Witnesses approve recovery via biometric authentication on their devices.

N-of-M シャミア秘密分散＋複数デバイスバインド。立会人が自分のデバイスで生体認証により復元を承認する。

```
Recovery request / 復元要求
  ↓
Push notification to witness devices / 立会人デバイスにプッシュ通知
「復元を要求しています。承認しますか？」
  ↓
Approve with biometrics / 承認ボタン（生体認証）
  ↓
N-of-M threshold reached → auto-recover / N-of-M達成 → 自動復元
  ↓
Audit log generated (who approved, when) / 監査ログ自動生成（誰がいつ承認したか）
```

**Metadata is public by design** — knowing who the witnesses are is harmless. Only the shard values are secret. Even if an attacker learns who holds shards, they cannot recover the secret without physically obtaining the shards.

**条件メタデータは公開設計** — 誰が立会人かは公開してよい。シャードの値だけが秘密。攻撃者が「誰が持っているか」を知っても、シャードを物理取得しない限り意味がない。

### Security Grades / セキュリティグレード設計

```rust
// Level 1: General users / 一般ユーザー
ctx.protect(secret)?;

// Level 2: Enterprise / 企業・組織
ctx.protect(secret)
    .with_witness(3, witnesses)?;

// Level 3: Government & Defense / 政府・防衛
ctx.protect(secret)
    .with_witness(3, witnesses)
    .with_duress_pin()?;
```

---

## Problems hyde Solves / hydeが解決する問題

### Physical Destruction / 物理破壊問題

Recovery paths are layered with OR conditions, eliminating single points of failure. PC destroyed → recover with phone. Phone destroyed → recover with witnesses. Each layer's security strength is independently maintained.

復元経路をOR条件で複数層用意することで単一障害点を排除。PCが壊れてもスマホで復元、スマホも壊れても立会人で復元。各層のセキュリティ強度は独立して保たれる。

### Insider Threat (The Vault Problem) / 金庫問題（内部犯行）

N-of-M design makes unauthorized solo access structurally impossible. Audit logs record even collusion attempts. This structurally eliminates the classic "keyholder insider attack" that traditional vaults have always faced.

N-of-M設計により単独での不正アクセスが構造的に不可能。監査ログにより共謀も記録される。従来の金庫が抱えてきた「鍵管理者による内部犯行」を構造的に排除する。

### Coerced Approval / 強制承認問題

Solved by policy, not technology. "Never approve under duress" is hyde's organizational operating principle — making coercion itself a deterrent. **Zero Negotiation Principle**.

技術ではなくポリシーで解決。「脅されても承認しない」をhydeの組織運用原則とすることで、脅しそのものの抑止力になる。**ゼロ交渉原則**。

---

## What Zero Trust Really Means / Zero Trust の本当の意味

The industry's "Zero Trust" stops at network design. hyde's Zero Trust means **never trusting the platform provider itself**.

世間の「Zero Trust」はネットワーク設計の話にとどまる。hydeの Zero Trust は**プラットフォーマー自身を信じない**設計。

- Cloud providers see only ciphertext / クラウド事業者は暗号文しか見えない
- Infrastructure providers cannot access data / インフラ提供者はデータにアクセスできない
- Admin privileges cannot decrypt / 管理者権限があっても復号不可能

---

## Future Vision: IoT × argo / 将来構想：IoT × argo

Embed TPM chips (ATECC608 etc.) into mailboxes, ballot boxes, delivery chains, and combine with argo's ZKP to build social infrastructure that **proves facts while keeping contents secret**.

郵便受け・投票箱・配送チェーン等にTPMチップ（ATECC608等）を埋め込み、argoのZKPと組み合わせることで「中身を秘匿したまま事実だけ証明」できる社会インフラを実現する。

```
Mailbox with TPM chip / 郵便受けTPMチップ
  → Signs at the moment of delivery / 投函の瞬間に署名
  → ZKP proves "delivery happened" / ZKPで「届いた事実」を証明
  → No one sees the contents / 中身は誰も見ていない
  → But "delivered" is mathematically provable / でも「届いた」は数学的に証明可能

"Trustworthy social infrastructure without trusting any person"
「信頼できる人間がいなくても信頼できる社会インフラ」
```

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

## Planned: Person Binding / 計画中: 人物バインディング

TPM-only configuration is vulnerable to SPI bus sniffing attacks ($300 hardware, 10 minutes). v0.3 will add PIN/Passphrase-based person binding to fulfill the "specific person" promise:

TPM-only構成はSPIバス盗聴攻撃（$300の機材・10分）に対して脆弱。v0.3でPIN/パスフレーズによる人物バインディングを追加し、「特定の人物」の約束を実現する：

```rust
let ctx = hyde::auto_detect(FallbackPolicy::Deny)?
    .with_person_binding(PersonBinding::Pin)?;

let protected = ctx.protect(secret)?;
// → dk is sealed with TPM + PIN layer
// → SPI sniffing alone cannot recover the key
```

See [docs/hyde-implementation-guide.md](docs/hyde-implementation-guide.md) for the full security analysis.

---

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
