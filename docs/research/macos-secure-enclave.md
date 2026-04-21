# macOS Secure Enclave + LocalAuthentication 技術調査

本文書は hyde (TPM ベース暗号化) および janus (クロスプラットフォーム person-binding) の macOS 対応を検討するための技術調査である。中心的な問いは、**macOS では Secure Enclave (SE) の鍵がアクセス制御フラグだけで「デバイス束縛」と「人物束縛」を同時に満たせるため、janus と hyde は単一の SE 統合として統合すべきか、それとも Windows (TPM + Windows Hello) の二層構造と抽象化を合わせるため別レイヤーに保つべきか**である。

本文書は事実と推測を区別する。Apple の内部実装で公開ドキュメントがない部分は「不明」と明記する。

---

## 1. Secure Enclave アーキテクチャ

### T2 vs Apple Silicon (M1/M2/M3/M4)

- **T2 (Intel Mac, 2017–2022)**: Apple T2 は独立した ARMv8 SoC として基板上に実装され、bridgeOS を実行する。SEP (Secure Enclave Processor) は T2 SoC 内のコプロセッサで、32-bit ARM CPU 上で sepOS (L4 系マイクロカーネル派生) を実行する。Secure Storage Component (SSC) は T2 世代では EEPROM ベース (gen 1)。
- **Apple Silicon (M1/M2/M3/M4)**: T2 相当機能は M シリーズ SoC に統合された。SEP はアプリケーションプロセッサと同一ダイ上の独立ブロックとなり、別チップは存在しない。M1 以降、SSC は gen 2 に置き換わり、anti-replay counter の機能が強化された。
- **M4 世代**: SEP の大きな公開アーキテクチャ変更は Apple Platform Security ガイド上では確認できなかった (2026-04 時点、不明)。
- T2 の完全廃止は 2023-06 (Mac Pro の Apple Silicon 移行完了) である。

### SEP + Secure Storage Component

SEP は以下を保持する:
- **Root cryptographic key** (UID): ハードウェア融合され、SEP 外から参照不可。
- **Secure Storage Component**: anti-replay カウンタ、biometric template、long-term key material を保持する不揮発ストレージ。M1 以降は gen 2 で replay 耐性が強化されている。
- **Memory Protection Engine**: SEP 専用のメモリに対して CMAC 認証と AES 暗号化を適用。A14/M1 以降は SE 用と Secure Neural Engine 用に 2 つの ephemeral key を持つ。

### sepOS の閉鎖性

sepOS は Apple 内部ビルドであり、ソースコードは非公開。アップデートは AP 経由で配信されるが、Secure Boot により Apple 署名済みイメージのみ起動できる。過去に公開された情報 (Mandt, Black Hat 2016 の "Demystifying the Secure Enclave Processor" や windknown による "Attack Secure Boot of SEP" PDF) は旧世代 SEP に関するもので、現行 M シリーズへの適用可能性は不明。

### 鍵生成・署名の物理的境界

SE 内で生成された private key は **SEP の外に平文で出ない**。署名および ECDH 演算は SEP 内部で完結し、AP (XNU カーネル・ユーザランド) には結果のみが返る。この境界は MMU と dedicated mailbox (IOReg 上の `AppleSEPManager` 経由) で強制される。

### Secure Neural Engine と生体認証経路

- Face ID (Mac では Mac Studio Display 等は非対応。Face ID は iPhone/iPad 系。Mac では **Touch ID のみ**) では Secure Neural Engine が深度マップ+赤外線画像を mathematical representation に変換。Mac は Touch ID のみサポート。
- Touch ID センサー (Magic Keyboard with Touch ID, MacBook built-in) は SEP と暗号化セッションで直結。指紋テンプレートは SSC に保存され、AP からも SEP API からも raw 取得不可。
- A14/M1 以降は Secure Neural Engine は AP の Neural Engine の secure mode として実装され、hardware security controller が AP/SEP 切替時に state を reset する。

---

## 2. LocalAuthentication / LAContext

### evaluatePolicy

`LAContext.evaluatePolicy(_:localizedReason:reply:)` は指定した `LAPolicy` を評価し、成功/失敗の boolean と `LAError` を返す。ブロッキング API ではなく、システム UI (Touch ID プロンプト) を表示する非同期呼び出しとなる。

### LAPolicy

- **`deviceOwnerAuthenticationWithBiometrics`**: 生体認証のみ。Touch ID が失敗/非利用可能なら即失敗。パスコードフォールバックなし。
- **`deviceOwnerAuthentication`**: 生体認証 → (iOS の場合は Apple Watch) → パスコードの順でフォールバック。
- **`deviceOwnerAuthenticationWithWatch`** (macOS 10.15+): Apple Watch による近接認証。
- **`deviceOwnerAuthenticationWithBiometricsOrWatch`** (macOS 10.15+): 生体 or Watch、パスコード不可。

### biometryCurrentSet vs biometryAny

これは `LAPolicy` ではなく `SecAccessControlCreateFlags` の値である。SE 鍵にアタッチするフラグで、enrollment 変更検出の粒度を制御する:

- **`biometryAny`**: 指紋が追加/削除されても鍵は生存。ユーザの利便性優先。
- **`biometryCurrentSet`**: enrollment セット (現在登録されている指紋一式) が変更された瞬間に鍵が無効化される (正確には鍵マテリアルを復号する access control が失敗する)。**攻撃者が新しい指紋を登録して回避することを防ぐ**。hyde/janus のような「人物束縛」用途では `biometryCurrentSet` 一択。

### LAError 主要ケース

- `biometryNotAvailable`: ハードウェアが生体認証非対応。
- `biometryNotEnrolled`: ハードウェアはあるが enrollment なし。
- `biometryLockout`: 5 回連続失敗によるロック。パスコード入力で解除。
- `userCancel`: ユーザがダイアログをキャンセル。
- `authenticationFailed`: 認証失敗 (指紋不一致)。
- `passcodeNotSet`: システムパスコード未設定。この状態だと SE の一部アクセス制御は機能しない。
- `appCancel` / `systemCancel`: アプリまたはシステムがキャンセル。
- `invalidContext`: LAContext が無効化 (invalidate 済み)。

### Touch ID / Face ID の API 上の扱い

API は統一されており、`LAContext.biometryType` (`.touchID` / `.faceID` / `.opticID` / `.none`) で区別する。Mac は現時点で Touch ID のみ。Face ID Mac 搭載は公開ロードマップなし (不明)。

---

## 3. Keychain Services + SE-bound 鍵

### SecKeyCreateRandomKey + kSecAttrTokenIDSecureEnclave

SE 鍵生成は以下の属性で行う:

```
kSecAttrKeyType:        kSecAttrKeyTypeECSECPrimeRandom
kSecAttrKeySizeInBits:  256
kSecAttrTokenID:        kSecAttrTokenIDSecureEnclave
kSecPrivateKeyAttrs: {
  kSecAttrIsPermanent:    true
  kSecAttrApplicationTag: <識別子>
  kSecAttrAccessControl:  <SecAccessControlRef>
}
```

### SecAccessControlCreateWithFlags

`SecAccessControlCreateWithFlags(nil, protection, flags, &error)` でアクセス制御オブジェクトを生成。

- **protection**: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` が SE 鍵の典型。iCloud 同期なし、ロック中アクセス不可。
- **flags** (`SecAccessControlCreateFlags`):
  - `.privateKeyUsage`: SE 鍵を使う場合必須。
  - `.biometryCurrentSet`: 現在の enrollment セットに束縛。
  - `.biometryAny`: 生体であれば誰でも (enrollment 変更に耐性)。
  - `.userPresence`: 生体またはパスコード。生体がない/失敗時にパスコードフォールバック。
  - `.devicePasscode`: パスコードのみ。
  - `.or` / `.and`: 複数条件の組み合わせ。

**hyde/janus 想定の推奨組み合わせ**: `[.privateKeyUsage, .biometryCurrentSet]` または `[.privateKeyUsage, .biometryCurrentSet, .and, .devicePasscode]` 相当。後者は生体 AND パスコード (段階的エスカレーション設計)。

### 鍵属性の制約 (重要)

- **ECC P-256 のみ**: SE は `kSecAttrKeyTypeECSECPrimeRandom` (NIST P-256) の 256 ビット鍵のみサポート。**RSA, Ed25519, P-384, P-521 は SE 内不可**。TPM と比べ著しく制約的。
- **操作**:
  - 署名: `ecdsaSignatureMessageX962SHA256` 等の ECDSA。
  - ECDH: `ecdhKeyExchangeStandard` / `ecdhKeyExchangeCofactor`。
  - 暗号化: **汎用の暗号化はできない**。ECIES ラップ (`eciesEncryptionCofactorX963SHA256AESGCM` 等) のみ。これは「受信者の公開鍵で ephemeral ECDH し、派生 AES-GCM で対称暗号化」する構造で、TPM の seal/unseal と大きく意味論が違う。
- **公開鍵**: SE 内 private key の公開鍵は `SecKeyCopyPublicKey` で取得可能。AP 上に平文で存在する。

---

## 4. hyde Secure Enclave バックエンドの設計

### hyde-core TeeBackend trait の SE マッピング

hyde-core (既存 Rust 実装、GitLab 上) の `TeeBackend` trait は TPM の seal/unseal を抽象化していると推測される (リポジトリ非確認、想定)。SE への単純な移植は以下の問題を生む:

| TPM (Windows/Linux)         | Secure Enclave (macOS)                     |
|-----------------------------|--------------------------------------------|
| RSA/ECC 任意、多種対称鍵     | ECC P-256 のみ                             |
| seal/unseal (任意データ保護) | なし (ECIES ラップのみ)                    |
| PCR バインディング            | なし (OS レベルの FileVault 等は別階層)    |
| 非対話                        | LAContext 評価が必要 (UI 表示)             |
| パスワード/PIN が TPM 内検証  | パスコード/生体は LA framework 経由        |

**設計方針案 A (Primary Key を SE)**:
- hyde "Primary Key" 相当を ECC P-256 SE 鍵として生成し `kSecAttrTokenIDSecureEnclave` で束縛。
- "Data Key" (AES-256) をアプリ側で生成、Primary Key の **公開鍵で ECIES 暗号化**して永続化。
- 復号時は `SecKeyCreateDecryptedData(privKey, .eciesEncryptionCofactorX963SHA256AESGCM, wrapped, &error)` を呼ぶ。この時点で `biometryCurrentSet` フラグが効いて Touch ID が要求される。

**設計方針案 B (ECDH 派生鍵 + AES-GCM)**:
- SE 鍵をアプリ側公開鍵と ECDH し、HKDF で対称鍵を派生、AES-GCM で手動シール。
- より制御可能だが、実装複雑度が上がる。ECIES を自前で再実装する形になる。

**推奨**: MVP は方針 A。`eciesEncryptionCofactorX963SHA256AESGCM` は Apple 提供で ephemeral 鍵生成から encapsulation まで自動化されており、実装負荷が低い。将来的に cross-platform wrap format の要請が強まったら方針 B に移行。

### janus との関係

SE 鍵の `[.privateKeyUsage, .biometryCurrentSet]` フラグは **鍵利用時に必ず Touch ID を要求する**。つまり SE 鍵アクセスが成立した時点で:
- 物理的にこの Mac である (鍵が SEP 外に出ない)
- enrollment された指紋の持ち主である (biometryCurrentSet)

が同時に証明される。Windows における「TPM で Data Key をアンラップ」+「Windows Hello で人物確認」の二段階が、macOS では **一段階で両方同時に達成される**。

---

## 5. Rust からのアクセス

### keychain-services.rs (iqlusioninc)

- リポジトリ: https://github.com/iqlusioninc/keychain-services.rs
- Tony Arcieri (iqlusion) がメンテ。SEP + TouchID ガード鍵に直接対応した API を公開。
- 公開バージョンは 0.1.x 系で "experimental" 扱い。長期間大きな更新がない可能性あり (要確認、2026-04 時点の直近コミット不明)。
- hyde のような production 用途にそのまま使うより、**参照実装として読む**のが妥当。メモリ安全性のリスクが注記されている。

### localauthentication-rs (caoimhebyrne)

- リポジトリ: https://github.com/caoimhebyrne/localauthentication-rs
- LAPolicy 4 種 (WithBiometrics / Default / WithWatch / WithBiometricsOrWatch) をカバー。
- 依存は objc crate 系の旧世代。"still in development" の注記あり。

### objc2 系 (madsmtm/objc2)

- `objc2-security`: Security framework (SecKey, SecAccessControl 等) の autogen バインディング。
- `objc2-local-authentication`: LAContext, LAPolicy のバインディング。Xcode 16.4 SDK から生成。
- `objc2-core-foundation`: CFTypeRef 系。
- **推奨**: hyde の macOS backend は objc2 系を直接使うのが無難。autogen で追従性が高く、メンテナンスが活発。

### entitlements と署名

- SE 鍵を扱うには **data-protection keychain** を使う必要があり、`keychain-access-groups` entitlement が必要。
- 単独 CLI バイナリには provisioning profile を埋め込めないため、**Developer ID 署名 + `keychain-access-groups` entitlement** 付きで配布するか、`.app` bundle 内部に閉じ込める必要がある。Apple Developer Forum には「CLI ツールを `.app` ライクな構造に包む」パターンが推奨されている。
- **Hardened Runtime**: Developer ID 経由で公証 (notarization) するには必須。Rust バイナリは `codesign --options runtime --entitlements foo.entitlements` で署名可能。
- **署名なしバイナリの制限**: `errSecMissingEntitlement` で SE 鍵生成自体が失敗する。ローカル開発用に自己署名 ("ad-hoc signing" + 開発用 keychain-access-groups) は動作するケースあり (要実験)。

---

## 6. 脅威モデルと既知の攻撃

### checkm8 / T2

- checkm8 (2019, axi0mX) は A5〜A11 (および派生の T2) の Boot ROM 脆弱性。物理アクセス必須。
- T2 への波及により Intel Mac の AP カーネルまでは取得可能。ただし **SEP 内部の任意コード実行は得られない**。FileVault 鍵の直接抽出も不可。
- 影響は「keylogger 仕込み」「AP 上の未暗号化データ読み取り」レベル。SE 鍵マテリアルは保護される。
- **Apple Silicon は影響外** (Boot ROM が別設計)。

### blackbird (2020)

- Luca Todesco による SEPROM code execution exploit。A8/A9/A10 (+ T2) に対して、checkm8 等の AP 側 exploit と併用して SEPROM 上でのコード実行。
- 2023 に iPhone firmware downgrade に使用された実例あり。
- **M1 以降および A12 以降は影響外** (公開情報範囲内では未確認、不明)。

### Passware Kit 2024

- Passware Kit 2024 v4 は T2 Mac に対して checkm8 経由で FileVault パスワード総当たり攻撃をサポート。物理アクセス + 長時間計算が必要。Apple Silicon Mac は非対応。
- これは SE そのものの突破ではなく、**ユーザパスワードの brute force を SE のレート制限外で走らせる**攻撃モデル。強いパスワードで緩和可能。

### "Ventricles"

- この名前の既知研究は web search 範囲で未確認 (不明)。ユーザ提供文脈の typo または内部用語の可能性。

### SEP ROM の immutability

- SEPROM はマスクロムで書き換え不可。Boot ROM レベル脆弱性が発覚しても **シリコン交換以外では修正不可**。
- 逆に言えば M1 以降で公開された SEPROM 脆弱性は現時点で存在しない (2026-04 時点の公開情報、要継続監視)。

### biometryCurrentSet の enrollment 変更検出

- フラグは SE 内の enrollment hash に鍵マテリアルを束縛する (Apple Platform Security Guide 記載)。
- 攻撃者が指紋追加/削除するだけで鍵は復号不可能になる。
- ただし **ユーザが騙されて自ら指紋を追加する (social engineering)** ケースは守れない。
- **パスコード盗難** + 物理アクセス → 指紋追加可能 → 新しい enrollment で再 enroll して古い鍵が無効化されるのみ。攻撃者は古い鍵マテリアルには到達しない (OK)。

### SE が守らないもの

- AP カーネル特権で動くマルウェア (ただし鍵使用時の Touch ID プロンプトはスキップ不可)。
- ユーザの誤操作によるプロンプト承認 (phishing 的に Touch ID を押させる攻撃)。janus/hyde の UI 文言設計でプロンプトの意図を明示することで緩和。
- カバーチャネル/サイドチャネル (電力解析等、研究レベル)。

---

## 7. クロスプラットフォーム設計への影響

### Windows/Linux との構造差

| レイヤー            | Windows                | macOS                         |
|---------------------|------------------------|-------------------------------|
| デバイス束縛         | TPM 2.0                | Secure Enclave                |
| 人物束縛             | Windows Hello (別層)   | SE access control flags (同層)|
| 鍵アルゴ             | RSA/ECC 任意            | ECC P-256 のみ                |
| seal/unseal          | TPM Seal (PCR 可)       | ECIES ラップのみ              |
| PIN/パスワード検証   | TPM 内 dictionary attack 対策 | LA framework + SE            |

### 抽象化の引き方

hyde-core で `TeeBackend` を現状の TPM 中心設計のまま SE にマップするのは aesthetically 無理がある。以下 2 案:

**案 1: TeeBackend を最小化し、`WrappedKey` ハンドル中心に再設計**
- `backend.wrap(data, policy)` / `backend.unwrap(wrapped)` の 2 操作のみを primitive とする。
- TPM: seal を使う。SE: ECIES で private key ラップ。
- 人物束縛は `policy: Policy::RequireUserBinding` として引数化 → backend 側で実装 (SE は access control flag、Windows は TPM 後に Hello 呼び出し)。

**案 2: hyde と janus を OS ごとに再合成**
- Windows/Linux: `hyde::TpmBackend` + `janus::HelloBinder` を層として分離。
- macOS: `hyde::SecureEnclaveBackend` が内部で janus 相当を包含 (access control flag で)。
- janus trait は capability を persist: `binding.is_device_bound() && binding.is_person_bound()` を問える。
- SE の場合は **単一オブジェクトが両方 true** を返す。Windows は 2 オブジェクトに分離。

### UserBinding trait の capabilities

```rust
trait UserBinding {
    fn requires_biometric_prompt(&self) -> bool;
    fn is_hardware_backed(&self) -> bool;
    fn enrollment_change_invalidates(&self) -> bool;  // biometryCurrentSet 相当
    fn device_bound(&self) -> bool;
    fn person_bound(&self) -> bool;
}
```

SE 実装は 5 つすべて true。Windows Hello 単体は person_bound=true, device_bound=false (TPM と組み合わせて初めて device_bound)。

### 「デバイス＋人物」が単一層で達成される事実

macOS ではこれは **API の自然な形** である。人為的に 2 層に分離すると、プロンプトが 2 回出る、エラー経路が複雑になる、等の害がある。SE の設計思想 (access control flag で両方表現する) を尊重する方が素直。

---

## 8. 先行実装

### 1Password

- macOS 版は Touch ID で "unlock" する設計。実体は **Secret Key + master password をローカル暗号化して保存、Touch ID 成功で復号鍵を解放** する。
- 公式ドキュメント上は Secure Enclave 直接利用の明言は限定的。SE 鍵というより LAContext gate + Keychain storage の組み合わせ (`.userPresence` or `.biometryCurrentSet` 相当) と推測される (内部実装は非公開、推定)。

### Bitwarden

- macOS デスクトップアプリで Touch ID アンロックをサポート。Keychain に vault key を保存、Touch ID 成功で取得する方式。
- `.userPresence` フラグ利用と思われる (パスコードフォールバック可能)。Bitwarden community で「TouchID 失敗時パスコードで解除できてしまう」議論があるのはこの設計の帰結。

### Chrome (Chrome 124+ / 2024-04)

- iCloud Keychain 統合を有効化 (macOS 13.5+)。passkey 生成時 Touch ID 要求。
- Safe Storage key は macOS Keychain に保存。Apple Silicon Mac では Keychain 項目の metadata は SE に束縛される。
- Trail of Bits が 2024-03 に独立監査を実施 (credential exfil ゼロ確認)。

### git-credential-manager (GCM)

- macOS では標準で login keychain に credential を保存。**Touch ID プロンプトは標準では出ない** (Windows のブローカー認証相当機能は macOS 未対応、2026-04 時点)。
- `security` コマンドの `-T` オプションや ACL で手動設定する必要あり。

### Signal Desktop

- 2024-07 に「キーが平文で保存されている」脆弱性が指摘され、**Electron safeStorage API** 経由で macOS Keychain 保存に変更。
- **Secure Enclave 鍵として保持しているわけではない** (Keychain item でアプリ単位の ACL)。
- Tom Plant の提案実装。SE bind は現在未対応 (2026-04 時点)。

### DPAPI-NG / Windows Hello との比較

| 観点                 | DPAPI-NG + Windows Hello     | macOS Keychain + SE bind         |
|----------------------|------------------------------|----------------------------------|
| OS ネイティブ暗号保護 | あり                          | あり                              |
| 人物束縛             | Windows Hello 別 API 呼び出し | access control flag で一体       |
| 鍵アルゴ             | RSA/ECDH 各種                 | ECC P-256 のみ                   |
| プロンプト           | Hello 側で制御                | LAContext or 鍵アクセス時自動    |

---

## 9. 提言

### janus 0.1 macOS バックエンド

**LAContext gate 型のみで出すべき**。理由:
- janus の 0.1 スコープは「人物束縛の確認機構」。SE 鍵生成まで踏み込むと hyde と仕事が重複する。
- Windows (Hello gate) / Linux (libfprint or 自前 gate) との API 一貫性が取りやすい。
- ただし capability として `supports_hardware_binding: true` を返し、**後段で hyde に "hardware bind できるよ" と伝える** インターフェースは用意すべき。

### hyde macOS バックエンド (Phase 3 前倒し)

**前倒しの価値あり**。理由:
- macOS ユーザの実需 (研究者・個人開発者の相当数が Mac)。
- SE は TPM より API が狭い分、実装が単純 (ECC P-256 + ECIES のみ集中対応)。
- janus との統合が自然 (access control flag で)。

優先度の判断: NEDO Q-2 (2026-06 成果物提出) との兼ね合いで Q-2 向け Web アプリ側が Mac 主体なら **前倒しすべき**。デスクトップ (native hyde) 用途が Windows/Linux 中心なら Phase 3 の元スケジュール維持でよい。

### 「macOS 版 hyde + janus」の統一設計

**別クレートに分ける価値は限定的**。推奨構成:

- `hyde-macos` (または `hyde-core` の feature `backend-secure-enclave`) 内で SE 鍵を `[.privateKeyUsage, .biometryCurrentSet]` で生成。
- janus の macOS backend は `hyde-macos` が提供する SE handle をラップし、`UserBinding` trait を実装する薄い adapter に留める。
- Windows では janus と hyde が別クレートで独立に動くが、**macOS では janus::MacBinding が内部的に hyde::SecureEnclaveBackend を参照** する構造。コード重複なし。

### MVP スコープ

1. SE 鍵生成 (ECC P-256, `biometryCurrentSet`)
2. ECIES ラップでの Data Key 保護 (`eciesEncryptionCofactorX963SHA256AESGCM`)
3. Touch ID プロンプト文言の i18n
4. enrollment 変更時のエラーハンドリング (`errSecAuthFailed` → 再セットアップ UI)
5. Developer ID 署名 + notarization された配布バイナリ
6. `objc2-security` + `objc2-local-authentication` ベース (experimental crate は非依存)

**非スコープ (v1)**: Apple Watch unlock, iCloud Keychain 同期, Passkey 連携, Face ID Mac (存在しない), App Store 配布。

### Developer ID 署名 / 配布戦略

- **Apple Developer Program 加入**: 年 $99 USD。研究グラント予算に計上。
- **バイナリ形態**: CLI ツールは `.app` bundle 内 or 独立バイナリ + `keychain-access-groups` entitlement。
- **Notarization**: `xcrun notarytool submit` で自動化可能。CI (GitLab CI) から notary 提出するスクリプトを用意。
- **代替案**: 当初は `.dmg` + Developer ID 署名のみ (notarization なし) で配布し、ユーザに「右クリック → 開く」を案内する暫定運用。本リリースで notarization。
- **App Store 配布は非推奨**: sandbox 制約が hyde の用途と衝突する可能性 (fs アクセス、Keychain 範囲)。Developer ID 外配布が自然。

---

## 結論 (中心的な問いへの回答)

**macOS では janus と hyde を物理的に統合するのは行き過ぎだが、「API レイヤーで janus を薄く保ち、hyde の SE backend が janus 相当機能を内包する」構造が最も合理的である**。

根拠:
1. SE の `kSecAttrAccessControl` フラグは設計上「鍵アクセス = 人物認証」を一体化しており、別レイヤーで janus を挟むとプロンプトが二重化する。
2. 一方、janus を抽象として保つことは Windows/Linux との API 一貫性に不可欠。janus trait そのものは残す。
3. 具体的には、`janus::UserBinding` の macOS 実装が内部で hyde の SE handle を参照する形。ユーザから見れば 1 プロンプト、開発者から見れば 2 クレートの trait 境界が温存される。

これは「抽象を維持しつつ、プラットフォーム固有の統合性を犠牲にしない」正しい妥協である。
