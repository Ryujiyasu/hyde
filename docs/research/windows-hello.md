# Windows Hello 技術調査 — janus 設計のための事前調査

本ドキュメントは、hyde に「person binding」層である **janus** を統合するための技術調査である。Windows Hello の内部構造、API、脅威モデル、クロスプラットフォーム対応を整理し、janus のスコープを提言する。

## 1. Windows Hello アーキテクチャ

### NGC (Next Generation Credentials) の構造

Windows Hello の実装基盤は内部的に **NGC (Next Generation Credentials)** と呼ばれる。もともと Microsoft が "Microsoft Passport" というマーケティング名で展開していた構想が、Windows 10 で NGC として製品化され、後に「Windows Hello」「Windows Hello for Business (WHfB)」にブランド再編された。Passport は名称上は廃止されたが、SDK の `Windows.Security.Credentials` namespace (旧 Passport API) には今もその痕跡がある。

NGC の核は **非対称鍵ペアをローカルデバイスに閉じ込め、生体/PIN で unseal する** という設計である。Azure AD / Entra ID / AD FS / オンプレ AD にはユーザの公開鍵のみが登録され、パスワードに相当する共有秘密がネットワーク上を流れない。

NGC の格納領域は `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc` にあり、SYSTEM / LocalService に限定した ACL で保護される。サブフォルダに鍵コンテナのメタデータ、TPM ハンドル参照、保護されたキーマテリアル (TPM 非搭載環境では DPAPI で暗号化されたソフトウェア鍵) が配置される。

### KeyCredentialManager / UserConsentVerifier API

アプリ開発者が触る WinRT 層の主要 API は 2 つある。

- `Windows.Security.Credentials.KeyCredentialManager`
  ユーザに紐付く非対称鍵ペアの作成・取得・署名を行う。`RequestCreateAsync` で鍵生成、`OpenAsync` でハンドル取得、`KeyCredential.RequestSignAsync` でチャレンジ署名。署名要求時に OS が自動的に Windows Hello の UI (PIN / 顔 / 指紋) を出す。秘密鍵はアプリには一切露出しない。
- `Windows.Security.Credentials.UI.UserConsentVerifier`
  「ユーザがここにいて同意した」ことだけを確認する軽量 API。鍵操作を伴わない。戻り値は `UserConsentVerificationResult` (Verified / DeviceNotPresent / DisabledByPolicy / NotConfiguredForUser / RetriesExhausted / Canceled)。

UWP 以外の Win32 プロセスから `UserConsentVerifier` を使う場合、`RequestVerificationAsync` は直接呼べず、`IUserConsentVerifierInterop::RequestVerificationForWindowAsync(HWND, HSTRING)` 経由で HWND を渡す必要がある。これはモーダルダイアログの親ウィンドウを明示するためで、渡し忘れると UI がバックグラウンドに隠れる。

### TPM との連携と鍵の保護

TPM 2.0 搭載機では、NGC が生成する非対称鍵の秘密鍵は TPM 内で生成され、TPM の外に平文で出ることはない。「PIN や生体で秘密鍵を復号する」という説明は不正確で、正しくは **TPM の auth value (認可値) が PIN / 生体ジェスチャで供給され、TPM がその値を検証したときだけ鍵オブジェクトを unseal して署名演算を実行する**。

生体ジェスチャはそれ自体が直接 auth value になるわけではない。Windows Biometric Service が生体照合に成功すると、事前に登録された secret (生体 unlock 用の認可値) を TPM に流し込み、TPM がそれを受けて鍵を解放する。PIN の場合はユーザが入力した PIN がそのまま TPM に渡る。結果として PIN / 指紋 / 顔はいずれも「TPM 鍵の解放条件」の別表現であり、オンラインにはユーザの公開鍵で署名された assertion しか出ない。

TPM が無い機種では、秘密鍵は DPAPI で暗号化されてディスクに置かれる (ソフトウェアフォールバック)。これはフィッシング耐性は維持されるが、マシンからの鍵吸い出しに対するハード保証は失われる。`certutil -csp "Microsoft Passport Key Storage Provider" -key -user` で格納場所 (TPM か software) を確認できる。

### 生体テンプレートの保存場所と保護

生体テンプレート (顔 / 指紋) は `C:\Windows\System32\WinBioDatabase\` の `.dat` ファイルに保存され、センサごとに別ファイルになる。各 DB ファイルは AES-CBC + SHA-256 でファイル固有の鍵により暗号化され、その鍵は「システム」に対して `CryptProtectData` (DPAPI / CNG DPAPI) で保護される。

重要な構造的制約: **暗号化に使われる DB 鍵はシステムの秘密のみで包まれており、TPM に封印されていない**。そのため SYSTEM / admin 権限があればこの DB は復号できる。これが後述の "Windows Hell No" (Black Hat 2025) の根本原因である。

ESS (Enhanced Sign-in Security) が有効な環境ではこの制約が緩和される。ESS は VBS (Virtualization-Based Security) で分離された VTL1 上に顔照合アルゴリズムと生体データ経路を閉じ込め、ハイパーバイザがカメラ → VTL1 のメモリ領域を隔離する。テンプレートは VTL1 内でのみ生成・照合され、ディスクに置くときの暗号鍵も VTL1 からしかアクセスできない。ただし ESS は対応 HW (SoC / カメラ / ドライバの条件) が必要で、対応機が限定される。

## 2. hyde への統合設計

### windows-rs crate の該当 namespace

Rust からは `windows` crate (microsoft/windows-rs) で WinRT / Win32 の両系統を叩ける。

- `windows::Security::Credentials::KeyCredentialManager`
- `windows::Security::Credentials::UI::UserConsentVerifier`
- `windows::Security::Credentials::UI::UserConsentVerificationResult`
- `windows::Win32::System::WinRT::IUserConsentVerifierInterop` (Win32 プロセス用)
- `windows::Win32::System::Com::CoCreateInstance` / `CoInitializeEx`

feature フラグ側は `Security_Credentials`, `Security_Credentials_UI`, `Win32_System_WinRT`, `Win32_System_Com`, `Win32_Foundation` を有効化する。

### HydeContext の unprotect 前に Windows Hello 承認を挟む設計

hyde は現状「デバイス鍵 (TPM)」で `unprotect` するが、janus レイヤでは **「デバイス鍵 ∧ ユーザの存在同意」** に強化する。選択肢は 2 つある。

1. **UserConsentVerifier 方式 (gate 型)**
   `HydeContext::unprotect` の入口で `UserConsentVerifier::RequestVerificationForWindowAsync` を呼び、Verified のときだけ TPM unseal に進む。実装は軽い。ただし暗号学的には「OS がユーザを見た」という主張の信頼に寄りかかっており、OS 信頼が崩れた場合 (kernel compromise) にバイパスされうる。

2. **KeyCredentialManager 方式 (bind 型)**
   hyde のデバイス鍵の上に NGC 鍵による追加の署名を被せ、`unprotect` を「デバイス鍵で復号した一時値を NGC 鍵で署名させ、その署名を次の段に渡す」構造にする。OS が生体 / PIN を要求しないと NGC が署名しないため、承認が暗号論的に鎖に組み込まれる。実装コストは高いが、janus の本来の目標はこちら。

推奨は **Phase 1 で (1)、Phase 2 で (2) に格上げ**。

### セッション/キャッシュ管理戦略

毎回の `unprotect` で UI を出すと UX が破綻する。以下を組み合わせる:

- `HydeContext` に `UserPresenceCache { verified_at: Instant, ttl: Duration, binding: SessionBinding }` を保持。TTL は 5〜15 分を default、機密度の高い操作 (鍵ローテーション等) は無視して強制再認証。
- `SessionBinding` はプロセス ID / HWND / ログオンセッション LUID を含めて、別プロセスが cache を使いまわすことを防ぐ。
- プロセスロック解除 / サスペンド復帰イベント (`WTS_SESSION_LOCK` 等) で cache を強制失効。
- cache 自体をメモリ上のみに保持し、`zeroize` する。

### エラーハンドリング

`UserConsentVerificationResult` の enum を hyde 側 `JanusError` にマップする。

| WinRT 結果 | janus 側扱い |
|---|---|
| Verified | Ok |
| Canceled | `JanusError::UserCancelled` (リトライ可能) |
| RetriesExhausted | `JanusError::LockedOut` (一定時間後再試行) |
| DeviceNotPresent | `JanusError::BackendUnavailable` (fallback へ) |
| DisabledByPolicy | `JanusError::PolicyBlocked` (fallback 禁止) |
| NotConfiguredForUser | `JanusError::NotEnrolled` (enroll 誘導) |
| DeviceBusy | 短い backoff でリトライ |

PIN fallback は Windows Hello 側が自動で提供するため、アプリ層で別経路を実装する必要はない。ただし `DeviceNotPresent` で hyde がどう振る舞うかはポリシー依存: 高保証モードでは失敗、低保証モードでは hyde デバイス鍵のみで続行。

### 擬似コード (Rust)

```rust
use windows::Security::Credentials::UI::{
    UserConsentVerifier, UserConsentVerificationResult,
};
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_ALL};
use windows::core::HSTRING;
use windows::Win32::Foundation::HWND;

pub struct JanusWindows {
    cache: parking_lot::Mutex<Option<UserPresenceCache>>,
    ttl: Duration,
}

impl JanusWindows {
    pub fn require_presence(&self, hwnd: HWND, reason: &str) -> Result<(), JanusError> {
        if let Some(c) = self.cache.lock().as_ref() {
            if c.is_valid(self.ttl) { return Ok(()); }
        }
        let msg = HSTRING::from(reason);
        let interop: IUserConsentVerifierInterop = unsafe {
            CoCreateInstance(&IUserConsentVerifierInterop::IID, None, CLSCTX_ALL)?
        };
        let op = unsafe { interop.RequestVerificationForWindowAsync(hwnd, &msg)? };
        let result = op.get()?;   // 実運用では async で await
        match result {
            UserConsentVerificationResult::Verified => {
                *self.cache.lock() = Some(UserPresenceCache::now());
                Ok(())
            }
            UserConsentVerificationResult::Canceled => Err(JanusError::UserCancelled),
            UserConsentVerificationResult::RetriesExhausted => Err(JanusError::LockedOut),
            UserConsentVerificationResult::DeviceNotPresent
            | UserConsentVerificationResult::NotConfiguredForUser
                => Err(JanusError::BackendUnavailable),
            UserConsentVerificationResult::DisabledByPolicy => Err(JanusError::PolicyBlocked),
            _ => Err(JanusError::Unknown),
        }
    }
}
```

HydeContext 統合側:

```rust
impl HydeContext {
    pub fn unprotect(&self, blob: &Sealed, janus: &dyn UserBinding) -> Result<Plain> {
        janus.require_presence("hyde: データの復号を承認してください")?;
        self.tpm_unseal(blob)
    }
}
```

## 3. 脅威モデルと既知の攻撃

### 主要 CVE と公開攻撃

- **CVE-2021-34466 — Windows Hello Face Spoofing** (2021-07, CVSS 6.1)
  CyberArk が報告。物理アクセス下で、IR カメラに対し攻撃者製作の USB カメラデバイスを接続し、ターゲットの顔の IR 画像を注入することで顔認証をバイパス。パッチ後は ESS 有効環境で防御されるが、ESS 非対応機では緩和策のみ。
- **Blackwing Intelligence — Fingerprint Sensor Bypass** (2023-11, CVE 番号は個別割当て)
  Microsoft Surface Pro X / Lenovo ThinkPad T14 / Dell Inspiron 15 の 3 機種で、ELAN / Synaptics / Goodix の指紋センサに対する AitM を実証。ELAN は SDCP 非対応でクリアテキスト通信、Synaptics は SDCP が default disabled で独自 TLS が弱い、Goodix は Linux/Windows の DB 切替を悪用。結論: **SDCP は OS ではなくファームに依存するため、カバレッジが OEM 任せ**。
- **CVE-2024-20671 — Windows Hello Security Feature Bypass** (2024)
  Windows Hello のセキュリティ機構を回避する脆弱性として Microsoft が月例で修正。
- **CVE-2025-26644 — Windows Hello Spoofing** (2025)
  顔認証アルゴリズムに対する adversarial perturbation を用いた spoofing。Microsoft は対策として顔照合に IR + 可視光カラーの両方を要求するよう変更し、暗所での顔認証は事実上無効化された。
- **"Windows Hell No" / Faceplant Attack** (Black Hat USA 2025, Baptiste David & Tillmann Osswald)
  ローカル admin 権限で `WinBioDatabase` を復号・改ざんし、攻撃者の顔/指紋テンプレートを注入して任意の WHfB ユーザとしてサインイン。原因は前述のとおり **WBDB 暗号鍵が TPM ではなくシステム秘密で保護されている** こと。Microsoft は ESS を推奨、非 ESS 環境では PIN のみ利用を推奨。根本修正は TPM 格納への変更が必要で困難とされる。

### biometric spoofing の現状

Windows Hello 単体の顔認証は、ESS 有効 + IR+RGB 併用環境ではかなり堅牢。ESS 無効・IR 単独環境では依然として物理アクセス+専用 HW の攻撃が可能。指紋は SDCP 有効センサに限れば中庸だが、SDCP 実装品質が OEM 依存で、Linux との dual-boot 機では DB 切替攻撃が残る。

### Enterprise bypass と守らないもの

Windows Hello / WHfB が守るのは「リモート認証におけるパスワードの共有と phishing」である。以下は守らない:

- unlock 後のセッション内で動く admin 権限マルウェア (LSASS / CloudAP / WBDB に到達できる)
- kernel / VSM 無しのハイパーバイザ改竄
- ドメイン側の AD / Entra ID 側の設定ミス (たとえば WHfB 鍵の trust 設定の誤り)
- 物理的な肩越し盗撮や PIN 覗き見
- OEM のセンサ FW バグ
- ESS 非対応 HW

### hyde の脅威モデルの変化

janus 統合前の hyde は「デバイスに鍵がバインドされているが、マルウェアがそのデバイスを動かしていれば復号できる」。janus 統合後は、

- **追加の防御**: 「対話的に存在するユーザの同意」が復号の必要条件になる。アイドル時のバックグラウンドマルウェアによる自動復号を抑止できる。
- **変わらない脅威**: OS カーネル compromise, 生体 DB 改竄 (non-ESS), 物理強要。
- **新たな依存**: Microsoft が管理する WBDB / NGC のセキュリティに hyde が依存することになる。janus の設計では、**Windows Hello は「存在の assertion」として使うだけで、hyde のデバイス鍵は従来通り TPM に独立にバインド**する。つまり janus 層の侵害は「存在判定のバイパス」までで、鍵マテリアルには到達しない。これを維持するのが設計不変条件。

## 4. クロスプラットフォーム状況

### macOS: Touch ID / Secure Enclave / LocalAuthentication

- Framework: `LocalAuthentication` (`LAContext`, `LAPolicy`)
  - `LAPolicy.deviceOwnerAuthenticationWithBiometrics`: Touch ID / Face ID のみ
  - `LAPolicy.deviceOwnerAuthentication`: 生体 or デバイスパスワード
- `LAContext.evaluatePolicy(_:localizedReason:reply:)` が UserConsentVerifier 相当。
- 鍵の側は `Security.framework` の `SecKeyCreateRandomKey` に `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave` と `SecAccessControl` (`.biometryCurrentSet` や `.userPresence`) を付けると、**鍵自体が Secure Enclave に格納され、生体認証なしでは `SecKeyCreateSignature` できなくなる**。これは hyde にとって理想形で、WHfB の KeyCredentialManager + TPM と完全に対応する。
- Rust bindings: `localauthentication-rs` (LAContext ラッパ), `keychain-services` crate (Secure Enclave/Keychain)。前例: `sekey`, `secretive` (Secure Enclave-backed SSH agent)。
- 注意: アプリは署名 + entitlement が必要。unsigned バイナリは Keychain の該当項目にアクセスできない。

macOS 側は Windows より API が素直で、janus の抽象化はほぼそのままハマる。

### Linux: fprintd / PAM / FIDO2 — ギャップの正直な評価

Linux にはユーザ空間プロセスから叩ける「生体付きデバイス鍵」の統一 API が **存在しない**。

- **fprintd + libfprint**: D-Bus 経由で指紋登録・照合。PAM 統合 (`pam_fprintd`) でログイン時に使える。ただし 2019 以来の既知問題として、**指紋テンプレートは平文で `/var/lib/fprint/` に保存される**。暗号化の保護はなく、SELinux / AppArmor の DAC/MAC に依存。テンプレートから元画像復元も可能 (ANSI INCITS 378 標準形式のため)。
- **systemd-homed**: FIDO2 と PIN / 回復鍵によるホーム暗号化。指紋サポートは long-standing の feature request で、現時点でも限定的。
- **FIDO2 / libfido2**: YubiKey 等の外部トークン経由の user verification。プラットフォーム認証ではなくローミング認証。
- **TPM 2.0 direct (tpm2-tss)**: 鍵を TPM に封印することはできるが、「生体同意で unseal」という Windows Hello 相当の統合は OS 側に存在しない。

つまり Linux 上で「Windows Hello 相当」を真面目にやろうとすると、janus 側が **自前で生体 → TPM auth value のブリッジを設計・実装する** 必要がある。正直、Phase 1 では無理。現実的には以下のフォールバック階層を提示する:

1. FIDO2 トークン + PIN (YubiKey 等の外部 authenticator)
2. TPM + PIN (生体なし)
3. Polkit / PAM auth (sudo 相当の対話的確認、暗号学的保証なし)

### UserBinding trait 抽象化案

```rust
pub trait UserBinding: Send + Sync {
    /// ユーザ存在を要求 (gate 型)
    fn require_presence(&self, reason: &str) -> Result<PresenceToken, JanusError>;

    /// 署名 (bind 型, Phase 2)
    fn sign_with_presence(
        &self,
        key_id: &KeyId,
        challenge: &[u8],
        reason: &str,
    ) -> Result<Vec<u8>, JanusError>;

    /// enroll / deregister
    fn enroll(&self, key_id: &KeyId) -> Result<(), JanusError>;
    fn is_enrolled(&self, key_id: &KeyId) -> Result<bool, JanusError>;

    /// バックエンド特性
    fn capabilities(&self) -> BindingCapabilities;
}

pub struct BindingCapabilities {
    pub hardware_bound: bool,          // TPM / SE に鍵が居るか
    pub biometric_available: bool,
    pub pin_fallback: bool,
    pub attestation_supported: bool,
}
```

実装: `JanusWindows` (Hello), `JanusMacOS` (SE + LAContext), `JanusFido2` (libfido2), `JanusFprintd` (Linux, 非ハード保証), `JanusNull` (テスト / 最低保証)。

## 5. 先行実装

### DPAPI-NG / CNG DPAPI

Microsoft native の「データ保護」API。`NCryptProtectSecret` / `NCryptUnprotectSecret` で、保護対象を principal (ユーザ SID, AD グループ SID, LOCAL, SDDL) で指定。domain-joined 環境では複数マシン間で復号可能。Windows Hello そのものではないが、NGC の software-backed モードでは内部的に DPAPI が使われる。janus は DPAPI-NG **に依存しない** 設計が望ましい (hyde は TPM 直結のため)。

### 1Password / Bitwarden の Windows Hello 統合方式

2025 年 11 月の Windows 11 更新で、サードパーティパスキーマネージャが OS レベルの credential provider になれる新 API (MSIX plugin) が GA。1Password / Bitwarden はそれに対応。流れは: MSIX パッケージが system provider として登録 → Windows Hello が「ローカルの gatekeeper」として存在確認 → 選択されたベンダーが実際の passkey を保存・同期。**Windows Hello 自体はユーザ存在判定のゲートに徹する** 設計で、janus が参考にすべき分離モデル。

vault unlock については、両者ともアプリ起動時に `UserConsentVerifier` で Hello を要求し、成功時に DPAPI / Keychain 等に保存された vault 鍵を取り出す classic な gate 型。暗号鍵そのものを TPM に bind する強い方式は採用していない (vault は同期前提のため)。

### rust-keyring の Windows Hello 対応

`keyring` crate (open-source-cooperative/keyring-rs) は Windows 上では Credential Manager を使うのみで、**Windows Hello の承認を要求する機能は持たない**。`WinCredential` は単に Generic Credential の CRUD。keyring-rs を janus のバックエンドに採用する価値は低い。

### 既存の Rust crate で Windows Hello を使っているもの

- `windows` crate 公式 (microsoft/windows-rs): バインディングのみ。
- `SubconsciousCompute/windows-credential-provider-rs`: Credential Provider (ログオン画面側) のサンプル。janus の用途とは逆方向だが、Rust で COM ベース Windows セキュリティ API を扱う参考になる。
- `localauthentication-rs` (macOS), `keychain-services` (macOS): こちらは充実。
- hyde のスコープに直接該当する「アプリ内から Windows Hello 同意 + TPM 鍵連携」を丸ごと提供する crate は、調査時点で見当たらず (不明)。これは janus が埋めるべきギャップである。

## 6. janus プロジェクトへの提言

### Windows Hello 統合は推奨か / どの Phase で入れるか

**推奨する。ただし段階的に。**

- **Phase 1 (MVP)**: `UserConsentVerifier` ベースの gate 型のみ。`HydeContext::unprotect` の前に対話的承認を挟む。hyde のデバイス鍵は従来通り TPM 独立。依存は軽い、UX は大きく変わる、暗号学的強度は OS 信頼モデルに寄る。
- **Phase 2**: `KeyCredentialManager` による bind 型。NGC 鍵が hyde の鍵ラップに暗号学的に参加する。ESS 対応機をターゲットとし、ESS 無効機では Phase 1 相当にフォールバック。
- **Phase 3**: attestation 連携。WHfB の鍵 attestation を使って「この鍵は TPM 内で生成され、生体で守られている」ことを hyde のサーバ側 (もしあるなら) に証明する。

### Linux 向けに「改良版 Windows Hello」を独自実装する価値

**長期的にはあり、短期的には避ける。**

- 短期: janus Linux 版は「FIDO2 + PIN + TPM」を組み合わせた PresenceProvider の実装で十分。fprintd は後述の理由でデフォルト採用しない。
- 長期: Linux 側の「生体 → TPM auth value」のギャップを埋めるプロジェクトは世界的に欠けており、hyde / plat のエコシステムにとって差別化要因になりうる。ただし libfprint への patch, TPM policy session 設計, systemd / PAM 統合を含み、janus 本体と同規模のサブプロジェクトになる。別プロジェクト化を推奨。
- 教訓: Windows Hello の最大の設計ミスは「WBDB を TPM に封印しなかった」ことである。改良版はこれを避け、**テンプレート DB そのものを TPM policy (PCR or auth value) で封印する** 方針を検討すべき。

### クロスプラットフォーム戦略の推奨

- Rust trait `UserBinding` を第一級の抽象化として置く。
- macOS を基準実装にする (Secure Enclave + LAContext の API が clean で、hyde の意図と一致)。Windows を第二実装として追随。Linux は fallback を明示する。
- 「hardware_bound = true の binding が利用可能な OS でのみ高保証モードを許可」というポリシーを hyde 側でも扱えるようにする。
- ESS 無効機 / TPM 非搭載機 / fprintd のみの Linux では、明示的にダウングレード警告を表示する。

### MVP スコープ提案

janus 0.1 で提供すべき最小セットは以下。

1. `UserBinding` trait (require_presence のみ) と `BindingCapabilities`。
2. `JanusWindows`: `UserConsentVerifier` 実装。PIN fallback は Hello 自身に任せる。cache TTL 5 分。
3. `JanusMacOS`: `LAContext.evaluatePolicy(deviceOwnerAuthenticationWithBiometrics)` 実装。
4. `JanusFido2`: libfido2 バックエンド (Linux / クロスプラットフォーム fallback)。PIN + user presence。
5. `JanusNull`: CI / テスト / 無保証モード用。
6. `HydeContext::unprotect_with_janus(&dyn UserBinding)` の追加 (既存 API は破壊しない)。
7. エラー型 `JanusError` とドキュメント化された fallback ポリシー。
8. ドキュメント: 「janus は存在判定であり、鍵の保護は TPM/SE が担う」という設計不変条件を README と hyde の脅威モデルに明記。

`KeyCredentialManager` 統合 / 生体テンプレート保護レビュー / Linux 独自実装は 0.2 以降にスコープアウト。0.1 の目的は **「hyde の aspect of presence を暗号ではなく UX/ポリシー層で導入し、後続の bind 型に API 互換で進化できる基盤を作る」** こと。

## 参考資料

- Microsoft Learn, "How Windows Hello for Business works"
- Microsoft Learn, "Windows Hello Enhanced Sign-in Security"
- Microsoft Learn, "CNG DPAPI" / "Data Protection API"
- Microsoft Learn, "UserConsentVerifier Class" / "KeyCredentialManager Class"
- microsoft/windows-rs docs (`windows::Security::Credentials::*`, `IUserConsentVerifierInterop`)
- Dirk-jan Mollema, "(Windows) Hello from the other side", NorthSec
- Clément Notin, "When Windows Hello fails at securely authenticating users and protecting credentials" (2019)
- Blackwing Intelligence, "A Touch of Pwn — Part I" (2023)
- CyberArk, "Bypassing Windows Hello Without Masks or Plastic Surgery" (CVE-2021-34466)
- Black Hat USA 2025, David & Osswald, "Windows Hell No for Business"
- Synacktiv, "WHFB and Entra ID: Say Hello to your new cache flow"
- Insinuator, "Windows Hello for Business — Past and Present Attacks" (2025)
- Apple Developer, "LocalAuthentication" / "Accessing Keychain Items with Face ID or Touch ID"
- oss-security / Debian BTS #926749, "fprintd: stores user fingerprints without encryption"
- Arch Wiki, "fprint" / "Universal 2nd Factor"
