# hyde — ロードマップ

> 「実行時保護のMissing Layer」を埋める唯一のOSS Rust crate

---

## ビジョン

データには3つの状態がある。2つは解決済み。1つは未解決。

```
保存時（at rest）  → BitLocker / FileVault  ✅
通信時（in transit）→ HTTPS / TLS           ✅
実行時（in use）   → ???                    ← hydeはここ
```

hydeのゴールは：
**「どのクラウドに保存されても、誰にも読めないドキュメント」を実現する基盤を、OSSとして世界に届ける。**

---

## Hyde エコシステム

hydeは3モジュール暗号エコシステムの基盤：

```
  守る (Protect)     証明する (Prove)     計算する (Compute)
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│    hyde      │──▶│    argo     │──▶│    plat     │
│  TPM + PQC   │   │    ZKP      │   │    FHE      │
│  ML-KEM-768  │   │  証明エンジン │   │  演算エンジン │
└─────────────┘   └─────────────┘   └─────────────┘
```

| モジュール | 技術 | 用途 | リポジトリ |
|-----------|------|------|-----------|
| **hyde** | TPM + PQC (ML-KEM-768) | データを守る | [gitlab.com/Ryujiyasu/hyde](https://gitlab.com/Ryujiyasu/hyde) |
| **argo** | ZKP (ゼロ知識証明) | データを見せずに証明する | [gitlab.com/Ryujiyasu/argo](https://gitlab.com/Ryujiyasu/argo) |
| **plat** | FHE (完全準同型暗号) | 暗号化したまま計算する | [gitlab.com/Ryujiyasu/plat](https://gitlab.com/Ryujiyasu/plat) |

### ２つの市場戦略

| 戦略 | ターゲット | アプローチ |
|------|----------|-----------|
| **強化型** | 防衛省・政府・金融 | 既存の防御を更に強化（hyde） |
| **OPEN型** | 病院・研究機関 | データを安全に利活用（argo + plat） |

---

## フェーズ全体像

```
Phase 1          Phase 1.5        Phase 2          Phase 3          Phase 4
TPM 2.0          PQC対応          クラウドTEE      モバイル          統合エコシステム
（完了）          （完了）          （6〜18ヶ月）    （12〜24ヶ月）    （18ヶ月〜）

Windows/Linux    ML-KEM-768       Intel TDX        iOS Secure        oxi統合
TPM 2.0対応      HNDL耐性         AMD SEV-SNP      Enclave           人単位ライセンス
基本API確立       二層暗号化        クラウドVM対応    Android           argo/plat統合
crates.io公開    チップ移行簡素化   サーバー側保護    TrustZone         SaaS展開
```

---

## Phase 1：TPM 2.0 ✅ 完了

**期間**：〜4ヶ月
**目標**：Windows 11のTPMで動くデモとcrates.io公開

### なぜTPMから始めるか

```
Windows 11の全ユーザーがTPM 2.0を持っている
→ 世界中のPCに既に搭載済み
→ 追加ハードウェア不要
→ 今すぐ使える
```

### 実装項目

```
コア：
- [ ] TeeBackend trait定義（将来の拡張を見据えた設計）
- [ ] TpmBackend実装（tss-esapi使用）
- [ ] Primary Key生成・永続化（デバイスに1つ）
- [ ] Data Key生成・ラップ（データごと）
- [ ] シーリング（PCRバインディング）
- [ ] アンシーリング
- [ ] VeilContext公開API（protect / unprotect / backup / restore）
- [ ] FallbackPolicy（deny / warn / software）
- [ ] SoftwareBackendスタブ

永続化：
- [ ] ProtectedDataのSerialize/Deserialize対応
- [ ] WrappedKey（Key Blob）のディスク保存

回復：
- [ ] パスフレーズベースの鍵バックアップ
- [ ] パスフレーズからの鍵回復（Argon2id鍵導出）

開発者体験：
- [ ] #[veil::protect] アトリビュートマクロ（基本版）
- [ ] swtpmを使った自動テスト
- [ ] GitHub Actions CI（Linux + Windows）
- [ ] ドキュメント（docs.rs）

公開：
- [ ] crates.io v0.1.0リリース
- [ ] セキュリティカンファレンスでの発表
- [ ] 技術ブログ記事
```

### 成功基準

```
✅ swtpmを使ったテストが全てパス
✅ 実機TPMでのエンドツーエンドデモが動作
✅ crates.io に公開済み
✅ 「protect → unprotect」の往復が30行以内のコードで書ける
✅ ProtectedDataをJSONに保存→再読み込み→復号のフローが動作
```

---

## Phase 1.5：ポスト量子暗号 (PQC) ✅ 完了

**目標**：HNDL攻撃耐性 + チップ移行の簡素化

### なぜPQCが必要か

```
HNDL (Harvest Now, Decrypt Later):
→ 暗号化データを今収集し、将来量子コンピュータで解読する攻撃
→ 医療データや機密文書をS3に保存 → 数年後に量子コンピュータで解読される
→ TPMのRSA鍵ラッピングだけでは不十分
```

### 実装項目 ✅

```
- [x] ML-KEM-768 (NIST FIPS 203) 鍵カプセル化
- [x] 二層暗号化：PQC（内側、チップ非依存）+ TPM（外側、デバイスバインド）
- [x] ProtectedData v2フォーマット（v1後方互換）
- [x] 常時PQC有効（開発者の選択不要 — SecurityLevelはキャッシュ制御のみ）
- [x] チップ移行時のデータ再暗号化不要（PQC層がチップ非依存）
```

### 設計判断

```
検討した2つのアプローチ：
1. 使い分け（重要度に応じてPQC有無を選択） → 却下
2. 全データPQC（常時最強暗号化）          → 採用 ✅

理由：
- 開発者に暗号強度の判断を押し付けるのはhydeの設計思想に反する
- 「重要じゃないと思ったデータ」が実は重要だったケースは多い
- PQCのコストは今後下がる
- APIがシンプルなまま保てる
```

---

## Phase 2：クラウドTEE対応

**期間**：Phase 1完了後〜6ヶ月
**目標**：クラウドVM上でのサーバーサイド実行時保護

### 対象ハードウェア

| テクノロジー | クラウド | 利用可能VM |
|------------|---------|----------|
| Intel TDX | Azure, GCP | DCesv6, C3 |
| AMD SEV-SNP | AWS, GCP, Azure | N2D, M3 |

### なぜクラウドTEEが重要か

```
現状：
クラウドプロバイダーは理論上、顧客のVMメモリにアクセスできる
→ 「クラウドを信頼しなければならない」

TDX/SEV-SNP後：
VMのメモリがハードウェアレベルで暗号化される
→ AWSの管理者も読めない
→ 国家機密をAWSに置けるようになる
```

### 実装項目

```
Intel TDX：
- [ ] tdx crateとの統合
- [ ] リモートアテステーション（証明書検証）
- [ ] TdxBackend実装（crates/veil-tdx/）

AMD SEV-SNP：
- [ ] sev crateとの統合
- [ ] アテステーションレポート検証
- [ ] SevBackend実装（crates/veil-sev/）

共通：
- [ ] クラウドプロバイダー別のTCTI設定
- [ ] アテステーションの抽象化API
- [ ] TeeBackend traitの拡張（attestation()メソッド追加）
- [ ] SoftwareBackendの本実装
```

### 成功基準

```
✅ Azure TDX VMでのデモ動作
✅ AWS Nitro Enclaveと同等の機能をOSSで実現
✅ 「サーバー上で処理中のデータもクラウドが読めない」のデモ
```

---

## Phase 3：モバイル対応

**期間**：Phase 1完了後〜12ヶ月
**目標**：iOS・Androidでの実行時保護

### 対象ハードウェア

| プラットフォーム | テクノロジー | 特徴 |
|--------------|------------|------|
| iOS / macOS | Secure Enclave | Apple独自・高信頼 |
| Android | TrustZone / StrongBox | ARM標準 |

### 実装項目

```
iOS / macOS（Swift bindings）：
- [ ] veil-swift パッケージ
- [ ] Secure EnclaveのRustラッパー
- [ ] SwiftからRustを呼び出すFFI層
- [ ] iOS Keychain連携

Android（Kotlin bindings）：
- [ ] veil-kotlin パッケージ
- [ ] Android Keystoreとの統合
- [ ] JNI経由でのRust呼び出し
- [ ] StrongBox対応

共通：
- [ ] 生体認証との連携API
  （Face ID / Touch ID / 指紋認証）
- [ ] 生体認証で保護した鍵のクラウド同期
  （クラウドは暗号文のみ保持）
```

### 成功基準

```
✅ iPhoneのFace IDで保護したドキュメントを
   同じiPhoneのFace IDでのみ復号できるデモ
✅ 「高市首相にしか読めない文章」の実装
```

---

## Phase 4：統合エコシステム

**期間**：Phase 1完了後〜18ヶ月
**目標**：oxiとの統合・エンタープライズSaaS展開

### oxi統合

```
目標：「誰も読めないGoogle Docs」
```

#### 統合シナリオ1：oxihanko + veil（PAdES署名のTEE化）

```
oxihankoは既にPKCS#7/PAdES署名を実装済み。
veilのTPM鍵でPAdES署名を行うことで、
署名鍵が特定のデバイス・特定の人物に紐付く。

実装：
- [ ] oxihankoの署名バックエンドにveilを統合
- [ ] TPM鍵によるPAdES署名の生成
- [ ] 署名鍵のTPMシーリング
- [ ] 印鑑（hanko）+ TEE署名の組み合わせデモ
```

#### 統合シナリオ2：リアルタイム協調編集 + E2E暗号化

```
oxi v2ではCRDT + zero-knowledge relayによる
リアルタイム協調編集が計画されている。
veilのTEEアテステーションで相手の実行環境を検証してから
鍵交換を行うことで、E2E暗号化の信頼性を強化。

実装：
- [ ] 協調編集セッション開始時のTEEアテステーション交換
- [ ] アテステーション検証後の鍵交換プロトコル
- [ ] リレーサーバーは暗号文のみ保持（zero-knowledge）
- [ ] 「編集中もクラウドが読めない」のエンドツーエンドデモ
```

#### 統合シナリオ3：ドキュメント暗号鍵のTPMシーリング

```
oxiで開いた.docx/.xlsx/.pptxの復号鍵を
veilで保護するもっとも基本的な統合パス。

実装：
- [ ] oxi-wasmからveilのprotect/unprotect呼び出し
- [ ] ドキュメント暗号鍵のProtectedData化
- [ ] 暗号化済みドキュメントのローカル保存・クラウド同期
- [ ] パスフレーズ回復によるデバイス移行フロー
```

### 人単位ライセンス管理SaaS

```
概念：
従来：シリアルキー → コピー可能・共有可能・盗難可能
veil：TPM＋生体認証 → 「この人・このデバイス」のみ有効

実装：
- [ ] ライセンスの発行API
- [ ] TPMアテステーション＋生体認証ハッシュへのバインド
- [ ] 退職・デバイス変更時の自動失効
- [ ] 管理ダッシュボード

ユースケース：
- SoftwareのTPMライセンス管理
- Adobe Creative Cloud代替のライセンスモデル
- 退職と同時に全ライセンスが失効する企業向けシステム

⚠️ 規制リスク：
- TPMシリアル番号・生体認証ハッシュは個人データに該当しうる
- GDPR（EU）、個人情報保護法（日本）の遵守が必要
- 生体認証テンプレートの保存・処理には明示的な同意が必須
- TPMアテステーション情報からのデバイストラッキングのリスク
- 対策：個人データの最小化、匿名化されたアテステーション、
  データ保護影響評価（DPIA）の実施
```

### エンタープライズ展開

```
ターゲット：
- 法律事務所（機密文書）
- 金融機関（取引データ）
- 医療機関（患者データ）
- 防衛関連（機密情報）
- 政府・官公庁（国家機密）

提供形態：
- veil OSSコア：永続無料（crates.io）
- エンタープライズサポート：SLA・監査・CVE対応（有償）
- 人単位ライセンス管理SaaS：月額課金（有償）
- 統合コンサルティング：既存システムへの組み込み（有償）
```

### デジタル庁・IPA連携

```
目標：
ガバメントクラウド上で国家機密文書を
安全に扱える基盤としての採用

アプローチ：
- IPA未踏採択を通じたネットワーク活用
- デジタル庁のガバメントクラウド要件との整合
- 実証実験の推進
```

---

## 技術的マイルストーン

```
v0.1.0（Phase 1完了） ✅
  └─ TPM 2.0対応・crates.io公開
  └─ マルチクレートワークスペース構成

v0.2.0（Phase 1.5完了） ✅
  └─ ML-KEM-768 PQC暗号化（常時有効）
  └─ 二層暗号化アーキテクチャ
  └─ HNDL攻撃耐性

v0.3.0
  └─ #[hyde::protect] マクロの完成版
  └─ Windows Hello連携

v0.4.0（Phase 2開始）
  └─ Intel TDX対応（hyde-tdx crate）

v0.5.0
  └─ AMD SEV-SNP対応（hyde-sev crate）
  └─ アテステーションAPI

v0.6.0（Phase 3開始）
  └─ iOS Secure Enclave対応

v0.7.0
  └─ Android TrustZone対応

v1.0.0（Phase 4）
  └─ oxi統合デモ（oxihanko + E2E + ドキュメント鍵保護）
  └─ argo (ZKP) / plat (FHE) エコシステム統合
  └─ 人単位ライセンスSaaS β版
  └─ エンタープライズサポート開始
```

---

## ビジネスモデル

```
                    認知                    収益
┌───────────────────────────────────────────────────────┐
│                                                       │
│   oxi（無料・OSS）──────────────→ hyde（有料・OSS＋）  │
│   Office互換エディタ              実行時保護基盤        │
│   世界中に普及                    企業向けSaaS          │
│                                                       │
│          hyde ecosystem:                              │
│          hyde (TPM+PQC) → argo (ZKP) → plat (FHE)    │
│          守る → 証明する → 計算する                     │
│                                                       │
└───────────────────────────────────────────────────────┘

収益源（hyde ecosystem）：
1. エンタープライズSLA・サポート契約
2. 人単位ライセンス管理SaaS（月額課金）
3. セキュリティ監査サービス
4. 統合コンサルティング
5. OPEN型：argo/platを活用した医療・研究データ利活用基盤
```

---

## 競合優位性の維持

```
参入障壁：
1. 技術的複雑性
   → TPM/TDX/SEV/Secure Enclave/TrustZoneの
     統一抽象化は非常に難しい
   → 先行者優位が大きい

2. エコシステム
   → oxiとの統合が独自の価値を生む
   → 単独では再現できない

3. 信頼
   → セキュリティソフトは信頼が最重要
   → OSSとして透明性を確保
   → 採用実績が信頼を生む

4. 特許リスクなし
   → ブラックボックステスト手法（oxi）
   → 既存OSSの統合（veil）
   → 新しいアルゴリズムは使わない
```

---

## 参考資料

- [tss-esapi crate](https://docs.rs/tss-esapi/)
- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [AMD SEV-SNP](https://www.amd.com/en/processors/amd-secure-encrypted-virtualization)
- [Apple Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)
