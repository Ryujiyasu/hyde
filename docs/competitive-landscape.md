# Competitive Landscape / 競合状況

> Last updated: 2026-04-06

hyde が占めるポジション — **TPM + PQC をアプリケーションレイヤーで統合し、「鍵のエクスポート自体をハードウェアが拒否する」ことでプライバシーインフラを構成する Rust crate** — に対する直接的な競合は、2026年4月時点で存在しない。

---

## 1. エコシステム各レイヤーの状況

| レイヤー | 状況 | 備考 |
|---|---|---|
| **TPM + PQC 統合 Rust crate** | **hyde 以外に存在しない** | 高確信度 |
| **任意言語での TPM + PQC 統合ライブラリ** | **存在しない** | |
| **TPM ハードウェア（PQC ネイティブ）** | 未出荷 | SEALSQ QVault TPM 185 が 2026 年後半にエンジニアリングサンプル予定 |
| **ソフトウェア PQC + TPM アクセス（別々）** | wolfTPM + wolfCrypt (C)、Parsec (Rust, 部分的) | |
| **法的フレーミング（暗号文 ≠ 個人情報）** | **hyde に固有** | |

---

## 2. 関連プロジェクト詳細

### 2.1 TPM バインディング (Rust)

- **tss-esapi** (Parallaxsecond) — TPM 2.0 TSS Enhanced System API の Rust ラッパー。PQC サポートなし。TPM v185 仕様 → tpm2-tss 実装 → tss-esapi バインディングの順で到達するため、まだ先。
- **tpm2-tss FFI** — 低レベル C FFI バインディング。同上。

### 2.2 PQC プリミティブ (Rust)

- **ml-kem / ml-dsa** (RustCrypto) — 純ソフトウェア ML-KEM (FIPS 203) / ML-DSA (FIPS 204)。TPM 統合なし。
- **pqcrypto** — PQClean の Rust バインディング。暗号プリミティブのみ。
- **liboqs-rust** — Open Quantum Safe の Rust バインディング。同上。

### 2.3 統合的アプローチ (他言語含む)

- **Parsec** (Arm/Parallaxsecond) — TPM・HSM・暗号バックエンドの抽象化サービス (Rust)。コンセプト的に最も近いが、PQC をファーストクラス操作として統合していない。
- **wolfTPM + wolfCrypt** (C) — wolfCrypt 経由でソフトウェア PQC は可能だが、TPM バウンド PQC 鍵操作はハードウェア待ち。
- **Google Tink** — 暗号抽象化ライブラリ。TPM サポート最小限。PQC-TPM 統合なし。
- **Microsoft CNG / NCrypt** — Windows 暗号 API。TPM バックド鍵をサポートするが、PQC は未出荷（2025年時点）。

---

## 3. TPM × PQC ハードウェアの動向

### 3.1 仕様 (TCG)

TCG は TPM 2.0 v185 仕様で ML-KEM (FIPS 203) と ML-DSA (FIPS 204) を統合。主な新コマンド：

- `TPM2_Encapsulate` / `TPM2_Decapsulate` — ハードウェア保護された ML-KEM 鍵カプセル化
- `TPM2_SignDigest` / `TPM2_VerifyDigest` — ML-DSA による署名・検証
- `SignVerifySequenceStart` / `SignSequenceComplete` / `VerifySequenceComplete` — ストリーミング署名

PC Client 向けプロファイル (v1.07 RC1):
- ML-DSA-65 または ML-DSA-87 のサポートが**必須** (SHALL)
- ML-KEM-512/768/1024 のサポートが**推奨** (SHOULD)

**hyde への含意:** 現在の hyde は ML-KEM-768 をソフトウェアで実装しているが、v185 対応 TPM が出回れば `TPM2_Encapsulate` / `TPM2_Decapsulate` で PQC 鍵交換自体がハードウェアに降りる。

### 3.2 チップベンダー

| ベンダー | 製品 | 状況 |
|---|---|---|
| **SEALSQ** | QVault TPM 183 (IoT, TCG 1.83) | 2026年3月 量産サンプル出荷済。FIPS 140-3 申請 5月、TCG認証 8月目標 |
| | QVault TPM 185 (IoT + PC/Server, TCG 1.85) | エンジニアリングサンプル 2026年7月。FIPS 申請 9月、TCG認証 10月 |
| | QS7001 V1 セキュアエレメント | ML-KEM-1024 + ML-DSA-87。2026年3月 量産サンプル出荷済 |
| **Dyber** | QuantaTPM | ML-KEM-768+ ネイティブ。QUAC 100 アクセラレータ: 120万 ops/sec |
| **Infineon** | OPTIGA TPM SLB 9672 | PQC 保護ファームウェアアップデート (XMSS) のみ。ML-KEM/ML-DSA ネイティブ実行は次世代待ち |
| | SLC27 セキュリティコントローラ | ML-KEM + ML-DSA の CC 認証済暗号ライブラリ搭載 (EAL6+、世界初) |
| | PSOC Control C3 | LMS 署名統合。ML-DSA/ML-KEM は crypto-agile API で将来拡張。2026年量産 |
| **wolfSSL** | wolfTPM (ソフトウェアスタック) | v1.85 の ML-DSA/ML-KEM コマンドサポート。CNSA 2.0 準拠目標 |

### 3.3 CNSA 2.0 規制タイムライン

| 期限 | 要件 |
|---|---|
| **2027年** | NSS 新規調達は CNSA 2.0 準拠必須 |
| **2030年** | RSA / ECDSA / EdDSA / DH / ECDH 非推奨化 (NIST) |
| **2031-2033年** | 全 NSS で CNSA 2.0 完全施行 |
| **2035年** | RSA / ECC 完全禁止 |

---

## 4. hyde の戦略的ポジション

### 追い風

- TPM v185 仕様の正式化により、hyde の「TPM が鍵エクスポートを拒否する」アーキテクチャが PQC でも公式サポートされることが確定
- CNSA 2.0 の 2027年期限が迫り、「TPM + PQC」への需要が急増中。hyde はこの組み合わせを Rust crate として提供する唯一の OSS
- SEALSQ QVault TPM 185 が 2026年後半にエンジニアリングサンプル到達すれば、hyde の PQC レイヤーをハードウェアに降ろす実証が可能

### 検討事項

- hyde は現在 ML-KEM-768 だが、CNSA 2.0 / SEALSQ は ML-KEM-1024 を推進。セキュリティレベルの選択肢として ML-KEM-1024 サポートの追加を検討
- wolfTPM が v1.85 対応を進めているため、hyde の TPM バックエンドとして wolfTPM の動向をウォッチ
- Infineon が最大シェアを持つので、OPTIGA TPM 次世代の v185 ネイティブサポート時期が市場普及のカギ

---

## 5. 結論

hyde は **TPM + PQC のアプリケーションレイヤー統合** というニッチで明確なファーストムーバーポジションを持つ。業界はハードウェア側（チップベンダー）とソフトウェア側（暗号ライブラリ）から TPM × PQC の収束に向けて動いているが、両者を統合してプライバシーインフラとして提供するプロジェクトは他にない。

2027年の CNSA 2.0 期限に向けたエコシステム整備は、hyde にとって採用土壌が広がるポジティブな動き。
