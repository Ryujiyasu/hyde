# argo Design Notes / argo設計メモ

## Input Validation Layer Architecture / 入力バリデーションの層構造

The "garbage in, garbage out" problem is the fundamental challenge for any encrypted computation system. argo addresses this with a layered validation architecture.

「ゴミを入れればゴミが出る」問題は、暗号化計算システムの根本的な課題である。argoは層構造のバリデーションアーキテクチャでこれに対処する。

```
Layer 0: IoT Sensor + TPM (hyde)
  Physical measurement signed by hardware
  物理世界の測定値をハードウェアで署名
  → Prevents false value declarations / 虚偽値申告を防ぐ

Layer 1: ZKP (argo) + FHE Format Proof
  Prove format correctness with ZKP at encryption time
  暗号化時にフォーマットの正しさをZKPで証明
  → Rejects garbage data before encryption / ゴミデータを暗号化前に排除
  Reference: TFHE-rs ZKP features, ZHE (IEEE S&P 2025)

Layer 2: plat (FHE)
  Compute on encrypted data
  暗号化されたまま集計演算

Layer 3: argo (ZKP)
  Prove correctness of computation process
  計算プロセスの正しさを証明
```

### What each layer guarantees / 各層が保証すること

| Layer | Guarantees / 保証 | Cannot guarantee / 保証できないこと |
|---|---|---|
| **Layer 0** (IoT + TPM) | Physical measurement is hardware-signed / 物理測定値がHW署名済み | Sensor accuracy (vendor responsibility) / センサー精度（ベンダー責任） |
| **Layer 1** (ZKP format) | Input conforms to expected format / 入力が期待フォーマットに適合 | Semantic correctness / 意味的な正しさ |
| **Layer 2** (FHE) | Computation is performed on encrypted data / 暗号化データ上で演算実行 | Input authenticity / 入力の真正性 |
| **Layer 3** (ZKP proof) | Computation process is correct / 計算プロセスが正しい | Input truthfulness / 入力の真実性 |

### The Garbage-In Problem / ゴミ入力問題

```
Layer 0 prevents physically   — hardware can't lie about what it measured
Layer 1 prevents structurally — malformed data is rejected before encryption
Layer 2-3 guarantee process   — computation correctness only

Layer 0で物理的に防ぐ
Layer 1でフォーマット的に防ぐ
Layer 2・3では計算の正しさのみを担保
```

The remaining gap — a correctly formatted, hardware-signed value that is nevertheless **semantically wrong** (e.g., a calibrated sensor that drifts) — is the oracle problem. No cryptographic system can solve this. hyde's position: acknowledge it honestly.

残るギャップ — フォーマットが正しくHW署名もあるが**意味的に間違っている**値（例：校正がずれたセンサー）— はオラクル問題。暗号技術では解決できない。hydeの立場：正直に認める。

---

## References / 参考文献

- TFHE-rs ZKP features: Zero-knowledge proofs for FHE ciphertext validity
- ZHE (IEEE S&P 2025): Zero-knowledge proofs for homomorphic encryption
- NIST FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
