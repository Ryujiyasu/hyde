# Changelog

Notable changes to `hyde-core`. This crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-16

Breaking. Fixes two bugs that silently produced unrecoverable or corrupted data.

### Fixed

- **Protected data now outlives the context that wrote it.** `HydeContext`
  generated an ML-KEM keypair per context and kept it in memory only — it was
  never sealed or persisted. Every v2 record was therefore undecryptable by any
  later context, including after a process restart with a durable TPM, even
  though `ProtectedData` is `Serialize`/`Deserialize` precisely so it can be
  stored. The failure was silent: ML-KEM's implicit rejection turns a wrong
  decapsulation key into a wrong shared secret instead of an error, so it
  surfaced only as a downstream AES-GCM `SealMismatch` that reads like a TPM
  fault. Records are now **v3**: each carries its own ML-KEM decapsulation key,
  sealed by the TEE under that record's data key.
- **`backup` / `restore` no longer return ciphertext as if it were plaintext.**
  `restore` built its result with `version: 1` and `kem_ciphertext: None`
  hardcoded, so `unprotect` skipped the PQC layer and handed back the PQC
  ciphertext — the plaintext plus 28 bytes of AES-GCM nonce and tag — reporting
  success.

### Changed (breaking)

- `HydeContext::restore` now takes the `&ProtectedData` being recovered rather
  than its `ciphertext: &[u8]`. Recovering the data key alone is not enough: a
  v3 record also needs its `kem_ciphertext` and sealed decapsulation key. Those
  are carried over from the record, and the recovered key still opens them
  because it unwraps to the same data key the record was sealed with.
- `ProtectedData` gained a `sealed_dk` field and now writes `version: 3`.
- MSRV is now **1.85**, required by `ml-dsa 0.1.1`. Previous releases declared
  1.74, which they never actually satisfied.

### Unrecoverable data

**v2 records cannot be migrated.** The key needed to decrypt them existed only
in the memory of the context that wrote them, so a v2 record persisted to disk
was never readable in the first place — this release does not take away a
capability that worked. `unprotect` now returns an explicit error saying so,
instead of failing as an opaque `SealMismatch`. v1 records are unaffected.

## [0.1.1]

### Fixed

- `ml-dsa 0.1.1` call sites: `SigningKey::<P>::from_seed` (was
  `MlDsa*::from_seed`). Added `from_seed_key_derivation_is_deterministic` to
  guard the derivation against dependency drift.

## [0.1.0]

### Added

- Core traits and types for the Hyde TEE abstraction.
