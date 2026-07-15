# Changelog

Notable changes to `hyde-tpm`. This crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-07-16

Metadata only. The compiled code is identical to 0.2.0 — nothing to migrate.

### Fixed

- **The `pqc` module is now documented on docs.rs.** docs.rs builds only the
  default feature set, which is `tss`, so the entire `pqc` module — the v1.85
  post-quantum path this release line exists for — was absent from the published
  documentation. `[package.metadata.docs.rs] features = ["pqc"]` now builds both
  paths.

### Changed

- **crates.io keywords now say what the crate is.** They were inherited from the
  workspace (`tee`, `tpm`, `encryption`, `security`, `hardware`) and contained no
  post-quantum term, so the crate did not surface in a crates.io search for
  `post-quantum`, `ml-kem`, or `ml-dsa`. They are now `tpm`, `post-quantum`,
  `ml-kem`, `ml-dsa`, `tpm2`.

## [0.2.0] - 2026-06-30

### Added

- **`pqc` feature — TCG TPM 2.0 v1.85 post-quantum: ML-KEM (FIPS 203) and
  ML-DSA (FIPS 204).** The v1.85 commands are marshalled in pure Rust and spoken
  over the mssim socket protocol. `tss-esapi` has no v1.85 support because
  `libtss2` has none, so this path depends on neither: it builds with **no C and
  no `libtss2`**, `std` only.
  - `PqcTpm::connect`, `ml_kem_roundtrip`, `ml_dsa_sign`, `ml_dsa_verify_on_tpm`
  - Command codes `0x1A3`–`0x1AA`; algorithm IDs ML-KEM `0x00A0`, ML-DSA `0x00A1`
- **Byte-oracle tests.** The v1.85 command marshalling is asserted byte-for-byte
  against captured reference wire from an independent C client. Runs in CI with
  no TPM.
- **Independent FIPS 204 verification** (`tests/independent_verify.rs`): a real
  TPM-produced ML-DSA-44 verifying key (1312 B) and signature (2420 B), checked
  by RustCrypto's `ml-dsa`. This is *evidence, not attestation* — verifying a TPM
  signature on the host does not replace TPM-rooted attestation verification, so
  the independent verifier is confined to tests and examples and is never exposed
  in the public API.
- `pqc_demo` example.

### Changed

- The crate is now split by feature. `default = ["tss"]`: the classic `tss-esapi`
  backend from 0.1.x is **unchanged**, and `tss-esapi`, `aes-gcm`, `hyde-core`,
  `zeroize` and `tracing` became optional dependencies gated under it.

### Known limitations

- **Firmware TPM only.** No shipping silicon implements v1.85 PQC yet, so the PQC
  path is demonstrated against a firmware TPM — the only implementation that
  exists. A real Infineon SLB9670 rejects these commands with
  `TPM_RC_COMMAND_CODE` while classic commands on the same chip succeed. The
  transport is TCTI-shaped, so the port to real silicon is expected to be
  unchanged, but that is unverified.
- **Some parameters are provisional.** A few Sequence-Start fields are pinned to
  observed wire. They are functionally successful — the TPM accepts them and
  verify returns a validation ticket — but cross-referencing their byte layout
  against the TCG Part 3 specification is outstanding. That is documentation,
  not whether they work.
- **Experimental proof-of-concept.** Response decoding is hand-written and the
  v1.85 additions are maintained as a fork-derived layer. Use at your own risk.

## [0.1.0]

### Added

- Classic TPM 2.0 backend via `tss-esapi`: sealing, device key wrap, and
  AES-256-GCM.
