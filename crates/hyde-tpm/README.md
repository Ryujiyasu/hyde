# hyde-tpm

TPM 2.0 backend for [Hyde](https://gitlab.com/Ryujiyasu/hyde). Two independent,
feature-gated paths:

- **`tss`** (default): classic TPM 2.0 via `tss-esapi` — sealing, device key
  wrap, AES-256-GCM. Backward-compatible with 0.1.x.
- **`pqc`**: pure-Rust **TCG TPM 2.0 v1.85 post-quantum** — ML-KEM (FIPS 203)
  and ML-DSA (FIPS 204). `tss-esapi` has no v1.85 PQC support, so this path
  marshals the v1.85 PQC commands directly and speaks the mssim socket protocol.
  Builds with **no C / `libtss2`** dependency.

```bash
# PQC path, no libtss2:
cargo test    -p hyde-tpm --no-default-features --features pqc
cargo run     -p hyde-tpm --no-default-features --features pqc --example pqc_demo
```

```rust
use hyde_tpm::pqc::{MlDsa, MlKem, PqcTpm};

let mut tpm = PqcTpm::connect("127.0.0.1:2321")?;
let secret  = tpm.ml_kem_roundtrip(MlKem::K512)?;       // KEM: encap == decap
let (pk, sig) = tpm.ml_dsa_sign(MlDsa::D44, message)?;  // hardware-rooted signature
```

## Evidence travels with the crate

The PQC command marshalling is validated **byte-for-byte against captured
reference wire from an independent C client** (the `pqc::oracle` tests), and a
real TPM-produced ML-DSA signature is checked by an **independent FIPS 204
implementation** (`tests/independent_verify.rs`). Both run in CI **without a
TPM**.

> Independent verification here is *evidence*, not attestation. Verifying a
> TPM signature on the host does **not** replace TPM-rooted attestation
> verification — it only demonstrates the signature is cryptographically valid.
> The independent verifier is therefore confined to tests/examples, not the
> public API.

## Status and limitations (not diluted)

- **Firmware TPM only.** No hardware TPM implementing v1.85 PQC exists yet, so
  this is demonstrated against the only existing implementation — a firmware
  TPM. Real-silicon validation awaits shipping hardware (the transport is TCTI-
  shaped, so the port is expected to be unchanged, but this is unverified). This
  is the frontier, not a weakness.
- **Some parameters are provisional.** A few Sequence-Start command fields are
  pinned to observed wire. They are **functionally successful** (the TPM accepts
  them and the verify path returns a validation ticket); what is outstanding is
  cross-referencing their byte layout against the TCG Part 3 specification —
  i.e. confirming spec-conformance as documentation, not whether they work.
- **Experimental (0.2.x), proof-of-concept.** Response decoding is hand-written;
  the v1.85 additions are maintained as a fork-derived layer. Use at your own
  risk.

## License

MIT
