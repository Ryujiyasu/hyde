// Smoke test for hyde-wasm (nodejs target).
// Run: node crates/hyde-wasm/tests/smoke.cjs
//
// Prereq: `wasm-pack build --target nodejs --out-dir pkg-node` has been run.

const {
  HydeWasm,
  PqcKeypairWasm,
  pqcEncrypt,
  pqcDecrypt,
} = require("../pkg-node/hyde_wasm.js");

function assertEq(actual, expected, label) {
  if (actual !== expected) {
    console.error(`FAIL [${label}]: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
    process.exit(1);
  }
  console.log(`  ok: ${label}`);
}

console.log("Tier A: high-level HydeWasm.protect/unprotect");
{
  const hyde = new HydeWasm();
  const msg = new TextEncoder().encode("hello from hyde-wasm");
  const blob = hyde.protect(msg);
  if (!(blob instanceof Uint8Array) || blob.byteLength === 0) {
    console.error("FAIL: protect returned empty/invalid blob");
    process.exit(1);
  }
  console.log(`  protect: ${blob.byteLength} bytes`);

  const recovered = hyde.unprotect(blob);
  assertEq(new TextDecoder().decode(recovered), "hello from hyde-wasm", "roundtrip");
}

console.log("\nTier B: Option Y hybrid (low-level PQC)");
{
  const kp = PqcKeypairWasm.generate();
  const ek = kp.ekBytes();
  const dk = kp.dkBytes();
  assertEq(ek.length, 1184, "ek size (ML-KEM-768)");
  assertEq(dk.length, 2400, "dk size (ML-KEM-768)");

  const plaintext = new TextEncoder().encode("Layer 1 only (hybrid)");
  const ct = pqcEncrypt(ek, plaintext);
  const pt = pqcDecrypt(dk, ct);
  assertEq(new TextDecoder().decode(pt), "Layer 1 only (hybrid)", "pqc roundtrip");
}

console.log("\nCross-instance isolation (protected blobs are per-instance)");
{
  const h1 = new HydeWasm();
  const h2 = new HydeWasm();
  const blob = h1.protect(new TextEncoder().encode("secret"));
  let caught = false;
  try {
    h2.unprotect(blob);
  } catch (e) {
    caught = true;
  }
  if (!caught) {
    console.error("FAIL: h2 unprotected h1's blob (should be impossible without shared keys)");
    process.exit(1);
  }
  console.log("  ok: cross-instance unprotect fails");
}

console.log("\nAll smoke tests passed.");
