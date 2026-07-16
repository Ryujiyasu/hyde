//! Pure-Rust TCG TPM 2.0 **v1.85 post-quantum** path (ML-KEM / ML-DSA).
//!
//! `tss-esapi` (the classic backend) has no v1.85 PQC support, so this module
//! marshals the v1.85 PQC commands directly and speaks the mssim socket protocol
//! to a TPM (firmware TPM today; real silicon unchanged once it ships).
//!
//! Command marshalling is byte-level and validated against captured reference
//! wire from an independent C client (see the `oracle` tests — they need no TPM
//! and run in CI). Live round-trips need a running TPM and are `#[ignore]`d.
//!
//! Status: experimental (0.2.x). Demonstrated against firmware TPM only; some
//! Sequence-Start parameter fields are wire-pinned pending TCG Part 3 hardening.

use std::io::{Read, Write};
use std::net::TcpStream;

// --- TCG v1.85 command codes / constants ---
const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const CC_SEQUENCE_UPDATE: u32 = 0x0000_015C;
const CC_VERIFY_SEQ_COMPLETE: u32 = 0x0000_01A3;
const CC_SIGN_SEQ_COMPLETE: u32 = 0x0000_01A4;
const CC_ENCAPSULATE: u32 = 0x0000_01A7;
const CC_DECAPSULATE: u32 = 0x0000_01A8;
const CC_VERIFY_SEQ_START: u32 = 0x0000_01A9;
const CC_SIGN_SEQ_START: u32 = 0x0000_01AA;

const RH_OWNER: u32 = 0x4000_0001;
const RS_PW: u32 = 0x4000_0009;
const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;

const ALG_SHA256: u16 = 0x000B;
const ALG_MLKEM: u16 = 0x00A0;
const ALG_MLDSA: u16 = 0x00A1;

/// ML-KEM parameter set selector.
#[derive(Clone, Copy)]
pub enum MlKem {
    K512 = 1,
    K768 = 2,
    K1024 = 3,
}
/// ML-DSA parameter set selector.
#[derive(Clone, Copy)]
pub enum MlDsa {
    D44 = 1,
    D65 = 2,
    D87 = 3,
}

// ---------------------------------------------------------------------------
// Minimal TPM 2.0 command marshaller (big-endian, TPM2B length-prefixed).
// ---------------------------------------------------------------------------
#[derive(Default)]
struct Buf(Vec<u8>);
impl Buf {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn tpm2b(&mut self, b: &[u8]) {
        self.u16(b.len() as u16);
        self.0.extend_from_slice(b);
    }
    fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
}

/// One TPM_RS_PW password session: empty nonce, continueSession, empty hmac.
fn pw_session() -> Vec<u8> {
    let mut s = Buf::default();
    s.u32(RS_PW);
    s.u16(0); // nonce (TPM2B, empty)
    s.u8(1); // sessionAttributes = continueSession
    s.u16(0); // hmac (TPM2B, empty)
    s.0
}

/// Marshal a command frame: tag, commandSize, commandCode, handles,
/// [authSize + auth area if sessions], parameters.
fn frame(cc: u32, handles: &[u32], sessions: &[Vec<u8>], params: &[u8]) -> Vec<u8> {
    let mut body = Buf::default();
    for &h in handles {
        body.u32(h);
    }
    if !sessions.is_empty() {
        let auth: Vec<u8> = sessions.concat();
        body.u32(auth.len() as u32);
        body.raw(&auth);
    }
    body.raw(params);

    let tag = if sessions.is_empty() {
        ST_NO_SESSIONS
    } else {
        ST_SESSIONS
    };
    let mut out = Buf::default();
    out.u16(tag);
    out.u32(10 + body.0.len() as u32);
    out.u32(cc);
    out.raw(&body.0);
    out.0
}

// --- TPMT_PUBLIC templates (wire-pinned against captured CreatePrimary) ---
fn tpmt_public_mlkem(param_set: u16) -> Vec<u8> {
    let mut p = Buf::default();
    p.u16(ALG_MLKEM); // object_type
    p.u16(ALG_SHA256); // name_alg
    p.u32(0x0002_0472); // object_attributes (decrypt)
    p.tpm2b(&[]); // auth_policy
    p.u16(0x0010); // TpmsMlkemParms.symmetric = TPMT_SYM_DEF_OBJECT NULL
    p.u16(param_set); // TpmsMlkemParms.parameter_set
    p.tpm2b(&[]); // unique (TPM generates)
    p.0
}
fn tpmt_public_mldsa(param_set: u16) -> Vec<u8> {
    let mut p = Buf::default();
    p.u16(ALG_MLDSA); // object_type
    p.u16(ALG_SHA256); // name_alg
    p.u32(0x0004_0472); // object_attributes (sign)
    p.tpm2b(&[]); // auth_policy
    p.u16(param_set); // TpmsMldsaParms.parameter_set
    p.u8(0); // TpmsMldsaParms.flag (wire-pinned 0x00; TCG Part 3)
    p.tpm2b(&[]); // unique (TPM generates)
    p.0
}
fn create_primary(template: &[u8]) -> Vec<u8> {
    let mut p = Buf::default();
    p.tpm2b(&[0, 0, 0, 0]); // inSensitive: empty userAuth + empty data
    p.tpm2b(template); // inPublic
    p.tpm2b(&[]); // outsideInfo
    p.u32(0); // creationPCR (empty TPML_PCR_SELECTION)
    frame(CC_CREATE_PRIMARY, &[RH_OWNER], &[pw_session()], &p.0)
}

// --- v1.85 command builders ---
fn encapsulate(key: u32) -> Vec<u8> {
    frame(CC_ENCAPSULATE, &[key], &[], &[])
}
fn decapsulate(key: u32, ciphertext: &[u8]) -> Vec<u8> {
    let mut p = Buf::default();
    p.tpm2b(ciphertext);
    frame(CC_DECAPSULATE, &[key], &[pw_session()], &p.0)
}
fn sign_seq_start(key: u32) -> Vec<u8> {
    let mut p = Buf::default();
    p.tpm2b(&[]); // auth
    p.u16(0); // hash_alg (NULL/0; wire-pinned)
    frame(CC_SIGN_SEQ_START, &[key], &[], &p.0)
}
fn sign_seq_complete(seq: u32, key: u32, message: &[u8]) -> Vec<u8> {
    let mut p = Buf::default();
    p.tpm2b(message);
    frame(
        CC_SIGN_SEQ_COMPLETE,
        &[seq, key],
        &[pw_session(), pw_session()],
        &p.0,
    )
}
fn verify_seq_start(key: u32) -> Vec<u8> {
    let mut p = Buf::default();
    p.tpm2b(&[]); // auth
    p.u16(0); // hash_alg
    p.u16(0); // sig_alg (wire-pinned; TCG Part 3)
    frame(CC_VERIFY_SEQ_START, &[key], &[], &p.0)
}
fn sequence_update(seq: u32, data: &[u8]) -> Vec<u8> {
    let mut p = Buf::default();
    p.tpm2b(data);
    frame(CC_SEQUENCE_UPDATE, &[seq], &[pw_session()], &p.0)
}
fn verify_seq_complete(seq: u32, key: u32, sig_alg: u16, sig: &[u8]) -> Vec<u8> {
    let mut p = Buf::default();
    p.u16(sig_alg); // TPMT_SIGNATURE.sigAlg
    p.tpm2b(sig); // TPM2B signature
    frame(CC_VERIFY_SEQ_COMPLETE, &[seq, key], &[pw_session()], &p.0)
}

fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

// ---------------------------------------------------------------------------
// mssim transport + high-level operations (need a running TPM).
// ---------------------------------------------------------------------------

/// A connection to a TPM over the mssim command port (firmware TPM / simulator).
pub struct PqcTpm {
    sock: TcpStream,
}

impl PqcTpm {
    /// Connect to a TPM mssim command port (e.g. `127.0.0.1:2321`) and start it.
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let mut t = PqcTpm {
            sock: TcpStream::connect(addr)?,
        };
        // TPM2_Startup(SU_CLEAR) — idempotent.
        let _ = t.transceive(&[0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0]);
        Ok(t)
    }

    fn transceive(&mut self, tpdu: &[u8]) -> std::io::Result<Vec<u8>> {
        self.sock.write_all(&8u32.to_be_bytes())?; // TPM_SEND_COMMAND
        self.sock.write_all(&[0u8])?; // locality
        self.sock.write_all(&(tpdu.len() as u32).to_be_bytes())?;
        self.sock.write_all(tpdu)?;
        let mut szb = [0u8; 4];
        self.sock.read_exact(&mut szb)?;
        let mut rsp = vec![0u8; u32::from_be_bytes(szb) as usize];
        self.sock.read_exact(&mut rsp)?;
        let mut ack = [0u8; 4];
        self.sock.read_exact(&mut ack)?;
        Ok(rsp)
    }

    fn rc(rsp: &[u8]) -> u32 {
        be32(rsp, 6)
    }

    /// ML-KEM key generation + Encapsulate/Decapsulate round-trip.
    /// Returns the 32-byte shared secret on success (Encap secret == Decap secret).
    pub fn ml_kem_roundtrip(&mut self, set: MlKem) -> std::io::Result<Vec<u8>> {
        let r = self.transceive(&create_primary(&tpmt_public_mlkem(set as u16)))?;
        let key = be32(&r, 10);
        // Encapsulate (NO_SESSIONS): rsp params = secret(TPM2B) then ciphertext(TPM2B).
        let r = self.transceive(&encapsulate(key))?;
        let sa = be16(&r, 10) as usize;
        let secret_a = r[12..12 + sa].to_vec();
        let ct_off = 12 + sa;
        let ct = r[ct_off + 2..ct_off + 2 + be16(&r, ct_off) as usize].to_vec();
        // Decapsulate (SESSIONS): rsp = ... parameterSize(4) | secret(TPM2B) | auth
        let r = self.transceive(&decapsulate(key, &ct))?;
        let sb = be16(&r, 14) as usize;
        let secret_b = r[16..16 + sb].to_vec();
        if secret_a == secret_b && !secret_a.is_empty() {
            Ok(secret_a)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "KEM secret mismatch",
            ))
        }
    }

    /// ML-DSA key generation + sign `message`.
    /// Returns `(public_key, signature)` (raw, TPM2B length stripped).
    pub fn ml_dsa_sign(
        &mut self,
        set: MlDsa,
        message: &[u8],
    ) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
        let r = self.transceive(&create_primary(&tpmt_public_mldsa(set as u16)))?;
        let key = be32(&r, 10);
        // out_public.unique = ML-DSA public key.
        let pk_len = be16(&r, 33) as usize;
        let pubkey = r[35..35 + pk_len].to_vec();

        let r = self.transceive(&sign_seq_start(key))?;
        let seq = be32(&r, 10);
        let r = self.transceive(&sign_seq_complete(seq, key, message))?;
        // rsp (SESSIONS): ... parameterSize(4) | TPMT_SIGNATURE{sig_alg(2), TPM2B sig} | auth
        let sig_len = be16(&r, 16) as usize;
        let sig = r[18..18 + sig_len].to_vec();
        Ok((pubkey, sig))
    }

    /// On-TPM verify of a signature against `message`: returns `true` if the TPM
    /// returns a validation ticket (MESSAGE_VERIFIED).
    pub fn ml_dsa_verify_on_tpm(
        &mut self,
        key: u32,
        message: &[u8],
        sig: &[u8],
    ) -> std::io::Result<bool> {
        let r = self.transceive(&verify_seq_start(key))?;
        let vseq = be32(&r, 10);
        self.transceive(&sequence_update(vseq, message))?;
        let r = self.transceive(&verify_seq_complete(vseq, key, ALG_MLDSA, sig))?;
        Ok(Self::rc(&r) == 0)
    }
}

// ---------------------------------------------------------------------------
// Byte-oracle: marshalling validated against independent C-client wire.
// These need no TPM and run in CI.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod oracle {
    use super::*;

    #[test]
    fn encapsulate_matches_captured_wire() {
        // conn034 (independent wolfTPM client), ML-KEM Encapsulate.
        assert_eq!(
            encapsulate(0x8000_0000),
            [0x80, 0x01, 0, 0, 0, 0x0e, 0, 0, 0x01, 0xa7, 0x80, 0, 0, 0]
        );
    }

    #[test]
    fn mlkem_template_matches_captured_wire() {
        // conn033 TPMT_PUBLIC(ML-KEM-512), verified byte-for-byte ×3 param sets.
        assert_eq!(
            tpmt_public_mlkem(MlKem::K512 as u16),
            [
                0x00, 0xa0, 0x00, 0x0b, 0x00, 0x02, 0x04, 0x72, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01,
                0x00, 0x00
            ]
        );
    }

    #[test]
    fn mldsa_template_matches_captured_wire() {
        // conn003 TPMT_PUBLIC(ML-DSA-44), verified byte-for-byte ×3 param sets.
        assert_eq!(
            tpmt_public_mldsa(MlDsa::D44 as u16),
            [
                0x00, 0xa1, 0x00, 0x0b, 0x00, 0x04, 0x04, 0x72, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00
            ]
        );
    }

    #[test]
    fn sign_seq_start_matches_captured_wire() {
        // conn004, SignSequenceStart.
        assert_eq!(
            sign_seq_start(0x8000_0000),
            [0x80, 0x01, 0, 0, 0, 0x12, 0, 0, 0x01, 0xaa, 0x80, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
