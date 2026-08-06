//! ADR-043 C1 P4 — integration tests for the offline TST verifier + the `commitment_proof_verify`
//! binary, driven by a REAL freeTSA RFC 3161 vector (see `tests/fixtures/README.md` for provenance).
//!
//! The whole file is gated on `offline-verify` (the feature that ships the crypto + the binary), so
//! `cargo test -p meshlogic-merkle` (no features) compiles it away and never regresses the base suite.
#![cfg(feature = "offline-verify")]

use meshlogic_merkle::anchor::{
    cert_pem_to_der, extract_tst_facts_matching_root, inspect_pinned_cert, verify_tst_full,
    verify_tst_pinned, TstVerifyError,
};
use meshlogic_merkle::proof_gen::{build_proof_bundle, ProofBundle, TstRef};
use meshlogic_merkle::roots_chain::build_roots_chain;
use sha2::{Digest, Sha256};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");

/// The frozen KAT p2 Merkle root (proof_gen.rs P2_ROOT) — the freeTSA fixture timestamps EXACTLY this
/// root, so the same token serves the crypto unit tests AND the end-to-end bundle test.
const KAT_ROOT_HEX: &str = "5fb58d89ca9e40abece0d6b1447d5783094112244c17e9b5b7aa5c89c84f8012";
const KAT_CONTENT_HASH: &str = "88496c1549d5dc5f6a0d91963892d3b681fc18540ebb3bd79c769a7a5993271a";

fn root_bytes() -> [u8; 32] {
    let mut r = [0u8; 32];
    hex::decode_to_slice(KAT_ROOT_HEX, &mut r).unwrap();
    r
}
fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIX}{name}")).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}
fn cacert_der() -> Vec<u8> {
    // The trusted root (DER), supplied out-of-band by the auditor.
    read_fixture("freetsa_cacert.der")
}
fn content_hash(label: &str) -> String {
    hex::encode(Sha256::digest(label.as_bytes()))
}

// ------------------------------------------------------------------------------------------------
// verify_tst_full against the REAL vector — the crypto correctness gate.
// ------------------------------------------------------------------------------------------------

#[test]
fn real_freetsa_vector_fully_verifies() {
    let resp = read_fixture("freetsa_kat_response.tsr");
    let roots = vec![cacert_der()];
    let v = verify_tst_full(&resp, root_bytes(), &roots)
        .expect("real freeTSA TST must fully verify (sig + chain + imprint)");
    // Facts read from the token match what openssl `ts -reply -text` reported.
    assert_eq!(
        v.serial,
        vec![0x05, 0xfd, 0x99, 0x08],
        "TSA serial 0x05FD9908"
    );
    // genTime is a FIXED fact of the committed fixture (2026-07-06 11:55:48 UTC). The freeTSA signer
    // cert window is 2026-02-15 .. 2040-02-02, so verify_tst_full's validity check covers it. NOTE
    // (AI-review #2002 LOW-3): the check is against genTime, NOT SystemTime::now(), so this does not
    // silently rot as wall-clock advances; if the signer cert is rotated past notAfter, regenerate
    // the fixture per tests/fixtures/README.md.
    assert_eq!(
        v.gen_time_unix, 1_783_338_948,
        "genTime Jul 6 2026 11:55:48 UTC (fixture constant)"
    );
    // The signer is freeTSA's TSA cert, ECDSA-with-SHA512 (1.2.840.10045.4.3.4).
    assert!(
        v.signer_subject.contains("Free TSA"),
        "signer: {}",
        v.signer_subject
    );
    assert!(
        v.trusted_root_subject.contains("Root CA"),
        "anchored at the supplied CA root: {}",
        v.trusted_root_subject
    );
    assert_eq!(v.cms_sig_alg, "1.2.840.10045.4.3.4", "ecdsa-with-SHA512");
}

/// TAMPER: flip one byte inside the ECDSA signature (the trailing INTEGER content) → SigInvalid.
/// Crucially, `extract_tst_facts_matching_root` STILL passes on the same tampered bytes — proving
/// `verify_tst_full` performs a REAL cryptographic check that the non-verifying `extract_` does not.
#[test]
fn tampered_signature_is_siginvalid_where_extract_is_blind() {
    let mut resp = read_fixture("freetsa_kat_response.tsr");
    let n = resp.len();
    resp[n - 1] ^= 0x01; // last byte = low byte of the ECDSA `s` value → structurally valid, crypto-invalid

    // extract_ (imprint + time only) is BLIND to the signature and still accepts.
    let facts = extract_tst_facts_matching_root(&resp, root_bytes())
        .expect("extract_ ignores the signature — still matches the root");
    assert_eq!(facts.serial, vec![0x05, 0xfd, 0x99, 0x08]);

    // verify_tst_full catches the forged signature.
    let roots = vec![cacert_der()];
    assert_eq!(
        verify_tst_full(&resp, root_bytes(), &roots),
        Err(TstVerifyError::SigInvalid),
        "a tampered signature MUST be rejected by the full verifier"
    );
}

/// Find the single occurrence of `needle` in `hay`; panics if absent or ambiguous (so a fixture
/// change that moves/duplicates the target is caught rather than silently mis-targeting a byte).
fn find_unique(hay: &[u8], needle: &[u8]) -> usize {
    let first = hay
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or_else(|| panic!("needle not found in fixture DER"));
    let second = hay[first + 1..]
        .windows(needle.len())
        .position(|w| w == needle);
    assert!(second.is_none(), "needle not unique in fixture DER");
    first
}

// DER of the CMS signed-attribute type OIDs (SEQUENCE inner `06 09 …`).
const OID_MESSAGE_DIGEST_DER: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04,
];
const OID_CONTENT_TYPE_DER: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03,
];

/// TAMPER: flip a byte INSIDE the `messageDigest` signed-attribute value. The messageDigest no longer
/// equals digest(eContent), so verify_tst_full rejects at the messageDigest cross-check (BEFORE the
/// signature check) → SigInvalid. Exercises that branch specifically (test-debt negative (i)).
#[test]
fn tampered_message_digest_is_siginvalid() {
    let mut resp = read_fixture("freetsa_kat_response.tsr");
    let oid = find_unique(&resp, OID_MESSAGE_DIGEST_DER);
    // After the 11-byte OID: SET (0x31) LEN, OCTET STRING (0x04) LEN, then the digest bytes.
    let set_tag = oid + OID_MESSAGE_DIGEST_DER.len();
    assert_eq!(resp[set_tag], 0x31, "messageDigest attr value is a SET");
    assert_eq!(resp[set_tag + 2], 0x04, "SET contains an OCTET STRING");
    let digest_first = set_tag + 4; // 0x31 LL 0x04 MM <digest…>
    resp[digest_first] ^= 0x01;
    let roots = vec![cacert_der()];
    assert_eq!(
        verify_tst_full(&resp, root_bytes(), &roots),
        Err(TstVerifyError::SigInvalid),
        "a messageDigest that no longer matches the eContent MUST be rejected"
    );
}

/// TAMPER: flip the terminal byte of the `contentType` signed-attribute OID value so it is no longer
/// id-ct-TSTInfo. verify_tst_full rejects at the contentType check → error (test-debt negative (ii)).
#[test]
fn tampered_content_type_is_rejected() {
    let mut resp = read_fixture("freetsa_kat_response.tsr");
    let oid = find_unique(&resp, OID_CONTENT_TYPE_DER);
    // After the 11-byte OID: SET (0x31) LEN, OID (0x06) MM, then MM value bytes.
    let set_tag = oid + OID_CONTENT_TYPE_DER.len();
    assert_eq!(resp[set_tag], 0x31, "contentType attr value is a SET");
    assert_eq!(resp[set_tag + 2], 0x06, "SET contains an OID");
    let mm = resp[set_tag + 3] as usize;
    let last_value_byte = set_tag + 4 + mm - 1; // flip the final arc → a valid but different OID
    resp[last_value_byte] ^= 0x01;
    let roots = vec![cacert_der()];
    match verify_tst_full(&resp, root_bytes(), &roots) {
        Err(_) => {} // contentType != id-ct-TSTInfo → rejected (SigInvalid), never Ok
        Ok(v) => panic!("a tampered contentType MUST be rejected, got Ok({v:?})"),
    }
}

#[test]
fn wrong_expected_root_is_imprint_mismatch() {
    let resp = read_fixture("freetsa_kat_response.tsr");
    let roots = vec![cacert_der()];
    let mut wrong = root_bytes();
    wrong[0] ^= 0x01;
    assert_eq!(
        verify_tst_full(&resp, wrong, &roots),
        Err(TstVerifyError::ImprintMismatch),
    );
}

#[test]
fn empty_trusted_roots_is_chain_invalid() {
    let resp = read_fixture("freetsa_kat_response.tsr");
    // Sig + imprint are fine, but with NO trusted anchor the chain cannot terminate.
    match verify_tst_full(&resp, root_bytes(), &[]) {
        Err(TstVerifyError::ChainInvalid(_)) => {}
        other => panic!("expected ChainInvalid, got {other:?}"),
    }
}

/// A non-CA / non-issuer certificate supplied as the "trusted root" (here the signer LEAF cert
/// itself) must not anchor the chain → ChainInvalid. Proves the anchor is the SUPPLIED root, and an
/// embedded root in the token is never trusted as an anchor.
#[test]
fn wrong_trusted_root_is_chain_invalid() {
    let resp = read_fixture("freetsa_kat_response.tsr");
    // The signer LEAF cert (CA:FALSE, subject != signer.issuer) as the sole "trusted root".
    let roots = vec![read_fixture("freetsa_tsa_leaf.der")];
    match verify_tst_full(&resp, root_bytes(), &roots) {
        Err(TstVerifyError::ChainInvalid(_)) => {}
        other => panic!("expected ChainInvalid for a non-CA trusted root, got {other:?}"),
    }
}

// ------------------------------------------------------------------------------------------------
// verify_tst_pinned (ADR-043 C1 P2) — PRODUCER-side anchor authenticity against a PINNED signer cert.
// The pinned cert is the freeTSA SIGNER LEAF (the SignerInfo signer), NOT the CA root — the CMS
// SignerInfo signature is produced by the leaf key, so that is what P2 authenticates against.
// ------------------------------------------------------------------------------------------------

/// The REAL freeTSA token verifies against freeTSA's OWN signer LEAF cert (the pinned cert) → Ok,
/// yielding the same facts the P4 full verifier read. This is the producer's happy path: the anchor
/// is cryptographically authenticated by the pinned key before the builder marks it anchored=true.
#[test]
fn pinned_verify_ok_against_the_real_signer_cert() {
    let resp = read_fixture("freetsa_kat_response.tsr");
    // freeTSA's signer LEAF cert (CA:FALSE, EKU timeStamping) — the key that signed the SignerInfo.
    let pinned = read_fixture("freetsa_tsa_leaf.der");
    let facts = verify_tst_pinned(&resp, root_bytes(), &pinned)
        .expect("real freeTSA TST must verify against the pinned freeTSA signer cert");
    assert_eq!(
        facts.serial,
        vec![0x05, 0xfd, 0x99, 0x08],
        "TSA serial 0x05FD9908"
    );
    assert_eq!(
        facts.gen_time_unix, 1_783_338_948,
        "genTime Jul 6 2026 11:55:48 UTC (fixture constant)"
    );
}

/// AUTHENTICITY (the load-bearing P2 property): the SAME real token verified against a DIFFERENT
/// pinned cert whose key did NOT produce the SignerInfo signature → SigInvalid. The different cert is
/// an unrelated EC cert (same ECDSA family as the freeTSA P-384 signer, but a DIFFERENT key), so the
/// rejection is a GENUINE cryptographic signature-verification failure — proving pinning authenticates
/// the SIGNER's KEY, not merely the token's embedded-cert integrity. A forger who re-signs the token
/// and swaps in their own embedded cert would be accepted by an embedded-cert-only check but is
/// REJECTED here because the pinned key never signed it.
#[test]
fn pinned_verify_against_different_cert_is_siginvalid() {
    let resp = read_fixture("freetsa_kat_response.tsr");
    // An unrelated EC cert (a different key of the same ECDSA family as the token's P-384 signer).
    let different = read_fixture("synthetic/syn_eleaf.der");
    assert_eq!(
        verify_tst_pinned(&resp, root_bytes(), &different),
        Err(TstVerifyError::SigInvalid),
        "a token pinned to a different key MUST fail the CMS signature check"
    );
}

/// AUTHENTICITY, cross-algorithm fail-closed: pinning to freeTSA's OWN CA ROOT (a real, related cert,
/// but an RSA key that did NOT sign the ECDSA SignerInfo) is ALSO rejected — here as `Unsupported`
/// (its RSA key cannot even attempt to verify an ECDSA signature), which is an even earlier fail-closed
/// than a crypto mismatch. Both this and the same-family `SigInvalid` case above are hard rejections:
/// only the PINNED signer key authenticates the token, never a related-but-wrong cert.
#[test]
fn pinned_verify_against_ca_root_is_rejected_fail_closed() {
    let resp = read_fixture("freetsa_kat_response.tsr");
    let ca = cacert_der(); // freeTSA CA root — RSA, NOT the ECDSA SignerInfo signer.
    assert!(
        matches!(
            verify_tst_pinned(&resp, root_bytes(), &ca),
            Err(TstVerifyError::Unsupported(_)) | Err(TstVerifyError::SigInvalid)
        ),
        "the CA root (wrong key) MUST be rejected fail-closed, not accepted"
    );
}

/// `cert_pem_to_der` recovers the exact DER from a clean PEM AND from a WHITESPACE-INDENTED PEM (the
/// shape a Terraform `<<-` heredoc can emit if it does not fully dedent). Both must yield the SAME DER
/// that then verifies the real token — proving the producer's PINNED_TSA_CERT_PEM config path is
/// robust to leading whitespace (the strict RFC 7468 decoder would otherwise reject it).
#[test]
fn cert_pem_to_der_is_whitespace_tolerant_and_round_trips() {
    let clean_pem = String::from_utf8(read_fixture("freetsa_tsa_leaf.crt")).unwrap();
    let expected_der = read_fixture("freetsa_tsa_leaf.der");

    let from_clean = cert_pem_to_der(&clean_pem).expect("clean PEM must parse");
    assert_eq!(from_clean, expected_der, "clean PEM → exact signer DER");

    // Simulate an under-dedented heredoc: 8 leading spaces + a stray blank line on every line.
    let indented: String = std::iter::once(String::new())
        .chain(clean_pem.lines().map(|l| format!("        {l}")))
        .collect::<Vec<_>>()
        .join("\n");
    let from_indented = cert_pem_to_der(&indented).expect("indented PEM must still parse");
    assert_eq!(
        from_indented, expected_der,
        "indented PEM → same signer DER"
    );

    // And the recovered DER really is the pinned signer: the real token authenticates against it.
    let resp = read_fixture("freetsa_kat_response.tsr");
    assert!(verify_tst_pinned(&resp, root_bytes(), &from_indented).is_ok());
}

/// `inspect_pinned_cert` (ADR-043 P2 init-time misconfig guard) classifies the RIGHT cert vs a
/// mis-pin: freeTSA's SIGNER leaf → has timeStamping EKU + NOT a CA; freeTSA's CA ROOT (the classic
/// wrong-cert mis-pin) → NO timeStamping EKU + IS a CA. Both expose a real `notAfter` for expiry
/// monitoring. This is the classification the builder warns on before AnchorVerifyFailures ever fires.
#[test]
fn inspect_pinned_cert_distinguishes_signer_leaf_from_ca_root() {
    let leaf = inspect_pinned_cert(&read_fixture("freetsa_tsa_leaf.der")).expect("leaf parses");
    assert!(
        leaf.has_timestamping_eku,
        "the TSA signer leaf carries the timeStamping EKU"
    );
    assert!(
        !leaf.is_ca,
        "the TSA signer leaf is an end-entity, not a CA"
    );
    // freeTSA signer notAfter = 2040-02-02 (well in the future) — a sane expiry fact.
    assert!(
        leaf.not_after_unix > 1_800_000_000,
        "leaf notAfter is a real future date: {}",
        leaf.not_after_unix
    );

    let ca = inspect_pinned_cert(&cacert_der()).expect("CA root parses");
    assert!(
        !ca.has_timestamping_eku,
        "the CA root lacks the timeStamping EKU — pinning it is the mis-pin the guard warns on"
    );
    assert!(ca.is_ca, "the CA root is a CA (basicConstraints CA:TRUE)");
    assert!(
        ca.not_after_unix > 1_800_000_000,
        "CA notAfter is a real date"
    );
}

/// A wrong `expected_root` is caught (the imprint is checked BEFORE the signature) → ImprintMismatch,
/// even though the pinned cert is correct — the distinct error keeps producer diagnostics precise.
#[test]
fn pinned_verify_wrong_root_is_imprint_mismatch() {
    let resp = read_fixture("freetsa_kat_response.tsr");
    let pinned = read_fixture("freetsa_tsa_leaf.der");
    let mut wrong = root_bytes();
    wrong[0] ^= 0x01;
    assert_eq!(
        verify_tst_pinned(&resp, wrong, &pinned),
        Err(TstVerifyError::ImprintMismatch),
    );
}

/// A tampered signature is caught by the pinned verifier where the imprint-only `extract_` is blind —
/// the same `extract_` ≠ `verify_` gap the full verifier closes, now closed on the PRODUCER path too.
#[test]
fn pinned_verify_tampered_signature_is_siginvalid_where_extract_is_blind() {
    let mut resp = read_fixture("freetsa_kat_response.tsr");
    let n = resp.len();
    resp[n - 1] ^= 0x01; // flip the low byte of the ECDSA `s` — structurally valid, crypto-invalid.

    // extract_ (imprint + time only) is BLIND to the signature and still accepts.
    let facts = extract_tst_facts_matching_root(&resp, root_bytes())
        .expect("extract_ ignores the signature — still matches the root");
    assert_eq!(facts.serial, vec![0x05, 0xfd, 0x99, 0x08]);

    // verify_tst_pinned catches the forged signature against the correct pinned signer cert.
    let pinned = read_fixture("freetsa_tsa_leaf.der");
    assert_eq!(
        verify_tst_pinned(&resp, root_bytes(), &pinned),
        Err(TstVerifyError::SigInvalid),
        "a tampered signature MUST be rejected by the pinned producer verifier"
    );
}

// ------------------------------------------------------------------------------------------------
// End-to-end: the `commitment_proof_verify` binary over a real bundle + the real TST + the CA root.
// ------------------------------------------------------------------------------------------------

/// Build a ProofBundle whose single period-0 Merkle root IS the frozen KAT root the fixture stamps,
/// so a real TST anchors it. `verify()` passes structurally; the binary then crypto-verifies the TST.
fn kat_bundle() -> ProofBundle {
    let p0 = vec![
        content_hash("leaf-C"),
        content_hash("leaf-D"),
        content_hash("leaf-E"),
    ];
    let chain = build_roots_chain(&[(0, p0.clone())]).unwrap();
    assert_eq!(
        hex::encode(chain[0].root_hash),
        KAT_ROOT_HEX,
        "period-0 root must equal the timestamped KAT root"
    );
    let tst_refs = vec![TstRef {
        period_id: 0,
        tst_ref: Some("roots-chain-tst/org-acme/0.tsr".into()),
        gen_time_unix: Some(1_783_338_948),
        serial_hex: Some("05fd9908".into()),
        anchored: true,
    }];
    build_proof_bundle(KAT_CONTENT_HASH, "org-acme", 0, &p0, &chain, tst_refs).unwrap()
}

fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mlc-p4-{}-{}-{name}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn bin_end_to_end_verified_and_tampered_failed() {
    let bundle = kat_bundle();
    // Sanity: the bundle is structurally sound before we even shell out.
    assert_eq!(bundle.verify(), Ok(()));
    let bundle_path = write_temp("bundle.json", bundle.to_json().to_string().as_bytes());

    let tst_path = format!("{FIX}freetsa_kat_response.tsr");
    let root_path = format!("{FIX}freetsa_cacert.pem");
    let bin = env!("CARGO_BIN_EXE_commitment_proof_verify");

    // --- VERIFIED path ---
    let out = std::process::Command::new(bin)
        .args([
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--tst",
            &tst_path,
            "--trusted-root",
            &root_path,
        ])
        .output()
        .expect("run commitment_proof_verify");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected exit 0 VERIFIED; got {:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("RESULT: VERIFIED"), "STDOUT:\n{stdout}");
    assert!(
        stdout.contains("\"verdict\":\"VERIFIED\""),
        "machine JSON present"
    );

    // --- FAILED path: tamper the TST signature; the bin must report FAILED (exit 2) ---
    let mut tampered = read_fixture("freetsa_kat_response.tsr");
    let n = tampered.len();
    tampered[n - 1] ^= 0x01;
    let tampered_path = write_temp("tampered.tsr", &tampered);
    let out2 = std::process::Command::new(bin)
        .args([
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--tst",
            tampered_path.to_str().unwrap(),
            "--trusted-root",
            &root_path,
        ])
        .output()
        .expect("run commitment_proof_verify (tampered)");
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert_eq!(
        out2.status.code(),
        Some(2),
        "tampered TST → exit 2 FAILED\n{stdout2}"
    );
    assert!(stdout2.contains("RESULT: FAILED"), "STDOUT:\n{stdout2}");

    let _ = std::fs::remove_file(&bundle_path);
    let _ = std::fs::remove_file(&tampered_path);
}
