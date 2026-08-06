//! ADR-043 C1 P4 — the zero-trust OFFLINE commitment-proof verifier.
//!
//! A standalone auditor tool that verifies a MeshLogic `ProofBundle` end-to-end WITHOUT trusting
//! MeshLogic and WITHOUT any AWS or network access. It combines:
//!
//!   1. STRUCTURAL verification — [`meshlogic_merkle::proof_gen::ProofBundle::verify`]: the RFC 6962
//!      inclusion proof reproduces the period root, and the roots-chain segment is genesis-anchored,
//!      hash-linked, and gap-free.
//!   2. CRYPTOGRAPHIC anchoring — for each period in the bundle's roots-chain, a caller-supplied RFC
//!      3161 Time-Stamp Token is FULLY verified with [`meshlogic_merkle::anchor::verify_tst_full`]:
//!      the CMS SignerInfo signature, the messageDigest/contentType signed attributes, the signer
//!      certificate's id-kp-timeStamping EKU + validity, and the certificate chain to a caller-supplied
//!      trusted root — AND the token's imprint equals that period's Merkle root.
//!
//! The verdict is VERIFIED only if the structure holds AND every covered period is anchored by a
//! TST that cryptographically verifies to a trusted root. Exit code 0 = VERIFIED, 2 = FAILED,
//! 64 = usage error.
//!
//! DECOUPLING NOTE: today's `ProofBundle` carries `tst_refs` (an S3 key + recorded facts), NOT the
//! token DER, so the TSTs are supplied as separate `--tst` inputs. Embedding the TST DER inside the
//! bundle (so it is fully self-contained) is a follow-up SEAM change to coordinate with
//! macos-tertiary — it is intentionally NOT part of this PR.

use meshlogic_merkle::anchor::{verify_tst_full, TstVerifyError};
use meshlogic_merkle::proof_gen::ProofBundle;
use std::process::ExitCode;

const USAGE: &str = "\
commitment_proof_verify — ADR-043 C1 P4 offline ProofBundle verifier (no AWS, no network)

USAGE:
    commitment_proof_verify --bundle <proofbundle.json> \\
        [--tst <token.der> ...] [--trusted-root <ca.pem|ca.der> ...]

OPTIONS:
    --bundle <FILE>         The ProofBundle JSON emitted by commitment_proof_gen (required).
    --tst <FILE>            An RFC 3161 TimeStampResp DER (.tsr). Repeatable. Each is matched to the
                            period whose Merkle root it timestamps. Supply one per covered period for
                            a fully-anchored VERIFIED verdict.
    --trusted-root <FILE>   A trusted CA certificate (PEM or DER). Repeatable. The chain anchor. An
                            auditor supplies this OUT OF BAND — a root embedded in a token is never
                            trusted as an anchor.
    -h, --help              Print this help.

EXIT CODES:
    0   VERIFIED   structure + every covered period cryptographically anchored to a trusted root
    2   FAILED     a structural or cryptographic check failed
    64  USAGE      bad arguments / unreadable input

WHAT IS CRYPTOGRAPHICALLY VERIFIED (be precise when relying on a VERIFIED verdict):
    * CMS SignerInfo signature (RSA-PKCS1 SHA-256/384/512; ECDSA P-256/P-384 SHA-256/384/512).
    * messageDigest + contentType(id-ct-TSTInfo) signed attributes bind the signature to the token.
    * signer cert chains to a supplied trusted root (issuer-signature verified), valid at genTime,
      carries the id-kp-timeStamping EKU; issuers are CAs.
    * the token imprint equals the period's Merkle root.
NOT verified here (remaining hardening): certificate REVOCATION (CRL/OCSP), RFC 5280 name/policy/
    path-length constraints. And P4 is NOT the whole tamper-evidence claim — the P3 customer WORM
    co-anchor is still required before asserting tamper-evidence.
";

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::from(0),
        Ok(false) => ExitCode::from(2),
        Err(code) => code,
    }
}

/// Returns Ok(true)=VERIFIED, Ok(false)=FAILED, Err(exitcode)=usage error.
fn run() -> Result<bool, ExitCode> {
    let mut bundle_path: Option<String> = None;
    let mut tst_paths: Vec<String> = Vec::new();
    let mut root_paths: Vec<String> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Err(ExitCode::from(0));
            }
            "--bundle" => bundle_path = Some(need_val(&mut args, "--bundle")?),
            "--tst" => tst_paths.push(need_val(&mut args, "--tst")?),
            "--trusted-root" => root_paths.push(need_val(&mut args, "--trusted-root")?),
            other => {
                eprintln!("error: unexpected argument '{other}'\n");
                eprint!("{USAGE}");
                return Err(ExitCode::from(64));
            }
        }
    }

    let bundle_path = bundle_path.ok_or_else(|| {
        eprintln!("error: --bundle is required\n");
        eprint!("{USAGE}");
        ExitCode::from(64)
    })?;

    // --- load inputs (all local files; no network) ---------------------------------------------
    let bundle_json = read_file(&bundle_path)?;
    let bundle_val: serde_json::Value = serde_json::from_slice(&bundle_json).map_err(|e| {
        eprintln!("error: --bundle is not valid JSON: {e}");
        ExitCode::from(64)
    })?;
    let bundle = ProofBundle::from_json(&bundle_val).map_err(|e| {
        eprintln!("error: --bundle is not a valid ProofBundle: {e}");
        ExitCode::from(64)
    })?;

    let tsts: Vec<(String, Vec<u8>)> = tst_paths
        .iter()
        .map(|p| read_file(p).map(|b| (p.clone(), b)))
        .collect::<Result<_, _>>()?;

    let mut trusted_roots: Vec<Vec<u8>> = Vec::new();
    for p in &root_paths {
        let bytes = read_file(p)?;
        for der in load_certs_der(&bytes).map_err(|e| {
            eprintln!("error: --trusted-root '{p}' could not be parsed: {e}");
            ExitCode::from(64)
        })? {
            trusted_roots.push(der);
        }
    }

    // --- report header -------------------------------------------------------------------------
    println!("MeshLogic offline commitment-proof verification (ADR-043 C1 P4)");
    println!("  bundle        : {bundle_path}");
    println!("  content_hash  : {}", bundle.content_hash);
    println!("  org_id        : {}", bundle.org_id);
    println!("  target period : {}", bundle.period_id);
    println!(
        "  TSTs supplied : {}   trusted roots supplied : {}",
        tsts.len(),
        trusted_roots.len()
    );
    println!();

    let mut all_ok = true;
    let mut checks: Vec<serde_json::Value> = Vec::new();

    // --- (1) STRUCTURAL --------------------------------------------------------------------------
    let structural = bundle.verify();
    match &structural {
        Ok(()) => {
            println!("[ OK ] structural: inclusion proof + genesis-anchored hash-chain verified");
            checks.push(serde_json::json!({"check":"structural","ok":true}));
        }
        Err(e) => {
            all_ok = false;
            println!("[FAIL] structural: {e}");
            checks
                .push(serde_json::json!({"check":"structural","ok":false,"reason":e.to_string()}));
        }
    }

    // --- (2) per-period cryptographic anchoring -------------------------------------------------
    // Only meaningful if the structure held (the period roots are otherwise untrusted).
    if structural.is_ok() {
        for row in &bundle.roots_chain {
            let period_root = row.root_hash;
            let mut period_result: Option<
                Result<meshlogic_merkle::anchor::VerifiedTst, TstVerifyError>,
            > = None;
            // Try each supplied TST against THIS period's root. verify_tst_full checks imprint ==
            // period_root internally, so a non-matching token yields ImprintMismatch (we keep trying);
            // a matching-but-invalid token yields a crypto error (we surface it, do NOT keep trying).
            for (_name, der) in &tsts {
                match verify_tst_full(der, period_root, &trusted_roots) {
                    Ok(v) => {
                        period_result = Some(Ok(v));
                        break;
                    }
                    Err(TstVerifyError::ImprintMismatch) => continue,
                    Err(e) => {
                        period_result = Some(Err(e));
                        break;
                    }
                }
            }
            match period_result {
                Some(Ok(v)) => {
                    println!(
                        "[ OK ] period {:>6}: anchored — sig+chain OK  (genTime={} serial=0x{} \
                         alg={} root={})",
                        row.period_id,
                        v.gen_time_unix,
                        hex::encode(&v.serial),
                        v.cms_sig_alg,
                        hex::encode(period_root),
                    );
                    println!(
                        "                    signer='{}'  trusted-root='{}'",
                        v.signer_subject, v.trusted_root_subject
                    );
                    checks.push(serde_json::json!({
                        "check":"period_anchor","period_id":row.period_id,"ok":true,
                        "gen_time_unix":v.gen_time_unix,"serial_hex":hex::encode(&v.serial),
                        "cms_sig_alg":v.cms_sig_alg,"signer":v.signer_subject,
                        "trusted_root":v.trusted_root_subject,
                    }));
                }
                Some(Err(e)) => {
                    all_ok = false;
                    println!("[FAIL] period {:>6}: {e}", row.period_id);
                    checks.push(serde_json::json!({
                        "check":"period_anchor","period_id":row.period_id,"ok":false,
                        "reason":e.to_string(),
                    }));
                }
                None => {
                    all_ok = false;
                    println!(
                        "[FAIL] period {:>6}: no supplied TST timestamps this period's root ({})",
                        row.period_id,
                        hex::encode(period_root),
                    );
                    checks.push(serde_json::json!({
                        "check":"period_anchor","period_id":row.period_id,"ok":false,
                        "reason":"no supplied TST matches this period root",
                    }));
                }
            }
        }
    }

    // --- verdict (human + machine readable) ----------------------------------------------------
    let verdict = if all_ok { "VERIFIED" } else { "FAILED" };
    println!();
    println!("RESULT: {verdict}");
    let machine = serde_json::json!({
        "adr":"ADR-043","phase":"P4","tool":"commitment_proof_verify",
        "content_hash":bundle.content_hash,"org_id":bundle.org_id,"period_id":bundle.period_id,
        "verdict":verdict,"checks":checks,
    });
    println!(
        "JSON: {}",
        serde_json::to_string(&machine).unwrap_or_else(|_| "{}".into())
    );

    Ok(all_ok)
}

fn need_val(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, ExitCode> {
    args.next().ok_or_else(|| {
        eprintln!("error: {flag} requires a value");
        ExitCode::from(64)
    })
}

fn read_file(path: &str) -> Result<Vec<u8>, ExitCode> {
    std::fs::read(path).map_err(|e| {
        eprintln!("error: cannot read '{path}': {e}");
        ExitCode::from(64)
    })
}

/// Parse one-or-more certificates from a file that is either PEM (one or more CERTIFICATE blocks) or
/// a single DER certificate. Returns each cert's DER encoding.
fn load_certs_der(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    use x509_cert::der::{Decode, Encode};
    // DER SEQUENCE starts with 0x30; PEM is ASCII text.
    if bytes.first() == Some(&0x30) {
        let cert =
            x509_cert::Certificate::from_der(bytes).map_err(|e| format!("DER decode: {e}"))?;
        return Ok(vec![cert.to_der().map_err(|e| e.to_string())?]);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "not DER and not UTF-8 PEM".to_string())?;
    let chain =
        x509_cert::Certificate::load_pem_chain(text.as_bytes()).map_err(|e| format!("PEM: {e}"))?;
    if chain.is_empty() {
        return Err("no CERTIFICATE blocks found".into());
    }
    chain
        .iter()
        .map(|c| c.to_der().map_err(|e| e.to_string()))
        .collect()
}
