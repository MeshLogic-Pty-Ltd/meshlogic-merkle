//! ADR-043 C1 slice-1a — commitment-leaf ANCHOR tool (the auditor-half of the tamper-evidence slice).
//!
//! Consumes one or more captured `CommitmentLeaf` JSON blobs (the output of the capture-at-stamp
//! PRODUCER, cloud-backend `telemetry_forward.rs` / PR #1961). For each leaf it base64-decodes
//! `canonical_preimage_b64` to the raw preimage, asserts `sha256(preimage) == content_hash` (the
//! auditor RE-DERIVATION — FAILS LOUD on mismatch), and parses the preimage to surface the deny
//! facts (disposition / path / control_id / endpoint). Then, across the set, it sorts MAC-1
//! (content_hash ascending), builds the RFC 6962 Merkle root, generates + re-verifies every leaf's
//! inclusion proof, RFC 3161-anchors the root against a live TSA (or records a clearly-marked
//! `TST_PENDING` carrying the built request if the TSA is unreachable — never a fabricated token),
//! and emits the committed auditor artifact JSON + a verification narrative markdown, plus a
//! bit-flip counter-demonstration.
//!
//! Run:
//!   cargo run -p meshlogic-merkle --features tsa-client --bin commitment_leaf_anchor -- \
//!       <leaf1.json> [leaf2.json ...] [--tsa-url <url>] [--out <artifact.json>] \
//!       [--narrative-out <narrative.md>]
//!   # generate reproducible synthetic demo leaves (offline, no producer / no network):
//!   cargo run -p meshlogic-merkle --features tsa-client --bin commitment_leaf_anchor -- \
//!       --gen-samples <dir>
//! Defaults: --tsa-url https://freetsa.org/tsr ; --out demo/adr-043-minimal-anchor/slice1a-artifact.json

use meshlogic_merkle::anchor::{
    build_timestamp_request, extract_tst_facts_matching_root, timestamp_root_via_tsa,
};
use meshlogic_merkle::commitment_leaf::{
    b64_encode, bit_flip_demo, build_anchored_set, build_artifact, load_and_verify_leaf,
    synthesize_leaf_blob, verification_narrative_md, TstStatus, VerifiedLeaf,
};
use serde_json::json;
use std::path::Path;
use std::process::exit;

const DEFAULT_TSA: &str = "https://freetsa.org/tsr";
const DEFAULT_OUT: &str = "demo/adr-043-minimal-anchor/slice1a-artifact.json";

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(1);
}

fn write_file(path: &str, bytes: &[u8]) {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                die(&format!("cannot create dir {}: {e}", parent.display()));
            }
        }
    }
    if let Err(e) = std::fs::write(path, bytes) {
        die(&format!("cannot write {path}: {e}"));
    }
}

/// Offline: write two reproducible synthetic demo leaves into `dir`. No producer, no network.
fn gen_samples(dir: &str) {
    let cases = [
        (
            "C:/Finance/payroll-2026Q2.xlsx",
            "SOC2-CC6.1",
            41u64,
            "EP-1111111111111111",
        ),
        (
            "C:/Legal/board-minutes.docx",
            "SOC2-CC6.7",
            42u64,
            "EP-1111111111111111",
        ),
    ];
    for (i, (path, control, seq, ep)) in cases.iter().enumerate() {
        let preimage = json!({
            "event_class": "File",
            "endpoint_id": ep,
            "organization_id": "org-acme",
            "event_id": seq,
            "file_details": { "disposition": "deny", "path": path, "status": 3221225488i64 },
            "compliance_details": { "control_id": control, "framework": "SOC2" },
        });
        let identity = json!({
            "endpoint_id": ep,
            "org_id": "org-acme",
            "event_sequence": seq,
            "event_class": "File",
            "captured_at": "2026-07-05T00:00:00+00:00",
        });
        let blob = synthesize_leaf_blob(&preimage, &identity)
            .unwrap_or_else(|e| die(&format!("synthesize leaf: {e}")));
        let out = format!("{dir}/leaf-{}.json", i + 1);
        write_file(&out, &blob);
        println!("wrote sample leaf: {out}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut tsa_url = DEFAULT_TSA.to_string();
    let mut out = DEFAULT_OUT.to_string();
    let mut narrative_out: Option<String> = None;
    let mut leaf_paths: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--gen-samples" => {
                let dir = args
                    .get(i + 1)
                    .unwrap_or_else(|| die("--gen-samples needs <dir>"));
                gen_samples(dir);
                return;
            }
            "--tsa-url" => {
                tsa_url = args
                    .get(i + 1)
                    .unwrap_or_else(|| die("--tsa-url needs a value"))
                    .clone();
                i += 2;
            }
            "--out" => {
                out = args
                    .get(i + 1)
                    .unwrap_or_else(|| die("--out needs a value"))
                    .clone();
                i += 2;
            }
            "--narrative-out" => {
                narrative_out = Some(
                    args.get(i + 1)
                        .unwrap_or_else(|| die("--narrative-out needs a value"))
                        .clone(),
                );
                i += 2;
            }
            "-h" | "--help" => {
                println!(
                    "usage: commitment_leaf_anchor <leaf.json>... [--tsa-url URL] [--out FILE] \
                     [--narrative-out FILE]\n       commitment_leaf_anchor --gen-samples <dir>"
                );
                return;
            }
            other if other.starts_with("--") => die(&format!("unknown flag: {other}")),
            other => {
                leaf_paths.push(other.to_string());
                i += 1;
            }
        }
    }

    if leaf_paths.is_empty() {
        die(
            "no CommitmentLeaf JSON file paths given (use --gen-samples <dir> to make demo leaves)",
        );
    }

    // Default the narrative next to the artifact (…-verification.md) unless overridden.
    let narrative_out = narrative_out.unwrap_or_else(|| {
        let p = Path::new(&out);
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("slice1a");
        let parent = p.parent().and_then(|s| s.to_str()).unwrap_or("");
        if parent.is_empty() {
            format!("{stem}-verification.md")
        } else {
            format!("{parent}/{stem}-verification.md")
        }
    });

    // 1. Load + RE-DERIVE every leaf (fail loud on any sha256 != content_hash mismatch).
    let mut leaves: Vec<VerifiedLeaf> = Vec::with_capacity(leaf_paths.len());
    for path in &leaf_paths {
        let raw = std::fs::read(path).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
        match load_and_verify_leaf(&raw) {
            Ok(l) => {
                println!(
                    "leaf OK  {}  re-derivation sha256(preimage)==content_hash  [{}]",
                    l.content_hash,
                    l.deny_facts.disposition.as_deref().unwrap_or("?")
                );
                leaves.push(l);
            }
            Err(e) => die(&format!("{path}: {e}")),
        }
    }

    // 2-3. MAC-1 sort → root → per-leaf inclusion proofs (self-verified inside).
    let set = build_anchored_set(leaves).unwrap_or_else(|e| die(&e.0));
    println!(
        "\nmerkle root : {}  (tree_size {})",
        set.root_hex(),
        set.tree_size()
    );

    // 4. Anchor the root to the TSA. If unreachable, emit TST_PENDING with the BUILT request — never
    //    fabricate a token (ADR-043 §6).
    println!("anchoring root to RFC 3161 TSA {tsa_url} ...");
    let tst = match timestamp_root_via_tsa(set.root, &tsa_url) {
        Ok(resp) => match extract_tst_facts_matching_root(&resp, set.root) {
            Ok(facts) => {
                println!(
                    "TSA token : covers root; genTime unix {} serial {}",
                    facts.gen_time_unix,
                    hex::encode(&facts.serial)
                );
                TstStatus::Anchored {
                    tsa_url: tsa_url.clone(),
                    response_der_b64: b64_encode(&resp),
                    gen_time_unix: facts.gen_time_unix,
                    serial_hex: hex::encode(&facts.serial),
                }
            }
            Err(e) => {
                eprintln!(
                    "warning: TSA responded but token did not match root ({e}) — TST_PENDING"
                );
                pending(&set, &tsa_url, &format!("token mismatch: {e}"))
            }
        },
        Err(e) => {
            eprintln!(
                "warning: TSA unreachable ({e}) — emitting TST_PENDING (no token fabricated)"
            );
            pending(&set, &tsa_url, &e.0)
        }
    };

    // 5. Emit the committed artifact + verification narrative.
    let artifact = build_artifact(&set, &tst);
    let artifact_bytes = serde_json::to_vec_pretty(&artifact)
        .unwrap_or_else(|e| die(&format!("serialize artifact: {e}")));
    write_file(&out, &artifact_bytes);
    write_file(
        &narrative_out,
        verification_narrative_md(&set, &tst).as_bytes(),
    );
    println!("\nartifact  : {out}");
    println!("narrative : {narrative_out}");

    // 6. Bit-flip counter-demonstration on the first leaf.
    match bit_flip_demo(&set, 0) {
        Ok(d) => {
            println!(
                "\nbit-flip counter-demo (leaf 0):\n  original content_hash : {}\n  altered  content_hash : {}\n  sha256(preimage)==content_hash after flip : {}\n  altered leaf verifies inclusion           : {}\n  ==> {}",
                d.original_content_hash,
                d.altered_content_hash,
                d.altered_rederivation_ok,
                d.altered_inclusion_ok,
                if d.correctly_rejected() {
                    "ALTERED / NOT-IN-LOG, correctly rejected"
                } else {
                    "UNEXPECTED — bit-flip was not rejected (bug!)"
                }
            );
            if !d.correctly_rejected() {
                exit(1);
            }
        }
        Err(e) => die(&e.0),
    }

    // Reflect the honest boundary at the CLI too.
    match &tst {
        TstStatus::Anchored { .. } => println!(
            "\nBOUNDARY: inclusion + imprint-coverage + asserted time checked. TSA CMS signature/chain \
             NOT verified (P4); NOT tamper-proof; T5 needs the P3 customer co-anchor."
        ),
        TstStatus::Pending { .. } => println!(
            "\nBOUNDARY: inclusion checked; timestamp PENDING (TSA unreachable — request recorded, no \
             token fabricated). NOT tamper-proof; T5 needs the P3 customer co-anchor."
        ),
    }
}

/// Build a `TST_PENDING` status carrying the RFC 3161 request DER we built over the root.
fn pending(
    set: &meshlogic_merkle::commitment_leaf::AnchoredSet,
    tsa_url: &str,
    reason: &str,
) -> TstStatus {
    let req = build_timestamp_request(set.root)
        .unwrap_or_else(|e| die(&format!("build TS request: {e}")));
    TstStatus::Pending {
        tsa_url: tsa_url.to_string(),
        reason: reason.to_string(),
        request_der_b64: b64_encode(&req),
    }
}
