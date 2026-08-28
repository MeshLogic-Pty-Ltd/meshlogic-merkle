//! ADR-043 C1 P1b PR-2 — commitment PROOF-GENERATION CLI (the auditor read path).
//!
//! Given one enforcement leaf's `content_hash` and its `org`, this tool re-derives a self-contained
//! [`ProofBundle`] by:
//!   (a) reading the org's roots-chain from DynamoDB (`ROOTS_CHAIN_TABLE`) — the genesis→period rows
//!       + their RFC 3161 timestamp references;
//!   (b) RE-LISTING the candidate period's commitment leaves from S3
//!       (`commitment-leaves/{org}/{yyyy}/{mm}/{dd}/`) and RE-DERIVING the period's leaf set — it does
//!       NOT trust any stored manifest/index (ADR-043 §5.2);
//!   (c) calling `meshlogic_merkle::proof_gen` to build + self-verify the bundle;
//!   (d) emitting the bundle as JSON (stdout and/or `--out`), plus a human summary.
//!
//! The emitted bundle is consumed by the frozen `chain_verify` verifiers (`verify_inclusion` +
//! `verify_chain`) — the tool refuses to emit a bundle that does not itself verify.
//!
//! AWS reads are behind the OPTIONAL `aws-reads` feature (same feature-gate style as the
//! `commitment_leaf_anchor` bin's `tsa-client`), so the shared Merkle/verify core stays
//! dependency-light and the offline verifier never links the AWS SDK.
//!
//! TARGETING (pick ONE — an unbounded org-wide S3 re-list is never the default; that would be a
//! cost/DoS vector against the commitment-leaf bucket):
//!   --period-id <n>          re-list only that day (days-since-epoch)
//!   --captured-at <rfc3339>  compute the day from the leaf's capture time; re-list that day ± 1
//!                            (skew) — the cheap default when the auditor knows roughly when it fired
//!   --scan                   OPT-IN fallback: scan the chain's periods (ascending), bounded by
//!                            --max-scan-days (default 62); prints a loud warning
//!
//! Run:
//!   cargo run -p meshlogic-merkle --features aws-reads --bin commitment_proof_gen -- \
//!       --content-hash <64-hex> --org <org-id> (--period-id <n> | --captured-at <rfc3339> | --scan) \
//!       [--max-scan-days <n>] [--allow-unanchored] [--table <name>] [--bucket <name>] \
//!       [--region <r>] [--out <artifact.json>]

use aws_sdk_dynamodb::types::AttributeValue;
use meshlogic_merkle::proof_gen::{
    build_proof_bundle, period_id_for_unix, AnchoringStatus, TstRef, SECONDS_PER_DAY,
};
use meshlogic_merkle::roots_chain::RootsChainRow;
use meshlogic_merkle::{
    leaf_bytes_from_content_hash, size_exceeds_cap, Hash, MAC_SPEC_VERSION, TREE_ALGORITHM,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::process::exit;

const DEFAULT_TABLE: &str = "meshlogic-tamper-evidence-roots-chain";
/// Default ceiling for the opt-in `--scan` mode — refuse to blindly re-list more days than this.
const DEFAULT_MAX_SCAN_DAYS: usize = 62;

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(1);
}

// ---------------------------------------------------------------------------
// Period math — MIRRORS the producer (tamper-evidence-builder) S3-layout helpers exactly, so the
// re-listed leaf set reproduces the anchored tree. period_id = days-since-Unix-epoch.
// ---------------------------------------------------------------------------

fn period_bounds(period_id: u64) -> (i64, i64) {
    let start = period_id as i64 * SECONDS_PER_DAY;
    (start, start + SECONDS_PER_DAY)
}

/// `commitment-leaves/{org}/{yyyy}/{mm}/{dd}/` for one org-day (period).
fn day_prefix(org_id: &str, period_id: u64) -> String {
    let (start, _) = period_bounds(period_id);
    let dt = chrono::DateTime::from_timestamp(start, 0)
        .expect("period_id * SECONDS_PER_DAY is always a valid unix timestamp");
    format!("commitment-leaves/{org_id}/{}/", dt.format("%Y/%m/%d"))
}

// ---------------------------------------------------------------------------
// Commitment-leaf JSON shape (matches the producer / commitment_leaf.rs).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct LeafIdentity {
    captured_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CommitmentLeafDoc {
    content_hash: String,
    identity: Option<LeafIdentity>,
}

fn leaf_captured_at_secs(leaf: &CommitmentLeafDoc) -> Option<i64> {
    leaf.identity
        .as_ref()
        .and_then(|id| id.captured_at.as_ref())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp())
}

/// The `content_hash`es whose `captured_at` falls in the half-open period `[start,end)` (a leaf with
/// no parseable `captured_at` is kept — its S3 key already scoped it to the day). Identical to the
/// producer's `content_hashes_in_period`.
fn content_hashes_in_period(leaves: &[CommitmentLeafDoc], start: i64, end: i64) -> Vec<String> {
    leaves
        .iter()
        .filter(|l| match leaf_captured_at_secs(l) {
            Some(t) => t >= start && t < end,
            None => true,
        })
        .map(|l| l.content_hash.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// One roots-chain row, decoded from DynamoDB.
// ---------------------------------------------------------------------------

struct ChainRow {
    period_id: u64,
    root_hash: Hash,
    prev_root_hash: Hash,
    tree_size: usize,
    /// The producer's frozen constants; drift is rejected at read time (fail loud).
    algorithm: &'static str,
    canon: &'static str,
    anchored: bool,
    tst_ref: Option<String>,
    gen_time_unix: Option<u64>,
    serial_hex: Option<String>,
}

impl ChainRow {
    fn as_roots_chain_row(&self) -> RootsChainRow {
        RootsChainRow {
            period_id: self.period_id,
            root_hash: self.root_hash,
            prev_root_hash: self.prev_root_hash,
            // MAC-1 rows (what this CLI reads today): the anchored digest IS the period Merkle root.
            // A MAC-2 producer read would additionally carry the inner period_root from the store.
            period_root: self.root_hash,
            tree_size: self.tree_size,
            algorithm: self.algorithm,
            canon: self.canon,
        }
    }
}

fn attr_s<'a>(item: &'a HashMap<String, AttributeValue>, k: &str) -> Option<&'a str> {
    item.get(k).and_then(|v| v.as_s().ok()).map(|s| s.as_str())
}

fn decode_row(item: &HashMap<String, AttributeValue>) -> Result<ChainRow, String> {
    let period_id = item
        .get("period_id")
        .and_then(|v| v.as_n().ok())
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or("row missing/invalid period_id")?;
    let root_hash = attr_s(item, "root_hash")
        .and_then(|s| leaf_bytes_from_content_hash(s).ok())
        .ok_or_else(|| format!("period {period_id}: missing/invalid root_hash"))?;
    let prev_root_hash = attr_s(item, "prev_root_hash")
        .and_then(|s| leaf_bytes_from_content_hash(s).ok())
        .ok_or_else(|| format!("period {period_id}: missing/invalid prev_root_hash"))?;
    let tree_size = item
        .get("tree_size")
        .and_then(|v| v.as_n().ok())
        .and_then(|n| n.parse::<usize>().ok())
        .ok_or_else(|| format!("period {period_id}: missing/invalid tree_size"))?;

    // Reject algorithm/canon drift at read (an auditor tool fails loud rather than emitting a proof
    // over a chain whose construction rules changed). Only the frozen constants map to the &'static.
    // Distinguish a MISSING attribute (malformed row / schema migration) from a real DRIFT mismatch —
    // conflating the two hides a schema change behind a confusing 'drift' message.
    let alg = attr_s(item, "algorithm")
        .ok_or_else(|| format!("period {period_id}: missing algorithm attribute"))?;
    if alg != TREE_ALGORITHM {
        return Err(format!(
            "period {period_id}: algorithm {alg:?} != {TREE_ALGORITHM} (chain drift)"
        ));
    }
    let can = attr_s(item, "canon")
        .ok_or_else(|| format!("period {period_id}: missing canon attribute"))?;
    if can != MAC_SPEC_VERSION {
        return Err(format!(
            "period {period_id}: canon {can:?} != {MAC_SPEC_VERSION} (chain drift)"
        ));
    }

    let anchored = item
        .get("anchored")
        .and_then(|v| v.as_bool().ok())
        .copied()
        .unwrap_or(false);
    let gen_time_unix = item
        .get("tst_gen_time_unix")
        .and_then(|v| v.as_n().ok())
        .and_then(|n| n.parse::<u64>().ok());

    Ok(ChainRow {
        period_id,
        root_hash,
        prev_root_hash,
        tree_size,
        algorithm: TREE_ALGORITHM,
        canon: MAC_SPEC_VERSION,
        anchored,
        tst_ref: attr_s(item, "tst_ref").map(|s| s.to_string()),
        gen_time_unix,
        serial_hex: attr_s(item, "tst_serial_hex").map(|s| s.to_string()),
    })
}

/// Query the org's full roots-chain (all periods, ascending by `period_id`).
async fn load_chain(
    ddb: &aws_sdk_dynamodb::Client,
    table: &str,
    org_id: &str,
) -> Result<Vec<ChainRow>, String> {
    let mut rows: Vec<ChainRow> = Vec::new();
    let mut start_key: Option<HashMap<String, AttributeValue>> = None;
    loop {
        let mut req = ddb
            .query()
            .table_name(table)
            .key_condition_expression("org_id = :o")
            .expression_attribute_values(":o", AttributeValue::S(org_id.into()))
            .scan_index_forward(true);
        if let Some(k) = start_key.clone() {
            req = req.set_exclusive_start_key(Some(k));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("query roots-chain for {org_id} failed: {e}"))?;
        for item in resp.items() {
            rows.push(decode_row(item)?);
        }
        match resp.last_evaluated_key() {
            Some(k) => start_key = Some(k.clone()),
            None => break,
        }
    }
    rows.sort_by_key(|r| r.period_id);
    Ok(rows)
}

/// Per-object cap: a commitment leaf is small JSON. Refuse anything larger rather than buffer an
/// arbitrary-size (malicious/corrupt) object into RAM (defence-in-depth; the tool does not trust
/// bucket contents even under a tight ACL).
const MAX_LEAF_BYTES: u64 = 1_048_576; // 1 MiB
/// Per-invocation total cap across all re-listed leaves — bounds worst-case memory/cost.
const MAX_TOTAL_BYTES: u64 = 512 * 1_048_576; // 512 MiB

/// RE-LIST one period's commitment leaves from S3 and re-derive its `content_hash` set (never a
/// stored index). Strict pagination: a truncated page with no continuation token is refused (would
/// yield a partial set — mirrors the producer's M4 guard). Per-object + running-total size caps
/// prevent an oversized/corrupt object from being pulled unbounded into memory.
async fn relist_period(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    org_id: &str,
    period_id: u64,
) -> Result<Vec<String>, String> {
    let prefix = day_prefix(org_id, period_id);
    let mut docs: Vec<CommitmentLeafDoc> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut token: Option<String> = None;
    loop {
        let mut req = s3.list_objects_v2().bucket(bucket).prefix(&prefix);
        if let Some(t) = token.clone() {
            req = req.continuation_token(t);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("list {prefix} failed: {e}"))?;
        for obj in resp.contents() {
            if let Some(key) = obj.key() {
                if key.ends_with('/') {
                    continue; // skip the folder placeholder object, if any
                }
                // LIST already reports the object size — reject oversized BEFORE downloading.
                // `Object::size()` is `Option<i64>`; `size_exceeds_cap` applies the explicit `> cap`
                // bound over that signed value (single tested source of truth — see lib.rs).
                if let Some(sz) = obj.size() {
                    if size_exceeds_cap(sz, MAX_LEAF_BYTES) {
                        return Err(format!(
                            "commitment leaf {key} is {sz} bytes (> {MAX_LEAF_BYTES} cap) — refusing"
                        ));
                    }
                }
                let out = s3
                    .get_object()
                    .bucket(bucket)
                    .key(key)
                    .send()
                    .await
                    .map_err(|e| format!("get {key} failed: {e}"))?;
                // Post-GET guard in case the LIST size was absent or lied. `content_length()` is also
                // `Option<i64>` — same explicit signed bound.
                if let Some(clen) = out.content_length() {
                    if size_exceeds_cap(clen, MAX_LEAF_BYTES) {
                        return Err(format!(
                            "commitment leaf {key} content-length {clen} > {MAX_LEAF_BYTES} cap — refusing"
                        ));
                    }
                }
                let bytes = out
                    .body
                    .collect()
                    .await
                    .map_err(|e| format!("read {key} failed: {e}"))?
                    .into_bytes();
                if bytes.len() as u64 > MAX_LEAF_BYTES {
                    return Err(format!(
                        "commitment leaf {key} is {} bytes (> {MAX_LEAF_BYTES} cap) — refusing",
                        bytes.len()
                    ));
                }
                total_bytes = total_bytes.saturating_add(bytes.len() as u64);
                if total_bytes > MAX_TOTAL_BYTES {
                    return Err(format!(
                        "re-list of {prefix} exceeded the {MAX_TOTAL_BYTES}-byte total cap — aborting"
                    ));
                }
                match serde_json::from_slice::<CommitmentLeafDoc>(&bytes) {
                    Ok(doc) => docs.push(doc),
                    Err(e) => {
                        // Fail loud: a leaf we cannot parse could change the tree — do not silently
                        // drop it and emit a proof over a different set than the producer committed.
                        return Err(format!("unparseable commitment leaf {key}: {e}"));
                    }
                }
            }
        }
        if resp.is_truncated().unwrap_or(false) {
            match resp.next_continuation_token() {
                Some(t) => token = Some(t.to_string()),
                None => {
                    return Err(format!(
                        "list {prefix} truncated but no continuation token — refusing a partial leaf set"
                    ))
                }
            }
        } else {
            break;
        }
    }
    let (start, end) = period_bounds(period_id);
    Ok(content_hashes_in_period(&docs, start, end))
}

/// How the target period is located — exactly one targeting mode (an unbounded default scan is a
/// cost/DoS vector, so there is no implicit "scan everything").
enum Target {
    /// Re-list exactly this period (days-since-epoch).
    Period(u64),
    /// Compute the period from a capture time and re-list that day ± 1 (leaf-key vs captured_at skew).
    CapturedAt(u64),
    /// OPT-IN fallback: scan the chain's periods ascending, bounded by `max_scan_days`.
    Scan { max_scan_days: usize },
}

struct Args {
    content_hash: String,
    org: String,
    target: Target,
    allow_unanchored: bool,
    table: String,
    bucket: Option<String>,
    region: Option<String>,
    out: Option<String>,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut content_hash: Option<String> = None;
    let mut org: Option<String> = None;
    let mut period_id: Option<u64> = None;
    let mut captured_at_period: Option<u64> = None;
    let mut scan = false;
    let mut max_scan_days: usize = DEFAULT_MAX_SCAN_DAYS;
    let mut allow_unanchored = false;
    let mut table =
        std::env::var("ROOTS_CHAIN_TABLE").unwrap_or_else(|_| DEFAULT_TABLE.to_string());
    let mut bucket = std::env::var("COMMITMENT_LEAF_BUCKET")
        .ok()
        .filter(|s| !s.is_empty());
    let mut region = std::env::var("AWS_REGION").ok().filter(|s| !s.is_empty());
    let mut out: Option<String> = None;

    let mut i = 0;
    while i < argv.len() {
        let need = |i: usize| -> String {
            argv.get(i + 1)
                .unwrap_or_else(|| die(&format!("{} needs a value", argv[i])))
                .clone()
        };
        match argv[i].as_str() {
            "--content-hash" => {
                content_hash = Some(need(i));
                i += 2;
            }
            "--org" => {
                org = Some(need(i));
                i += 2;
            }
            "--period-id" => {
                period_id = Some(
                    need(i)
                        .parse::<u64>()
                        .unwrap_or_else(|_| die("--period-id must be a u64 (days-since-epoch)")),
                );
                i += 2;
            }
            "--captured-at" => {
                let raw = need(i);
                let secs = chrono::DateTime::parse_from_rfc3339(&raw)
                    .unwrap_or_else(|_| {
                        die("--captured-at must be an RFC 3339 timestamp (e.g. 2026-07-05T12:00:00Z)")
                    })
                    .timestamp();
                captured_at_period = Some(period_id_for_unix(secs));
                i += 2;
            }
            "--scan" => {
                scan = true;
                i += 1;
            }
            "--max-scan-days" => {
                max_scan_days = need(i)
                    .parse::<usize>()
                    .unwrap_or_else(|_| die("--max-scan-days must be a positive integer"));
                i += 2;
            }
            "--allow-unanchored" => {
                allow_unanchored = true;
                i += 1;
            }
            "--table" => {
                table = need(i);
                i += 2;
            }
            "--bucket" => {
                bucket = Some(need(i));
                i += 2;
            }
            "--region" => {
                region = Some(need(i));
                i += 2;
            }
            "--out" => {
                out = Some(need(i));
                i += 2;
            }
            "-h" | "--help" => {
                println!(
                    "usage: commitment_proof_gen --content-hash <64-hex> --org <org-id> \
                     (--period-id <n> | --captured-at <rfc3339> | --scan) [--max-scan-days <n>] \
                     [--allow-unanchored] [--table <name>] [--bucket <name>] [--region <r>] [--out FILE]"
                );
                exit(0);
            }
            other => die(&format!("unknown argument: {other}")),
        }
    }

    // Exactly one targeting mode. No implicit unbounded scan.
    let modes = period_id.is_some() as u8 + captured_at_period.is_some() as u8 + scan as u8;
    if modes == 0 {
        die("specify a targeting mode: --period-id <n>, --captured-at <rfc3339>, or --scan (opt-in)");
    }
    if modes > 1 {
        die("--period-id, --captured-at and --scan are mutually exclusive — pick one");
    }
    let target = if let Some(p) = period_id {
        Target::Period(p)
    } else if let Some(p) = captured_at_period {
        Target::CapturedAt(p)
    } else {
        Target::Scan { max_scan_days }
    };

    Args {
        content_hash: content_hash.unwrap_or_else(|| die("--content-hash is required")),
        org: org.unwrap_or_else(|| die("--org is required")),
        target,
        allow_unanchored,
        table,
        bucket,
        region,
        out,
    }
}

#[tokio::main]
async fn main() {
    let args = parse_args();

    // Validate the content_hash charset up front (fail before any AWS call).
    if let Err(e) = leaf_bytes_from_content_hash(&args.content_hash) {
        die(&format!("invalid --content-hash: {e}"));
    }
    let bucket = args
        .bucket
        .clone()
        .unwrap_or_else(|| die("--bucket (or COMMITMENT_LEAF_BUCKET) is required"));

    let mut cfg_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(r) = &args.region {
        cfg_loader = cfg_loader.region(aws_config::Region::new(r.clone()));
    }
    let shared = cfg_loader.load().await;
    let ddb = aws_sdk_dynamodb::Client::new(&shared);
    let s3 = aws_sdk_s3::Client::new(&shared);

    // 1. Load the org's roots-chain (all periods).
    let chain = load_chain(&ddb, &args.table, &args.org)
        .await
        .unwrap_or_else(|e| die(&e));
    if chain.is_empty() {
        die(&format!("no roots-chain rows for org {}", args.org));
    }
    println!(
        "roots-chain: {} periods for org {} (periods {}..={})",
        chain.len(),
        args.org,
        chain.first().unwrap().period_id,
        chain.last().unwrap().period_id
    );

    // 2. Determine the candidate periods to re-list from the TARGETING mode (never an implicit
    //    unbounded org-wide scan). Only periods present in the chain are considered.
    let in_chain = |p: u64| chain.iter().any(|r| r.period_id == p);
    let candidates: Vec<u64> = match &args.target {
        Target::Period(p) => {
            if !in_chain(*p) {
                die(&format!(
                    "--period-id {p} is not in org {}'s chain",
                    args.org
                ));
            }
            vec![*p]
        }
        Target::CapturedAt(p) => {
            // The target day plus immediate neighbours (leaf S3-key date vs captured_at can differ
            // by a day at the boundary). At most 3 day re-lists — bounded regardless of chain length.
            let mut cand: Vec<u64> = [p.saturating_sub(1), *p, p.saturating_add(1)]
                .into_iter()
                .filter(|&d| in_chain(d))
                .collect();
            cand.dedup();
            if cand.is_empty() {
                die(&format!(
                    "no chain period near captured-at day {p} for org {} (checked {p}±1)",
                    args.org
                ));
            }
            println!("targeting captured-at day {p} (±1 for skew): candidates {cand:?}");
            cand
        }
        Target::Scan { max_scan_days } => {
            if chain.len() > *max_scan_days {
                die(&format!(
                    "--scan would re-list {} periods (> --max-scan-days {}); narrow with --period-id \
                     or --captured-at, or raise --max-scan-days deliberately",
                    chain.len(),
                    max_scan_days
                ));
            }
            eprintln!(
                "WARNING: --scan re-lists up to {} period-days from S3 for org {} to locate the leaf. \
                 This is an unbounded-ish cost path; prefer --period-id / --captured-at when known.",
                chain.len(),
                args.org
            );
            chain.iter().map(|r| r.period_id).collect()
        }
    };

    let mut found: Option<(u64, Vec<String>)> = None;
    for pid in candidates {
        let hashes = relist_period(&s3, &bucket, &args.org, pid)
            .await
            .unwrap_or_else(|e| die(&e));
        if hashes.iter().any(|h| h == &args.content_hash) {
            println!(
                "leaf FOUND in period {pid} ({} re-listed leaves under {})",
                hashes.len(),
                day_prefix(&args.org, pid)
            );
            found = Some((pid, hashes));
            break;
        }
    }
    let (period_id, period_hashes) = found.unwrap_or_else(|| {
        die(&format!(
            "content_hash {} not found in any re-listed period for org {}",
            args.content_hash, args.org
        ))
    });

    // 3. Collect the genesis→period roots-chain segment + its TST references.
    let segment: Vec<RootsChainRow> = chain
        .iter()
        .filter(|r| r.period_id <= period_id)
        .map(|r| r.as_roots_chain_row())
        .collect();
    let tst_refs: Vec<TstRef> = chain
        .iter()
        .filter(|r| r.period_id <= period_id)
        .map(|r| TstRef {
            period_id: r.period_id,
            tst_ref: r.tst_ref.clone(),
            gen_time_unix: r.gen_time_unix,
            serial_hex: r.serial_hex.clone(),
            anchored: r.anchored,
        })
        .collect();

    // 4. Build + self-verify the bundle (refuse to emit one that does not verify).
    let bundle = build_proof_bundle(
        &args.content_hash,
        &args.org,
        period_id,
        &period_hashes,
        &segment,
        tst_refs,
    )
    .unwrap_or_else(|e| die(&format!("building proof bundle: {e}")));

    if let Err(e) = bundle.verify() {
        die(&format!(
            "self-verification FAILED — refusing to emit an unverifiable bundle: {e}"
        ));
    }

    // 4b. ANCHORING gate (HIGH-1): a bundle over un-anchored roots is inclusion + chain-linkage
    //     ONLY — NOT externally-timestamped tamper-evidence. Refuse to emit by default so a consumer
    //     can never mistake one for the other; --allow-unanchored emits it with the state surfaced.
    let anchoring = bundle.anchoring_status();
    if let AnchoringStatus::Unanchored { periods } = &anchoring {
        eprintln!(
            "WARNING: periods {periods:?} are NOT RFC 3161 anchored — this proof is inclusion + \
             roots-chain-linkage ONLY, NOT externally-timestamped tamper-evidence."
        );
        if !args.allow_unanchored {
            die(
                "refusing to emit a proof over un-anchored periods; pass --allow-unanchored to \
                 emit anyway (the artifact records fully_anchored=false)",
            );
        }
        eprintln!("--allow-unanchored set: emitting anyway with fully_anchored=false recorded.");
    }

    // 5. Emit JSON (stdout and/or --out) + a human summary.
    let json = bundle.to_json();
    let pretty = serde_json::to_string_pretty(&json)
        .unwrap_or_else(|e| die(&format!("serialize bundle: {e}")));
    if let Some(path) = &args.out {
        std::fs::write(path, pretty.as_bytes())
            .unwrap_or_else(|e| die(&format!("write {path}: {e}")));
        println!("artifact  : {path}");
    }
    println!("{pretty}");

    let period_row = segment
        .iter()
        .find(|r| r.period_id == period_id)
        .expect("target period must be present in the genesis→period segment");
    let anchored_line = match &anchoring {
        AnchoringStatus::FullyAnchored => {
            "yes (all covered periods carry an RFC 3161 TST)".to_string()
        }
        AnchoringStatus::Unanchored { periods } => {
            format!("NO — periods {periods:?} un-anchored (fully_anchored=false)")
        }
    };
    println!(
        "\nSUMMARY\n  leaf found     : yes (content_hash {})\n  period         : {period_id}\n  period_root    : {}\n  chain length   : {} rows (genesis→period)\n  structural     : verify_inclusion + verify_chain OK (self-checked)\n  fully anchored : {anchored_line}\n\nBOUNDARY: inclusion + roots-chain linkage/contiguity checked. Anchoring is a separate claim \
         (see fully_anchored). RFC 3161 CMS signature/chain NOT verified here (P4); T5 needs the P3 \
         customer co-anchor.",
        args.content_hash,
        period_row.root_hash_hex(),
        segment.len()
    );
}
