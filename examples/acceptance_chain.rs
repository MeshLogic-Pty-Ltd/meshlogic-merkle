//! M6-c acceptance-artifact generator for MESHLOGIC03's `evchain-verify.py` (gates a–e + [6]).
//!
//! Produces a REAL cooperation-decision chain through the SHIPPED writer (`append_decision_to_file` +
//! the frozen v=1 `DecisionRecord` canonicalization + this crate's JCS), signed with the FROZEN
//! GOLDEN-VECTOR key (seed=[0x42;32] → key_id `mlc-ed25519-3097e2dee2cb4a34`) that Windows #562,
//! macOS #563, and the verifier have all independently pinned. Nothing here is a fixture-signer hack:
//! it is the exact production crypto path exercised with the one key all three sides already agree on,
//! so acceptance can run BEFORE a live-enforced leaf ships.
//!
//! HONEST SCOPE: the decision *records* are representative (enforcement isn't armed on the acceptance
//! box, so these are hand-built rather than captured live), but every cryptographic operation — key,
//! canonical preimage, hash-linking, Ed25519 signatures, key_id derivation — is the real shipped code.
//! One row is intentionally UNSIGNED to exercise the honest un-enrolled (unsigned-1a) gate.
//!
//! Run: `cargo run -p meshlogic-merkle --example acceptance_chain --features leaf-verify -- <outdir>`

use ed25519_dalek::SigningKey;
use meshlogic_merkle::decision_chain::{
    append_decision_to_file, append_unsigned_decision_to_file, load_chain_file,
    verify_decision_chain, DECISION_CHAIN_GENESIS,
};
use meshlogic_merkle::decision_record::{canonical_preimage, source_kind_for, DecisionRecord};
use meshlogic_merkle::signed_leaf::{EnrolledAgentKey, EnrolledAgentTrustStore};
use sha2::{Digest, Sha256};

/// key_id = "mlc-ed25519-" + lowercase_hex(sha256(pubkey_raw_32)[..8]) — the ONE fleet standard.
fn key_id_for(vk: &ed25519_dalek::VerifyingKey) -> String {
    format!(
        "mlc-ed25519-{}",
        hex::encode(&Sha256::digest(vk.as_bytes())[..8])
    )
}

fn main() {
    // An explicit output directory is REQUIRED — this example writes a chain signed with the PUBLIC
    // golden-vector key, so it must never default to the cwd, and it must never use the production
    // reader's filename (`cooperation-decisions.jsonl`). Both would risk a golden-key-signed artifact
    // landing where a real reader picks it up.
    let outdir = match std::env::args().nth(1) {
        Some(d) => d,
        None => {
            eprintln!(
                "usage: cargo run -p meshlogic-merkle --example acceptance_chain --features leaf-verify -- <outdir>\n\
                 <outdir> is required (no cwd default): this writes a golden-key-signed acceptance chain."
            );
            std::process::exit(2);
        }
    };
    // Example-specific filename — deliberately NOT the production `cooperation-decisions.jsonl` a
    // deployed reader consumes.
    let chain_path = std::path::Path::new(&outdir).join("acceptance-chain.jsonl");
    if let Some(parent) = chain_path.parent() {
        std::fs::create_dir_all(parent).expect("create outdir");
    }
    let _ = std::fs::remove_file(&chain_path);

    // Frozen golden-vector identity: Win #562 == Mac #563 == evchain-verify.py all pin this exact key.
    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let key_id = key_id_for(&sk.verifying_key());

    // A representative ADJUDICATED set (the frozen population): a cred-deny (enforcement/policy), a
    // lane_b prompt + a lane_b promote (cooperation/behavioural). Real frozen v=1 records; the JCS
    // canonicalizes each identically to the Windows + macOS producers.
    let records = [
        DecisionRecord {
            event_id: 1001,
            ts: 133_000_000_000_000_001,
            decision: "deny",
            rule_kind: "policy",
            rule_id: "builtin.sensitive_file",
            data_class: 8,
            actor_pid: 4321,
            actor_path: r"C:\Program Files\Claude\claude.exe",
            object_path: Some(r"C:\Users\a\.aws\credentials"),
            object_content_hash: None,
            // canon-v2 fields (#3): None ⇒ these stay v=1 records, byte-identical to the frozen leaves.
            object_file_id: None,
            object_size: None,
        },
        DecisionRecord {
            event_id: 1002,
            ts: 133_000_000_000_000_002,
            decision: "prompt",
            rule_kind: "behavioural",
            rule_id: "coop.lane_b.cred_then_net",
            data_class: 8,
            actor_pid: 4321,
            actor_path: r"C:\Program Files\Claude\claude.exe",
            object_path: Some(r"C:\Users\a\.ssh\id_ed25519"),
            object_content_hash: None,
            // canon-v2 fields (#3): None ⇒ these stay v=1 records, byte-identical to the frozen leaves.
            object_file_id: None,
            object_size: None,
        },
        DecisionRecord {
            event_id: 1003,
            ts: 133_000_000_000_000_003,
            decision: "promote",
            rule_kind: "behavioural",
            rule_id: "coop.lane_b.actor_promote",
            data_class: 0,
            actor_pid: 4321,
            actor_path: r"C:\Program Files\Claude\claude.exe",
            object_path: None, // actor-promotion has no file object → explicit null in the preimage
            object_content_hash: None,
            // canon-v2 fields (#3): None ⇒ these stay v=1 records, byte-identical to the frozen leaves.
            object_file_id: None,
            object_size: None,
        },
    ];

    // Rows 0–1 SIGNED with the golden key; row 2 UNSIGNED (honest un-enrolled path — never fixture-signed).
    let mut leaf0_preimage_hex = String::new();
    for (i, rec) in records.iter().enumerate() {
        let preimage = canonical_preimage(rec);
        if i == 0 {
            leaf0_preimage_hex = hex::encode(&preimage);
        }
        let source_kind = source_kind_for(rec.rule_kind);
        let identity = serde_json::json!({
            "endpoint_id": "EP-ACCEPTANCE-DEMO",
            "org_id": "org-91e162b2-eb00-49c5-8a70-d952f4571506",
            "event_class": "CooperationDecision",
            "captured_at": 1_655_526_400u64 + i as u64,
        });
        if i < 2 {
            append_decision_to_file(&chain_path, source_kind, &preimage, identity, &sk, &key_id)
                .expect("signed append");
        } else {
            append_unsigned_decision_to_file(&chain_path, source_kind, &preimage, identity)
                .expect("unsigned append");
        }
    }

    // Independent local re-derivation (sanity before handoff): the chain re-links from the genesis and
    // every PRESENT signature verifies against the golden key (require_signatures=false ⇒ the unsigned
    // row is allowed, exactly as the honest un-enrolled path intends).
    let rows = load_chain_file(&chain_path).expect("load chain");
    let trust = EnrolledAgentTrustStore::new(vec![EnrolledAgentKey {
        key_id: key_id.clone(),
        verifying_key: sk.verifying_key(),
        not_before: None,
        not_after: None,
    }]);
    let tip = verify_decision_chain(&rows, DECISION_CHAIN_GENESIS, &trust, u64::MAX, false)
        .expect("chain must independently re-derive");

    println!("=== M6-c acceptance artifact (shipped writer + frozen golden-vector key) ===");
    println!("chain_file      : {}", chain_path.display());
    println!("rows            : {}  (2 signed + 1 unsigned)", rows.len());
    println!("re-derived tip  : {tip}");
    println!("key_id          : {key_id}");
    println!(
        "pubkey_hex      : {}",
        hex::encode(sk.verifying_key().as_bytes())
    );
    println!("leaf0_preimage  : {leaf0_preimage_hex}");
    println!(
        "\nHand to MESHLOGIC03: the chain_file, key_id -> pubkey_hex, and leaf0_preimage (HEX)."
    );
}
