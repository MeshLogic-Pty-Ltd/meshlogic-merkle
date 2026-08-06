//! C1 P1a Task 3 — the thin auditor-verifiable demo (ADR-043 §7 Phase 1a "shown verifiable").
//!
//! Proves ONE compliance record end-to-end: its `content_hash` is a Merkle leaf, INCLUDED in a
//! root, and that root is RFC 3161 TIMESTAMP-ANCHORED by a real TSA — then re-verifies both from
//! scratch and prints the auditor line. No durable infra (single-period, in-memory) — P1b builds
//! the durable commitment log; P4 adds the full offline signature verifier.
//!
//! Run (needs network for the live TSA):
//!   cargo run -p meshlogic-merkle --features tsa-client --bin tamper_evidence_demo \
//!       -- <content_hash_64hex> [tsa_url]
//! Defaults: content_hash = SHA-256("abc"); tsa_url = https://freetsa.org/tsr

use meshlogic_merkle::anchor::{extract_tst_facts_matching_root, timestamp_root_via_tsa};
use meshlogic_merkle::{
    hash_leaf, inclusion_proof, leaf_bytes_from_content_hash, merkle_tree_hash, verify_inclusion,
    Hash,
};

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let ch_hex = args.get(1).cloned().unwrap_or_else(|| {
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into()
    });
    let tsa_url = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "https://freetsa.org/tsr".into());

    let leaf: Hash = match leaf_bytes_from_content_hash(&ch_hex) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("invalid content_hash: {e}");
            std::process::exit(2);
        }
    };

    // One record → single-period Merkle tree → root + inclusion proof.
    let leaves = vec![leaf];
    let root = merkle_tree_hash(&leaves);
    let proof = inclusion_proof(0, &leaves).expect("proof for index 0");
    let leaf_hash = hash_leaf(&leaf);

    println!("record content_hash : {ch_hex}");
    println!("merkle root         : {}", hexs(&root));
    let included = verify_inclusion(0, leaves.len(), leaf_hash, &proof, root);
    println!(
        "inclusion proof     : {} ({} sibling hash(es))",
        if included { "VERIFIED" } else { "FAILED" },
        proof.len()
    );
    if !included {
        eprintln!("inclusion verification failed — aborting");
        std::process::exit(1);
    }

    // Anchor the root to a real RFC 3161 TSA, then re-verify the token covers exactly our root.
    println!("anchoring root to TSA {tsa_url} ...");
    let tst = match timestamp_root_via_tsa(root, &tsa_url) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("TSA round-trip failed: {e}");
            std::process::exit(1);
        }
    };
    let facts = match extract_tst_facts_matching_root(&tst, root) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("TST verification failed: {e}");
            std::process::exit(1);
        }
    };

    println!(
        "\n==> INCLUDED in root {} — TSA-timestamped at unix {} (serial {})",
        hexs(&root),
        facts.gen_time_unix,
        hexs(&facts.serial)
    );
    println!(
        "    imprint-coverage + time checked. TSA SIGNATURE CHAIN NOT VERIFIED in P1a \
         (ADR-043 §6 — that is the P4 offline verifier's job); do not quote this as cryptographic proof."
    );

    // Counter-demonstration: a one-bit-altered record no longer matches the same proof/root.
    let mut altered = leaf;
    altered[0] ^= 0x01;
    let altered_ok = verify_inclusion(0, leaves.len(), hash_leaf(&altered), &proof, root);
    println!(
        "altered record      : {}",
        if altered_ok {
            "WRONGLY VERIFIED (bug!)"
        } else {
            "ALTERED / NOT-IN-LOG (correctly rejected)"
        }
    );
}
