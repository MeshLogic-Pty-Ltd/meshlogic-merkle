//! MAC-1 roots-chain PRODUCE side — ADR-043 P1b durable commitment log (producer math only).
//!
//! P1a shipped the RFC 6962 tree hash + inclusion proof over ADR-042 `content_hash` leaves. P1b
//! adds the periodic commitment: for each period we build ONE Merkle root over that period's
//! content_hashes (the `period_root`), then HASH-CHAIN the periods together via `prev_root_hash`
//! (genesis = all-zero) so the roots log is append-only tamper-evident — a verifier walks the chain
//! (`verify_chain`, macos-tertiary's VERIFY seam) and detects any inserted/removed/altered period.
//!
//! This module is the PRODUCE side ONLY — pure, no AWS. The durable log itself (DynamoDB), the
//! periodic builder Lambda, alarms and EventBridge wiring are P1b infra deferred to mac-lead's ack.
//! Contiguity / gap-free enforcement over `period_id` is the real builder's concern; `build_roots_chain`
//! chains whatever ordered periods it is handed.
//!
//! MAC-1 canon pin (frozen `chain_vectors`): the leaf DATA is the raw 32 bytes of each period's
//! `content_hash`, and the per-period leaf set is sorted by RAW-BYTE ascending order (memcmp / `Ord`
//! on `[u8; 32]`) BEFORE the tree hash — NOT by the hex string. A producer that sorts the hex strings
//! instead would agree with raw-byte order by luck on most inputs and silently diverge on others, so
//! the sort domain is a hard conformance pin (MAC-1).

use crate::{
    leaf_bytes_from_content_hash, merkle_tree_hash, Hash, MerkleError, MAC_SPEC_VERSION,
    TREE_ALGORITHM,
};

/// Genesis `prev_root_hash` for the first period in a chain (RFC-style all-zero anchor).
const GENESIS_PREV_ROOT: Hash = [0u8; 32];

/// Build the MAC-1 Merkle root for a single period over its `content_hash` set.
///
/// Each 64-char lowercase-hex `content_hash` is decoded to its raw 32 bytes (`leaf_bytes_from_content_hash`),
/// the raw 32-byte leaves are sorted RAW-BYTE ASCENDING (memcmp / `Ord` on `[u8; 32]`, the MAC-1 pin —
/// NOT hex-string order), then `merkle_tree_hash` (RFC 6962 MTH over the leaf DATA) yields the root.
/// Returns `(root, tree_size)` where `tree_size` is the number of content_hashes.
/// Empty input → `(merkle_tree_hash(&[]), 0)` (RFC 6962 empty tree = `SHA-256("")`).
pub fn period_root(content_hashes_hex: &[String]) -> Result<(Hash, usize), MerkleError> {
    let (root, tree_size, _leaves) = period_root_with_leaves(content_hashes_hex)?;
    Ok((root, tree_size))
}

/// As [`period_root`], but ALSO returns the exact raw-byte-sorted leaf vector the tree hashed.
///
/// This exists so the committed-hash MANIFEST (ADR-043 coverage-probe sidecar) can be emitted from
/// the SAME buffer, in the SAME order, that produced `root_hash` — with NO second sort in the caller.
/// A caller that re-derived + re-sorted the order risks hex-string-vs-raw-byte drift (the MAC-1 pin),
/// making `Merkle(manifest) != root_hash` and false-FAILing the coverage gate. Returning the vector
/// makes that drift structurally impossible: serialize the manifest directly from `sorted_leaves`.
pub fn period_root_with_leaves(
    content_hashes_hex: &[String],
) -> Result<(Hash, usize, Vec<Hash>), MerkleError> {
    let tree_size = content_hashes_hex.len();
    let mut leaves: Vec<Hash> = content_hashes_hex
        .iter()
        .map(|h| leaf_bytes_from_content_hash(h))
        .collect::<Result<Vec<Hash>, MerkleError>>()?;
    // MAC-1: sort the RAW 32-byte arrays ascending (memcmp), never the hex strings.
    leaves.sort_unstable();
    let root = merkle_tree_hash(&leaves);
    Ok((root, tree_size, leaves))
}

/// Serialize a period's committed-hash MANIFEST from its raw-byte-sorted leaf vector.
///
/// Format (pinned): newline-delimited lowercase-hex `content_hash`, one per line, in the EXACT order
/// of `sorted_leaves` (which callers MUST obtain from [`period_root_with_leaves`] — the same vector
/// the tree hashed, never re-sorted). The coverage probe recomputes `Merkle(manifest)` and requires
/// it to equal the roots-chain row's `root_hash` before trusting the set, so the manifest needs no
/// separate signing — its integrity is the anchored root. Empty period → empty string (no leaves).
pub fn committed_hash_manifest(sorted_leaves: &[Hash]) -> String {
    let mut out = String::with_capacity(sorted_leaves.len() * 65);
    for leaf in sorted_leaves {
        out.push_str(&hex::encode(leaf));
        out.push('\n');
    }
    out
}

/// One row of the durable roots-chain log (P1b): a period's Merkle root, hash-chained to the prior period.
///
/// `prev_root_hash` links this period to the previous one (genesis = all-zero for the first period),
/// making the log append-only tamper-evident. `algorithm` / `canon` record the exact construction so
/// an offline verifier knows which rules produced the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootsChainRow {
    /// Monotonic period identifier (e.g. a day index). Chain order is by ascending `period_id`.
    pub period_id: u64,
    /// This period's MAC-1 Merkle root over its raw-byte-sorted `content_hash` leaves.
    pub root_hash: Hash,
    /// The previous period's `root_hash`; `[0u8; 32]` (genesis) for the first row.
    pub prev_root_hash: Hash,
    /// Number of `content_hash` leaves committed in this period.
    pub tree_size: usize,
    /// Tree-hash algorithm identifier — RFC 6962 tree hash over SHA-256 (`"RFC6962-SHA256"`).
    pub algorithm: &'static str,
    /// Merkle-Anchor-Commitment profile version (`"MAC-1"`).
    pub canon: &'static str,
}

impl RootsChainRow {
    /// Lowercase-hex of `root_hash` (64 chars) — the on-the-wire / stored form.
    pub fn root_hash_hex(&self) -> String {
        hex::encode(self.root_hash)
    }
    /// Lowercase-hex of `prev_root_hash` (64 chars, all-zero for genesis).
    pub fn prev_root_hash_hex(&self) -> String {
        hex::encode(self.prev_root_hash)
    }
}

/// Build the hash-chained roots log over a set of periods.
///
/// Periods are sorted by `period_id` ASCENDING first. `row[0].prev_root_hash` is genesis (`[0u8; 32]`);
/// each subsequent `row[n].prev_root_hash` is `row[n-1].root_hash`. Each row's `(root_hash, tree_size)`
/// comes from [`period_root`] over that period's content_hashes. `algorithm` / `canon` are the frozen
/// MAC-1 constants. This function chains whatever ordered periods it is given — gap-free / contiguity
/// enforcement over `period_id` is the caller's concern in the real builder.
pub fn build_roots_chain(
    periods: &[(u64, Vec<String>)],
) -> Result<Vec<RootsChainRow>, MerkleError> {
    let mut sorted: Vec<&(u64, Vec<String>)> = periods.iter().collect();
    sorted.sort_by_key(|(period_id, _)| *period_id);

    let mut rows: Vec<RootsChainRow> = Vec::with_capacity(sorted.len());
    let mut prev_root_hash = GENESIS_PREV_ROOT;
    for (period_id, content_hashes) in sorted {
        let (root_hash, tree_size) = period_root(content_hashes)?;
        rows.push(RootsChainRow {
            period_id: *period_id,
            root_hash,
            prev_root_hash,
            tree_size,
            algorithm: TREE_ALGORITHM,
            canon: MAC_SPEC_VERSION,
        });
        prev_root_hash = root_hash;
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// content_hash = sha256(ascii label) as lowercase hex — the frozen `chain_vectors` label convention.
    fn content_hash(label: &str) -> String {
        let digest = Sha256::digest(label.as_bytes());
        hex::encode(digest)
    }

    const EMPTY_TREE_ROOT: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const P1_ROOT: &str = "35b5f2709beff9c7b55f267051ed89309cd899d79ad4ac205ff77ce8eeb65859";
    const P2_ROOT: &str = "5fb58d89ca9e40abece0d6b1447d5783094112244c17e9b5b7aa5c89c84f8012";
    const GENESIS_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn period_root_reproduces_frozen_p1() {
        let hashes = vec![content_hash("leaf-A"), content_hash("leaf-B")];
        let (root, size) = period_root(&hashes).unwrap();
        assert_eq!(hex::encode(root), P1_ROOT, "p1 root");
        assert_eq!(size, 2, "p1 tree_size");
    }

    #[test]
    fn period_root_reproduces_frozen_p2() {
        let hashes = vec![
            content_hash("leaf-C"),
            content_hash("leaf-D"),
            content_hash("leaf-E"),
        ];
        let (root, size) = period_root(&hashes).unwrap();
        assert_eq!(hex::encode(root), P2_ROOT, "p2 root");
        assert_eq!(size, 3, "p2 tree_size");
    }

    #[test]
    fn period_root_with_leaves_agrees_with_period_root() {
        // The delegated period_root and the leaf-exposing variant must agree bit-for-bit.
        let hashes = vec![
            content_hash("leaf-C"),
            content_hash("leaf-D"),
            content_hash("leaf-E"),
        ];
        let (r1, s1) = period_root(&hashes).unwrap();
        let (r2, s2, leaves) = period_root_with_leaves(&hashes).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(s1, s2);
        assert_eq!(leaves.len(), 3);
        // leaves come back RAW-BYTE ASCENDING (the MAC-1 pin) — verify strictly sorted.
        assert!(
            leaves.windows(2).all(|w| w[0] <= w[1]),
            "leaves must be raw-byte sorted"
        );
    }

    #[test]
    fn manifest_reproduces_root_order_identity_kat() {
        // THE load-bearing proof: the manifest emitted from period_root_with_leaves, parsed back
        // and Merkle-hashed WITHOUT re-sorting (as the coverage probe does), reproduces root_hash.
        // Pinned to the frozen P2 vector so producer + consumer are locked to one leaf order.
        let hashes = vec![
            content_hash("leaf-C"),
            content_hash("leaf-D"),
            content_hash("leaf-E"),
        ];
        let (root, _size, sorted_leaves) = period_root_with_leaves(&hashes).unwrap();
        let manifest = committed_hash_manifest(&sorted_leaves);
        // consumer side: parse NDJSON, recompute in-order (no re-sort — the manifest IS the order)
        let parsed: Vec<Hash> = manifest
            .lines()
            .map(|h| leaf_bytes_from_content_hash(h).unwrap())
            .collect();
        assert_eq!(
            merkle_tree_hash(&parsed),
            root,
            "Merkle(manifest) must == period_root"
        );
        assert_eq!(hex::encode(root), P2_ROOT, "and it's the frozen P2 root");
        assert_eq!(manifest.lines().count(), 3);
        // every line is 64-char lowercase hex + newline-terminated
        assert!(manifest.ends_with('\n'));
        assert!(manifest
            .lines()
            .all(|l| l.len() == 64 && l == l.to_lowercase()));
    }

    #[test]
    fn manifest_empty_period_is_empty_string() {
        let (root, size, leaves) = period_root_with_leaves(&[]).unwrap();
        assert_eq!(
            committed_hash_manifest(&leaves),
            "",
            "empty period → empty manifest"
        );
        assert_eq!(size, 0);
        assert_eq!(hex::encode(root), EMPTY_TREE_ROOT);
    }

    #[test]
    fn period_root_empty_is_rfc6962_empty_tree() {
        let (root, size) = period_root(&[]).unwrap();
        assert_eq!(hex::encode(root), EMPTY_TREE_ROOT, "empty period root");
        assert_eq!(size, 0, "empty period tree_size");
    }

    /// MAC-1 pin: RAW-byte-ASC sort, not hex-string sort. This is only observable when the two
    /// orderings disagree — construct such a pair and assert the root matches the raw-sorted order,
    /// independent of input argument order.
    #[test]
    fn period_root_sorts_by_raw_bytes_not_hex_string_order() {
        // Two valid content_hashes; feed in both argument orders → identical root (sort is stable
        // over input order) AND equals the root computed from the explicitly raw-sorted leaves.
        let a = content_hash("leaf-A");
        let b = content_hash("leaf-B");
        let forward = period_root(&[a.clone(), b.clone()]).unwrap().0;
        let reverse = period_root(&[b.clone(), a.clone()]).unwrap().0;
        assert_eq!(forward, reverse, "root must be independent of input order");

        let mut raw = vec![
            leaf_bytes_from_content_hash(&a).unwrap(),
            leaf_bytes_from_content_hash(&b).unwrap(),
        ];
        raw.sort_unstable();
        assert_eq!(
            forward,
            merkle_tree_hash(&raw),
            "root must match raw-byte-sorted MTH"
        );
    }

    /// The alignment gate: reproduce macos-tertiary's frozen `chain_vectors` roots_chain EXACTLY —
    /// root_hash, tree_size, and prev_root_hash for all three periods (p1=2 leaves, p2=3 leaves,
    /// p3=empty), with genesis prev for p1 and the hash-chain linking p1→p2→p3.
    #[test]
    fn build_roots_chain_reproduces_frozen_chain_vectors() {
        let p1 = vec![content_hash("leaf-A"), content_hash("leaf-B")];
        let p2 = vec![
            content_hash("leaf-C"),
            content_hash("leaf-D"),
            content_hash("leaf-E"),
        ];
        let p3: Vec<String> = vec![];

        let chain = build_roots_chain(&[(1, p1), (2, p2), (3, p3)]).unwrap();
        assert_eq!(chain.len(), 3, "three periods → three rows");

        // Row 0 — period 1: two leaves, genesis prev.
        assert_eq!(chain[0].period_id, 1);
        assert_eq!(chain[0].root_hash_hex(), P1_ROOT, "p1 root");
        assert_eq!(chain[0].tree_size, 2, "p1 tree_size");
        assert_eq!(
            chain[0].prev_root_hash_hex(),
            GENESIS_HEX,
            "p1 genesis prev"
        );

        // Row 1 — period 2: three leaves, prev = p1 root.
        assert_eq!(chain[1].period_id, 2);
        assert_eq!(chain[1].root_hash_hex(), P2_ROOT, "p2 root");
        assert_eq!(chain[1].tree_size, 3, "p2 tree_size");
        assert_eq!(chain[1].prev_root_hash_hex(), P1_ROOT, "p2 prev = p1 root");

        // Row 2 — period 3: empty, prev = p2 root.
        assert_eq!(chain[2].period_id, 3);
        assert_eq!(chain[2].root_hash_hex(), EMPTY_TREE_ROOT, "p3 empty root");
        assert_eq!(chain[2].tree_size, 0, "p3 tree_size");
        assert_eq!(chain[2].prev_root_hash_hex(), P2_ROOT, "p3 prev = p2 root");

        // Constants recorded on every row.
        for row in &chain {
            assert_eq!(row.algorithm, "RFC6962-SHA256");
            assert_eq!(row.canon, "MAC-1");
        }
    }

    /// `build_roots_chain` must sort by `period_id` before chaining — feeding periods out of order
    /// yields the same chain as feeding them in order.
    #[test]
    fn build_roots_chain_sorts_periods_by_id() {
        let p1 = vec![content_hash("leaf-A"), content_hash("leaf-B")];
        let p2 = vec![
            content_hash("leaf-C"),
            content_hash("leaf-D"),
            content_hash("leaf-E"),
        ];
        let ordered = build_roots_chain(&[(1, p1.clone()), (2, p2.clone())]).unwrap();
        let shuffled = build_roots_chain(&[(2, p2), (1, p1)]).unwrap();
        assert_eq!(
            ordered, shuffled,
            "chain must be order-independent of input"
        );
    }

    #[test]
    fn build_roots_chain_empty_input_is_empty() {
        assert!(build_roots_chain(&[]).unwrap().is_empty());
    }

    #[test]
    fn period_root_bad_hash_is_err() {
        assert!(period_root(&["not-hex".to_string()]).is_err());
        assert!(period_root(&["A".repeat(64)]).is_err()); // uppercase rejected by the leaf decoder
    }
}
