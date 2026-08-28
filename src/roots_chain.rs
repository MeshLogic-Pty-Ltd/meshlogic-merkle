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
use sha2::{Digest, Sha256};

/// Genesis `prev_root_hash` for the first period in a chain (RFC-style all-zero anchor).
const GENESIS_PREV_ROOT: Hash = [0u8; 32];

/// A1 (CRITICAL) remediation — the MAC-2 committed roots-chain canon (windows-master DRI-concurred,
/// 2026-08-28; corroborated by macos-master + macos-secondary).
///
/// ## The defect (audit A1, verdict_A.md CONFIRMED-CRITICAL)
/// In MAC-1 the anchored `root_hash` is `period_root(content_hashes)` ONLY — it never folds in
/// `period_id` or `prev_root_hash`. So `verify_chain`'s linkage (`prev_root_hash == prev.root_hash`)
/// compares two INDEPENDENT stored values a store attacker can set at will, and a witness of the head
/// root commits to NOTHING prior — the "witnessing head@P transitively witnesses every period <= P"
/// claim is unsound. A past period can be rewritten / renumbered and the free-standing pointers fixed
/// up, and the chain still verifies.
///
/// ## The fix (MAC-2), scoped to the ROOTS-CHAIN DIGEST ONLY
/// A new canon. MAC-1 is FROZEN unchanged (already-anchored MAC-1 roots exist in the wild — changing
/// the construction in place would break every live anchor's verification). New rows are stamped
/// `canon = "MAC-2"` and the anchored digest FOLDS the period ordinal and the prior digest:
///
/// ```text
/// root_hash = SHA-256( MAC2_ROOTSCHAIN_DOMAIN || be64(period_id) || prev_root_hash || period_root )
/// ```
///
/// where `period_root = period_root(content_hashes)` is the UNCHANGED RFC 6962 Merkle root and
/// `prev_root_hash` chains the FOLDED digests (genesis `0^32`). Now `root_hash` cryptographically
/// depends on `prev_root_hash`, so the head is a true chain commitment and transitive-witness is sound
/// by construction. The VERIFIER selects the construction by the row's `canon` and, for MAC-2,
/// RECOMPUTES the digest — a re-linked/renumbered chain that only re-points stored fields no longer
/// reproduces it.
///
/// SCOPE: this changes ONLY the roots-chain digest. The per-RECORD leaf preimage / `DecisionChainRow`
/// v=1 canonicalization and `verify_record_chain` are NOT touched (360 live signed leaves are
/// committed under that frozen shape). HONESTY: MAC-1 history remains per-record-anchored only
/// (its chain-transitive-witness is DROPPED, it was never sound); MAC-2 forward restores the chain claim.
pub const MAC2_SPEC_VERSION: &str = "MAC-2";

/// Domain-separation tag for the MAC-2 roots-chain digest — binds the folded `root_hash` to THIS
/// construction so it can never collide with a bare Merkle root/leaf/node hash. FROZEN.
pub const MAC2_ROOTSCHAIN_DOMAIN: &[u8] = b"meshlogic.mac.rootschain.v2\x00";

/// Compute the MAC-2 folded roots-chain digest for one period:
/// `SHA-256(MAC2_ROOTSCHAIN_DOMAIN || be64(period_id) || prev_root_hash || period_root)`.
///
/// `period_id` and `tree_size`-independent `period_root` are fixed-width; `prev_root_hash` and
/// `period_root` are 32 bytes each — an unambiguous fixed-layout preimage. This is the single source
/// of truth the producer ([`build_roots_chain_v2`]) and verifier
/// ([`crate::chain_verify::verify_chain_from`]) both call, so they can never drift.
pub fn mac2_root_digest(period_id: u64, prev_root_hash: &Hash, period_root: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(MAC2_ROOTSCHAIN_DOMAIN);
    h.update(period_id.to_be_bytes());
    h.update(prev_root_hash);
    h.update(period_root);
    h.finalize().into()
}

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
    /// The ANCHORED roots-chain digest for this period. MAC-1: the bare RFC 6962 Merkle root over the
    /// period's raw-byte-sorted `content_hash` leaves (== [`Self::period_root`]). MAC-2: the FOLDED
    /// digest [`mac2_root_digest`]`(period_id, prev_root_hash, period_root)` — a true chain commitment.
    pub root_hash: Hash,
    /// The previous period's `root_hash`; `[0u8; 32]` (genesis) for the first row. Under MAC-2 the
    /// `root_hash` cryptographically commits to this value, so the linkage is no longer inert.
    pub prev_root_hash: Hash,
    /// The RFC 6962 Merkle root over this period's raw-byte-sorted `content_hash` leaves — the value an
    /// inclusion proof reproduces. For MAC-1 this EQUALS `root_hash`; for MAC-2 it is the inner value
    /// folded into `root_hash`. Stored so the verifier can recompute the MAC-2 digest without the leaves.
    pub period_root: Hash,
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
    /// Lowercase-hex of `period_root` (64 chars) — the RFC 6962 Merkle root an inclusion proof reproduces.
    pub fn period_root_hex(&self) -> String {
        hex::encode(self.period_root)
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
            // MAC-1: the anchored digest IS the period Merkle root, so period_root == root_hash.
            period_root: root_hash,
            tree_size,
            algorithm: TREE_ALGORITHM,
            canon: MAC_SPEC_VERSION,
        });
        prev_root_hash = root_hash;
    }
    Ok(rows)
}

/// Build the MAC-2 committed roots-chain over a set of periods (A1 remediation, DRI-concurred).
///
/// Like [`build_roots_chain`], but each row's ANCHORED `root_hash` is the FOLDED digest
/// [`mac2_root_digest`]`(period_id, prev_root_hash, period_root)` rather than the bare Merkle root, and
/// `prev_root_hash` chains those folded digests (genesis `0^32`). `period_root` (the RFC 6962 Merkle
/// root, UNCHANGED from MAC-1) is stored on the row so the verifier can recompute the digest and so an
/// inclusion proof can bind to it. Rows are stamped `canon = "MAC-2"`. The tree construction is
/// IDENTICAL to MAC-1 (same `period_root`); only the roots-chain digest changes.
pub fn build_roots_chain_v2(
    periods: &[(u64, Vec<String>)],
) -> Result<Vec<RootsChainRow>, MerkleError> {
    let mut sorted: Vec<&(u64, Vec<String>)> = periods.iter().collect();
    sorted.sort_by_key(|(period_id, _)| *period_id);

    let mut rows: Vec<RootsChainRow> = Vec::with_capacity(sorted.len());
    let mut prev_root_hash = GENESIS_PREV_ROOT;
    for (period_id, content_hashes) in sorted {
        let (period_root_val, tree_size) = period_root(content_hashes)?;
        let root_hash = mac2_root_digest(*period_id, &prev_root_hash, &period_root_val);
        rows.push(RootsChainRow {
            period_id: *period_id,
            root_hash,
            prev_root_hash,
            period_root: period_root_val,
            tree_size,
            algorithm: TREE_ALGORITHM,
            canon: MAC2_SPEC_VERSION,
        });
        // The NEXT period links to THIS folded digest — the chain commitment.
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

    // ---- MAC-2 committed roots-chain (A1 remediation, DRI-concurred) ---------------------------

    /// FREEZE MAC-1: a MAC-1 row's `period_root` equals its `root_hash` (the anchored digest IS the
    /// bare Merkle root). The MAC-2 field addition must not disturb the frozen MAC-1 construction.
    #[test]
    fn mac1_rows_have_period_root_equal_to_root_hash() {
        let p1 = vec![content_hash("leaf-A"), content_hash("leaf-B")];
        let chain = build_roots_chain(&[(1, p1)]).unwrap();
        assert_eq!(
            chain[0].period_root, chain[0].root_hash,
            "MAC-1: period_root == root_hash"
        );
        assert_eq!(chain[0].canon, "MAC-1");
    }

    /// NON-VACUITY (the whole original bug was a folded-but-ignored field): `period_id` AND
    /// `prev_root_hash` AND `period_root` EACH change the MAC-2 digest — none is decorative.
    #[test]
    fn mac2_digest_is_non_vacuous_in_every_folded_field() {
        let prev = [9u8; 32];
        let period_root = [7u8; 32];
        let base = mac2_root_digest(1, &prev, &period_root);
        assert_ne!(
            base,
            mac2_root_digest(2, &prev, &period_root),
            "period_id must change the digest"
        );
        assert_ne!(
            base,
            mac2_root_digest(1, &[10u8; 32], &period_root),
            "prev_root_hash must change the digest"
        );
        assert_ne!(
            base,
            mac2_root_digest(1, &prev, &[8u8; 32]),
            "period_root must change the digest"
        );
        // Domain separation: the folded digest is NOT the bare Merkle root it commits to.
        assert_ne!(
            base, period_root,
            "the MAC-2 digest is domain-separated from period_root"
        );
    }

    /// MAC-2 producer: each `root_hash` is the folded digest, `prev_root_hash` chains the folded
    /// digests (genesis first), `period_root` is the UNCHANGED MAC-1 Merkle root, canon is "MAC-2".
    #[test]
    fn build_roots_chain_v2_folds_and_chains_the_committed_digests() {
        let p1 = vec![content_hash("leaf-A"), content_hash("leaf-B")];
        let p2 = vec![
            content_hash("leaf-C"),
            content_hash("leaf-D"),
            content_hash("leaf-E"),
        ];
        let chain = build_roots_chain_v2(&[(0, p1.clone()), (1, p2)]).unwrap();
        assert_eq!(chain.len(), 2);

        // period_root is byte-identical to the MAC-1 Merkle root for the same leaves.
        assert_eq!(
            chain[0].period_root_hex(),
            P1_ROOT,
            "MAC-2 reuses the MAC-1 tree root"
        );
        // root_hash is the FOLDED digest (not the bare Merkle root).
        assert_ne!(
            chain[0].root_hash, chain[0].period_root,
            "MAC-2 root_hash folds, != period_root"
        );
        assert_eq!(
            chain[0].root_hash,
            mac2_root_digest(0, &GENESIS_PREV_ROOT, &chain[0].period_root),
            "row 0 digest reproduces from its fields"
        );
        // prev_root_hash chains the FOLDED digest, and row 1 folds it in.
        assert_eq!(
            chain[1].prev_root_hash, chain[0].root_hash,
            "row 1 links to row 0's folded digest"
        );
        assert_eq!(
            chain[1].root_hash,
            mac2_root_digest(1, &chain[0].root_hash, &chain[1].period_root),
            "row 1 digest folds the prior folded digest"
        );
        for row in &chain {
            assert_eq!(row.canon, "MAC-2");
            assert_eq!(row.algorithm, "RFC6962-SHA256");
        }
    }

    /// FROZEN MAC-2 golden vector (DRI-concurred construction). Pins the exact folded head digest so
    /// producer + verifier are locked to one construction; regenerate deliberately via
    /// `emit_mac2_chain_vectors --ignored` if (and only if) the concurred construction ever changes.
    const MAC2_HEAD_DIGEST: &str =
        "3d816ebac69943bf720c9432510408f0157a7e885c6bf5230991e609ba6d65a7";

    #[test]
    #[ignore = "run with --ignored to print the frozen MAC-2 golden head digest for MAC2_HEAD_DIGEST"]
    fn print_mac2_golden_head() {
        let chain = golden_mac2_chain();
        println!(
            "MAC2_HEAD_DIGEST = {}",
            chain.last().unwrap().root_hash_hex()
        );
    }

    fn golden_mac2_chain() -> Vec<RootsChainRow> {
        let p1 = vec![content_hash("leaf-A"), content_hash("leaf-B")];
        let p2 = vec![
            content_hash("leaf-C"),
            content_hash("leaf-D"),
            content_hash("leaf-E"),
        ];
        let p3: Vec<String> = vec![];
        build_roots_chain_v2(&[(0, p1), (1, p2), (2, p3)]).unwrap()
    }

    #[test]
    fn mac2_golden_head_is_frozen() {
        let chain = golden_mac2_chain();
        assert_eq!(
            chain.last().unwrap().root_hash_hex(),
            MAC2_HEAD_DIGEST,
            "the MAC-2 folded head digest must match the frozen golden vector"
        );
    }

    fn mac2_vectors_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/conformance/merkle-anchor/mac2_chain_vectors.json")
    }

    /// Regenerator for the MAC-2 golden vectors JSON (run: `cargo test emit_mac2_chain_vectors --
    /// --ignored`). Emits the DRI-concurred construction + values for windows-master review and
    /// cross-language parity, alongside (never replacing) the frozen MAC-1 `vectors.json`.
    #[test]
    #[ignore = "regenerator: run with --ignored to (re)emit the MAC-2 golden vectors JSON"]
    fn emit_mac2_chain_vectors() {
        let chain = golden_mac2_chain();
        let rows: Vec<serde_json::Value> = chain
            .iter()
            .map(|r| {
                serde_json::json!({
                    "period_id": r.period_id,
                    "root_hash": r.root_hash_hex(),
                    "prev_root_hash": r.prev_root_hash_hex(),
                    "period_root": r.period_root_hex(),
                    "tree_size": r.tree_size,
                    "algorithm": r.algorithm,
                    "canon": r.canon,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "_note": "MAC-2 committed roots-chain golden vectors — windows-master DRI-concurred (2026-08-28). MAC-1 vectors.json is FROZEN and unchanged.",
            "finding": "A1 (CRITICAL) — roots-chain links not cryptographically committed",
            "spec_version": MAC2_SPEC_VERSION,
            "tree_algorithm": TREE_ALGORITHM,
            "domain_separation_tag_hex": hex::encode(MAC2_ROOTSCHAIN_DOMAIN),
            "digest_preimage": "SHA256( domain || be64(period_id) || prev_root_hash || period_root )",
            "genesis_prev_root": hex::encode(GENESIS_PREV_ROOT),
            "head_root_hash": chain.last().unwrap().root_hash_hex(),
            "rows": rows,
        });
        std::fs::write(
            mac2_vectors_path(),
            format!("{}\n", serde_json::to_string_pretty(&doc).unwrap()),
        )
        .expect("write MAC-2 golden vectors");
    }

    /// Lock the MAC-2 golden vectors JSON to the code: it must exist and its stored digests must
    /// reproduce from the current construction (the frozen-golden discipline MAC-1 has, applied to MAC-2).
    #[test]
    fn mac2_chain_vectors_reproduce_from_code() {
        let raw = std::fs::read_to_string(mac2_vectors_path())
            .expect("MAC-2 golden vectors present (run emit_mac2_chain_vectors --ignored once)");
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(doc["spec_version"], MAC2_SPEC_VERSION);
        let chain = golden_mac2_chain();
        assert_eq!(
            doc["head_root_hash"].as_str().unwrap(),
            chain.last().unwrap().root_hash_hex(),
            "frozen head digest drifted from the code"
        );
        for (i, row) in chain.iter().enumerate() {
            let v = &doc["rows"][i];
            assert_eq!(
                v["root_hash"].as_str().unwrap(),
                row.root_hash_hex(),
                "row {i} root_hash"
            );
            assert_eq!(
                v["period_root"].as_str().unwrap(),
                row.period_root_hex(),
                "row {i} period_root"
            );
            assert_eq!(v["canon"], MAC2_SPEC_VERSION);
        }
    }
}
