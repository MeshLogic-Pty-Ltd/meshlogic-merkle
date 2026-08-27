//! MAC-1 P1b VERIFY side — roots-chain linkage + RFC 9162 consistency verification.
//!
//! This is the VERIFY counterpart to the capture-at-stamp PRODUCER (`roots_chain.rs`, a sibling
//! module landing separately). Both sides validate against the SAME frozen `chain_vectors`, so the
//! two can never drift (ADR-043 §5 — determinism is the whole product). Everything here is a
//! faithful port of the authoritative Phase-0 reference
//! `tests/conformance/merkle-anchor/reference_merkle.py` (RFC 6962 / RFC 9162, MAC-1 canon):
//!
//!   * [`verify_consistency`] — RFC 9162 §2.1.4.2, ported line-for-line from the reference (incl.
//!     the power-of-two `first_root` prepend). Proves a size-`n` tree is an append-only extension
//!     of a size-`m` tree (anti retroactive-deletion / log-fork).
//!   * [`consistency_proof`] — RFC 6962 §2.1.2 generator (the reference `_subproof` form), so the
//!     generate ⇄ verify round-trip can be cross-checked at every `(m, n)`.
//!   * [`verify_chain`] — the P1b-NEW roots-chain verifier: LINKAGE + CONTIGUITY over contiguous
//!     `period_id`s (it does NOT recompute roots — that is inclusion verification). Adds a
//!     canon/algorithm drift check on top of the reference `verify_chain`.
//!
//! SCOPE NOTE: this module is deliberately named `chain_verify` (distinct from the producer's
//! `roots_chain`) so the two `pub mod` lines in `lib.rs` never hard-collide before both merge.

use crate::{hash_node, merkle_tree_hash, Hash, MerkleError, MAC_SPEC_VERSION, TREE_ALGORITHM};

/// The genesis "no predecessor" sentinel: the first period's `prev_root_hash` is all-zero, giving
/// the chain a well-defined start (reference `CHAIN_GENESIS_PREV_HEX = "00" * 32`).
pub const CHAIN_GENESIS_PREV: Hash = [0u8; 32];

// ---- RFC 9162 §2.1.4.2 consistency verification -----------------------------------------------

/// Verify that the size-`n` tree (root `second_root`) is an append-only extension of the size-`m`
/// tree (root `first_root`), given a consistency `proof`. RFC 9162 §2.1.4.2.
///
/// Ported EXACTLY from `reference_merkle.py::verify_consistency` — argument order
/// `(m, n, proof, first_root, second_root)` matches the reference and the frozen
/// `verify_consistency_sig` in the vectors. Returns `true` iff the proof is valid.
pub fn verify_consistency(
    m: usize,
    n: usize,
    proof: &[Hash],
    first_root: &Hash,
    second_root: &Hash,
) -> bool {
    if m > n {
        return false;
    }
    if m == n {
        // identical trees: no proof, roots must match.
        return proof.is_empty() && *first_root == *second_root;
    }
    if m == 0 {
        // the empty tree is a prefix of every tree; no proof needed, first_root must be the
        // RFC 6962 empty-tree root (reference EMPTY_TREE_ROOT_BYTES()).
        return proof.is_empty() && *first_root == merkle_tree_hash(&[]);
    }
    if proof.is_empty() {
        return false;
    }

    // RFC 9162: if m is an exact power of two, first_root is the implicit first node and is
    // prepended to the path.
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if (m & (m - 1)) == 0 {
        path.push(*first_root);
    }
    path.extend_from_slice(proof);

    let (mut fnn, mut sn) = (m - 1, n - 1);
    while (fnn & 1) == 1 {
        fnn >>= 1;
        sn >>= 1;
    }
    let mut fr = path[0];
    let mut sr = path[0];
    for c in &path[1..] {
        if sn == 0 {
            return false;
        }
        if (fnn & 1) == 1 || fnn == sn {
            fr = hash_node(c, &fr);
            sr = hash_node(c, &sr);
            if (fnn & 1) == 0 {
                loop {
                    fnn >>= 1;
                    sn >>= 1;
                    if (fnn & 1) == 1 || fnn == 0 {
                        break;
                    }
                }
            }
        } else {
            sr = hash_node(&sr, c);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    sn == 0 && fr == *first_root && sr == *second_root
}

// ---- RFC 6962 §2.1.2 consistency-proof generation ---------------------------------------------

/// Largest power of two STRICTLY less than `n` (RFC 6962 split point). `n` must be >= 2.
/// Mirrors the private `largest_pow2_lt` in `lib.rs` (kept local to keep this module
/// self-contained and the `lib.rs` edit a single `pub mod` line).
fn largest_pow2_lt(n: usize) -> usize {
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 6962 §2.1.2 consistency proof between the first `m` leaves and all `n` leaves.
/// `leaves` are the leaf-DATA inputs (as fed to [`crate::merkle_tree_hash`]).
/// Ported from `reference_merkle.py::consistency_proof`.
pub fn consistency_proof(m: usize, leaves: &[Hash]) -> Result<Vec<Hash>, MerkleError> {
    let n = leaves.len();
    if m == 0 || m > n {
        return Err(MerkleError("consistency_proof requires 0 < m <= n".into()));
    }
    Ok(subproof(m, leaves, true))
}

fn subproof(m: usize, leaves: &[Hash], b: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if b {
            Vec::new()
        } else {
            vec![merkle_tree_hash(leaves)]
        };
    }
    let k = largest_pow2_lt(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], b);
        p.push(merkle_tree_hash(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(merkle_tree_hash(&leaves[..k]));
        p
    }
}

// ---- P1b-NEW: roots-chain linkage verification ------------------------------------------------

/// A borrowed view of one roots-log row for [`verify_chain`]. Field-for-field compatible with the
/// producer's `roots_chain::RootsChainRow { period_id: u64, root_hash, prev_root_hash, tree_size,
/// algorithm, canon }` — once that module merges, `verify_chain` can trivially consume it, e.g.
/// `rows.iter().map(|r| ChainRowView { period_id: r.period_id, root_hash: r.root_hash,
/// prev_root_hash: r.prev_root_hash, tree_size: r.tree_size, algorithm: &r.algorithm,
/// canon: &r.canon }).collect()`.
#[derive(Debug, Clone, Copy)]
pub struct ChainRowView<'a> {
    pub period_id: u64,
    pub root_hash: Hash,
    pub prev_root_hash: Hash,
    pub tree_size: usize,
    pub algorithm: &'a str,
    pub canon: &'a str,
}

/// Every way a roots-chain segment can fail verification. Each carries the offending `period_id`
/// (except the structural ones) so an auditor sees exactly where the chain broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// No rows supplied.
    Empty,
    /// `row[0].prev_root_hash` does not equal the expected predecessor (genesis constant, or a
    /// co-anchored checkpoint when walking forward from a trusted period — tail-truncation guard).
    BadGenesis,
    /// A zero-leaf period claims a `root_hash` other than the RFC 6962 empty-tree root — a
    /// tree_size=0 row cannot carry a forged root.
    ForgedEmptyRoot { period_id: u64 },
    /// `period_id` is not strictly greater than its predecessor (a duplicate or out-of-order row).
    NotSorted { period_id: u64 },
    /// `period_id` skips a value — a gap, i.e. a possible silently-deleted period.
    Gap { period_id: u64 },
    /// `prev_root_hash` does not match the previous row's `root_hash` — the hash chain is broken.
    BrokenLink { period_id: u64 },
    /// `algorithm` is not [`TREE_ALGORITHM`] — reject to prevent silent tree-rule drift.
    BadAlgorithm { period_id: u64 },
    /// `canon` is not [`MAC_SPEC_VERSION`] — reject to prevent silent canon drift.
    BadCanon { period_id: u64 },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::Empty => write!(f, "empty chain segment"),
            ChainError::BadGenesis => write!(
                f,
                "first row does not link to expected predecessor (genesis/checkpoint)"
            ),
            ChainError::ForgedEmptyRoot { period_id } => write!(
                f,
                "period {period_id} claims empty (tree_size=0) but root != RFC6962 empty-tree root"
            ),
            ChainError::NotSorted { period_id } => write!(
                f,
                "period_id {period_id} is not strictly ascending (dup/out-of-order)"
            ),
            ChainError::Gap { period_id } => write!(
                f,
                "non-contiguous period_id at {period_id} (gap -> possible deleted period)"
            ),
            ChainError::BrokenLink { period_id } => write!(
                f,
                "broken link at period {period_id} (prev_root_hash != previous root)"
            ),
            ChainError::BadAlgorithm { period_id } => {
                write!(f, "period {period_id} has algorithm != {TREE_ALGORITHM}")
            }
            ChainError::BadCanon { period_id } => {
                write!(f, "period {period_id} has canon != {MAC_SPEC_VERSION}")
            }
        }
    }
}

impl std::error::Error for ChainError {}

/// Verify a contiguous segment of the roots log is a gap-free hash chain anchored at genesis.
/// Convenience over [`verify_chain_from`] with the all-zero genesis predecessor.
pub fn verify_chain(rows: &[ChainRowView<'_>]) -> Result<(), ChainError> {
    verify_chain_from(rows, &CHAIN_GENESIS_PREV)
}

/// Verify a contiguous roots-log segment links back to `expected_first_prev` (the genesis constant
/// when the segment starts at the first period, or a known co-anchored checkpoint root when an
/// auditor walks forward from their last trusted period — the tail-truncation defense).
///
/// Checks LINKAGE + CONTIGUITY + canon only — it does NOT recompute roots (that is inclusion
/// verification). Faithful to `reference_merkle.py::verify_chain`, with two P1b refinements noted
/// inline: (1) the reference's single "non-contiguous" reason is split into [`ChainError::NotSorted`]
/// vs [`ChainError::Gap`] for diagnostic precision (identical accept/reject behaviour); (2) an
/// algorithm/canon equality check the reference rows do not carry (canon-drift defense).
pub fn verify_chain_from(
    rows: &[ChainRowView<'_>],
    expected_first_prev: &Hash,
) -> Result<(), ChainError> {
    let first = rows.first().ok_or(ChainError::Empty)?;

    // Genesis / checkpoint linkage of the first row (reference checks this first).
    if first.prev_root_hash != *expected_first_prev {
        return Err(ChainError::BadGenesis);
    }

    let empty_root = merkle_tree_hash(&[]);
    for (i, row) in rows.iter().enumerate() {
        // P1b addition (not in the reference rows): reject any algorithm/canon drift.
        if row.algorithm != TREE_ALGORITHM {
            return Err(ChainError::BadAlgorithm {
                period_id: row.period_id,
            });
        }
        if row.canon != MAC_SPEC_VERSION {
            return Err(ChainError::BadCanon {
                period_id: row.period_id,
            });
        }
        // Empty-period invariant: a zero-leaf period MUST commit the RFC 6962 empty-tree root, so
        // an idle interval still emits a chain row and cannot carry a forged root.
        if row.tree_size == 0 && row.root_hash != empty_root {
            return Err(ChainError::ForgedEmptyRoot {
                period_id: row.period_id,
            });
        }
        if i == 0 {
            continue;
        }
        let prev = &rows[i - 1];
        // Strictly ascending, contiguous period_id (reference: period_id == prev + 1).
        if row.period_id <= prev.period_id {
            return Err(ChainError::NotSorted {
                period_id: row.period_id,
            });
        }
        if row.period_id != prev.period_id + 1 {
            return Err(ChainError::Gap {
                period_id: row.period_id,
            });
        }
        // Hash-chain linkage.
        if row.prev_root_hash != prev.root_hash {
            return Err(ChainError::BrokenLink {
                period_id: row.period_id,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash_leaf, leaf_bytes_from_content_hash, verify_inclusion};
    use serde_json::Value;

    /// Decode 64 lowercase-hex chars to a 32-byte hash (reuses the crate's validated decoder).
    fn h(s: &str) -> Hash {
        leaf_bytes_from_content_hash(s).expect("valid 32-byte lowercase hex")
    }

    fn corpus() -> Value {
        // Vendored in the standalone repo (self-contained CI); falls back to the monorepo location
        // when this crate is built nested in meshlogic-platform/crates/meshlogic-merkle. The corpus is
        // FROZEN (the exact S3 conformance vectors), so the vendored copy does not drift by design.
        let vendored = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/conformance/merkle-anchor/vectors.json"
        );
        let nested = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/conformance/merkle-anchor/vectors.json"
        );
        let raw = std::fs::read_to_string(vendored)
            .or_else(|_| std::fs::read_to_string(nested))
            .expect("read merkle corpus (vendored or monorepo)");
        serde_json::from_str(&raw).expect("parse merkle corpus")
    }

    fn row<'a>(
        period_id: u64,
        root_hash: Hash,
        prev_root_hash: Hash,
        tree_size: usize,
    ) -> ChainRowView<'a> {
        ChainRowView {
            period_id,
            root_hash,
            prev_root_hash,
            tree_size,
            algorithm: TREE_ALGORITHM,
            canon: MAC_SPEC_VERSION,
        }
    }

    // ---- STEP 3: the FROZEN C1-P1b vectors (exact hex from s3://.../c1-p1b-chain-vectors.json) --
    //
    // The S3 vectors label periods as ISO dates ("2026-07-05".."2026-07-07"); since the producer's
    // RootsChainRow.period_id is u64, the three CONTIGUOUS days map to contiguous u64 ordinals
    // 0,1,2. The security-load-bearing fields (root_hash / prev_root_hash / algorithm / canon) use
    // the EXACT S3 hex below — that is the frozen corpus.

    const P1_ROOT: &str = "35b5f2709beff9c7b55f267051ed89309cd899d79ad4ac205ff77ce8eeb65859";
    const P2_ROOT: &str = "5fb58d89ca9e40abece0d6b1447d5783094112244c17e9b5b7aa5c89c84f8012";
    const P3_EMPTY_ROOT: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn frozen_s3_verify_chain_ok() {
        let (p1, p2, p3) = (h(P1_ROOT), h(P2_ROOT), h(P3_EMPTY_ROOT));
        let rows = [
            row(0, p1, CHAIN_GENESIS_PREV, 2),
            row(1, p2, p1, 3),
            row(2, p3, p2, 0), // empty period commits the RFC6962 empty-tree root
        ];
        assert_eq!(
            verify_chain(&rows),
            Ok(()),
            "frozen S3 roots-chain must verify"
        );
    }

    #[test]
    fn frozen_s3_verify_chain_tamper_each_field() {
        let (p1, p2, p3) = (h(P1_ROOT), h(P2_ROOT), h(P3_EMPTY_ROOT));
        let base = [
            row(0, p1, CHAIN_GENESIS_PREV, 2),
            row(1, p2, p1, 3),
            row(2, p3, p2, 0),
        ];
        // genesis
        let mut t = base;
        t[0].prev_root_hash = [0xAA; 32];
        assert_eq!(verify_chain(&t), Err(ChainError::BadGenesis));
        // broken link
        let mut t = base;
        t[1].prev_root_hash = [0xBB; 32];
        assert_eq!(
            verify_chain(&t),
            Err(ChainError::BrokenLink { period_id: 1 })
        );
        // gap
        let mut t = base;
        t[2].period_id = 3;
        assert_eq!(verify_chain(&t), Err(ChainError::Gap { period_id: 3 }));
        // not sorted (duplicate)
        let mut t = base;
        t[2].period_id = 1;
        assert_eq!(
            verify_chain(&t),
            Err(ChainError::NotSorted { period_id: 1 })
        );
        // forged empty-period root (tree_size 0 but non-empty root)
        let mut t = base;
        t[2].root_hash = p1;
        assert_eq!(
            verify_chain(&t),
            Err(ChainError::ForgedEmptyRoot { period_id: 2 })
        );
        // bad algorithm
        let mut t = base;
        t[1].algorithm = "RFC6962-SHA512";
        assert_eq!(
            verify_chain(&t),
            Err(ChainError::BadAlgorithm { period_id: 1 })
        );
        // bad canon
        let mut t = base;
        t[2].canon = "MAC-2";
        assert_eq!(verify_chain(&t), Err(ChainError::BadCanon { period_id: 2 }));
    }

    #[test]
    fn frozen_s3_inclusion_kat() {
        // exact hex from inclusion_kat: leaf 1 of a size-3 tree.
        let content_hash = "88496c1549d5dc5f6a0d91963892d3b681fc18540ebb3bd79c769a7a5993271a";
        let expected_leaf_hash = "cffbef5ae6d91230b05c3d7804c6ac9269477ce3a312db253e38664847c73eaf";
        let leaf = hash_leaf(&h(content_hash));
        assert_eq!(
            hex::encode(leaf),
            expected_leaf_hash,
            "leaf hash must match frozen KAT"
        );
        let proof = [
            h("1eef9df07f41a67a133a2a383f42e0d494bb5a22b8d1ca8a2b1d8fb6f42218b3"),
            h("f0f1a01391c7d35f6b2d016450b77f36db19f2652e957cfeddac550775de99b7"),
        ];
        let expected_root = h(P2_ROOT); // 5fb58d... == period-2 root
        assert!(
            verify_inclusion(1, 3, leaf, &proof, expected_root),
            "frozen inclusion KAT must verify to the expected root"
        );
        // a mutated leaf must be rejected
        let mut bad = leaf;
        bad[0] ^= 0x01;
        assert!(!verify_inclusion(1, 3, bad, &proof, expected_root));
    }

    #[test]
    fn frozen_s3_consistency_kat() {
        // exact hex from consistency_kat: m=3, n=4.
        let first_root = h("331b7f6eebd33fe86ec54037bcc1711beaf31d0b8beed46c6d7be6f446570dbb");
        let second_root = h("5db60ec2d01a404ab1b66118cbea5bf8eae891c4cffc8c3b9bab770d993e5c24");
        let proof = [
            h("01131b6468f4babb9ba0669cd7e5b8d1eb22fd59552e1699207c786e91b7e792"),
            h("e1e2e6647ce963d120a2a919fe2f04b7be0bdf3821032c0d9638cab1e3922951"),
            h("4d6887396504d931c5eb1a4054bb83dca700f8428ee94dc94c8095cd69c8d83e"),
        ];
        assert!(
            verify_consistency(3, 4, &proof, &first_root, &second_root),
            "frozen consistency KAT (m=3,n=4) must verify"
        );
        // a forged second root must NOT verify
        let mut forged = second_root;
        forged[0] ^= 0x01;
        assert!(!verify_consistency(3, 4, &proof, &first_root, &forged));
    }

    // ---- Wire in the EXISTING frozen corpus (previously never exercised by any Rust test) -------

    #[test]
    fn corpus_chain_vectors_valid_and_errors() {
        let c = corpus();
        let cv = &c["chain_vectors"];

        // valid case
        let valid = &cv["valid"];
        let first_prev = h(valid["expected_first_prev"].as_str().unwrap());
        let rows = parse_chain_rows(valid);
        let views: Vec<ChainRowView> = rows
            .iter()
            .map(|(pid, root, prev, sz)| row(*pid, *root, *prev, *sz))
            .collect();
        assert_eq!(
            verify_chain_from(&views, &first_prev),
            Ok(()),
            "corpus valid chain must verify"
        );

        // error cases -> each must map to the specific expected variant
        for e in cv["errors"].as_array().unwrap() {
            let name = e["name"].as_str().unwrap();
            let fp = h(e["expected_first_prev"].as_str().unwrap());
            let rows = parse_chain_rows(e);
            let views: Vec<ChainRowView> = rows
                .iter()
                .map(|(pid, root, prev, sz)| row(*pid, *root, *prev, *sz))
                .collect();
            let got = verify_chain_from(&views, &fp);
            let ok = match name {
                "chain_broken_link" => matches!(got, Err(ChainError::BrokenLink { .. })),
                "chain_gap_deleted_period" => matches!(got, Err(ChainError::Gap { .. })),
                "chain_genesis_mismatch" => matches!(got, Err(ChainError::BadGenesis)),
                "chain_forged_empty_root" => {
                    matches!(got, Err(ChainError::ForgedEmptyRoot { .. }))
                }
                other => panic!("unhandled corpus chain error vector: {other}"),
            };
            assert!(ok, "corpus chain error vector {name} produced {got:?}");
        }
    }

    #[allow(clippy::type_complexity)]
    fn parse_chain_rows(v: &Value) -> Vec<(u64, Hash, Hash, usize)> {
        v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["period_id"].as_u64().unwrap(),
                    h(r["root_hash"].as_str().unwrap()),
                    h(r["prev_root_hash"].as_str().unwrap()),
                    r["tree_size"].as_u64().unwrap() as usize,
                )
            })
            .collect()
    }

    #[test]
    fn corpus_consistency_vectors_verify_and_reject_forgery() {
        let c = corpus();
        for cv in c["consistency_vectors"].as_array().unwrap() {
            let name = cv["name"].as_str().unwrap();
            let m = cv["first_size"].as_u64().unwrap() as usize;
            let n = cv["second_size"].as_u64().unwrap() as usize;
            let first_root = h(cv["first_root"].as_str().unwrap());
            let second_root = h(cv["second_root"].as_str().unwrap());
            let proof: Vec<Hash> = cv["consistency_proof"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| h(x.as_str().unwrap()))
                .collect();
            assert!(
                verify_consistency(m, n, &proof, &first_root, &second_root),
                "frozen consistency vector {name} must verify"
            );
            if m != n {
                let mut forged = second_root;
                forged[0] ^= 0x01;
                assert!(
                    !verify_consistency(m, n, &proof, &first_root, &forged),
                    "forged second root MUST reject {name}"
                );
            }
        }
    }

    // ---- generate <-> verify cross-check across every (m, n) shape (mirrors reference selftest) -

    #[test]
    fn consistency_gen_verify_property_1_to_32() {
        fn leaf(i: usize) -> Hash {
            // deterministic synthetic leaf-DATA
            let mut d = [0u8; 32];
            let b = (i as u64).to_be_bytes();
            d[..8].copy_from_slice(&b);
            d
        }
        for n in 1..=32usize {
            let leaves: Vec<Hash> = (0..n).map(leaf).collect();
            let root_n = merkle_tree_hash(&leaves);
            for m in 1..=n {
                let root_m = merkle_tree_hash(&leaves[..m]);
                let proof = consistency_proof(m, &leaves).unwrap();
                assert!(
                    verify_consistency(m, n, &proof, &root_m, &root_n),
                    "gen+verify consistency must hold (m={m} n={n})"
                );
                if m != n {
                    let mut forged = root_n;
                    forged[0] ^= 0x01;
                    assert!(
                        !verify_consistency(m, n, &proof, &root_m, &forged),
                        "forged second root MUST reject (m={m} n={n})"
                    );
                }
            }
        }
        // consistency_proof rejects out-of-range m.
        let leaves: Vec<Hash> = (0..4).map(leaf).collect();
        assert!(consistency_proof(0, &leaves).is_err());
        assert!(consistency_proof(5, &leaves).is_err());
    }

    #[test]
    fn verify_consistency_edge_cases() {
        let empty = merkle_tree_hash(&[]);
        // m == n: identical roots, empty proof.
        let r = merkle_tree_hash(&[[7u8; 32]]);
        assert!(verify_consistency(1, 1, &[], &r, &r));
        assert!(!verify_consistency(1, 1, &[], &r, &empty)); // different roots
                                                             // m == 0: first_root must be the empty-tree root, empty proof.
        assert!(verify_consistency(0, 5, &[], &empty, &r));
        assert!(!verify_consistency(0, 5, &[], &r, &r)); // non-empty first_root
                                                         // m > n never verifies.
        assert!(!verify_consistency(3, 2, &[], &r, &r));
        // empty chain segment rejected.
        assert_eq!(verify_chain(&[]), Err(ChainError::Empty));
    }
}
