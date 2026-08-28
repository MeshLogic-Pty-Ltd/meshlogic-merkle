//! MAC-2 COMMITTED roots-chain — A1 (CRITICAL) remediation.
//!
//! ## The defect this closes (audit finding A1, verdict CONFIRMED-CRITICAL)
//! The MAC-1 roots chain ([`crate::roots_chain`] / [`crate::chain_verify`]) links periods with a
//! bare `prev_root_hash` that is NEVER hashed into `root_hash` nor into any per-row committed digest.
//! `verify_chain` only *compares* stored fields (`row.prev_root_hash == prev.root_hash` +
//! contiguity); it "does NOT recompute roots". So a store attacker (the exact tamper-evidence threat
//! model) can rewrite a past period's leaves, fix up the free-standing `prev_root_hash` pointers, and
//! re-present a fully self-consistent chain that `verify_chain` accepts — the linkage is
//! cryptographically inert. Worse, `coanchor` claims "witnessing head@P transitively witnesses every
//! period <= P", which is FALSE: `root_P` has zero cryptographic dependence on `root_{P-1}`, so a
//! Rekor/RFC-3161 witness of the bare head says nothing about any earlier period. Neither `org_id`
//! nor `period_id` is committed anywhere, so a valid proof from one org/period is interchangeable
//! with another (cross-context confusion).
//!
//! ## The construction (MAC-2)
//! Each period carries a COMMITTED chain digest that folds every security-load-bearing field of the
//! period AND the previous digest:
//!
//! ```text
//! C_P = SHA-256( ROOTSCHAIN_V2_DOMAIN
//!              || len_be64(org_id) || org_id
//!              || be64(period_id)
//!              || be64(tree_size)
//!              || root_hash          (32 bytes)
//!              || C_{P-1}            (32 bytes, genesis = 0^32) )
//! ```
//!
//! `C_P` (NOT the bare `root_hash`) is the value production co-anchors to RFC 3161 / Rekor. Because
//! `C_P` commits to `org_id`, `period_id`, `tree_size`, `root_hash` and `C_{P-1}` transitively, an
//! external witness of `C_P` cryptographically binds EVERY field of EVERY period <= P — "transitive
//! witness" becomes true by construction. [`verify_committed_chain_from`] RECOMPUTES `C_i` for each
//! row (it does not trust the stored digest) and returns the head `C_P`, which the caller compares
//! against the externally-anchored value. A splice/renumber that an attacker fully re-derives still
//! yields a DIFFERENT head, so it no longer matches the pinned anchor; a partial tamper (a field
//! changed without re-deriving the digest) is caught per-row by the recompute gate.
//!
//! ## ⚠ NEEDS windows-master DESIGN CONCURRENCE (signed-contract / frozen-vector change)
//! MAC-2 is a NEW canonical construction. It changes what is committed and what is co-anchored, and
//! it REQUIRES a regenerated frozen golden-vector / KAT set (see `mac2_vectors.PROPOSED.json`). Per
//! the remediation charter (HARD RULE 5) the MAC-1 frozen `vectors.json` is LEFT UNTOUCHED here
//! (back-compat verification only); MAC-2 ships alongside it, gated on `canon == "MAC-2"`, and the
//! cutover of the production producer + the finalisation of the regenerated vectors MUST NOT merge
//! until windows-master signs off on the construction (field order, encodings, domain tag) and the
//! regenerated vectors. This module is the PROPOSAL + its locking tests, not a silent canon swap.

use crate::proof_gen::InclusionProof;
use crate::{
    hash_leaf, leaf_bytes_from_content_hash, merkle_tree_hash, Hash, MerkleError, TREE_ALGORITHM,
};
use sha2::{Digest, Sha256};

/// MAC-2 profile identifier, recorded on every committed row and checked by the verifier. Distinct
/// from MAC-1 so a MAC-1 row can never be fed to the MAC-2 verifier (or vice-versa) undetected.
pub const MAC2_SPEC_VERSION: &str = "MAC-2";

/// Domain-separation tag for the committed chain digest — binds `C_P` to THIS construction so it can
/// never collide with a leaf/node hash or be replayed as some other MeshLogic digest. FROZEN once the
/// producer cuts over (NEEDS windows-master concurrence).
pub const ROOTSCHAIN_V2_DOMAIN: &[u8] = b"meshlogic.mac.rootschain.v2\x00";

/// Genesis predecessor digest `C_{-1}` for the first period (all-zero, RFC-style anchor).
pub const COMMITTED_CHAIN_GENESIS_DIGEST: Hash = [0u8; 32];

/// Compute the MAC-2 committed chain digest `C_P` for one period.
///
/// `org_id` is length-prefixed (8-byte big-endian length + raw UTF-8 bytes) so a variable-length org
/// identifier can never shift the field boundary (a concat-ambiguity a bare join would allow). Every
/// other field is fixed-width big-endian. This is the single source of truth both the producer
/// ([`build_committed_chain`]) and the verifier ([`verify_committed_chain_from`]) call — they can
/// never drift on the preimage.
pub fn compute_chain_digest(
    org_id: &str,
    period_id: u64,
    tree_size: u64,
    root_hash: &Hash,
    prev_digest: &Hash,
) -> Hash {
    let mut h = Sha256::new();
    h.update(ROOTSCHAIN_V2_DOMAIN);
    h.update((org_id.len() as u64).to_be_bytes());
    h.update(org_id.as_bytes());
    h.update(period_id.to_be_bytes());
    h.update(tree_size.to_be_bytes());
    h.update(root_hash);
    h.update(prev_digest);
    h.finalize().into()
}

/// One row of the MAC-2 committed roots-chain log.
///
/// Carries the same period fields as [`crate::roots_chain::RootsChainRow`] PLUS the committed
/// `chain_digest` (`C_P`), its predecessor `prev_chain_digest` (`C_{P-1}`), and the `org_id` the
/// digest binds. `chain_digest` — not `root_hash` — is the value co-anchored externally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedChainRow {
    /// Monotonic period identifier. Chain order is by ascending `period_id`.
    pub period_id: u64,
    /// The organisation this period's chain belongs to — folded into `chain_digest` so a proof can
    /// never be replayed across orgs.
    pub org_id: String,
    /// This period's MAC-1/RFC-6962 Merkle root over its raw-byte-sorted `content_hash` leaves.
    pub root_hash: Hash,
    /// The previous period's `root_hash` (genesis `0^32` for the first row) — retained for diagnostic
    /// linkage; the CRYPTOGRAPHIC link is `chain_digest`.
    pub prev_root_hash: Hash,
    /// The committed chain digest `C_P` — the externally co-anchored value that transitively witnesses
    /// every field of every period <= P.
    pub chain_digest: Hash,
    /// The previous period's committed digest `C_{P-1}` (genesis [`COMMITTED_CHAIN_GENESIS_DIGEST`]).
    pub prev_chain_digest: Hash,
    /// Number of `content_hash` leaves committed in this period.
    pub tree_size: usize,
    /// Tree-hash algorithm identifier (`"RFC6962-SHA256"`).
    pub algorithm: &'static str,
    /// Committed-chain profile version (`"MAC-2"`).
    pub canon: &'static str,
}

impl CommittedChainRow {
    /// Lowercase-hex of the committed digest `C_P` (64 chars) — the co-anchored / stored form.
    pub fn chain_digest_hex(&self) -> String {
        hex::encode(self.chain_digest)
    }
}

/// Build the MAC-2 committed roots-chain over a set of periods for ONE org.
///
/// Periods are sorted by `period_id` ascending. Each row's `root_hash` comes from the frozen MAC-1
/// [`crate::roots_chain::period_root_with_leaves`] (the tree construction is UNCHANGED — MAC-2 only
/// adds the committed digest on top), and each `chain_digest` folds `org_id`, `period_id`,
/// `tree_size`, `root_hash` and the previous digest. `row[0].prev_chain_digest` is the genesis
/// digest; each subsequent `prev_chain_digest` is `row[n-1].chain_digest`.
pub fn build_committed_chain(
    org_id: &str,
    periods: &[(u64, Vec<String>)],
) -> Result<Vec<CommittedChainRow>, MerkleError> {
    let mut sorted: Vec<&(u64, Vec<String>)> = periods.iter().collect();
    sorted.sort_by_key(|(period_id, _)| *period_id);

    let mut rows: Vec<CommittedChainRow> = Vec::with_capacity(sorted.len());
    let mut prev_root_hash = [0u8; 32];
    let mut prev_chain_digest = COMMITTED_CHAIN_GENESIS_DIGEST;
    for (period_id, content_hashes) in sorted {
        let (root_hash, tree_size, _leaves) =
            crate::roots_chain::period_root_with_leaves(content_hashes)?;
        let chain_digest = compute_chain_digest(
            org_id,
            *period_id,
            tree_size as u64,
            &root_hash,
            &prev_chain_digest,
        );
        rows.push(CommittedChainRow {
            period_id: *period_id,
            org_id: org_id.to_string(),
            root_hash,
            prev_root_hash,
            chain_digest,
            prev_chain_digest,
            tree_size,
            algorithm: TREE_ALGORITHM,
            canon: MAC2_SPEC_VERSION,
        });
        prev_root_hash = root_hash;
        prev_chain_digest = chain_digest;
    }
    Ok(rows)
}

/// Every way MAC-2 committed-chain verification can fail. Each carries the offending `period_id`
/// (except the structural ones) so an auditor sees exactly where — and how — the chain broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommittedChainError {
    /// No rows supplied.
    Empty,
    /// `row[0].prev_chain_digest` does not equal the expected predecessor digest (genesis, or a
    /// trusted co-anchored checkpoint digest when walking forward).
    BadGenesisDigest,
    /// A row's `org_id` does not equal the caller's expected org — a cross-org splice.
    OrgMismatch { period_id: u64 },
    /// A zero-leaf period claims a `root_hash` other than the RFC 6962 empty-tree root.
    ForgedEmptyRoot { period_id: u64 },
    /// `period_id` is not strictly greater than its predecessor (a duplicate or out-of-order row).
    NotSorted { period_id: u64 },
    /// `period_id` skips a value — a gap, i.e. a possible silently-deleted period.
    Gap { period_id: u64 },
    /// `prev_root_hash` does not match the previous row's `root_hash` (diagnostic linkage).
    BrokenLink { period_id: u64 },
    /// `prev_chain_digest` does not match the previous row's `chain_digest` — the COMMITTED link is
    /// broken.
    BadPrevDigest { period_id: u64 },
    /// The recomputed `C_i` does not reproduce the row's stored `chain_digest` — a field was altered
    /// without (or the anchored digest itself was tampered). THE committed-digest gate.
    DigestMismatch { period_id: u64 },
    /// `algorithm` is not [`TREE_ALGORITHM`].
    BadAlgorithm { period_id: u64 },
    /// `canon` is not [`MAC2_SPEC_VERSION`] — a MAC-1 (or other) row fed to the MAC-2 verifier.
    BadCanon { period_id: u64 },
}

impl std::fmt::Display for CommittedChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CommittedChainError::*;
        match self {
            Empty => write!(f, "empty committed-chain segment"),
            BadGenesisDigest => {
                write!(f, "first row does not link to the expected predecessor digest")
            }
            OrgMismatch { period_id } => {
                write!(f, "period {period_id}: org_id != expected org (cross-org splice)")
            }
            ForgedEmptyRoot { period_id } => write!(
                f,
                "period {period_id} claims empty (tree_size=0) but root != RFC6962 empty-tree root"
            ),
            NotSorted { period_id } => {
                write!(f, "period_id {period_id} is not strictly ascending (dup/out-of-order)")
            }
            Gap { period_id } => {
                write!(f, "non-contiguous period_id at {period_id} (gap -> possible deleted period)")
            }
            BrokenLink { period_id } => {
                write!(f, "broken diagnostic link at period {period_id} (prev_root_hash mismatch)")
            }
            BadPrevDigest { period_id } => write!(
                f,
                "broken COMMITTED link at period {period_id} (prev_chain_digest != previous C)"
            ),
            DigestMismatch { period_id } => write!(
                f,
                "period {period_id}: recomputed C != stored chain_digest (field altered / digest forged)"
            ),
            BadAlgorithm { period_id } => {
                write!(f, "period {period_id} has algorithm != {TREE_ALGORITHM}")
            }
            BadCanon { period_id } => {
                write!(f, "period {period_id} has canon != {MAC2_SPEC_VERSION}")
            }
        }
    }
}

impl std::error::Error for CommittedChainError {}

/// Verify a contiguous MAC-2 committed-chain segment anchored at the genesis digest, returning the
/// head digest `C_P`. Convenience over [`verify_committed_chain_from`].
pub fn verify_committed_chain(
    rows: &[CommittedChainRow],
    expected_org: &str,
) -> Result<Hash, CommittedChainError> {
    verify_committed_chain_from(rows, expected_org, &COMMITTED_CHAIN_GENESIS_DIGEST)
}

/// Verify a contiguous MAC-2 committed-chain segment links back to `expected_first_digest` (the
/// genesis digest when the segment starts at the first period, or a KNOWN co-anchored checkpoint
/// digest `C_k` when an auditor walks forward from their last trusted period).
///
/// Unlike the MAC-1 verifier, this RECOMPUTES `C_i` from the row's own fields for every row and
/// requires it to reproduce the stored `chain_digest`; it also binds every row to `expected_org`.
/// Returns the verified HEAD digest `C_P` on success — the value the caller MUST compare against the
/// externally-anchored digest (an in-band chain that verifies internally still proves nothing until
/// its head is pinned to an out-of-band witness; that comparison is the caller's, exactly as A1's
/// remediation requires).
pub fn verify_committed_chain_from(
    rows: &[CommittedChainRow],
    expected_org: &str,
    expected_first_digest: &Hash,
) -> Result<Hash, CommittedChainError> {
    use CommittedChainError as E;
    let first = rows.first().ok_or(E::Empty)?;
    if first.prev_chain_digest != *expected_first_digest {
        return Err(E::BadGenesisDigest);
    }

    let empty_root = merkle_tree_hash(&[]);
    let mut head = *expected_first_digest;
    for (i, row) in rows.iter().enumerate() {
        if row.algorithm != TREE_ALGORITHM {
            return Err(E::BadAlgorithm {
                period_id: row.period_id,
            });
        }
        if row.canon != MAC2_SPEC_VERSION {
            return Err(E::BadCanon {
                period_id: row.period_id,
            });
        }
        if row.org_id != expected_org {
            return Err(E::OrgMismatch {
                period_id: row.period_id,
            });
        }
        if row.tree_size == 0 && row.root_hash != empty_root {
            return Err(E::ForgedEmptyRoot {
                period_id: row.period_id,
            });
        }
        if i > 0 {
            let prev = &rows[i - 1];
            if row.period_id <= prev.period_id {
                return Err(E::NotSorted {
                    period_id: row.period_id,
                });
            }
            if row.period_id != prev.period_id + 1 {
                return Err(E::Gap {
                    period_id: row.period_id,
                });
            }
            if row.prev_root_hash != prev.root_hash {
                return Err(E::BrokenLink {
                    period_id: row.period_id,
                });
            }
            if row.prev_chain_digest != prev.chain_digest {
                return Err(E::BadPrevDigest {
                    period_id: row.period_id,
                });
            }
        }
        // THE committed-digest gate: recompute C_i from this row's own fields + prev digest and
        // require it to reproduce the stored digest. A splice/renumber that alters any field without
        // faithfully re-deriving C — or that tampers C itself — fails HERE.
        let recomputed = compute_chain_digest(
            &row.org_id,
            row.period_id,
            row.tree_size as u64,
            &row.root_hash,
            &row.prev_chain_digest,
        );
        if recomputed != row.chain_digest {
            return Err(E::DigestMismatch {
                period_id: row.period_id,
            });
        }
        head = row.chain_digest;
    }
    Ok(head)
}

/// Every way binding a leaf's inclusion to a committed (MAC-2) chain can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommittedProofError {
    /// The committed roots-chain segment failed verification (carries the precise error).
    Chain(CommittedChainError),
    /// The verified head digest did not equal the externally-pinned head (the segment is internally
    /// self-consistent but is NOT the witnessed history).
    HeadNotPinned,
    /// The expected period is not present in the committed-chain segment.
    PeriodNotInChain { period_id: u64 },
    /// The inclusion `period_root` / `tree_size` does not match the committed row for the period.
    RootMismatch { period_id: u64 },
    /// A content_hash / hex value was malformed.
    Merkle(MerkleError),
    /// `verify_inclusion` rejected the audit path against the committed row's root.
    Inclusion,
}

impl std::fmt::Display for CommittedProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CommittedProofError::*;
        match self {
            Chain(e) => write!(f, "committed roots-chain verification failed: {e}"),
            HeadNotPinned => write!(
                f,
                "committed-chain head digest != the externally-pinned head (not the witnessed history)"
            ),
            PeriodNotInChain { period_id } => {
                write!(f, "period {period_id} not present in the committed-chain segment")
            }
            RootMismatch { period_id } => {
                write!(f, "inclusion root/tree_size != committed row at period {period_id}")
            }
            Merkle(e) => write!(f, "{e}"),
            Inclusion => write!(f, "inclusion proof does not reproduce the committed period root"),
        }
    }
}

impl std::error::Error for CommittedProofError {}

/// Verify a leaf's inclusion BOUND to a specific org + period under a committed (MAC-2) chain whose
/// head is externally pinned — the A1 "bind proof verification to org/period" fix.
///
/// Ties together, in order:
///   1. the committed chain verifies for `expected_org` and reproduces `pinned_head_digest` (a
///      forged-but-internally-consistent chain fails at the head-pin, a cross-org chain fails at
///      `OrgMismatch`);
///   2. the row for `expected_period_id` is present and its `root_hash`/`tree_size` match the
///      inclusion proof (binds the leaf to THIS period, not a substituted one);
///   3. the RFC 6962 inclusion path reproduces that committed period root.
///
/// A proof re-derived for org A / period 1 therefore FAILS when verified with `expected_org = "B"`
/// (chain `OrgMismatch`) or against a different `pinned_head_digest` (`HeadNotPinned`) — closing the
/// cross-context confusion A1's second half names.
pub fn verify_committed_inclusion(
    content_hash_hex: &str,
    expected_org: &str,
    expected_period_id: u64,
    inclusion: &InclusionProof,
    committed_chain: &[CommittedChainRow],
    pinned_head_digest: &Hash,
) -> Result<(), CommittedProofError> {
    let head = verify_committed_chain(committed_chain, expected_org)
        .map_err(CommittedProofError::Chain)?;
    if head != *pinned_head_digest {
        return Err(CommittedProofError::HeadNotPinned);
    }
    let row = committed_chain
        .iter()
        .find(|r| r.period_id == expected_period_id)
        .ok_or(CommittedProofError::PeriodNotInChain {
            period_id: expected_period_id,
        })?;
    if row.root_hash != inclusion.period_root || row.tree_size != inclusion.tree_size {
        return Err(CommittedProofError::RootMismatch {
            period_id: expected_period_id,
        });
    }
    let leaf_hash = hash_leaf(
        &leaf_bytes_from_content_hash(content_hash_hex).map_err(CommittedProofError::Merkle)?,
    );
    if !crate::verify_inclusion(
        inclusion.leaf_index,
        inclusion.tree_size,
        leaf_hash,
        &inclusion.audit_path,
        inclusion.period_root,
    ) {
        return Err(CommittedProofError::Inclusion);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_verify::{verify_chain, ChainRowView, CHAIN_GENESIS_PREV};
    use crate::proof_gen::build_inclusion_proof;
    use crate::roots_chain::RootsChainRow;
    use crate::MAC_SPEC_VERSION;
    use sha2::{Digest, Sha256};

    const ORG_A: &str = "org-acme";
    const ORG_B: &str = "org-evil";

    fn content_hash(label: &str) -> String {
        hex::encode(Sha256::digest(label.as_bytes()))
    }

    fn three_period_chain(org: &str) -> Vec<CommittedChainRow> {
        let p0 = vec![content_hash("a0"), content_hash("a1")];
        let p1 = vec![content_hash("b0"), content_hash("b1"), content_hash("b2")];
        let p2 = vec![content_hash("c0")];
        build_committed_chain(org, &[(0, p0), (1, p1), (2, p2)]).unwrap()
    }

    #[test]
    fn clean_committed_chain_verifies_and_returns_head() {
        let chain = three_period_chain(ORG_A);
        let head = verify_committed_chain(&chain, ORG_A).expect("clean chain verifies");
        assert_eq!(
            head,
            chain.last().unwrap().chain_digest,
            "returned head == C_P"
        );
        // genesis fold is real: C_0 folds the genesis digest, C_1 folds C_0, ...
        assert_eq!(chain[0].prev_chain_digest, COMMITTED_CHAIN_GENESIS_DIGEST);
        assert_eq!(chain[1].prev_chain_digest, chain[0].chain_digest);
        assert_eq!(chain[2].prev_chain_digest, chain[1].chain_digest);
    }

    #[test]
    fn digest_commits_to_org_period_size_and_root() {
        // Any single-field change produces a different digest — the commitment is real.
        let base = compute_chain_digest(ORG_A, 1, 3, &[7u8; 32], &[9u8; 32]);
        assert_ne!(
            base,
            compute_chain_digest(ORG_B, 1, 3, &[7u8; 32], &[9u8; 32]),
            "org"
        );
        assert_ne!(
            base,
            compute_chain_digest(ORG_A, 2, 3, &[7u8; 32], &[9u8; 32]),
            "period"
        );
        assert_ne!(
            base,
            compute_chain_digest(ORG_A, 1, 4, &[7u8; 32], &[9u8; 32]),
            "size"
        );
        assert_ne!(
            base,
            compute_chain_digest(ORG_A, 1, 3, &[8u8; 32], &[9u8; 32]),
            "root"
        );
        assert_ne!(
            base,
            compute_chain_digest(ORG_A, 1, 3, &[7u8; 32], &[1u8; 32]),
            "prev"
        );
    }

    /// THE headline A1 locking test — a splice/renumber the OLD MAC-1 verifier ACCEPTS but MAC-2 (with
    /// its head externally pinned) REJECTS. Delete genuine period 1, renumber old period 2 -> 1, and
    /// fully re-derive every field INCLUDING the committed digests (the strongest attacker). The
    /// forged chain is internally self-consistent, so MAC-1's `verify_chain` accepts it and MAC-2's
    /// internal verify also returns Ok — but the re-derived HEAD digest no longer equals the genuinely
    /// anchored head, so the head-pin comparison (which the co-anchor provides) rejects it.
    #[test]
    fn splice_renumber_accepted_by_mac1_but_rejected_by_pinned_mac2_head() {
        let genuine = three_period_chain(ORG_A);
        let genuine_head = *genuine.last().map(|r| &r.chain_digest).unwrap(); // C_2 — what we anchor

        // --- Attacker deletes period 1 and renumbers old period 2 -> new period 1 ---
        let p0 = vec![content_hash("a0"), content_hash("a1")];
        let p2_leaves = vec![content_hash("c0")]; // old period 2's leaves, now presented as period 1
        let forged = build_committed_chain(ORG_A, &[(0, p0), (1, p2_leaves)]).unwrap();

        // MAC-1 view of the SAME forged rows: build the MAC-1 ChainRowView and confirm verify_chain
        // ACCEPTS (linkage + contiguity satisfied — MAC-1 is cryptographically inert).
        let mac1_views: Vec<ChainRowView> = forged
            .iter()
            .map(|r| ChainRowView {
                period_id: r.period_id,
                root_hash: r.root_hash,
                prev_root_hash: r.prev_root_hash,
                tree_size: r.tree_size,
                algorithm: TREE_ALGORITHM,
                canon: MAC_SPEC_VERSION, // MAC-1 canon — what the legacy verifier expects
            })
            .collect();
        assert_eq!(
            verify_chain(&mac1_views),
            Ok(()),
            "MAC-1 verify_chain ACCEPTS the spliced/renumbered chain (the A1 defect)"
        );

        // MAC-2 internal verify passes (attacker re-derived the digests) …
        let forged_head =
            verify_committed_chain(&forged, ORG_A).expect("forged chain is internally consistent");
        // … but the pinned-head comparison (the co-anchor) REJECTS: the head changed.
        assert_ne!(
            forged_head, genuine_head,
            "MAC-2 co-anchored head DETECTS the splice: a witness of C_2 no longer matches"
        );
    }

    /// Transitive witness: co-anchoring ONLY the head C_P detects a single-bit change to ANY period
    /// <= P (a full re-derivation shifts the head; a partial tamper trips the per-row recompute gate).
    #[test]
    fn head_witness_detects_single_bit_change_to_any_earlier_period() {
        let genuine = three_period_chain(ORG_A);
        let anchored_head = verify_committed_chain(&genuine, ORG_A).unwrap();

        // Full-re-derivation attacker: flip one leaf in period 0 and rebuild the whole chain honestly.
        let mut p0 = vec![content_hash("a0"), content_hash("a1")];
        p0[0] = content_hash("a0-TAMPERED");
        let p1 = vec![content_hash("b0"), content_hash("b1"), content_hash("b2")];
        let p2 = vec![content_hash("c0")];
        let tampered = build_committed_chain(ORG_A, &[(0, p0), (1, p1), (2, p2)]).unwrap();
        let tampered_head = verify_committed_chain(&tampered, ORG_A).unwrap();
        assert_ne!(
            tampered_head, anchored_head,
            "a single-bit change to period 0 changes the witnessed head C_2"
        );

        // Partial-tamper attacker: change period 0's root_hash but leave its committed digest → the
        // per-row recompute gate fires directly.
        let mut partial = genuine.clone();
        partial[0].root_hash[0] ^= 0x01;
        assert_eq!(
            verify_committed_chain(&partial, ORG_A),
            Err(CommittedChainError::DigestMismatch { period_id: 0 }),
            "a tampered field with a stale digest is caught by the recompute gate"
        );
    }

    #[test]
    fn tampered_committed_digest_alone_is_rejected() {
        let mut chain = three_period_chain(ORG_A);
        chain[1].chain_digest[0] ^= 0x01; // forge the anchored digest itself
        assert_eq!(
            verify_committed_chain(&chain, ORG_A),
            Err(CommittedChainError::DigestMismatch { period_id: 1 })
        );
    }

    #[test]
    fn cross_org_chain_is_rejected_for_the_expected_org() {
        let chain = three_period_chain(ORG_A);
        assert_eq!(
            verify_committed_chain(&chain, ORG_B),
            Err(CommittedChainError::OrgMismatch { period_id: 0 }),
            "a chain built for org A must not verify as org B"
        );
    }

    #[test]
    fn broken_committed_link_is_rejected() {
        let mut chain = three_period_chain(ORG_A);
        // Relink period 1 to a bogus predecessor digest (and fix its own digest so only the link is
        // wrong) — the committed-link gate must fire.
        chain[1].prev_chain_digest = [0xAB; 32];
        chain[1].chain_digest = compute_chain_digest(
            ORG_A,
            chain[1].period_id,
            chain[1].tree_size as u64,
            &chain[1].root_hash,
            &chain[1].prev_chain_digest,
        );
        assert_eq!(
            verify_committed_chain(&chain, ORG_A),
            Err(CommittedChainError::BadPrevDigest { period_id: 1 })
        );
    }

    #[test]
    fn mac1_canon_row_rejected_by_mac2_verifier() {
        let mut chain = three_period_chain(ORG_A);
        chain[0].canon = MAC_SPEC_VERSION; // a MAC-1 row must not pass the MAC-2 verifier
        assert_eq!(
            verify_committed_chain(&chain, ORG_A),
            Err(CommittedChainError::BadCanon { period_id: 0 })
        );
    }

    #[test]
    fn empty_period_must_commit_the_empty_tree_root() {
        let chain = build_committed_chain(ORG_A, &[(0, vec![])]).unwrap();
        assert_eq!(chain[0].root_hash, merkle_tree_hash(&[]));
        assert_eq!(verify_committed_chain(&chain, ORG_A).map(|_| ()), Ok(()));
    }

    // ---- proof binding (A1 second half + A4-ii cryptographic foundation) ----------------------

    fn committed_inclusion_fixture() -> (Vec<CommittedChainRow>, InclusionProof, String, u64, Hash)
    {
        // period 1 (org A) with three leaves; prove leaf-b1's inclusion, bound to org A / period 1.
        let p0 = vec![content_hash("a0"), content_hash("a1")];
        let p1 = vec![content_hash("b0"), content_hash("b1"), content_hash("b2")];
        let chain = build_committed_chain(ORG_A, &[(0, p0), (1, p1.clone())]).unwrap();
        let target = content_hash("b1");
        let inclusion = build_inclusion_proof(&target, &p1).unwrap();
        let head = verify_committed_chain(&chain, ORG_A).unwrap();
        (chain, inclusion, target, 1, head)
    }

    #[test]
    fn committed_inclusion_binds_to_org_and_period() {
        let (chain, inclusion, target, period, head) = committed_inclusion_fixture();
        // Correct org + period + head → verifies.
        assert_eq!(
            verify_committed_inclusion(&target, ORG_A, period, &inclusion, &chain, &head),
            Ok(())
        );
        // Wrong org → the chain fails OrgMismatch (cross-org replay blocked).
        assert!(matches!(
            verify_committed_inclusion(&target, ORG_B, period, &inclusion, &chain, &head),
            Err(CommittedProofError::Chain(
                CommittedChainError::OrgMismatch { .. }
            ))
        ));
        // Wrong pinned head → HeadNotPinned (a forged-but-consistent chain cannot pass).
        let mut wrong_head = head;
        wrong_head[0] ^= 0x01;
        assert_eq!(
            verify_committed_inclusion(&target, ORG_A, period, &inclusion, &chain, &wrong_head),
            Err(CommittedProofError::HeadNotPinned)
        );
        // Wrong period → the inclusion no longer matches that committed row.
        assert!(matches!(
            verify_committed_inclusion(&target, ORG_A, 0, &inclusion, &chain, &head),
            Err(CommittedProofError::RootMismatch { period_id: 0 })
        ));
    }

    // ---- PROPOSED MAC-2 frozen vectors (NEEDS windows-master concurrence to finalise) ----------

    /// The deterministic org + periods the PROPOSED MAC-2 golden vectors are generated from — the
    /// SAME leaf-label convention as the MAC-1 `chain_vectors` (sha256 of an ascii label), one org,
    /// three contiguous periods (2 leaves, 3 leaves, empty), so a reviewer can diff MAC-2 against
    /// MAC-1 leaf-for-leaf.
    fn proposed_vector_chain() -> Vec<CommittedChainRow> {
        let p0 = vec![content_hash("leaf-A"), content_hash("leaf-B")];
        let p1 = vec![
            content_hash("leaf-C"),
            content_hash("leaf-D"),
            content_hash("leaf-E"),
        ];
        let p2: Vec<String> = vec![];
        build_committed_chain("org-acme", &[(0, p0), (1, p1), (2, p2)]).unwrap()
    }

    fn proposed_vectors_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/conformance/merkle-anchor/mac2_vectors.PROPOSED.json")
    }

    /// Regenerator for the PROPOSED MAC-2 vectors (run explicitly:
    /// `cargo test emit_proposed_mac2_vectors -- --ignored`). Emits the file so windows-master can
    /// review the exact frozen construction/values before they are finalised. Ignored by default so a
    /// normal CI run never rewrites the (proposed) golden file.
    #[test]
    #[ignore = "regenerator: run with --ignored to (re)emit the PROPOSED MAC-2 golden vectors"]
    fn emit_proposed_mac2_vectors() {
        let chain = proposed_vector_chain();
        let rows: Vec<serde_json::Value> = chain
            .iter()
            .map(|r| {
                serde_json::json!({
                    "period_id": r.period_id,
                    "org_id": r.org_id,
                    "root_hash": hex::encode(r.root_hash),
                    "prev_root_hash": hex::encode(r.prev_root_hash),
                    "prev_chain_digest": hex::encode(r.prev_chain_digest),
                    "chain_digest": hex::encode(r.chain_digest),
                    "tree_size": r.tree_size,
                    "algorithm": r.algorithm,
                    "canon": r.canon,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "_STATUS": "PROPOSED — NEEDS windows-master DESIGN CONCURRENCE before finalisation/merge (charter HARD RULE 5)",
            "_finding": "A1 (CRITICAL) — roots-chain links not cryptographically committed",
            "spec_version": MAC2_SPEC_VERSION,
            "tree_algorithm": TREE_ALGORITHM,
            "domain_separation_tag_hex": hex::encode(ROOTSCHAIN_V2_DOMAIN),
            "domain_separation_tag_ascii": String::from_utf8_lossy(ROOTSCHAIN_V2_DOMAIN),
            "genesis_chain_digest": hex::encode(COMMITTED_CHAIN_GENESIS_DIGEST),
            "digest_preimage": "SHA256( domain || be64(len(org_id)) || org_id || be64(period_id) || be64(tree_size) || root_hash || prev_chain_digest )",
            "org_id": "org-acme",
            "head_chain_digest": hex::encode(chain.last().unwrap().chain_digest),
            "rows": rows,
        });
        std::fs::write(
            proposed_vectors_path(),
            format!("{}\n", serde_json::to_string_pretty(&doc).unwrap()),
        )
        .expect("write PROPOSED MAC-2 vectors");
    }

    /// Lock the PROPOSED MAC-2 vectors to the code: the committed file must exist, verify clean, and
    /// its stored digests must reproduce exactly from the current construction. If a future edit
    /// changes the MAC-2 preimage without regenerating the vectors (or vice-versa), this fails —
    /// exactly the frozen-golden-vector discipline MAC-1 has, applied to the proposal.
    #[test]
    fn proposed_mac2_vectors_reproduce_from_code() {
        let raw = std::fs::read_to_string(proposed_vectors_path()).expect(
            "PROPOSED MAC-2 vectors present (run emit_proposed_mac2_vectors --ignored once)",
        );
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(doc["spec_version"], MAC2_SPEC_VERSION);
        let chain = proposed_vector_chain();
        // Head + per-row digests in the file must match the freshly built chain byte-for-byte.
        assert_eq!(
            doc["head_chain_digest"].as_str().unwrap(),
            chain.last().unwrap().chain_digest_hex(),
            "frozen head digest drifted from the code"
        );
        for (i, row) in chain.iter().enumerate() {
            let v = &doc["rows"][i];
            assert_eq!(
                v["chain_digest"].as_str().unwrap(),
                row.chain_digest_hex(),
                "row {i} digest"
            );
            assert_eq!(
                v["root_hash"].as_str().unwrap(),
                hex::encode(row.root_hash),
                "row {i} root"
            );
            assert_eq!(v["canon"], MAC2_SPEC_VERSION);
        }
        // And the vectors verify under the real verifier.
        assert!(verify_committed_chain(&chain, "org-acme").is_ok());
    }

    /// Sanity: the MAC-2 row's `root_hash` is byte-identical to the MAC-1 producer's root for the same
    /// leaves — MAC-2 only ADDS the committed digest; it does not change the tree construction, so the
    /// existing frozen MAC-1 root vectors are unaffected by this module.
    #[test]
    fn mac2_root_hash_matches_mac1_producer() {
        let leaves = vec![content_hash("a0"), content_hash("a1")];
        let mac1: RootsChainRow = crate::roots_chain::build_roots_chain(&[(0, leaves.clone())])
            .unwrap()
            .remove(0);
        let mac2 = build_committed_chain(ORG_A, &[(0, leaves)])
            .unwrap()
            .remove(0);
        assert_eq!(
            mac1.root_hash, mac2.root_hash,
            "MAC-2 reuses the MAC-1 tree root"
        );
        assert_eq!(
            CHAIN_GENESIS_PREV, mac2.prev_root_hash,
            "genesis prev_root_hash unchanged"
        );
    }
}
