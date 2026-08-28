//! MAC-1 Merkle commitment — `meshlogic-merkle` shared crate (ADR-043 P1a).
//!
//! A STANDALONE crate (mac-lead P1a Q1) so the tamper-evidence PRODUCER (cloud-backend) and the
//! zero-trust OFFLINE VERIFIER shipped to auditors run byte-identical Merkle logic and can never
//! drift. Depends only on public crates (no backend coupling); its own isolated CI.
//!
//! Port of the authoritative Phase-0 reference (`tests/conformance/merkle-anchor/
//! reference_merkle.py`, spec `docs/specs/merkle-anchor-commitment-v1.md`, profile MAC-1):
//! an RFC 6962 (Certificate Transparency) Merkle tree over ADR-042 `content_hash` leaves,
//! plus inclusion proofs. Every root/proof MUST reproduce the frozen `vectors.json`
//! byte-for-byte (the conformance test below) — determinism is the whole product (ADR-043 §5):
//! a verifier that rejects an intact record false-alarms in front of an auditor; one that
//! accepts an altered record voids the guarantee.
//!
//! SCOPE (P1a): tree hash + inclusion proof only. Consistency proofs + the gap-free roots
//! chain are MAC-1 machinery deferred to P1b (ADR-043 §5). The producer caller (cloud-backend
//! path-dependency + Docker COPY of this crate) is wired in P1a Task 3, not here.

use sha2::{Digest, Sha256};

/// RFC 3161 timestamp anchoring over a Merkle root (ADR-043 P1a Task 2).
pub mod anchor;

/// MAC-1 roots-chain PRODUCE side — periodic Merkle roots + hash-chain math (ADR-043 P1b).
pub mod roots_chain;

/// ADR-043 C1 slice-1a — offline commitment-leaf verification + auditor-artifact assembly
/// (the ANCHOR half; consumes the capture-at-stamp producer's `CommitmentLeaf` blobs).
pub mod commitment_leaf;

/// ADR-043 C1 P1b — roots-chain linkage + RFC 9162 consistency VERIFY side (sibling of the
/// capture-at-stamp `roots_chain` PRODUCER; both validate the same frozen `chain_vectors`).
pub mod chain_verify;

/// ADR-043 C1 P1b PR-2 — proof GENERATION (auditor read path): re-derives an inclusion + chain
/// proof (`ProofBundle`) for a leaf's `content_hash`, consumable by `chain_verify`'s verifiers.
pub mod proof_gen;

/// A1 (CRITICAL) remediation — MAC-2 COMMITTED roots-chain: folds `org_id`/`period_id`/`tree_size`/
/// `root_hash`/`C_{P-1}` into a per-row committed digest `C_P` (the value co-anchored, not the bare
/// root), so witnessing the head transitively witnesses every prior period and proofs bind to
/// org/period. ⚠ NEW canon + regenerated frozen vectors — NEEDS windows-master design concurrence
/// before the production producer cuts over (charter HARD RULE 5); ships ALONGSIDE the untouched
/// MAC-1 path, gated on `canon`.
pub mod committed_chain;

/// ADR-043 C1 P4 — the offline auditor's FULL RFC 3161 TST cryptographic verifier (`verify_tst_full`):
/// CMS SignerInfo signature + X.509 chain-to-trusted-root. Feature-gated (`offline-verify`) so the
/// shared Merkle/producer core stays dependency-light. Re-exported at `anchor::` for the API surface.
#[cfg(feature = "offline-verify")]
pub mod tst_verify;

/// ADR-043 C1 P3 — production OFFLINE co-anchor VERIFIER for the Sigstore Rekor public transparency
/// log: graded [`coanchor::CoAnchorStatus`] over the proven receipt/checkpoint crypto, plus a
/// rotation-capable pinned-key [`coanchor::RekorTrustStore`]. Feature-gated (`rekor-verify`) so the
/// shared Merkle/producer core stays dependency-light (only P-256 is pulled). NETWORK-FREE — the
/// live publish path is the producer PR's concern, not this module.
#[cfg(feature = "rekor-verify")]
pub mod coanchor;

/// ADR-043 C1 M6-a — the SIGNED commitment-leaf verifier (the "signed collection boundary"): binds
/// each leaf to its collecting agent's enrolled Ed25519 identity (ADR-062) over the FULL canonical
/// leaf envelope, verified FAIL-CLOSED against a pinned, rotation-capable fleet-identity trust store.
/// Feature-gated (`leaf-verify`) so the shared Merkle/producer core stays dependency-light (only
/// `ed25519-dalek` is pulled). Closes the gap where a store writer could inject a fabricated leaf
/// under a genuinely-anchored root.
#[cfg(feature = "leaf-verify")]
pub mod signed_leaf;

/// M6-c increment 1a: the per-decision signed HASH-LINKED chain (the PROOF-pillar producer +
/// independent re-derive/verify). Feeds the increment-2 [`roots_chain`] Merkle accumulator.
#[cfg(feature = "leaf-verify")]
pub mod decision_chain;

/// GENERIC record chain (ADR-025 / ADR-176) — the ONE shared tamper-evidence primitive. A [`LeafRecord`]
/// yields (`source_kind`, `canon_spec_version`, `canonical_preimage`); [`record_chain::append_record_to_file`]
/// hash-links + signs it onto a chain file exactly like the decision chain, returning the new
/// [`record_chain::ChainHead`]. `decision_record::DecisionRecord` is one such leaf type; the offline-cache
/// telemetry-batch WAL (ADR-025) is another. Same `leaf-verify` gate as the signing machinery it uses.
#[cfg(feature = "leaf-verify")]
pub mod record_chain;

/// RFC 8785 (JCS) canonical-JSON serialisation — the ONE shared implementation of the MLCH-1 canon
/// family, reused by [`signed_leaf`]'s leaf-envelope canon and R7's [`self_contained`] proof-bundle
/// signing canon, so the two can never independently drift. Not itself feature-gated on either
/// consumer's name — gated on `any(...)` of both, so a plain no-features build carries no dead code
/// and neither consumer's feature has to imply the other's (heavier) dependencies.
#[cfg(any(feature = "offline-verify", feature = "leaf-verify"))]
pub mod jcs;

/// M6-c FROZEN v=1 decision-record canonicalization (the shared leaf content both agent producers +
/// the verifier canonicalize identically). Uses this crate's `jcs`, so it shares its feature gate.
#[cfg(any(feature = "offline-verify", feature = "leaf-verify"))]
pub mod decision_record;

/// R7 — the self-contained proof-bundle types (`docs/superpowers/plans/2026-07-25-r7-proof-
/// bundle.md`, Task 1): a customer-downloadable bundle wrapping `proof_gen::ProofBundle` +
/// `coanchor::RekorReceipt` per evidence record/period, and the offline verifier's graded verdict
/// shape. Feature-gated (`offline-verify`) — same gate as the crypto it wraps, so the shared
/// Merkle/producer core stays dependency-light.
#[cfg(feature = "offline-verify")]
pub mod self_contained;

/// R7 Task 4 — the `meshlogic_verify` bin's render + exit-code logic (`report_and_code`), pulled
/// into the library so it is directly unit-testable without a fixture that reaches PROVEN through
/// the real pinned trust roots. Feature-gated (`offline-verify`) — same gate as `self_contained`.
#[cfg(feature = "offline-verify")]
pub mod verify_report;

/// A 32-byte SHA-256 output (a leaf-data digest, a node hash, or a root).
pub type Hash = [u8; 32];

/// MAC-1 Merkle-Anchor-Commitment profile version. Recorded in every roots-log row (P1b) so a
/// verifier knows exactly which construction produced a root; bump on any tree-rule change.
pub const MAC_SPEC_VERSION: &str = "MAC-1";
/// Tree-hash algorithm identifier recorded alongside each root (RFC 6962 tree hash over SHA-256).
pub const TREE_ALGORITHM: &str = "RFC6962-SHA256";
/// RFC 6962 domain separation prefixes — prevent second-preimage / leaf-vs-node confusion.
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleError(pub String);
impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "merkle error: {}", self.0)
    }
}
impl std::error::Error for MerkleError {}

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The leaf DATA fed to the tree is the 32 raw bytes of the ADR-042 `content_hash` (a 64-char
/// lowercase-hex SHA-256). We commit the digest, not a re-canonicalization of the record (ADR-043 §4).
pub fn leaf_bytes_from_content_hash(content_hash_hex: &str) -> Result<Hash, MerkleError> {
    if content_hash_hex.len() != 64 {
        return Err(MerkleError(
            "content_hash must be a 64-char hex string".into(),
        ));
    }
    // Lowercase-hex is part of the frozen MLCH-1/MAC-1 contract. Validate the charset FIRST —
    // `hex::decode` accepts uppercase, so an after-the-fact reject would be fragile (AI-review
    // #1934 MED). With length (64) + lowercase-hex charset both checked, the decode and the
    // 32-byte conversion are infallible — the `expect`s document that invariant (AI-review #1938).
    if !content_hash_hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(MerkleError("content_hash must be lowercase hex".into()));
    }
    let out: Hash = hex::decode(content_hash_hex)
        .expect("64 lowercase-hex chars always decode")
        .try_into()
        .expect("64 hex chars always yield 32 bytes");
    Ok(out)
}

/// True iff an S3-reported object size (`size_bytes`) exceeds `max_bytes`.
///
/// The AWS SDK reports object sizes as a SIGNED `i64` (`aws_sdk_s3::types::Object::size()` and
/// `GetObjectOutput::content_length()` are both `Option<i64>`), so this takes an `i64`. The check is
/// an EXPLICIT `>` bound: a nonsensical negative size (which S3 never emits) is treated as
/// not-oversized. Prefer this over the `size_bytes.max(0) as u64 > max` idiom at call sites — that
/// idiom is a correct signed-negative clamp but reads like a no-op, which repeatedly draws
/// false-positive "unsigned .max(0) is a no-op / the size cap is unenforced" review flags. The bound
/// was always enforced (the trailing `> max` fires regardless of the `.max(0)`); this is the single,
/// unit-tested source of truth the size-guarded S3 readers (the P1b builder + the proof-gen CLI) share
/// so the cap can never silently drift or read ambiguously (ADR-043 C1 hardening).
pub fn size_exceeds_cap(size_bytes: i64, max_bytes: u64) -> bool {
    size_bytes > 0 && (size_bytes as u64) > max_bytes
}

/// RFC 6962 leaf hash: `SHA-256(0x00 || leaf_data)`.
pub fn hash_leaf(leaf_data: &[u8]) -> Hash {
    sha256(&[&[LEAF_PREFIX], leaf_data])
}

/// RFC 6962 interior node: `SHA-256(0x01 || left || right)`.
pub fn hash_node(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[NODE_PREFIX], left, right])
}

/// Largest power of two STRICTLY less than `n` (RFC 6962 split point). `n` must be >= 2.
fn largest_pow2_lt(n: usize) -> usize {
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 6962 §2.1 Merkle Tree Hash over the leaf-data list. Empty tree = `SHA-256("")`.
pub fn merkle_tree_hash(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => sha256(&[b""]),
        1 => hash_leaf(&leaves[0]),
        n => {
            let k = largest_pow2_lt(n);
            hash_node(
                &merkle_tree_hash(&leaves[..k]),
                &merkle_tree_hash(&leaves[k..]),
            )
        }
    }
}

/// RFC 6962 §2.1.1 inclusion (audit) path for 0-based leaf index `m`.
pub fn inclusion_proof(m: usize, leaves: &[Hash]) -> Result<Vec<Hash>, MerkleError> {
    let n = leaves.len();
    if m >= n {
        return Err(MerkleError("leaf index out of range".into()));
    }
    Ok(audit_path(m, leaves))
}

fn audit_path(m: usize, leaves: &[Hash]) -> Vec<Hash> {
    let n = leaves.len();
    if n == 1 {
        return Vec::new();
    }
    let k = largest_pow2_lt(n);
    if m < k {
        let mut p = audit_path(m, &leaves[..k]);
        p.push(merkle_tree_hash(&leaves[k..]));
        p
    } else {
        let mut p = audit_path(m - k, &leaves[k..]);
        p.push(merkle_tree_hash(&leaves[..k]));
        p
    }
}

/// RFC 9162 §2.1.3.2 iterative inclusion verifier — recompute the root from a leaf hash + audit
/// path WITHOUT the full tree (what an auditor runs). Returns true iff it matches `root`.
pub fn verify_inclusion(
    leaf_index: usize,
    tree_size: usize,
    leaf_hash: Hash,
    proof: &[Hash],
    root: Hash,
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    let (mut f, mut s) = (leaf_index, tree_size - 1);
    let mut r = leaf_hash;
    for p in proof {
        if s == 0 {
            return false; // proof longer than the tree path
        }
        if (f & 1) == 1 || f == s {
            r = hash_node(p, &r);
            if (f & 1) == 0 {
                // left-sibling consumed: advance to the next set bit
                loop {
                    f >>= 1;
                    s >>= 1;
                    if (f & 1) == 1 || f == 0 {
                        break;
                    }
                }
            }
        } else {
            r = hash_node(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && r == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

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

    fn hx(s: &str) -> Hash {
        leaf_bytes_from_content_hash(s).expect("valid 32-byte hex")
    }

    #[test]
    fn size_exceeds_cap_enforces_an_explicit_bound() {
        const CAP: u64 = 1_048_576; // 1 MiB, the commitment-leaf per-object cap.
                                    // Over the cap → oversized.
        assert!(
            size_exceeds_cap(CAP as i64 + 1, CAP),
            "one byte over the cap is oversized"
        );
        assert!(size_exceeds_cap(10 * CAP as i64, CAP));
        assert!(
            size_exceeds_cap(i64::MAX, CAP),
            "a huge object is oversized"
        );
        // At or under the cap → allowed (boundary is inclusive of the cap value).
        assert!(
            !size_exceeds_cap(CAP as i64, CAP),
            "exactly at the cap is allowed"
        );
        assert!(!size_exceeds_cap(CAP as i64 - 1, CAP));
        assert!(!size_exceeds_cap(1, CAP));
        // A nonsensical zero / negative size (S3 never emits these) is NOT treated as oversized —
        // matching the prior `.max(0) as u64` clamp, but explicit.
        assert!(!size_exceeds_cap(0, CAP));
        assert!(!size_exceeds_cap(-1, CAP));
        assert!(!size_exceeds_cap(i64::MIN, CAP));
    }

    #[test]
    fn reproduces_frozen_tree_and_inclusion_vectors() {
        let c = corpus();
        assert_eq!(
            c["spec_version"].as_str().unwrap(),
            MAC_SPEC_VERSION,
            "spec drift"
        );
        assert_eq!(c["tree_algorithm"].as_str().unwrap(), TREE_ALGORITHM);
        // Empty-tree known-answer anchor (RFC 6962 MTH({}) = SHA-256("")).
        assert_eq!(
            hex::encode(merkle_tree_hash(&[])),
            c["empty_tree_root"].as_str().unwrap()
        );

        // tree_vectors: MTH reproduces each frozen root, AND every index's generated
        // inclusion proof verifies (gen ⇄ verify cross-check), AND a mutated leaf is rejected.
        for tv in c["tree_vectors"].as_array().unwrap() {
            let name = tv["name"].as_str().unwrap();
            let leaves: Vec<Hash> = tv["leaves"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| hx(h.as_str().unwrap()))
                .collect();
            let root = merkle_tree_hash(&leaves);
            assert_eq!(
                hex::encode(root),
                tv["root"].as_str().unwrap(),
                "tree root {name}"
            );
            for i in 0..leaves.len() {
                let path = inclusion_proof(i, &leaves).unwrap();
                let lh = hash_leaf(&leaves[i]);
                assert!(
                    verify_inclusion(i, leaves.len(), lh, &path, root),
                    "gen+verify inclusion {name} idx {i}"
                );
                let mut bad = lh;
                bad[0] ^= 0x01;
                assert!(
                    !verify_inclusion(i, leaves.len(), bad, &path, root),
                    "mutated leaf MUST be rejected {name} idx {i}"
                );
            }
        }

        // inclusion_vectors: verify against the FROZEN audit paths (an auditor's exact input).
        for iv in c["inclusion_vectors"].as_array().unwrap() {
            let name = iv["name"].as_str().unwrap();
            let leaf_data = hx(iv["leaf_content_hash"].as_str().unwrap());
            let lh = hash_leaf(&leaf_data);
            assert_eq!(
                hex::encode(lh),
                iv["leaf_hash"].as_str().unwrap(),
                "leaf_hash {name}"
            );
            let path: Vec<Hash> = iv["audit_path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| hx(h.as_str().unwrap()))
                .collect();
            let root = hx(iv["root"].as_str().unwrap());
            let idx = iv["leaf_index"].as_u64().unwrap() as usize;
            let size = iv["tree_size"].as_u64().unwrap() as usize;
            assert!(
                verify_inclusion(idx, size, lh, &path, root),
                "frozen inclusion vector {name}"
            );
        }
    }

    #[test]
    fn bad_content_hash_is_err_not_panic() {
        assert!(leaf_bytes_from_content_hash("too-short").is_err());
        assert!(leaf_bytes_from_content_hash(&"a".repeat(63)).is_err());
        assert!(leaf_bytes_from_content_hash(&"g".repeat(64)).is_err()); // non-hex
        assert!(leaf_bytes_from_content_hash(&"A".repeat(64)).is_err()); // uppercase rejected
        assert!(leaf_bytes_from_content_hash(&format!("Ab{}", "0".repeat(62))).is_err()); // MIXED case
        assert!(leaf_bytes_from_content_hash(&"0".repeat(64)).is_ok());
    }

    // AI-review #1934 HIGH — exhaustive verifier property test. The frozen vectors cover only a few
    // tree SHAPES and only mutate the leaf; this exercises EVERY (tree_size, leaf_index) up to 64
    // leaves (all non-power-of-2 geometries) with bit-flips, so a verify_inclusion geometry bug
    // (accept-invalid / reject-valid — the ADR-043 §5 worst case) cannot hide. Generation
    // (inclusion_proof) is cross-checked against verification (verify_inclusion) at every shape.
    #[test]
    fn verify_inclusion_property_all_shapes_1_to_64() {
        fn leaf(i: usize) -> Hash {
            sha256(&[b"prop-leaf-", &(i as u64).to_be_bytes()])
        }
        for n in 1..=64usize {
            let leaves: Vec<Hash> = (0..n).map(leaf).collect();
            let root = merkle_tree_hash(&leaves);
            for i in 0..n {
                let proof = inclusion_proof(i, &leaves).unwrap();
                let lh = hash_leaf(&leaves[i]);
                assert!(
                    verify_inclusion(i, n, lh, &proof, root),
                    "valid proof MUST verify (n={n} i={i})"
                );
                let mut bad_root = root;
                bad_root[0] ^= 0x01;
                assert!(
                    !verify_inclusion(i, n, lh, &proof, bad_root),
                    "wrong root MUST reject (n={n} i={i})"
                );
                let mut bad_leaf = lh;
                bad_leaf[7] ^= 0x01;
                assert!(
                    !verify_inclusion(i, n, bad_leaf, &proof, root),
                    "flipped leaf MUST reject (n={n} i={i})"
                );
                if !proof.is_empty() {
                    let mut bad_proof = proof.clone();
                    bad_proof[0][0] ^= 0x01;
                    assert!(
                        !verify_inclusion(i, n, lh, &bad_proof, root),
                        "flipped proof element MUST reject (n={n} i={i})"
                    );
                    // A different leaf's hash under THIS index+proof must not spuriously verify.
                    let j = (i + 1) % n;
                    let lj = hash_leaf(&leaves[j]);
                    assert!(
                        !verify_inclusion(i, n, lj, &proof, root),
                        "other leaf under this index MUST reject (n={n} i={i})"
                    );
                }
            }
        }
    }
}
