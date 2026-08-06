//! ADR-043 C1 P1b — proof GENERATION (the auditor-facing READ path). PR-2.
//!
//! P1a shipped the RFC 6962 tree hash + inclusion proof; PR-1 shipped the roots-chain PRODUCER
//! (`roots_chain`) + VERIFY side (`chain_verify`). This module is the READ path an auditor drives:
//! given one enforcement leaf's `content_hash`, RE-DERIVE its inclusion proof against the period's
//! Merkle tree and assemble a self-contained [`ProofBundle`] that carries everything a verifier
//! needs — the inclusion proof + the genesis→period roots-chain segment — so the auditor can run
//! the SAME frozen primitives (`verify_inclusion`, `verify_chain`) that ship in `chain_verify`.
//!
//! PURE here (no AWS): the caller supplies the period's `content_hash` set and the roots-chain
//! rows. The `commitment_proof_gen` binary (behind the `aws-reads` feature) does the S3 re-listing
//! + DynamoDB roots-chain read and calls into this module. The period leaf set MUST be obtained by
//! RE-LISTING the S3 commitment-leaf store — never a stored/trusted index (ADR-043 §5.2). This
//! module re-derives the leaf ORDER (MAC-1 raw-byte-ASC) and the audit path from that raw set;
//! it never trusts a precomputed leaf_index or audit_path.
//!
//! SEAM (produce ⇄ verify): a bundle this module builds is consumed by `chain_verify`'s
//! `verify_inclusion` + `verify_chain` unchanged — [`ProofBundle::verify`] IS that auditor path,
//! reusing those exact functions (no fork). The bundle round-trips through JSON losslessly so the
//! producer emits it and an offline auditor reads it back and re-verifies.

use crate::chain_verify::{verify_chain_from, ChainError, ChainRowView, CHAIN_GENESIS_PREV};
use crate::roots_chain::RootsChainRow;
use crate::{
    hash_leaf, inclusion_proof, leaf_bytes_from_content_hash, merkle_tree_hash, verify_inclusion,
    Hash, MerkleError, MAC_SPEC_VERSION, TREE_ALGORITHM,
};
use serde_json::{json, Value};

/// The re-derived RFC 6962 inclusion (audit) proof for one leaf within a single period's tree.
///
/// `leaf_index` / `audit_path` / `tree_size` are all re-derived from the RAW (MAC-1 raw-byte-ASC
/// sorted) leaf set — the exact inputs an auditor feeds to [`verify_inclusion`], where the leaf hash
/// is `hash_leaf(leaf_bytes_from_content_hash(content_hash))` and the expected root is `period_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// 0-based index of the target leaf in the MAC-1 raw-byte-ASC sorted leaf set.
    pub leaf_index: usize,
    /// RFC 6962 audit path (sibling hashes leaf→root).
    pub audit_path: Vec<Hash>,
    /// The period's MAC-1 Merkle root the path reproduces (== the roots-chain row's `root_hash`).
    pub period_root: Hash,
    /// Number of leaves committed in the period (== the roots-chain row's `tree_size`).
    pub tree_size: usize,
}

/// A reference (NOT a verified token) to the RFC 3161 timestamp anchoring one period's root.
///
/// Carried for the auditor's convenience — the CMS signature/chain is NOT verified here (P4). A
/// verifier can fetch `tst_ref` from the TST bucket and check it out-of-band; the security-load-
/// bearing chain/inclusion verification does not depend on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TstRef {
    pub period_id: u64,
    /// S3 key of the timestamp-token DER (`roots-chain-tst/{org}/{period}.tsr`), if anchored.
    pub tst_ref: Option<String>,
    /// RFC 3161 `genTime` (unix seconds) recorded by the producer, if anchored.
    pub gen_time_unix: Option<u64>,
    /// TSA token serial (hex), if anchored.
    pub serial_hex: Option<String>,
    /// Whether the producer marked the period fully anchored.
    pub anchored: bool,
}

/// One roots-chain row in a serializable, owned form (the JSON carrier for [`ProofBundle`]).
///
/// Field-for-field the producer's [`RootsChainRow`], but with OWNED `algorithm` / `canon` strings so
/// the bundle round-trips through JSON. Convert from the producer type with [`BundleChainRow::from_row`]
/// and back to the verifier's borrowed [`ChainRowView`] with [`BundleChainRow::view`] — so `verify_chain`
/// consumes it unchanged. Owning the strings (rather than pinning the `&'static` constants) is
/// deliberate: a tampered `algorithm`/`canon` survives the JSON round-trip and is caught by
/// `verify_chain` as `BadAlgorithm`/`BadCanon` rather than being silently normalised away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleChainRow {
    pub period_id: u64,
    pub root_hash: Hash,
    pub prev_root_hash: Hash,
    pub tree_size: usize,
    pub algorithm: String,
    pub canon: String,
}

impl BundleChainRow {
    /// Lift a producer [`RootsChainRow`] into the owned bundle carrier.
    pub fn from_row(r: &RootsChainRow) -> Self {
        Self {
            period_id: r.period_id,
            root_hash: r.root_hash,
            prev_root_hash: r.prev_root_hash,
            tree_size: r.tree_size,
            algorithm: r.algorithm.to_string(),
            canon: r.canon.to_string(),
        }
    }

    /// Borrow this row as the verifier's [`ChainRowView`] (what `verify_chain` consumes).
    pub fn view(&self) -> ChainRowView<'_> {
        ChainRowView {
            period_id: self.period_id,
            root_hash: self.root_hash,
            prev_root_hash: self.prev_root_hash,
            tree_size: self.tree_size,
            algorithm: &self.algorithm,
            canon: &self.canon,
        }
    }
}

/// A self-contained inclusion + chain proof for ONE enforcement leaf's `content_hash`.
///
/// Shaped so an auditor verifies it with the frozen `chain_verify` primitives (see [`Self::verify`]):
///   1. `verify_chain(roots_chain)` — genesis (`0×32`) + linkage + gap-free contiguity,
///   2. `verify_inclusion(inclusion)` reproduces `period_root`,
///   3. `period_root == roots_chain[period_id].root_hash` (binds inclusion to the anchored chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBundle {
    /// The 64-char lowercase-hex `content_hash` this proof is for (ADR-042).
    pub content_hash: String,
    /// The organisation whose roots-chain / commitment-leaf store this was re-derived from.
    pub org_id: String,
    /// The `period_id` (days-since-epoch) whose tree contains the leaf.
    pub period_id: u64,
    /// The re-derived inclusion proof within the period's tree.
    pub inclusion: InclusionProof,
    /// The roots-chain segment genesis→period (contiguous, ascending `period_id`).
    pub roots_chain: Vec<BundleChainRow>,
    /// RFC 3161 timestamp references for the covered periods (NOT verified here — P4).
    pub tst_refs: Vec<TstRef>,
}

/// Every way building or verifying a [`ProofBundle`] can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// A content_hash / hex value was malformed (delegated to the crate's leaf decoder).
    Merkle(MerkleError),
    /// The roots-chain segment failed `verify_chain` (carries the precise `ChainError`).
    Chain(ChainError),
    /// The target `period_id` is not present in the supplied roots-chain segment.
    PeriodNotInChain(u64),
    /// The re-derived `period_root` does not equal the chain row's anchored `root_hash`.
    RootMismatch { period_id: u64 },
    /// The inclusion `tree_size` does not equal the chain row's `tree_size`.
    TreeSizeMismatch { period_id: u64 },
    /// `verify_inclusion` rejected the audit path against `period_root`.
    Inclusion,
    /// The bundle is structurally valid (inclusion + chain linkage) but one or more covered periods
    /// are NOT RFC 3161 anchored (no timestamp token). Such a proof is inclusion + chain-linkage
    /// ONLY — it is NOT externally-timestamped tamper-evidence. Reported by [`ProofBundle::verify_anchored`].
    Unanchored { periods: Vec<u64> },
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofError::Merkle(e) => write!(f, "{e}"),
            ProofError::Chain(e) => write!(f, "roots-chain verification failed: {e}"),
            ProofError::PeriodNotInChain(p) => {
                write!(f, "period {p} not present in the roots-chain segment")
            }
            ProofError::RootMismatch { period_id } => write!(
                f,
                "re-derived period_root != anchored root_hash at period {period_id}"
            ),
            ProofError::TreeSizeMismatch { period_id } => write!(
                f,
                "inclusion tree_size != anchored tree_size at period {period_id}"
            ),
            ProofError::Inclusion => {
                write!(f, "inclusion proof does not reproduce the period root")
            }
            ProofError::Unanchored { periods } => write!(
                f,
                "periods {periods:?} are not RFC 3161 anchored — inclusion + chain-linkage only, \
                 NOT externally-timestamped tamper-evidence"
            ),
        }
    }
}

impl std::error::Error for ProofError {}

impl From<MerkleError> for ProofError {
    fn from(e: MerkleError) -> Self {
        ProofError::Merkle(e)
    }
}

/// The RFC 3161 anchoring state of a [`ProofBundle`] across every covered period.
///
/// `verify_chain` + `verify_inclusion` prove inclusion and hash-chain LINKAGE only — they say
/// nothing about whether the roots were externally timestamped. This surfaces that distinction so a
/// consumer never mistakes a chain-linkage-only proof for externally-timestamped tamper-evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchoringStatus {
    /// Every covered period carries `anchored=true` and a `tst_ref` — externally timestamped.
    FullyAnchored,
    /// One or more covered periods lack an RFC 3161 timestamp token (`anchored=false` or no `tst_ref`).
    Unanchored { periods: Vec<u64> },
}

/// Re-derive the RFC 6962 inclusion proof for `content_hash_hex` within a period's leaf set.
///
/// `period_content_hashes` is the period's FULL `content_hash` set as RE-LISTED from the S3
/// commitment-leaf store (never a trusted index). Each is decoded to its raw 32 bytes and the set
/// is sorted RAW-BYTE ASCENDING — byte-identical to the producer's [`crate::roots_chain::period_root`]
/// MAC-1 pin — so the re-derived `leaf_index` / `period_root` match the anchored root exactly. The
/// audit path comes from the crate's [`inclusion_proof`]; no MAC-1 / RFC 6962 logic is re-implemented.
///
/// DUPLICATE `content_hash`es: the producer ([`crate::roots_chain::period_root`]) does NOT dedup —
/// it decodes ALL leaves, sorts raw-byte-ASC, and hashes the full multiset (so `tree_size` counts
/// every occurrence). This function mirrors that exactly (no dedup), so the re-derived `tree_size`
/// and `period_root` match the anchored root even when a `content_hash` repeats. When the target
/// occurs more than once it deterministically selects the LOWEST such index (all occurrences share
/// identical leaf DATA, so every one yields a valid proof — the lowest is chosen for reproducibility).
///
/// Errors if the target is not present in the period (a leaf that was never committed cannot be
/// proven — fail loud, do not fabricate a path).
pub fn build_inclusion_proof(
    content_hash_hex: &str,
    period_content_hashes: &[String],
) -> Result<InclusionProof, MerkleError> {
    let target = leaf_bytes_from_content_hash(content_hash_hex)?;
    // MAC-1: decode every content_hash to raw 32 bytes and sort RAW-BYTE ASC (memcmp / `Ord` on
    // `[u8; 32]`) — the SAME domain as the producer, so index + root reproduce the anchored tree.
    let mut leaves: Vec<Hash> = period_content_hashes
        .iter()
        .map(|h| leaf_bytes_from_content_hash(h))
        .collect::<Result<Vec<Hash>, MerkleError>>()?;
    leaves.sort_unstable();
    // Deterministic: `partition_point` gives the FIRST index whose value is >= target; if that slot
    // holds the target it is the lowest matching index (stable across duplicate occurrences). This
    // avoids `binary_search`'s "any-match" nondeterminism among equal elements.
    let leaf_index = leaves.partition_point(|h| h < &target);
    if leaf_index >= leaves.len() || leaves[leaf_index] != target {
        return Err(MerkleError(format!(
            "content_hash {content_hash_hex} is not among the period's {} re-listed leaves",
            leaves.len()
        )));
    }
    let audit_path = inclusion_proof(leaf_index, &leaves)?;
    let period_root = merkle_tree_hash(&leaves);
    Ok(InclusionProof {
        leaf_index,
        audit_path,
        period_root,
        tree_size: leaves.len(),
    })
}

/// Seconds in one UTC day — the MAC-1 period is one UTC day (mirrors the producer's `SECONDS_PER_DAY`).
pub const SECONDS_PER_DAY: i64 = 86_400;

/// The `period_id` (days-since-Unix-epoch) for a unix-seconds instant. Negative-safe floor division,
/// byte-identical to the producer's `days_since_epoch`. Used by the CLI to target the single day to
/// re-list from a caller-supplied `captured_at`, rather than scanning the whole chain (cost/DoS).
pub fn period_id_for_unix(unix_secs: i64) -> u64 {
    unix_secs.div_euclid(SECONDS_PER_DAY) as u64
}

/// Assemble a [`ProofBundle`] for `content_hash_hex` in `period_id`.
///
/// Re-derives the inclusion proof from `period_content_hashes` (re-listed from S3) and binds it to
/// the supplied `roots_chain`: the target period MUST be present and its anchored `root_hash` MUST
/// equal the re-derived `period_root` (fail loud otherwise — a proof that does not tie back to the
/// anchored chain is worthless). The bundle carries exactly the genesis→target segment (rows with
/// `period_id <= period_id` — any trailing rows the caller supplies are dropped so the bundle's
/// `roots_chain` and its anchoring state describe only the periods this proof depends on). The
/// returned bundle is guaranteed to pass [`ProofBundle::verify`].
#[allow(clippy::too_many_arguments)]
pub fn build_proof_bundle(
    content_hash_hex: &str,
    org_id: &str,
    period_id: u64,
    period_content_hashes: &[String],
    roots_chain: &[RootsChainRow],
    tst_refs: Vec<TstRef>,
) -> Result<ProofBundle, ProofError> {
    let inclusion = build_inclusion_proof(content_hash_hex, period_content_hashes)?;
    let period_row = roots_chain
        .iter()
        .find(|r| r.period_id == period_id)
        .ok_or(ProofError::PeriodNotInChain(period_id))?;
    if period_row.root_hash != inclusion.period_root {
        return Err(ProofError::RootMismatch { period_id });
    }
    if period_row.tree_size != inclusion.tree_size {
        return Err(ProofError::TreeSizeMismatch { period_id });
    }
    // Carry exactly the genesis→target segment (+ its TST refs), so anchoring state describes only
    // the periods this proof relies on — not any later, irrelevant periods.
    let segment: Vec<BundleChainRow> = roots_chain
        .iter()
        .filter(|r| r.period_id <= period_id)
        .map(BundleChainRow::from_row)
        .collect();
    let tst_refs: Vec<TstRef> = tst_refs
        .into_iter()
        .filter(|t| t.period_id <= period_id)
        .collect();
    let bundle = ProofBundle {
        content_hash: content_hash_hex.to_string(),
        org_id: org_id.to_string(),
        period_id,
        inclusion,
        roots_chain: segment,
        tst_refs,
    };
    Ok(bundle)
}

impl ProofBundle {
    /// STRUCTURAL verification — reuses the frozen `chain_verify` primitives (the SEAM):
    /// `verify_chain` for the roots-chain segment, `verify_inclusion` for the leaf, plus the binding
    /// `period_root == roots_chain[period_id].root_hash`. Returns `Ok(())` iff all hold.
    ///
    /// This proves the leaf is included under a hash-chain-linked root — it does NOT prove the root
    /// was externally timestamped. Anchoring is a SEPARATE claim: check [`Self::anchoring_status`] or
    /// use [`Self::verify_anchored`] before presenting a bundle as externally-timestamped evidence.
    pub fn verify(&self) -> Result<(), ProofError> {
        // 1. Roots-chain: genesis anchor + linkage + gap-free contiguity + canon/algorithm.
        let views: Vec<ChainRowView> = self.roots_chain.iter().map(BundleChainRow::view).collect();
        verify_chain_from(&views, &CHAIN_GENESIS_PREV).map_err(ProofError::Chain)?;

        // 2. Bind the inclusion to the anchored chain row for this period.
        let period_row = self
            .roots_chain
            .iter()
            .find(|r| r.period_id == self.period_id)
            .ok_or(ProofError::PeriodNotInChain(self.period_id))?;
        if period_row.root_hash != self.inclusion.period_root {
            return Err(ProofError::RootMismatch {
                period_id: self.period_id,
            });
        }
        if period_row.tree_size != self.inclusion.tree_size {
            return Err(ProofError::TreeSizeMismatch {
                period_id: self.period_id,
            });
        }

        // 3. Inclusion: recompute the leaf hash (RFC 6962 leaf = SHA-256(0x00 || content_hash bytes))
        //    and run the frozen verifier against the period root.
        let leaf_hash = hash_leaf(&leaf_bytes_from_content_hash(&self.content_hash)?);
        if !verify_inclusion(
            self.inclusion.leaf_index,
            self.inclusion.tree_size,
            leaf_hash,
            &self.inclusion.audit_path,
            self.inclusion.period_root,
        ) {
            return Err(ProofError::Inclusion);
        }
        Ok(())
    }

    /// The RFC 3161 anchoring state across every covered period. A period counts as anchored ONLY if
    /// its `tst_refs` entry has `anchored=true` AND a `tst_ref` present; a missing entry counts as
    /// un-anchored. This reads the bundle's OWN `tst_refs` — it does NOT verify the CMS token (P4).
    pub fn anchoring_status(&self) -> AnchoringStatus {
        let unanchored: Vec<u64> = self
            .roots_chain
            .iter()
            .filter(|row| {
                let ok = self
                    .tst_refs
                    .iter()
                    .any(|t| t.period_id == row.period_id && t.anchored && t.tst_ref.is_some());
                !ok
            })
            .map(|row| row.period_id)
            .collect();
        if unanchored.is_empty() {
            AnchoringStatus::FullyAnchored
        } else {
            AnchoringStatus::Unanchored {
                periods: unanchored,
            }
        }
    }

    /// STRUCTURAL verification ([`Self::verify`]) AND a requirement that every covered period is RFC
    /// 3161 anchored. Use this before presenting a bundle as externally-timestamped tamper-evidence:
    /// [`Self::verify`] alone passes on un-anchored roots (inclusion + chain-linkage only), which must
    /// not be mistaken for anchored evidence. Returns [`ProofError::Unanchored`] if any period lacks a token.
    pub fn verify_anchored(&self) -> Result<(), ProofError> {
        self.verify()?;
        match self.anchoring_status() {
            AnchoringStatus::FullyAnchored => Ok(()),
            AnchoringStatus::Unanchored { periods } => Err(ProofError::Unanchored { periods }),
        }
    }

    /// Serialize to a stable JSON document (hashes as lowercase hex). This is the emitted artifact.
    pub fn to_json(&self) -> Value {
        let (fully_anchored, unanchored_periods) = match self.anchoring_status() {
            AnchoringStatus::FullyAnchored => (true, Vec::new()),
            AnchoringStatus::Unanchored { periods } => (false, periods),
        };
        json!({
            "adr": "ADR-043",
            "kind": "commitment-inclusion-proof",
            "profile": MAC_SPEC_VERSION,
            "algorithm": TREE_ALGORITHM,
            "content_hash": self.content_hash,
            "org_id": self.org_id,
            "period_id": self.period_id,
            // PROMINENT anchoring claim: false ⇒ inclusion + chain-linkage only, NOT externally
            // timestamped. A consumer must not treat an un-anchored bundle as timestamped evidence.
            "fully_anchored": fully_anchored,
            "unanchored_periods": unanchored_periods,
            "inclusion": {
                "leaf_index": self.inclusion.leaf_index,
                "tree_size": self.inclusion.tree_size,
                "period_root": hex::encode(self.inclusion.period_root),
                "audit_path": self.inclusion.audit_path.iter().map(hex::encode).collect::<Vec<_>>(),
            },
            "roots_chain": self.roots_chain.iter().map(|r| json!({
                "period_id": r.period_id,
                "root_hash": hex::encode(r.root_hash),
                "prev_root_hash": hex::encode(r.prev_root_hash),
                "tree_size": r.tree_size,
                "algorithm": r.algorithm,
                "canon": r.canon,
            })).collect::<Vec<_>>(),
            "tst_refs": self.tst_refs.iter().map(|t| json!({
                "period_id": t.period_id,
                "tst_ref": t.tst_ref,
                "gen_time_unix": t.gen_time_unix,
                "serial_hex": t.serial_hex,
                "anchored": t.anchored,
            })).collect::<Vec<_>>(),
            "verification": "STRUCTURAL: verify_chain(roots_chain)==OK AND \
                verify_inclusion(leaf_index, tree_size, hash_leaf(decode(content_hash)), audit_path, \
                period_root)==true AND period_root==roots_chain[period_id].root_hash. \
                ANCHORING is a SEPARATE claim (`fully_anchored`): when false, this is inclusion + \
                chain-linkage only, NOT externally-timestamped evidence. Even when true, the RFC 3161 \
                CMS signature/chain is NOT verified here (P4); T5 needs the P3 customer co-anchor.",
        })
    }

    /// Parse a [`ProofBundle`] back from its [`Self::to_json`] form (what an offline auditor reads).
    /// Does NOT verify — call [`Self::verify`] after parsing.
    pub fn from_json(v: &Value) -> Result<Self, MerkleError> {
        // General 32-byte lowercase-hex decoder for audit-path nodes / root_hash / prev_root_hash.
        // Wraps the crate's decoder (same 64-char lowercase-hex contract) but keeps the caller's
        // `ctx` in the error so a bad audit-path node does not surface a "content_hash" message.
        fn hx(v: &Value, ctx: &str) -> Result<Hash, MerkleError> {
            let s = v
                .as_str()
                .ok_or_else(|| MerkleError(format!("{ctx}: expected hex string")))?;
            leaf_bytes_from_content_hash(s).map_err(|e| MerkleError(format!("{ctx}: {}", e.0)))
        }
        fn u(v: &Value, ctx: &str) -> Result<u64, MerkleError> {
            v.as_u64()
                .ok_or_else(|| MerkleError(format!("{ctx}: expected integer")))
        }
        fn s(v: &Value, ctx: &str) -> Result<String, MerkleError> {
            Ok(v.as_str()
                .ok_or_else(|| MerkleError(format!("{ctx}: expected string")))?
                .to_string())
        }

        let inc = &v["inclusion"];
        let audit_path = inc["audit_path"]
            .as_array()
            .ok_or_else(|| MerkleError("inclusion.audit_path: expected array".into()))?
            .iter()
            .map(|h| hx(h, "audit_path node"))
            .collect::<Result<Vec<Hash>, MerkleError>>()?;
        let inclusion = InclusionProof {
            leaf_index: u(&inc["leaf_index"], "inclusion.leaf_index")? as usize,
            tree_size: u(&inc["tree_size"], "inclusion.tree_size")? as usize,
            period_root: hx(&inc["period_root"], "inclusion.period_root")?,
            audit_path,
        };

        let roots_chain = v["roots_chain"]
            .as_array()
            .ok_or_else(|| MerkleError("roots_chain: expected array".into()))?
            .iter()
            .map(|r| {
                Ok(BundleChainRow {
                    period_id: u(&r["period_id"], "row.period_id")?,
                    root_hash: hx(&r["root_hash"], "row.root_hash")?,
                    prev_root_hash: hx(&r["prev_root_hash"], "row.prev_root_hash")?,
                    tree_size: u(&r["tree_size"], "row.tree_size")? as usize,
                    algorithm: s(&r["algorithm"], "row.algorithm")?,
                    canon: s(&r["canon"], "row.canon")?,
                })
            })
            .collect::<Result<Vec<BundleChainRow>, MerkleError>>()?;

        let tst_refs = v["tst_refs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|t| {
                        Ok(TstRef {
                            period_id: u(&t["period_id"], "tst.period_id")?,
                            tst_ref: t["tst_ref"].as_str().map(|s| s.to_string()),
                            gen_time_unix: t["gen_time_unix"].as_u64(),
                            serial_hex: t["serial_hex"].as_str().map(|s| s.to_string()),
                            anchored: t["anchored"].as_bool().unwrap_or(false),
                        })
                    })
                    .collect::<Result<Vec<TstRef>, MerkleError>>()
            })
            .transpose()?
            .unwrap_or_default();

        Ok(ProofBundle {
            content_hash: s(&v["content_hash"], "content_hash")?,
            org_id: s(&v["org_id"], "org_id")?,
            period_id: u(&v["period_id"], "period_id")?,
            inclusion,
            roots_chain,
            tst_refs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roots_chain::build_roots_chain;
    use sha2::{Digest, Sha256};

    /// content_hash = lowercase-hex sha256(label) — the frozen `chain_vectors` label convention
    /// (identical to the producer tests, so p1/p2 roots reproduce byte-for-byte).
    fn content_hash(label: &str) -> String {
        hex::encode(Sha256::digest(label.as_bytes()))
    }

    const P1_ROOT: &str = "35b5f2709beff9c7b55f267051ed89309cd899d79ad4ac205ff77ce8eeb65859";
    const P2_ROOT: &str = "5fb58d89ca9e40abece0d6b1447d5783094112244c17e9b5b7aa5c89c84f8012";

    // The frozen inclusion KAT (from chain_verify.rs / vectors): leaf 1 of the size-3 p2 tree.
    const KAT_CONTENT_HASH: &str =
        "88496c1549d5dc5f6a0d91963892d3b681fc18540ebb3bd79c769a7a5993271a";
    const KAT_PATH_0: &str = "1eef9df07f41a67a133a2a383f42e0d494bb5a22b8d1ca8a2b1d8fb6f42218b3";
    const KAT_PATH_1: &str = "f0f1a01391c7d35f6b2d016450b77f36db19f2652e957cfeddac550775de99b7";

    fn p2_leaves() -> Vec<String> {
        vec![
            content_hash("leaf-C"),
            content_hash("leaf-D"),
            content_hash("leaf-E"),
        ]
    }

    /// The re-derived inclusion proof for the frozen KAT leaf reproduces the frozen leaf_index +
    /// audit path + period_root (5fb58d…), AND verifies via the crate's `verify_inclusion`.
    #[test]
    fn build_inclusion_reproduces_frozen_kat() {
        let inc = build_inclusion_proof(KAT_CONTENT_HASH, &p2_leaves()).unwrap();
        assert_eq!(inc.leaf_index, 1, "frozen KAT is leaf 1 of the size-3 tree");
        assert_eq!(inc.tree_size, 3, "p2 tree_size");
        assert_eq!(hex::encode(inc.period_root), P2_ROOT, "re-derived p2 root");
        assert_eq!(
            inc.audit_path.iter().map(hex::encode).collect::<Vec<_>>(),
            vec![KAT_PATH_0.to_string(), KAT_PATH_1.to_string()],
            "re-derived audit path == frozen KAT path"
        );
        // The exact auditor call: leaf hash = hash_leaf(decode(content_hash)).
        let leaf_hash = hash_leaf(&leaf_bytes_from_content_hash(KAT_CONTENT_HASH).unwrap());
        assert!(
            verify_inclusion(
                inc.leaf_index,
                inc.tree_size,
                leaf_hash,
                &inc.audit_path,
                inc.period_root
            ),
            "frozen KAT inclusion must verify to the period root"
        );
    }

    #[test]
    fn build_inclusion_rejects_leaf_not_in_period() {
        let absent = content_hash("leaf-NOT-COMMITTED");
        assert!(build_inclusion_proof(&absent, &p2_leaves()).is_err());
    }

    /// Build a full 3-period chain (p1=2, p2=3, p3=empty) and a bundle for the KAT leaf in p2, then
    /// verify the SEAM end-to-end: verify_chain OK, verify_inclusion==period_root, root==5fb58d…,
    /// and the period_root ties to roots_chain[period].root_hash.
    fn frozen_bundle() -> ProofBundle {
        let p1 = vec![content_hash("leaf-A"), content_hash("leaf-B")];
        let p2 = p2_leaves();
        let p3: Vec<String> = vec![];
        // Contiguous period_ids 0,1,2 (the S3 vectors' three contiguous days map to 0,1,2).
        let chain = build_roots_chain(&[(0, p1), (1, p2.clone()), (2, p3)]).unwrap();
        // Fully anchored: every covered period (0..=1, the genesis→target segment) has a TST. Empty
        // periods are also anchored by the producer, so period 2 would carry one too in a full chain.
        let tst_refs = (0u64..=1)
            .map(|pid| TstRef {
                period_id: pid,
                tst_ref: Some(format!("roots-chain-tst/org-acme/{pid}.tsr")),
                gen_time_unix: Some(1_751_760_000 + pid),
                serial_hex: Some(format!("abcd{pid}")),
                anchored: true,
            })
            .collect();
        build_proof_bundle(KAT_CONTENT_HASH, "org-acme", 1, &p2, &chain, tst_refs).unwrap()
    }

    #[test]
    fn frozen_bundle_verifies_and_reproduces_root() {
        let bundle = frozen_bundle();
        assert_eq!(bundle.verify(), Ok(()), "frozen bundle must verify");
        assert_eq!(
            hex::encode(bundle.inclusion.period_root),
            P2_ROOT,
            "period_root reproduces the frozen 5fb58d… p2 root"
        );
        // period_root ties to the anchored chain row.
        let period_row = bundle
            .roots_chain
            .iter()
            .find(|r| r.period_id == 1)
            .unwrap();
        assert_eq!(period_row.root_hash, bundle.inclusion.period_root);
        // sanity: the p2 root is not the p1 root.
        assert_ne!(hex::encode(period_row.root_hash), P1_ROOT);
    }

    #[test]
    fn bundle_json_roundtrips_and_reverifies() {
        let bundle = frozen_bundle();
        let json = bundle.to_json();
        let parsed = ProofBundle::from_json(&json).unwrap();
        assert_eq!(parsed, bundle, "JSON round-trip must be lossless");
        assert_eq!(parsed.verify(), Ok(()), "parsed bundle must re-verify");
    }

    /// TAMPER: flipping one byte of an audit-path node breaks the inclusion proof — proves the proof
    /// is bound to the exact content (a re-derived root would differ).
    #[test]
    fn tamper_audit_path_fails_inclusion() {
        let mut bundle = frozen_bundle();
        bundle.inclusion.audit_path[0][0] ^= 0x01;
        assert_eq!(
            bundle.verify(),
            Err(ProofError::Inclusion),
            "flipped audit-path node MUST fail inclusion"
        );
        // And the raw verifier agrees.
        let leaf_hash = hash_leaf(&leaf_bytes_from_content_hash(&bundle.content_hash).unwrap());
        assert!(!verify_inclusion(
            bundle.inclusion.leaf_index,
            bundle.inclusion.tree_size,
            leaf_hash,
            &bundle.inclusion.audit_path,
            bundle.inclusion.period_root
        ));
    }

    /// TAMPER: flipping the target content_hash to a DIFFERENT committed leaf must not verify under
    /// the original leaf's index+path (binds the proof to the exact content).
    #[test]
    fn tamper_content_hash_fails_inclusion() {
        let mut bundle = frozen_bundle();
        // Swap in leaf-C's content_hash if the KAT is not leaf-C (a different committed leaf); its
        // hash under the KAT's index+path must not reproduce the root.
        let other = content_hash("leaf-C");
        let other = if other == bundle.content_hash {
            content_hash("leaf-D")
        } else {
            other
        };
        bundle.content_hash = other;
        assert_eq!(bundle.verify(), Err(ProofError::Inclusion));
    }

    /// TAMPER: breaking the roots-chain hash linkage fails `verify_chain` (BrokenLink), before
    /// inclusion is even reached — the chain segment is bound to genesis.
    #[test]
    fn tamper_chain_link_fails_verify_chain() {
        let mut bundle = frozen_bundle();
        bundle.roots_chain[1].prev_root_hash = [0xBB; 32];
        assert_eq!(
            bundle.verify(),
            Err(ProofError::Chain(ChainError::BrokenLink { period_id: 1 }))
        );
    }

    /// TAMPER: substituting a forged period_root (that no longer equals the anchored chain row) is
    /// caught by the root-binding check even if it were internally consistent.
    #[test]
    fn tamper_period_root_fails_binding() {
        let mut bundle = frozen_bundle();
        bundle.inclusion.period_root[0] ^= 0x01;
        // RootMismatch fires first (period_root != anchored root_hash).
        assert_eq!(
            bundle.verify(),
            Err(ProofError::RootMismatch { period_id: 1 })
        );
    }

    /// TAMPER via JSON: flipping a hex nibble of the emitted period_root is caught on re-verify.
    #[test]
    fn tamper_json_period_root_fails_on_reverify() {
        let bundle = frozen_bundle();
        let mut json = bundle.to_json();
        let root = json["inclusion"]["period_root"]
            .as_str()
            .unwrap()
            .to_string();
        let mut chars: Vec<char> = root.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        json["inclusion"]["period_root"] = Value::from(chars.into_iter().collect::<String>());
        let parsed = ProofBundle::from_json(&json).unwrap();
        assert!(
            parsed.verify().is_err(),
            "tampered JSON root must not verify"
        );
    }

    // ---- HIGH-1: anchoring honesty ------------------------------------------------------------

    /// A fully-anchored bundle: `verify()` OK, `anchoring_status()==FullyAnchored`, `verify_anchored()` OK,
    /// and `to_json().fully_anchored == true`.
    #[test]
    fn fully_anchored_bundle_verify_anchored_ok() {
        let bundle = frozen_bundle();
        assert_eq!(bundle.verify(), Ok(()));
        assert_eq!(bundle.anchoring_status(), AnchoringStatus::FullyAnchored);
        assert_eq!(bundle.verify_anchored(), Ok(()));
        assert_eq!(bundle.to_json()["fully_anchored"], Value::Bool(true));
    }

    /// An un-anchored period (anchored=false / no tst_ref) must NOT be presented as fully valid:
    /// `verify()` still passes (inclusion + chain-linkage only), but `verify_anchored()` reports
    /// `Unanchored` and `to_json().fully_anchored == false` with the offending period surfaced.
    #[test]
    fn unanchored_bundle_verify_ok_but_verify_anchored_fails() {
        let mut bundle = frozen_bundle();
        // Drop period 0's anchoring (simulate a missing/failed RFC 3161 stamp).
        bundle.tst_refs.retain(|t| t.period_id != 0);
        // Structural verification is unaffected.
        assert_eq!(bundle.verify(), Ok(()));
        // But anchoring is now incomplete and MUST be surfaced.
        assert_eq!(
            bundle.anchoring_status(),
            AnchoringStatus::Unanchored { periods: vec![0] }
        );
        assert_eq!(
            bundle.verify_anchored(),
            Err(ProofError::Unanchored { periods: vec![0] })
        );
        let json = bundle.to_json();
        assert_eq!(json["fully_anchored"], Value::Bool(false));
        assert_eq!(json["unanchored_periods"], json!([0]));
    }

    /// `anchored=true` but a MISSING `tst_ref` still counts as un-anchored (no token to check).
    #[test]
    fn anchored_flag_without_tst_ref_is_unanchored() {
        let mut bundle = frozen_bundle();
        for t in &mut bundle.tst_refs {
            if t.period_id == 1 {
                t.tst_ref = None; // anchored flag set but no token reference
            }
        }
        assert_eq!(
            bundle.anchoring_status(),
            AnchoringStatus::Unanchored { periods: vec![1] }
        );
    }

    // ---- MEDIUM-2: duplicate content_hash parity with the producer ----------------------------

    /// A period containing a DUPLICATED content_hash: the producer (`period_root`) hashes the full
    /// multiset (no dedup), so the re-derived tree_size counts the duplicate and the root matches the
    /// anchored chain row; the bundle verifies, and the duplicate leaf's proof is deterministic (lowest index).
    #[test]
    fn duplicate_content_hash_matches_producer_and_verifies() {
        // Period with leaf-C twice + leaf-D (3 leaves, one repeated).
        let dup = content_hash("leaf-C");
        let period = vec![dup.clone(), content_hash("leaf-D"), dup.clone()];
        // Producer reference root over the SAME multiset.
        let (producer_root, producer_size) = crate::roots_chain::period_root(&period).unwrap();
        assert_eq!(producer_size, 3, "producer counts the duplicate (no dedup)");

        let inc = build_inclusion_proof(&dup, &period).unwrap();
        assert_eq!(
            inc.tree_size, 3,
            "re-derived tree_size counts the duplicate"
        );
        assert_eq!(
            inc.period_root, producer_root,
            "re-derived root matches the producer's multiset root"
        );
        // Deterministic: the two identical leaves sort adjacently; the lowest matching index is chosen.
        assert!(
            build_inclusion_proof(&dup, &period).unwrap().leaf_index == inc.leaf_index,
            "duplicate index selection must be deterministic across calls"
        );
        // Full bundle over a chain whose period 0 is this duplicated set verifies structurally.
        let chain = build_roots_chain(&[(0, period.clone())]).unwrap();
        let tst = vec![TstRef {
            period_id: 0,
            tst_ref: Some("roots-chain-tst/org/0.tsr".into()),
            gen_time_unix: Some(1),
            serial_hex: Some("00".into()),
            anchored: true,
        }];
        let bundle = build_proof_bundle(&dup, "org", 0, &period, &chain, tst).unwrap();
        assert_eq!(bundle.verify(), Ok(()));
        assert_eq!(bundle.verify_anchored(), Ok(()));
    }

    // ---- HIGH-2: captured_at → period_id targeting arithmetic ---------------------------------

    #[test]
    fn period_id_for_unix_is_days_since_epoch() {
        assert_eq!(period_id_for_unix(0), 0, "epoch is day 0");
        assert_eq!(
            period_id_for_unix(SECONDS_PER_DAY - 1),
            0,
            "just before midnight day 1"
        );
        assert_eq!(period_id_for_unix(SECONDS_PER_DAY), 1, "midnight day 1");
        // Any instant within day N maps to N: midnight, noon, and one-second-before-next-midnight.
        let n = 20_000i64;
        let midnight = n * SECONDS_PER_DAY;
        assert_eq!(period_id_for_unix(midnight), n as u64);
        assert_eq!(
            period_id_for_unix(midnight + SECONDS_PER_DAY / 2),
            n as u64,
            "noon"
        );
        assert_eq!(
            period_id_for_unix(midnight + SECONDS_PER_DAY - 1),
            n as u64,
            "23:59:59"
        );
        assert_eq!(
            period_id_for_unix(midnight + SECONDS_PER_DAY),
            (n + 1) as u64,
            "next midnight rolls the period"
        );
    }

    // ---- LOW-1: from_json error strings keep the caller ctx (not "content_hash") ---------------

    #[test]
    fn from_json_audit_path_error_uses_context_not_content_hash() {
        let bundle = frozen_bundle();
        let mut json = bundle.to_json();
        json["inclusion"]["audit_path"] = json!(["zz"]); // invalid hex
        let err = ProofBundle::from_json(&json).unwrap_err();
        assert!(
            err.0.contains("audit_path node"),
            "error must reference the audit-path context, got: {}",
            err.0
        );
    }
}
