//! ADR-043 C1 slice-1a — the ANCHOR half: verify captured `CommitmentLeaf` blobs, build the
//! MAC-1 Merkle root + per-leaf inclusion proofs, and assemble the committed auditor artifact.
//!
//! This module is the OFFLINE, network-free core (default features, so CI's `cargo test` runs it).
//! The live RFC 3161 TSA round-trip lives in the `commitment_leaf_anchor` bin (feature `tsa-client`);
//! this module builds/records the anchor facts the bin hands it and never touches the network.
//!
//! It consumes the output of the capture-at-stamp PRODUCER (cloud-backend `telemetry_forward.rs`,
//! PR #1961). The leaf JSON is:
//! ```json
//! { "content_hash": "<64-hex>", "source_kind": "enforcement",
//!   "canonical_preimage_b64": "<STANDARD base64 of the RAW canonicalize() bytes>",
//!   "canon_spec_version": "MLCH-1",
//!   "identity": { "endpoint_id":…, "org_id":…, "event_sequence":…, "event_class":…,
//!                 "captured_at":"<rfc3339>" } }
//! ```
//! The auditor re-derivation is BY CONSTRUCTION byte-faithful:
//! `sha256(base64_decode(canonical_preimage_b64)) == content_hash`. That decoded preimage is the
//! canonical MLCH-1 JSON of the enforcement record, so it also parses back to the deny facts
//! (disposition / path / control_id / endpoint).
//!
//! CLAIM BOUNDARY (ADR-043 §6, verbatim intent in [`claim_boundary_json`]): the artifact asserts
//! INCLUSION + TIMESTAMP over CAPTURED-PREIMAGE records only. It is explicitly NOT tamper-proof /
//! immutable; the T5 "cannot be silently edited" property needs the P3 customer co-anchor; and the
//! TSA's CMS signature / certificate chain is NOT verified until the P4 offline verifier.

use crate::{
    hash_leaf, inclusion_proof, leaf_bytes_from_content_hash, merkle_tree_hash, verify_inclusion,
    Hash, MAC_SPEC_VERSION, TREE_ALGORITHM,
};
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Standard (padded) base64 — MUST match the producer's `STANDARD.encode(&canonical_preimage)`.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentLeafError(pub String);
impl std::fmt::Display for CommitmentLeafError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "commitment-leaf error: {}", self.0)
    }
}
impl std::error::Error for CommitmentLeafError {}

fn err<T>(msg: impl Into<String>) -> Result<T, CommitmentLeafError> {
    Err(CommitmentLeafError(msg.into()))
}

/// Lower-hex SHA-256 of `bytes` — the auditor's re-derivation primitive.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Deny facts decoded from a File-deny enforcement preimage (surfaced into the artifact so an
/// auditor sees WHAT was blocked, not just that a hash exists). All optional — a preimage missing a
/// field yields `None` there rather than failing the whole leaf.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DenyFacts {
    pub disposition: Option<String>,
    pub target_path: Option<String>,
    pub control_id: Option<String>,
    pub endpoint: Option<String>,
    pub event_class: Option<String>,
}

impl DenyFacts {
    fn from_preimage(v: &Value) -> Self {
        let s = |val: Option<&Value>| val.and_then(Value::as_str).map(str::to_string);
        DenyFacts {
            disposition: s(v.pointer("/file_details/disposition")),
            // The producer stores the blocked path under file_details.path; accept a top-level
            // target_path fallback so a differently-shaped enforcement class still surfaces it.
            target_path: s(v.pointer("/file_details/path")).or_else(|| s(v.get("target_path"))),
            control_id: s(v.pointer("/compliance_details/control_id")),
            endpoint: s(v.get("endpoint_id")),
            event_class: s(v.get("event_class")),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "disposition": self.disposition,
            "target_path": self.target_path,
            "control_id": self.control_id,
            "endpoint": self.endpoint,
            "event_class": self.event_class,
        })
    }
}

/// A loaded leaf whose re-derivation has been checked. Construction via [`load_and_verify_leaf`]
/// FAILS LOUD on `sha256(preimage) != content_hash`, so an existing `VerifiedLeaf` is a leaf whose
/// preimage is proven to hash to its content_hash (`rederivation_ok` is therefore always true, but
/// carried explicitly so the artifact records it as an asserted fact, not an assumption).
#[derive(Debug, Clone)]
pub struct VerifiedLeaf {
    pub content_hash: String,
    pub canon_spec_version: String,
    pub source_kind: String,
    /// Raw decoded preimage bytes (base64-decoded `canonical_preimage_b64`).
    pub preimage: Vec<u8>,
    /// The preimage parsed back to JSON (the canonical enforcement record).
    pub preimage_json: Value,
    /// The leaf's `identity` object, verbatim.
    pub identity: Value,
    pub deny_facts: DenyFacts,
    pub rederivation_ok: bool,
}

/// Load + verify ONE leaf from its JSON bytes. The core auditor check: base64-decode the preimage,
/// SHA-256 it, and require it to equal the leaf's `content_hash` — FAIL LOUD on any mismatch
/// (an altered / mismatched leaf must never enter the tree).
pub fn load_and_verify_leaf(raw: &[u8]) -> Result<VerifiedLeaf, CommitmentLeafError> {
    let v: Value = serde_json::from_slice(raw)
        .map_err(|e| CommitmentLeafError(format!("leaf is not JSON: {e}")))?;

    let content_hash = match v.get("content_hash").and_then(Value::as_str) {
        Some(h) => h.to_string(),
        None => return err("leaf missing string `content_hash`"),
    };
    let b64 = match v.get("canonical_preimage_b64").and_then(Value::as_str) {
        Some(s) => s,
        None => return err("leaf missing string `canonical_preimage_b64`"),
    };
    let canon_spec_version = v
        .get("canon_spec_version")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let source_kind = v
        .get("source_kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let identity = v.get("identity").cloned().unwrap_or(Value::Null);

    let preimage = B64.decode(b64).map_err(|e| {
        CommitmentLeafError(format!("canonical_preimage_b64 is not valid base64: {e}"))
    })?;

    // THE auditor re-derivation — byte-faithful by construction. FAIL LOUD on mismatch.
    let recomputed = sha256_hex(&preimage);
    if recomputed != content_hash {
        return err(format!(
            "RE-DERIVATION FAILED — sha256(preimage)={recomputed} != content_hash={content_hash} \
             (leaf ALTERED or preimage/hash mismatch; refusing to anchor)"
        ));
    }

    // The preimage IS the canonical MLCH-1 JSON of the enforcement record — parse to surface facts.
    let preimage_json: Value = serde_json::from_slice(&preimage).map_err(|e| {
        CommitmentLeafError(format!(
            "preimage re-derives correctly but is not parseable JSON ({e}) — cannot surface deny facts"
        ))
    })?;
    let deny_facts = DenyFacts::from_preimage(&preimage_json);

    Ok(VerifiedLeaf {
        content_hash,
        canon_spec_version,
        source_kind,
        preimage,
        preimage_json,
        identity,
        deny_facts,
        rederivation_ok: true,
    })
}

/// A set of verified leaves sorted MAC-1 (content_hash-ASCENDING), with the Merkle root and a
/// per-leaf inclusion proof (parallel to `leaves`) that has been re-verified against the root.
pub struct AnchoredSet {
    /// Leaves in MAC-1 order (content_hash ascending).
    pub leaves: Vec<VerifiedLeaf>,
    /// The 32-byte leaf DATA (content_hash bytes) fed to the tree, parallel to `leaves`.
    pub leaf_data: Vec<Hash>,
    pub root: Hash,
    /// Inclusion (audit) path per leaf, parallel to `leaves`.
    pub proofs: Vec<Vec<Hash>>,
}

impl AnchoredSet {
    pub fn root_hex(&self) -> String {
        hex::encode(self.root)
    }
    pub fn tree_size(&self) -> usize {
        self.leaves.len()
    }
}

/// Sort leaves MAC-1 (content_hash ascending), build the root, generate every leaf's inclusion
/// proof, and RE-VERIFY each proof against the root (a proof that does not verify is a hard error —
/// the tooling must never emit an artifact whose own proofs don't check).
pub fn build_anchored_set(
    mut leaves: Vec<VerifiedLeaf>,
) -> Result<AnchoredSet, CommitmentLeafError> {
    if leaves.is_empty() {
        return err("no commitment leaves to anchor");
    }
    // MAC-1 ordering: content_hash ASCENDING.
    leaves.sort_by(|a, b| a.content_hash.cmp(&b.content_hash));

    let mut leaf_data: Vec<Hash> = Vec::with_capacity(leaves.len());
    for l in &leaves {
        let h = leaf_bytes_from_content_hash(&l.content_hash)
            .map_err(|e| CommitmentLeafError(format!("leaf {}: {e}", l.content_hash)))?;
        leaf_data.push(h);
    }

    let root = merkle_tree_hash(&leaf_data);
    let n = leaf_data.len();
    let mut proofs: Vec<Vec<Hash>> = Vec::with_capacity(n);
    for (i, ld) in leaf_data.iter().enumerate() {
        let proof = inclusion_proof(i, &leaf_data)
            .map_err(|e| CommitmentLeafError(format!("inclusion_proof idx {i}: {e}")))?;
        if !verify_inclusion(i, n, hash_leaf(ld), &proof, root) {
            return err(format!(
                "self-check FAILED: generated inclusion proof for idx {i} does not verify against the root"
            ));
        }
        proofs.push(proof);
    }

    Ok(AnchoredSet {
        leaves,
        leaf_data,
        root,
        proofs,
    })
}

/// The RFC 3161 anchor outcome the bin hands to [`build_artifact`]. `Anchored` after a live TSA
/// round-trip; `Pending` when the TSA was unreachable — we still record the BUILT request DER and
/// never fabricate a token (ADR-043 §6 honesty boundary).
pub enum TstStatus {
    Anchored {
        tsa_url: String,
        /// The raw RFC 3161 `TimeStampResp` DER, base64 (STANDARD).
        response_der_b64: String,
        gen_time_unix: u64,
        serial_hex: String,
    },
    Pending {
        tsa_url: String,
        reason: String,
        /// The RFC 3161 `TimeStampReq` DER we built over the root, base64 (STANDARD) — no token faked.
        request_der_b64: String,
    },
}

/// Base64 (STANDARD) helper so the bin encodes DER exactly as this module's tests expect.
pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

impl TstStatus {
    fn to_json(&self) -> Value {
        match self {
            TstStatus::Anchored {
                tsa_url,
                response_der_b64,
                gen_time_unix,
                serial_hex,
            } => json!({
                "status": "ANCHORED",
                "tsa_url": tsa_url,
                "rfc3161_response_der_b64": response_der_b64,
                "gen_time_unix": gen_time_unix,
                "serial_hex": serial_hex,
                "boundary_note": "Imprint-coverage + asserted time were checked (the TST's messageImprint IS the Merkle root). The TSA's CMS signature and certificate CHAIN are NOT verified here — that is the P4 offline verifier. Do not quote this as cryptographic proof.",
            }),
            TstStatus::Pending {
                tsa_url,
                reason,
                request_der_b64,
            } => json!({
                "status": "TST_PENDING",
                "tsa_url": tsa_url,
                "reason": reason,
                "rfc3161_request_der_b64": request_der_b64,
                "note": "TSA was unreachable at runtime. The built RFC 3161 request over this exact root is recorded so the anchor can be completed later. NO timestamp token was fabricated (ADR-043 §6).",
            }),
        }
    }
}

/// The verbatim CLAIM BOUNDARY block (ADR-043 §6). Emitted into every artifact so the guarantee is
/// stated where the evidence is — an auditor never has to infer the scope.
pub fn claim_boundary_json() -> Value {
    json!({
        "spec": "ADR-043 slice-1a",
        "asserts": [
            "INCLUSION: each listed content_hash is a leaf of the stated MAC-1 Merkle root, proven by its recorded RFC 6962 audit path.",
            "TIMESTAMP: the Merkle root was submitted to an RFC 3161 TSA whose token's messageImprint IS that root (existence-before-time), when status=ANCHORED.",
            "RE-DERIVATION: for every leaf, sha256(base64_decode(canonical_preimage_b64)) == content_hash — the captured preimage byte-faithfully hashes to the committed value.",
            "SCOPE: these properties hold over the CAPTURED-PREIMAGE records only (what the producer persisted at stamp time)."
        ],
        "does_not_assert": [
            "NOT tamper-proof / NOT immutable: this artifact demonstrates inclusion + a trusted timestamp; it does not by itself prevent or prove non-editing of the underlying store.",
            "T5 'cannot be silently edited' is NOT established here — it requires the P3 CUSTOMER CO-ANCHOR (an independent party also holding the root).",
            "TSA CMS SIGNATURE / CERTIFICATE CHAIN is NOT verified — extract-only (imprint match + time). Full cryptographic verification is the P4 offline verifier.",
            "Does not attest correctness of the enforcement decision, only that the captured record was included and timestamped."
        ]
    })
}

/// One leaf's JSON block for the artifact.
fn leaf_json(leaf: &VerifiedLeaf, index: usize, leaf_data: &Hash, proof: &[Hash]) -> Value {
    json!({
        "leaf_index": index,
        "content_hash": leaf.content_hash,
        "source_kind": leaf.source_kind,
        "canon_spec_version": leaf.canon_spec_version,
        "rederivation": {
            "method": "sha256(base64_decode(canonical_preimage_b64))",
            "ok": leaf.rederivation_ok,
            "recomputed_content_hash": sha256_hex(&leaf.preimage),
            "preimage_bytes": leaf.preimage.len(),
        },
        "identity": leaf.identity,
        "deny_facts": leaf.deny_facts.to_json(),
        "inclusion_proof": {
            "leaf_hash": hex::encode(hash_leaf(leaf_data)),
            "audit_path": proof.iter().map(hex::encode).collect::<Vec<_>>(),
            "verified": true,
        },
    })
}

/// Assemble the committed auditor artifact JSON: identities, per-leaf re-derivation + deny facts,
/// the Merkle root, per-leaf inclusion proofs, the TST facts, and the verbatim claim boundary.
pub fn build_artifact(set: &AnchoredSet, tst: &TstStatus) -> Value {
    let leaves: Vec<Value> = set
        .leaves
        .iter()
        .enumerate()
        .map(|(i, l)| leaf_json(l, i, &set.leaf_data[i], &set.proofs[i]))
        .collect();

    json!({
        "artifact_version": "1",
        "adr": "ADR-043",
        "slice": "1a",
        "title": "Commitment-leaf inclusion + RFC 3161 timestamp anchor",
        "spec": {
            "canon_spec_version": "MLCH-1",
            "mac_spec_version": MAC_SPEC_VERSION,
            "tree_algorithm": TREE_ALGORITHM,
            "leaf_ordering": "content_hash ASCENDING (MAC-1)",
            "leaf_data": "32 raw bytes of content_hash (RFC 6962 leaf over 0x00||leaf_data)",
        },
        "merkle_root": set.root_hex(),
        "tree_size": set.tree_size(),
        "leaves": leaves,
        "timestamp_anchor": tst.to_json(),
        "claim_boundary": claim_boundary_json(),
    })
}

/// Auditor-facing "how to reproduce this yourself" narrative (markdown).
pub fn verification_narrative_md(set: &AnchoredSet, tst: &TstStatus) -> String {
    let mut s = String::new();
    s.push_str("# ADR-043 slice-1a — how an auditor reproduces this artifact\n\n");
    s.push_str(&format!(
        "Merkle root: `{}` over **{}** commitment leaf(ves), ordered content_hash-ascending (MAC-1).\n\n",
        set.root_hex(),
        set.tree_size()
    ));
    s.push_str("For EACH leaf in the artifact:\n\n");
    s.push_str("1. **Re-derive** — base64-decode `canonical_preimage_b64` to the raw preimage bytes, then `sha256(preimage)`. It MUST equal the leaf's `content_hash`. This is byte-faithful by construction: the producer captured these exact bytes at stamp time.\n");
    s.push_str("2. **Leaf** — the tree leaf DATA is the 32 raw bytes of that `content_hash`; the RFC 6962 leaf hash is `sha256(0x00 || leaf_data)`.\n");
    s.push_str("3. **Inclusion** — fold the leaf hash with the recorded `audit_path` (RFC 6962 / RFC 9162 iterative verifier). The result MUST equal the `merkle_root`.\n");
    s.push_str("4. **Inspect** — the decoded preimage is the canonical MLCH-1 JSON of the enforcement record; parse it to read `disposition` / path / `control_id` / endpoint (surfaced as `deny_facts`).\n\n");
    match tst {
        TstStatus::Anchored {
            tsa_url,
            gen_time_unix,
            ..
        } => {
            s.push_str(&format!(
                "5. **Timestamp** — the artifact's `rfc3161_response_der_b64` is the TSA (`{tsa_url}`) `TimeStampResp`. Decode it and confirm the token's `messageImprint` IS the `merkle_root`, and read its `genTime` (asserted unix {gen_time_unix}). Existence-before-time: the root — hence every included record — existed no later than that time.\n\n"
            ));
        }
        TstStatus::Pending {
            tsa_url, reason, ..
        } => {
            s.push_str(&format!(
                "5. **Timestamp (PENDING)** — the live TSA (`{tsa_url}`) was unreachable ({reason}). The artifact records the BUILT RFC 3161 request over this exact root (`rfc3161_request_der_b64`); no token was fabricated. Re-submit that request to any RFC 3161 TSA to complete the anchor.\n\n"
            ));
        }
    }
    s.push_str("**Bit-flip counter-check** — flip any bit of a preimage: step 1 fails (`sha256(preimage) != content_hash`) AND step 3 fails (the altered leaf's hash no longer folds to the root). Altered / not-in-log is correctly rejected.\n\n");
    s.push_str("## Claim boundary\n\n");
    s.push_str("- **Asserts:** inclusion of each captured content_hash in the root, and (when ANCHORED) a trusted timestamp over that root, plus byte-faithful re-derivation of each preimage.\n");
    s.push_str("- **Does NOT assert:** tamper-proof / immutability; the T5 'cannot be silently edited' property (needs the P3 customer co-anchor); TSA CMS signature/chain validity (P4 offline verifier).\n");
    s
}

/// Result of the bit-flip counter-demonstration on one leaf (all offline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitFlipDemo {
    /// The unaltered leaf verifies (sanity): sha256 matches AND it is included.
    pub original_rederivation_ok: bool,
    pub original_inclusion_ok: bool,
    /// After flipping one preimage bit: sha256 no longer matches content_hash.
    pub altered_rederivation_ok: bool,
    /// After flipping one preimage bit: the recomputed leaf no longer folds to the root.
    /// (`None` when the altered content_hash is not decodable as a leaf — also a rejection.)
    pub altered_inclusion_ok: bool,
    pub original_content_hash: String,
    pub altered_content_hash: String,
}

impl BitFlipDemo {
    /// True iff the demo shows the correct behaviour: original accepted, altered rejected on BOTH
    /// the re-derivation and the inclusion check.
    pub fn correctly_rejected(&self) -> bool {
        self.original_rederivation_ok
            && self.original_inclusion_ok
            && !self.altered_rederivation_ok
            && !self.altered_inclusion_ok
    }
}

/// Flip one bit of leaf `index`'s preimage and show that (a) `sha256(preimage) != content_hash` and
/// (b) the altered leaf no longer verifies inclusion against the unchanged root/proof — while the
/// original still does. Pure/offline.
pub fn bit_flip_demo(set: &AnchoredSet, index: usize) -> Result<BitFlipDemo, CommitmentLeafError> {
    let leaf = set
        .leaves
        .get(index)
        .ok_or_else(|| CommitmentLeafError(format!("bit_flip_demo: index {index} out of range")))?;
    if leaf.preimage.is_empty() {
        return err("bit_flip_demo: leaf preimage is empty");
    }
    let n = set.leaves.len();
    let proof = &set.proofs[index];
    let root = set.root;

    // Original sanity.
    let original_content_hash = leaf.content_hash.clone();
    let original_rederivation_ok = sha256_hex(&leaf.preimage) == original_content_hash;
    let original_inclusion_ok =
        verify_inclusion(index, n, hash_leaf(&set.leaf_data[index]), proof, root);

    // Flip a bit → altered preimage → altered content_hash.
    let mut altered = leaf.preimage.clone();
    altered[0] ^= 0x01;
    let altered_content_hash = sha256_hex(&altered);
    let altered_rederivation_ok = altered_content_hash == original_content_hash; // must be false

    // The altered content_hash yields a different leaf-data → recompute its leaf hash and check it
    // against the SAME index+proof+root the original occupied. Must NOT verify.
    let altered_inclusion_ok = match leaf_bytes_from_content_hash(&altered_content_hash) {
        Ok(ld) => verify_inclusion(index, n, hash_leaf(&ld), proof, root),
        Err(_) => false, // undecodable → treated as not-in-log (rejected)
    };

    Ok(BitFlipDemo {
        original_rederivation_ok,
        original_inclusion_ok,
        altered_rederivation_ok,
        altered_inclusion_ok,
        original_content_hash,
        altered_content_hash,
    })
}

/// Synthesize a self-consistent `CommitmentLeaf` JSON blob OFFLINE from an enforcement-record
/// preimage `Value` — used by the tests and by the bin's `--gen-samples` mode to produce
/// reproducible demo input WITHOUT the producer or the network. `content_hash` is computed FROM the
/// serialized preimage bytes, so `sha256(base64_decode(canonical_preimage_b64)) == content_hash`
/// holds by construction (exactly what the producer guarantees).
pub fn synthesize_leaf_blob(
    preimage: &Value,
    identity: &Value,
) -> Result<Vec<u8>, CommitmentLeafError> {
    // Compact, deterministic bytes stand in for the producer's MLCH-1 canonical bytes: the anchor
    // tool is agnostic to the preimage's internal byte-format — it requires only that the recorded
    // bytes hash to content_hash and parse as JSON (both true here).
    let preimage_bytes = serde_json::to_vec(preimage)
        .map_err(|e| CommitmentLeafError(format!("serialize synthetic preimage: {e}")))?;
    let content_hash = sha256_hex(&preimage_bytes);
    let blob = json!({
        "leaf_version": "1",
        "content_hash": content_hash,
        "canon_spec_version": "MLCH-1",
        "source_kind": "enforcement",
        "canonical_preimage_b64": B64.encode(&preimage_bytes),
        "identity": identity,
    });
    serde_json::to_vec_pretty(&blob)
        .map_err(|e| CommitmentLeafError(format!("serialize synthetic leaf: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic enforcement File-deny preimage + identity for a given path/control/seq.
    fn synth(path: &str, control: &str, seq: u64) -> (Value, Value) {
        let preimage = json!({
            "event_class": "File",
            "endpoint_id": "EP-aaaaaaaaaaaaaaaa",
            "organization_id": "org-acme",
            "event_id": seq,
            "file_details": { "disposition": "deny", "path": path, "status": 3221225488i64 },
            "compliance_details": { "control_id": control, "framework": "SOC2" },
        });
        let identity = json!({
            "endpoint_id": "EP-aaaaaaaaaaaaaaaa",
            "org_id": "org-acme",
            "event_sequence": seq,
            "event_class": "File",
            "captured_at": "2026-07-05T00:00:00+00:00",
        });
        (preimage, identity)
    }

    fn synth_leaf(path: &str, control: &str, seq: u64) -> VerifiedLeaf {
        let (p, id) = synth(path, control, seq);
        let blob = synthesize_leaf_blob(&p, &id).expect("synthesize");
        load_and_verify_leaf(&blob).expect("load+verify")
    }

    #[test]
    fn rederivation_holds_sha256_preimage_equals_content_hash() {
        let (p, id) = synth("C:/secret/payroll.xlsx", "SOC2-CC6.1", 1);
        let blob = synthesize_leaf_blob(&p, &id).unwrap();
        let leaf = load_and_verify_leaf(&blob).expect("must load");
        // THE re-derivation assert: sha256(preimage) == content_hash.
        assert_eq!(sha256_hex(&leaf.preimage), leaf.content_hash);
        assert!(leaf.rederivation_ok);
        // Deny facts were surfaced from the decoded preimage.
        assert_eq!(leaf.deny_facts.disposition.as_deref(), Some("deny"));
        assert_eq!(
            leaf.deny_facts.target_path.as_deref(),
            Some("C:/secret/payroll.xlsx")
        );
        assert_eq!(leaf.deny_facts.control_id.as_deref(), Some("SOC2-CC6.1"));
        assert_eq!(
            leaf.deny_facts.endpoint.as_deref(),
            Some("EP-aaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn tampered_content_hash_fails_loud_on_load() {
        let (p, id) = synth("C:/x", "SOC2-CC6.1", 1);
        let mut blob: Value =
            serde_json::from_slice(&synthesize_leaf_blob(&p, &id).unwrap()).unwrap();
        // Corrupt the recorded content_hash so it no longer matches the preimage.
        blob["content_hash"] = json!("0".repeat(64));
        let raw = serde_json::to_vec(&blob).unwrap();
        let e = load_and_verify_leaf(&raw).expect_err("mismatch MUST fail loud");
        assert!(e.0.contains("RE-DERIVATION FAILED"), "got: {}", e.0);
    }

    #[test]
    fn multi_leaf_root_and_all_inclusion_proofs_verify() {
        let leaves = vec![
            synth_leaf("C:/a", "SOC2-CC6.1", 1),
            synth_leaf("C:/b", "SOC2-CC6.7", 2),
            synth_leaf("C:/c", "SOC2-CC7.2", 3),
            synth_leaf("C:/d", "SOC2-CC6.1", 4),
            synth_leaf("C:/e", "SOC2-CC6.1", 5),
        ];
        let set = build_anchored_set(leaves).expect("anchor set");
        // MAC-1: content_hash ascending.
        for w in set.leaves.windows(2) {
            assert!(w[0].content_hash <= w[1].content_hash, "not MAC-1 sorted");
        }
        // Every proof verifies against the root (build_anchored_set already self-checks, re-assert).
        let n = set.tree_size();
        for i in 0..n {
            assert!(
                verify_inclusion(i, n, hash_leaf(&set.leaf_data[i]), &set.proofs[i], set.root),
                "inclusion idx {i}"
            );
        }
    }

    #[test]
    fn bit_flip_rejects_on_both_rederivation_and_inclusion() {
        let leaves = vec![
            synth_leaf("C:/a", "SOC2-CC6.1", 1),
            synth_leaf("C:/b", "SOC2-CC6.7", 2),
            synth_leaf("C:/c", "SOC2-CC7.2", 3),
        ];
        let set = build_anchored_set(leaves).expect("anchor set");
        for i in 0..set.tree_size() {
            let d = bit_flip_demo(&set, i).expect("demo");
            assert!(d.original_rederivation_ok, "orig re-derivation idx {i}");
            assert!(d.original_inclusion_ok, "orig inclusion idx {i}");
            // The two rejections the counter-demo must show:
            assert!(
                !d.altered_rederivation_ok,
                "altered sha256 MUST differ idx {i}"
            );
            assert!(
                !d.altered_inclusion_ok,
                "altered leaf MUST NOT be in log idx {i}"
            );
            assert!(d.correctly_rejected(), "idx {i} must be correctly rejected");
            assert_ne!(d.original_content_hash, d.altered_content_hash);
        }
    }

    #[test]
    fn artifact_has_claim_boundary_and_per_leaf_proofs() {
        let leaves = vec![
            synth_leaf("C:/a", "SOC2-CC6.1", 1),
            synth_leaf("C:/b", "SOC2-CC6.7", 2),
        ];
        let set = build_anchored_set(leaves).expect("anchor set");
        // Offline TST_PENDING path (no network).
        let tst = TstStatus::Pending {
            tsa_url: "https://freetsa.org/tsr".into(),
            reason: "offline unit test".into(),
            request_der_b64: b64_encode(&crate::anchor::build_timestamp_request(set.root).unwrap()),
        };
        let art = build_artifact(&set, &tst);

        // Claim boundary present + says the load-bearing things.
        let cb = &art["claim_boundary"];
        assert!(cb.is_object(), "claim_boundary must be present");
        let text = serde_json::to_string(cb).unwrap();
        assert!(
            text.contains("NOT tamper-proof"),
            "must disclaim tamper-proof"
        );
        assert!(
            text.contains("P3 CUSTOMER CO-ANCHOR"),
            "must reference P3 co-anchor for T5"
        );
        assert!(
            text.contains("CERTIFICATE CHAIN is NOT verified"),
            "must disclaim TSA chain (P4)"
        );

        // Root + tree_size + per-leaf inclusion proofs present, one per leaf, all verified=true.
        assert_eq!(art["merkle_root"].as_str().unwrap(), set.root_hex());
        assert_eq!(art["tree_size"].as_u64().unwrap() as usize, set.tree_size());
        let arr = art["leaves"].as_array().unwrap();
        assert_eq!(arr.len(), set.tree_size());
        for (i, lj) in arr.iter().enumerate() {
            assert_eq!(lj["leaf_index"].as_u64().unwrap() as usize, i);
            assert_eq!(lj["rederivation"]["ok"], json!(true));
            assert_eq!(lj["inclusion_proof"]["verified"], json!(true));
            assert!(
                lj["inclusion_proof"]["audit_path"].is_array(),
                "audit_path must be present"
            );
            assert!(lj["deny_facts"]["disposition"].is_string());
        }

        // TST_PENDING carries the built request, no fabricated token.
        assert_eq!(art["timestamp_anchor"]["status"], json!("TST_PENDING"));
        assert!(art["timestamp_anchor"]["rfc3161_request_der_b64"].is_string());
        assert!(art["timestamp_anchor"]
            .get("rfc3161_response_der_b64")
            .is_none());
    }

    #[test]
    fn narrative_covers_rederivation_inclusion_and_timestamp() {
        let set = build_anchored_set(vec![synth_leaf("C:/a", "SOC2-CC6.1", 1)]).unwrap();
        let tst = TstStatus::Anchored {
            tsa_url: "https://freetsa.org/tsr".into(),
            response_der_b64: "AA==".into(),
            gen_time_unix: 1_751_000_000,
            serial_hex: "04".into(),
        };
        let md = verification_narrative_md(&set, &tst);
        assert!(md.contains("sha256(preimage)"), "narrative: re-derivation");
        assert!(md.contains("audit_path"), "narrative: inclusion");
        assert!(md.contains("messageImprint"), "narrative: timestamp");
        assert!(md.contains("Bit-flip"), "narrative: counter-check");
    }

    #[test]
    fn empty_set_is_error() {
        assert!(build_anchored_set(vec![]).is_err());
    }
}
