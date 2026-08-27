//! GENERIC hash-linked record chain (ADR-025 / ADR-176) — the ONE shared tamper-evidence primitive.
//!
//! The decision chain ([`crate::decision_chain`]) is a hash-linked, signed, re-derivable chain of leaves
//! whose only decision-specific piece is the RECORD's canonicalization ([`crate::decision_record`]). The
//! leaf/chain machinery — [`crate::signed_leaf::build_commitment_leaf_with_spec`],
//! [`crate::signed_leaf::sign_leaf`], `row_from_signed`, `decision_chain_hash`, the locked durable append —
//! is entirely record-agnostic. This module exposes that machinery generically so a NEW record type (the
//! ADR-025 offline-cache telemetry-batch WAL) can share the SAME primitive instead of forking a parallel
//! chain: one primitive is the only way the ADR-176 cross-OS symmetry holds, and the only place the
//! signing/canon discipline can't drift.
//!
//! ## Domain separation lives in the signed ENVELOPE, not the content_hash
//! A leaf's `source_kind` is part of the signed leaf envelope (`sign_leaf` covers
//! `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes`, which includes `source_kind`), NOT inside the
//! `content_hash` preimage. So a record's `content_hash` stays byte-identical to the same content produced
//! elsewhere (e.g. the lake leaf for a telemetry batch — the re-derivation cross-check), while a telemetry
//! leaf still cannot be re-presented as a decision leaf: the signature binds `source_kind`, and the
//! OBLIGATION this puts on a verifier is that it MUST pin the `source_kind` it expects for a chain (reject a
//! row whose `source_kind` is not the chain's domain). Envelope separation is only sound with that pin.

use serde_json::Value;

use crate::decision_chain::{append_leaf_to_file, DecisionChainRow};

/// A record that can be committed as ONE leaf on a [generic chain](append_record_to_file). It yields the
/// three leaf-INTRINSIC values; provenance `identity` (endpoint/org, and the `event_sequence` the chain
/// stamps under its append lock) is CONTEXTUAL and supplied at append time — exactly how the decision
/// chain already separates the "what" (record) from the "where/who" (identity).
pub trait LeafRecord {
    /// Signed-ENVELOPE domain tag — the cross-type replay boundary. e.g. `"enforcement_decision"`,
    /// `"meshlogic.offline-cache.telemetry-batch"`. A verifier MUST pin the value it expects for a chain.
    fn source_kind(&self) -> &str;
    /// The record's STAMPED canonicalization spec (e.g. `"MLCH-1"`); a verifier re-derives THIS leaf under
    /// this spec (canonicalize-by-stamped-version), never a sibling leaf's spec.
    fn canon_spec_version(&self) -> &str;
    /// The canonical (JCS / MLCH) preimage bytes — `sha256` of these is the leaf `content_hash`.
    fn canonical_preimage(&self) -> Vec<u8>;
}

/// The tip of a chain after an append: `chain_hash` is what an external anchor (increment-2 / P3) pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainHead {
    /// 0-based position of the appended row in the chain.
    pub seq: u64,
    /// The new tip hash (`sha256_hex(prev_tip_hex + content_hash_hex)`).
    pub chain_hash: String,
}

impl From<DecisionChainRow> for ChainHead {
    fn from(row: DecisionChainRow) -> Self {
        ChainHead {
            seq: row.seq,
            chain_hash: row.chain_hash,
        }
    }
}

/// Append `record` as ONE SIGNED leaf on the chain file at `path`, returning the new [`ChainHead`].
/// `identity` is the provenance descriptor (endpoint/org); the chain stamps `event_sequence` into it under
/// the per-path append lock. `signing_key`/`key_id` are the INJECTED ADR-062 enrolled per-agent identity —
/// never a global handle (ADR-025 §5). Durable: per-path append lock + fsync, same as the decision chain.
pub fn append_record_to_file<R: LeafRecord>(
    path: &std::path::Path,
    record: &R,
    identity: Value,
    signing_key: &ed25519_dalek::SigningKey,
    key_id: &str,
) -> std::io::Result<ChainHead> {
    let preimage = record.canonical_preimage();
    let row = append_leaf_to_file(
        path,
        record.source_kind(),
        record.canon_spec_version(),
        &preimage,
        identity,
        signing_key,
        key_id,
    )?;
    Ok(ChainHead::from(row))
}

/// [`crate::decision_record::DecisionRecord`] is ONE leaf type on the generic chain. This impl routes to
/// the EXACT frozen decision canonicalization and the same `source_kind_for` / `"MLCH-1"` the decision
/// chain uses, so a `DecisionRecord` appended via [`append_record_to_file`] is byte-identical to one
/// appended via [`crate::decision_chain::append_decision_to_file`] (asserted by the tests below — the
/// preimage-stability gate that protects every already-anchored decision leaf).
impl LeafRecord for crate::decision_record::DecisionRecord<'_> {
    fn source_kind(&self) -> &str {
        crate::decision_record::source_kind_for(self.rule_kind)
    }
    fn canon_spec_version(&self) -> &str {
        "MLCH-1"
    }
    fn canonical_preimage(&self) -> Vec<u8> {
        crate::decision_record::canonical_preimage(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision_record::{
        canonical_preimage as dr_canonical_preimage, source_kind_for, DecisionRecord,
    };
    use crate::signed_leaf::{build_commitment_leaf, build_commitment_leaf_with_spec};
    use serde_json::json;

    fn sample() -> DecisionRecord<'static> {
        DecisionRecord {
            event_id: 42,
            ts: 116_444_736_000_000_001,
            decision: "deny",
            rule_kind: "policy",
            rule_id: "builtin.sensitive_file",
            data_class: 8,
            actor_pid: 1234,
            actor_path: r"C:\Program Files\Claude\claude.exe",
            object_path: Some(r"C:\Users\a\.aws\credentials"),
            object_content_hash: None,
            object_file_id: None,
            object_size: None,
        }
    }

    fn identity() -> Value {
        json!({
            "endpoint_id": "EP-aaaaaaaaaaaaaaaa",
            "org_id": "org-acme",
            "event_class": "File",
            "captured_at": "2026-07-05T00:00:00+00:00",
        })
    }

    /// GOLDEN-VECTOR (preimage stability) — the acceptance gate. The `LeafRecord` impl MUST route to the
    /// frozen decision canonicalization byte-for-byte; if it ever drifts, every already-anchored decision
    /// leaf fails re-derivation. Also pins the source_kind + canon spec the decision chain uses.
    #[test]
    fn decision_record_leafrecord_preimage_is_byte_identical() {
        let rec = sample();
        assert_eq!(
            LeafRecord::canonical_preimage(&rec),
            dr_canonical_preimage(&rec),
            "LeafRecord preimage drifted from the frozen decision canonicalization"
        );
        assert_eq!(rec.source_kind(), source_kind_for(rec.rule_kind));
        assert_eq!(rec.canon_spec_version(), "MLCH-1");
    }

    /// MIGRATION PROOF — the generic leaf build == the decision leaf build for the same record: one
    /// primitive, byte-identical leaves, no fork. (`event_sequence` is stamped later under the lock in both
    /// paths, so it is absent+identical here.)
    #[test]
    fn generic_leaf_equals_decision_leaf() {
        let rec = sample();
        let id = identity();
        let decision_leaf = build_commitment_leaf(
            source_kind_for(rec.rule_kind),
            &dr_canonical_preimage(&rec),
            id.clone(),
        );
        let generic_leaf = build_commitment_leaf_with_spec(
            rec.source_kind(),
            rec.canon_spec_version(),
            &LeafRecord::canonical_preimage(&rec),
            id,
        );
        assert_eq!(decision_leaf.leaf_version, generic_leaf.leaf_version);
        assert_eq!(decision_leaf.content_hash, generic_leaf.content_hash);
        assert_eq!(
            decision_leaf.canon_spec_version,
            generic_leaf.canon_spec_version
        );
        assert_eq!(decision_leaf.source_kind, generic_leaf.source_kind);
        assert_eq!(
            decision_leaf.canonical_preimage_b64,
            generic_leaf.canonical_preimage_b64
        );
        assert_eq!(decision_leaf.identity, generic_leaf.identity);
    }

    /// END-TO-END row identity (the actual safety property, not just the unsigned leaf): the SAME
    /// DecisionRecord appended via `append_record_to_file` (generic path) and via
    /// `decision_chain::append_decision_to_file` (decision path) produces a BYTE-IDENTICAL on-disk row —
    /// signature, under-lock `event_sequence` stamp, and `chain_hash` included. (Ed25519 is deterministic,
    /// so identical signed bytes ⇒ identical signature.) This closes the "byte-identical row" gate an
    /// independent review flagged; leaf-level equality alone did not exercise sign/stamp/link.
    #[test]
    fn append_record_to_file_equals_append_decision_to_file_byte_for_byte() {
        use crate::decision_chain::{append_decision_to_file, load_chain_file};
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let key_id = "kid-e2e";
        let rec = sample();
        let id = identity();
        let dir = tempfile::tempdir().expect("tempdir");
        let pa = dir.path().join("decision.jsonl");
        let pb = dir.path().join("generic.jsonl");

        let row_decision = append_decision_to_file(
            &pa,
            source_kind_for(rec.rule_kind),
            &dr_canonical_preimage(&rec),
            id.clone(),
            &sk,
            key_id,
        )
        .expect("decision append");
        let head_generic =
            append_record_to_file(&pb, &rec, id, &sk, key_id).expect("generic append");

        // ChainHead matches the decision row's (seq, tip)…
        assert_eq!(head_generic.seq, row_decision.seq);
        assert_eq!(head_generic.chain_hash, row_decision.chain_hash);
        // …and the FULL persisted row is byte-identical (DecisionChainRow: PartialEq over every field).
        let rows_generic = load_chain_file(&pb).expect("load generic");
        assert_eq!(rows_generic.len(), 1);
        assert_eq!(
            rows_generic[0], row_decision,
            "generic append produced a different row than the decision append for the same record"
        );
    }

    /// A non-decision record (mimics the ADR-025 telemetry-batch WAL leaf) carries its OWN envelope
    /// source_kind + its own canon spec, and its content_hash is independent of the decision leaf. The
    /// actual REJECTION of such a leaf spliced onto a decision chain is proven by
    /// `decision_chain::tests::foreign_source_kind_is_rejected_even_when_validly_signed` (the verifier pin).
    #[test]
    fn generic_record_carries_its_own_envelope_domain() {
        struct BatchRec;
        impl LeafRecord for BatchRec {
            fn source_kind(&self) -> &str {
                "meshlogic.offline-cache.telemetry-batch"
            }
            fn canon_spec_version(&self) -> &str {
                "MLCH-1"
            }
            fn canonical_preimage(&self) -> Vec<u8> {
                b"[{\"e\":1}]".to_vec()
            }
        }
        let batch = BatchRec;
        let leaf = build_commitment_leaf_with_spec(
            batch.source_kind(),
            batch.canon_spec_version(),
            &batch.canonical_preimage(),
            identity(),
        );
        assert_eq!(leaf.source_kind, "meshlogic.offline-cache.telemetry-batch");
        // Distinct domain in the envelope; content_hash follows only from the (distinct) preimage.
        assert_ne!(leaf.source_kind, source_kind_for("policy"));
    }
}
