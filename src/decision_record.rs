//! M6-c decision-record canonicalization — the FROZEN v=1 leaf CONTENT that the Windows agent
//! (cloud-sync) and the macOS agent (esf-core) canonicalize IDENTICALLY, byte-for-byte, so the signed
//! chain and the independent verifier never drift. Lives in this SHARED crate (not in either agent) for
//! exactly that reason — it is the one place both producers + the verifier agree on the bytes.
//!
//! Schema frozen cross-platform (windows-master ⋈ macos-master ⋈ MESHLOGIC03 verifier): integers stay
//! integers; absent `object` fields are explicit `null` (never omitted) so the record HONESTLY states
//! what was bound. VERSION-SELECTED object shape: v=1 = `{path, content_hash}` (object-by-path);
//! **v=2** adds intrinsic object identity `{path, content_hash, file_id, size}` (1b — bind the OBJECT by
//! its on-disk id, not just its path). A record upgrades to v=2 only when it carries `file_id`/`size`, so
//! v=1 leaves stay byte-identical; the verifier re-derives each leaf under its own `"v"`. Canonicalized
//! via this crate's JCS.

use serde_json::{json, Value};

/// One adjudicated decision — the "what" the leaf commits to. Populated at the platform decision site
/// (Windows: a `UnifiedEvent`'s `FileDetails` + process; macOS: `AuthDecision` + `EsfEvent`).
pub struct DecisionRecord<'a> {
    /// Canonical per-record id (the unique per-emit join key).
    pub event_id: u64,
    /// Decision timestamp.
    pub ts: u64,
    /// Disposition: `"allow"` | `"deny"` | `"prompt"` (+ lane_b `"promote"`).
    pub decision: &'a str,
    /// `"policy"` (enforcement) | `"behavioural"` (cooperation / lane_b).
    pub rule_kind: &'a str,
    /// e.g. `"builtin.sensitive_file"`.
    pub rule_id: &'a str,
    /// Data class (8 = credential today).
    pub data_class: u32,
    /// The DIRECT acting / reading process.
    pub actor_pid: u32,
    pub actor_path: &'a str,
    /// `None` (→ explicit `null`) for a cooperation / actor-promotion decision with no file object.
    pub object_path: Option<&'a str>,
    /// `None` (→ explicit `null`) when the content was not hashed at decision time (honest 1a).
    pub object_content_hash: Option<&'a str>,
    /// v=2 INTRINSIC OBJECT IDENTITY (ratified canon-v2, windows-master ⋈ macos-master ⋈ MESHLOGIC03).
    /// `file_id` = the on-disk object id as a DECIMAL STRING — Windows NTFS
    /// `FileInternalInformation.IndexNumber`, macOS `st_ino` — string-encoded because it is a u64 beyond
    /// JSON's 2^53 safe-integer range (same rule as a >2^53 ts / policy_version). Binds the object AT
    /// DECISION TIME; NTFS/APFS ids are reusable after delete, so this is intrinsic-at-decision, NOT a
    /// delete-stable permanent identity (delete-stable id is a separate future field, out of 1b scope).
    pub object_file_id: Option<&'a str>,
    /// v=2 object size in bytes (fits i64). Companion to `object_file_id`.
    pub object_size: Option<u64>,
}

/// The leaf `source_kind`, from the rule domain: policy ⇒ enforcement, behavioural ⇒ cooperation.
pub fn source_kind_for(rule_kind: &str) -> &'static str {
    match rule_kind {
        "policy" => "enforcement_decision",
        _ => "cooperation_decision",
    }
}

/// The COMPLETE set of `source_kind` values a decision leaf can carry (the full range of
/// [`source_kind_for`]). A decision-chain verifier pins against THIS set: a row whose `source_kind` is not
/// one of these is a FOREIGN / cross-type leaf (e.g. an offline-cache telemetry-batch WAL leaf) and must
/// be rejected even when validly signed by the same enrolled key — the envelope-domain separation the
/// generic [`crate::record_chain`] relies on is only sound with that verifier pin. Keep in lockstep with
/// `source_kind_for` (a `#[test]` below asserts every `source_kind_for` output is a member).
pub const DECISION_SOURCE_KINDS: [&str; 2] = ["enforcement_decision", "cooperation_decision"];

/// True iff `source_kind` is one a decision leaf legitimately carries ([`DECISION_SOURCE_KINDS`]). The
/// decision-chain verifier ([`crate::decision_chain::verify_decision_chain`]) rejects any row for which
/// this is false — cross-type replay resistance, enforced (not just documented).
pub fn is_decision_source_kind(source_kind: &str) -> bool {
    DECISION_SOURCE_KINDS.contains(&source_kind)
}

/// The decision record as a JSON value (JCS sorts keys at canon time; `Option` → `null`).
///
/// VERSION-SELECTED object shape (ratified canon-v2): a record carrying INTRINSIC OBJECT IDENTITY
/// (`file_id`/`size`) serializes as **v=2** with the 4-key object `{path, content_hash, file_id, size}`;
/// without it, **v=1** with the 2-key object `{path, content_hash}` — BYTE-IDENTICAL to already-sealed
/// v=1 leaves. This is why it's a version bump, not a plain add: appending a key to v=1 (even `null`)
/// would change every existing leaf's preimage and break re-derivation of the live signed chain. The
/// independent verifier re-derives EACH leaf under its own `"v"` (it hashes the stored preimage as opaque
/// bytes), so mixed v1/v2 chains stay valid — exactly like today's mixed signed/unsigned chain.
pub fn decision_record_value(rec: &DecisionRecord<'_>) -> Value {
    if rec.object_file_id.is_some() || rec.object_size.is_some() {
        json!({
            "v": 2,
            "event_id": rec.event_id,
            "ts": rec.ts,
            "decision": rec.decision,
            "rule_kind": rec.rule_kind,
            "rule_id": rec.rule_id,
            "data_class": rec.data_class,
            "actor": { "pid": rec.actor_pid, "path": rec.actor_path },
            "object": {
                "path": rec.object_path,
                "content_hash": rec.object_content_hash,
                "file_id": rec.object_file_id,
                "size": rec.object_size,
            },
        })
    } else {
        json!({
            "v": 1,
            "event_id": rec.event_id,
            "ts": rec.ts,
            "decision": rec.decision,
            "rule_kind": rec.rule_kind,
            "rule_id": rec.rule_id,
            "data_class": rec.data_class,
            "actor": { "pid": rec.actor_pid, "path": rec.actor_path },
            "object": { "path": rec.object_path, "content_hash": rec.object_content_hash },
        })
    }
}

/// The canonical MLCH-1 preimage bytes (RFC-8785 JCS) — the exact bytes hashed to `content_hash` and
/// carried (base64) in the leaf. Byte-identical across Windows, macOS, and the independent verifier.
pub fn canonical_preimage(rec: &DecisionRecord<'_>) -> Vec<u8> {
    crate::jcs::canonical_json_bytes(&decision_record_value(rec))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        object_path: Option<&'static str>,
        ch: Option<&'static str>,
    ) -> DecisionRecord<'static> {
        DecisionRecord {
            event_id: 42,
            ts: 116_444_736_000_000_001,
            decision: "deny",
            rule_kind: "policy",
            rule_id: "builtin.sensitive_file",
            data_class: 8,
            actor_pid: 1234,
            actor_path: r"C:\Program Files\Claude\claude.exe",
            object_path,
            object_content_hash: ch,
            // No intrinsic object id → v=1 (byte-identical to already-sealed leaves).
            object_file_id: None,
            object_size: None,
        }
    }

    /// Same record but carrying the v=2 intrinsic object identity.
    fn sample_v2(file_id: Option<&'static str>, size: Option<u64>) -> DecisionRecord<'static> {
        DecisionRecord {
            object_file_id: file_id,
            object_size: size,
            ..sample(Some(r"C:\Users\a\.aws\credentials"), None)
        }
    }

    #[test]
    fn canon_is_deterministic() {
        let a = canonical_preimage(&sample(Some(r"C:\Users\a\.aws\credentials"), None));
        let b = canonical_preimage(&sample(Some(r"C:\Users\a\.aws\credentials"), None));
        assert_eq!(a, b);
    }

    #[test]
    fn jcs_sorts_keys_and_has_no_whitespace() {
        let s = String::from_utf8(canonical_preimage(&sample(Some("/x"), None))).unwrap();
        // RFC-8785: sorted keys, no insignificant whitespace. Top-level order:
        // actor < data_class < decision < event_id < object < rule_id < rule_kind < ts < v.
        assert!(
            s.starts_with(r#"{"actor":{"path":"#),
            "keys must be JCS-sorted: {s}"
        );
        assert!(!s.contains(", "), "no whitespace in canonical form");
        assert!(s.ends_with(r#""v":1}"#), "trailing key is v: {s}");
    }

    #[test]
    fn absent_object_fields_are_explicit_null_not_omitted() {
        // Cooperation / actor-promotion: no file object → object={content_hash:null,path:null}.
        let s = String::from_utf8(canonical_preimage(&sample(None, None))).unwrap();
        assert!(
            s.contains(r#""object":{"content_hash":null,"path":null}"#),
            "null-not-omit: {s}"
        );
        let s2 =
            String::from_utf8(canonical_preimage(&sample(Some("/f"), Some("abc123")))).unwrap();
        assert!(s2.contains(r#""content_hash":"abc123""#));
    }

    #[test]
    fn integers_stay_integers() {
        let s = String::from_utf8(canonical_preimage(&sample(Some("/f"), None))).unwrap();
        assert!(
            s.contains(r#""event_id":42"#)
                && s.contains(r#""data_class":8"#)
                && s.contains(r#""pid":1234"#)
        );
        assert!(!s.contains("42.0") && !s.contains(r#""42""#));
    }

    #[test]
    fn source_kind_maps_rule_domain() {
        assert_eq!(source_kind_for("policy"), "enforcement_decision");
        assert_eq!(source_kind_for("behavioural"), "cooperation_decision");
        assert_eq!(source_kind_for("anything-else"), "cooperation_decision");
    }

    // ---- canon-v2 intrinsic object identity (ratified) ----

    #[test]
    fn no_object_id_stays_frozen_v1_byte_identical() {
        // THE BACKWARD-COMPAT GUARANTEE: a record without file_id/size must serialize EXACTLY as the
        // frozen v=1 (2-key object, trailing "v":1) so already-sealed leaves keep re-deriving. If this
        // ever changes, MESHLOGIC03's live signed chain breaks.
        let s = String::from_utf8(canonical_preimage(&sample(Some(r"/c/creds"), None))).unwrap();
        assert!(
            s.contains(r#""object":{"content_hash":null,"path":"/c/creds"}"#),
            "v1 2-key object: {s}"
        );
        assert!(
            !s.contains("file_id") && !s.contains(r#""size""#),
            "v1 must NOT carry object id: {s}"
        );
        assert!(s.ends_with(r#""v":1}"#), "v1 trailing key: {s}");
    }

    #[test]
    fn object_id_upgrades_to_v2_four_key_object() {
        let s = String::from_utf8(canonical_preimage(&sample_v2(
            Some("1152921504606846978"),
            Some(4096),
        )))
        .unwrap();
        // v=2 object has EXACTLY the 4 keys, JCS-sorted: content_hash < file_id < path < size.
        assert!(
            s.contains(
                r#""object":{"content_hash":null,"file_id":"1152921504606846978","path":"C:\\Users\\a\\.aws\\credentials","size":4096}"#
            ),
            "v2 4-key JCS object: {s}"
        );
        assert!(s.ends_with(r#""v":2}"#), "v2 trailing key: {s}");
    }

    #[test]
    fn file_id_is_a_decimal_string_not_a_json_number() {
        // A u64 file_id beyond 2^53 must survive JSON as a STRING (no precision loss), like a >2^53 ts.
        let big = "18446744073709551615"; // u64::MAX
        let s = String::from_utf8(canonical_preimage(&sample_v2(Some(big), Some(1)))).unwrap();
        assert!(
            s.contains(&format!(r#""file_id":"{big}""#)),
            "file_id quoted: {s}"
        );
        assert!(
            !s.contains(&format!("\"file_id\":{big}")),
            "file_id must not be a bare number: {s}"
        );
    }

    #[test]
    fn size_only_still_v2_with_null_file_id() {
        // Either object-id field present → v=2 (4 keys, the absent one explicit null).
        let s = String::from_utf8(canonical_preimage(&sample_v2(None, Some(64)))).unwrap();
        assert!(
            s.contains(r#""file_id":null"#) && s.contains(r#""size":64"#),
            "v2 with null file_id: {s}"
        );
        assert!(s.ends_with(r#""v":2}"#));
    }

    // Drift guard: every value `source_kind_for` can return MUST be a member of DECISION_SOURCE_KINDS, so
    // the verifier's domain pin can never reject a legitimate decision leaf. "policy" and any other
    // rule_kind cover both arms of `source_kind_for`.
    #[test]
    fn source_kind_for_outputs_are_all_decision_source_kinds() {
        for rk in ["policy", "behavioural", "anything-else"] {
            assert!(
                is_decision_source_kind(source_kind_for(rk)),
                "source_kind_for({rk:?}) not in DECISION_SOURCE_KINDS — the verifier pin would reject a real leaf"
            );
        }
        assert!(!is_decision_source_kind(
            "meshlogic.offline-cache.telemetry-batch"
        ));
    }
}
