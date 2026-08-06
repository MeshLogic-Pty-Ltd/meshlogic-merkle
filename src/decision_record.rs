//! M6-c decision-record canonicalization — the FROZEN v=1 leaf CONTENT that the Windows agent
//! (cloud-sync) and the macOS agent (esf-core) canonicalize IDENTICALLY, byte-for-byte, so the signed
//! chain and the independent verifier never drift. Lives in this SHARED crate (not in either agent) for
//! exactly that reason — it is the one place both producers + the verifier agree on the bytes.
//!
//! Schema frozen cross-platform (windows-master ⋈ macos-master, v=1): integers stay integers; absent
//! `object` fields are explicit `null` (never omitted) so the record HONESTLY states what was bound
//! (object-by-path today; intrinsic `content_hash` / FileId is the 1b enrichment — the
//! computed-not-joined gap made visible in the evidence plane). Canonicalized via this crate's JCS.

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
}

/// The leaf `source_kind`, from the rule domain: policy ⇒ enforcement, behavioural ⇒ cooperation.
pub fn source_kind_for(rule_kind: &str) -> &'static str {
    match rule_kind {
        "policy" => "enforcement_decision",
        _ => "cooperation_decision",
    }
}

/// The FROZEN v=1 decision record as a JSON value (JCS sorts keys at canon time; `Option` → `null`).
pub fn decision_record_value(rec: &DecisionRecord<'_>) -> Value {
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
        assert!(s.starts_with(r#"{"actor":{"path":"#), "keys must be JCS-sorted: {s}");
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
        let s2 = String::from_utf8(canonical_preimage(&sample(Some("/f"), Some("abc123")))).unwrap();
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
}
