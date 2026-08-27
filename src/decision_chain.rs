//! Per-decision signed HASH-LINKED chain (M6-c increment 1a) — the PROOF-pillar producer.
//!
//! One [`DecisionChainRow`] per cooperation/enforcement decision. Each row carries a signed
//! [`CommitmentLeaf`] (its public fields, flattened) plus a `chain_hash` that hash-links to the
//! previous row's tip, so any reorder, deletion, or edit of the on-disk `decisions.jsonl` breaks the
//! tip. The tip re-derives INDEPENDENTLY from the leaf PREIMAGES (never from an asserted value), which
//! is what makes the chain auditable — [`verify_decision_chain`] is the Rust mirror of the acceptance
//! harness (`evchain-verify.py`).
//!
//! ## Layering (no format break)
//! This is the LEAF-level chain (increment 1a). Increment 2 batches these leaves' `content_hash`es
//! into period Merkle roots via [`crate::roots_chain`] + [`crate::chain_verify`] and anchors the roots
//! — the leaf `content_hash` IS the Merkle leaf, so 1a's on-disk format is forward-compatible.
//!
//! ## Honesty tier (banked with MESHLOGIC03)
//! 1a earns *"tamper-evident chain exists + re-derives WITHIN a trusted-boot session"*. Robustness
//! ACROSS host compromise (a box owner rewriting the whole file into a self-consistent FALSE chain)
//! additionally requires an EXTERNAL monotonic/TPM rewind counter (1b) and the periodic external anchor
//! (increment 2). This module never claims more than it proves: an un-enrolled box emits HONEST
//! unsigned rows (empty `key_id`/`sig_b64`) rather than fixture-signing a forged proof.
//!
//! ## Wire-up status (the "closes the 100%-empty chain" claim is not yet closed-loop)
//! This crate is the shared WRITER + independent re-deriver. It is not self-activating: until a producer
//! call site invokes [`append_decision_to_file`] at its decision point, the deployed reader still sees
//! zero rows. Wire-up is per-platform — Windows: the per-decision seam in
//! `meshlogic-etw-consumer::cloud_forwarder` (`is_enforcement_block`); macOS: the esf-core decision
//! sites (`evaluate_policy` / `evaluate_auth_open` / `lane_b::decide`). Tracked as the M6-c 1a wire-up
//! follow-up; the loop closes (reader sees `records>0`, nonzero re-derivable tip) only once a call site lands.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commitment_leaf::sha256_hex;
use crate::signed_leaf::{
    build_commitment_leaf, build_commitment_leaf_with_spec, sign_leaf, verify_leaf_signature,
    CommitmentLeaf, EnrolledAgentTrustStore, LeafSigStatus, LeafSignature, SignedCommitmentLeaf,
};

/// Genesis predecessor tip for the first row — the EMPTY string (matches the acceptance verifier's
/// default genesis). If this ever changes, the verifier's `--genesis` must change in lockstep.
pub const DECISION_CHAIN_GENESIS: &str = "";

/// One on-disk decision-chain record (a `decisions.jsonl` line). Carries the full signed leaf (its
/// public fields) so the record is SELF-SUFFICIENT for independent verification — the signature is over
/// the whole leaf envelope (incl. `identity`), so a row without `identity` could not be verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionChainRow {
    /// 0-based monotonic sequence index (position in the chain).
    pub seq: u64,
    /// `sha256_hex( utf8( prev_tip_hex + content_hash_hex ) )` — the hash-link to the previous tip.
    ///
    /// SERIALIZED AS `"hash"` (not `chain_hash`) to match the ALREADY-DEPLOYED reader
    /// `incident_evidence.rs::read_decision_chain`, which takes the last record's `"hash"` as the
    /// evidence-chain tip on BOTH platforms. The independent verifier (`evchain-verify.py`) reads the
    /// same `"hash"` field. The Rust field keeps the clearer name; only the wire key is `hash`.
    #[serde(rename = "hash")]
    pub chain_hash: String,
    // ── the signed leaf's public fields (the signed subject) ──
    /// Leaf-envelope format version (`"1"`).
    pub leaf_version: String,
    /// SHA-256 hex of the canonical preimage (ADR-042 `content_hash`).
    pub content_hash: String,
    /// Record canonicalization spec (`"MLCH-1"`).
    pub canon_spec_version: String,
    /// `enforcement_decision` (block / cred-deny) or `cooperation_decision` (promote / prompt / allow).
    pub source_kind: String,
    /// STANDARD base64 of the raw MLCH-1 canonical preimage (the decision-record bytes).
    pub canonical_preimage_b64: String,
    /// The provenance identity `{endpoint_id, org_id, event_sequence, event_class, captured_at}`.
    pub identity: Value,
    // ── the collection-boundary signature (empty when un-enrolled) ──
    /// Enrolled per-agent Ed25519 `key_id` that signed the leaf (empty ⇒ unsigned / un-enrolled box).
    pub key_id: String,
    /// STANDARD base64 of the 64-byte Ed25519 signature over the domain-separated leaf preimage
    /// (`LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes`). Empty ⇒ the chain re-derives but is NOT
    /// signature-backed (`tamper_evident` stays honestly false upstream).
    pub sig_b64: String,
}

impl DecisionChainRow {
    /// Reconstruct the signed leaf this row represents (for verification / re-derivation).
    fn to_signed_leaf(&self) -> Result<SignedCommitmentLeaf, DecisionChainError> {
        use base64::Engine as _;
        let leaf = CommitmentLeaf {
            leaf_version: self.leaf_version.clone(),
            content_hash: self.content_hash.clone(),
            canon_spec_version: self.canon_spec_version.clone(),
            source_kind: self.source_kind.clone(),
            canonical_preimage_b64: self.canonical_preimage_b64.clone(),
            identity: self.identity.clone(),
        };
        let signature = if self.sig_b64.is_empty() {
            None
        } else {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(self.sig_b64.as_bytes())
                .map_err(|_| DecisionChainError::BadSignatureEncoding { seq: self.seq })?;
            let sig: [u8; 64] = raw
                .try_into()
                .map_err(|_| DecisionChainError::BadSignatureEncoding { seq: self.seq })?;
            Some(LeafSignature {
                key_id: self.key_id.clone(),
                sig,
            })
        };
        Ok(SignedCommitmentLeaf::new(leaf, signature))
    }
}

/// The hash-link: `sha256_hex( utf8( prev_tip_hex + content_hash_hex ) )` — HEX-STRING concat (the two
/// hex strings joined, then SHA-256), empty-string genesis. This is the EXACT formula the independent
/// acceptance verifier (`evchain-verify.py`) re-derives; keep the two in lockstep.
///
/// # Invariant — why the bare concat is unambiguous (no domain separator)
/// Both operands are FIXED-WIDTH: `content_hash` is always 64 lowercase-hex chars (SHA-256), and
/// `prev_tip` is either 64 hex chars (a prior `chain_hash`) or the empty genesis (0 chars). So the
/// split point is unambiguous and no crafted input can shift the boundary — a length-extension /
/// concat-ambiguity attack is impossible for THESE operands. Do NOT reuse this function for
/// variable-length inputs. (If the chain format is ever versioned, add a domain tag here AND in
/// `evchain-verify.py` in lockstep — see the LOW AI-review note on #3054.)
pub fn decision_chain_hash(prev_tip: &str, content_hash: &str) -> String {
    let mut s = String::with_capacity(prev_tip.len() + content_hash.len());
    s.push_str(prev_tip);
    s.push_str(content_hash);
    sha256_hex(s.as_bytes())
}

/// The current tip = the last row's `chain_hash` (or [`DECISION_CHAIN_GENESIS`] when empty).
pub fn tip(rows: &[DecisionChainRow]) -> String {
    rows.last()
        .map(|r| r.chain_hash.clone())
        .unwrap_or_else(|| DECISION_CHAIN_GENESIS.to_string())
}

/// Assemble a [`DecisionChainRow`] from an already-built [`SignedCommitmentLeaf`] and the previous tip.
/// Kept separate from [`append_decision`] so an UN-ENROLLED box can emit an honest unsigned row
/// (pass a leaf wrapped with `signature = None`) without ever fixture-signing.
pub fn row_from_signed(
    seq: u64,
    prev_tip: &str,
    signed: &SignedCommitmentLeaf,
) -> DecisionChainRow {
    use base64::Engine as _;
    let content_hash = signed.leaf.content_hash.clone();
    let chain_hash = decision_chain_hash(prev_tip, &content_hash);
    let (key_id, sig_b64) = match &signed.signature {
        Some(s) => (
            s.key_id.clone(),
            base64::engine::general_purpose::STANDARD.encode(s.sig),
        ),
        None => (String::new(), String::new()),
    };
    DecisionChainRow {
        seq,
        chain_hash,
        leaf_version: signed.leaf.leaf_version.clone(),
        content_hash,
        canon_spec_version: signed.leaf.canon_spec_version.clone(),
        source_kind: signed.leaf.source_kind.clone(),
        canonical_preimage_b64: signed.leaf.canonical_preimage_b64.clone(),
        identity: signed.leaf.identity.clone(),
        key_id,
        sig_b64,
    }
}

/// The decision to record — the "what" half of an append, grouped so [`append_decision`] stays a
/// small, ergonomic public API (no `too_many_arguments`).
pub struct DecisionInput<'a> {
    /// 0-based monotonic sequence index (position in the chain).
    pub seq: u64,
    /// The previous row's `chain_hash`, or [`DECISION_CHAIN_GENESIS`] for the first row.
    pub prev_tip: &'a str,
    /// `enforcement_decision` (block / cred-deny) or `cooperation_decision` (promote / prompt / allow).
    pub source_kind: &'a str,
    /// The raw MLCH-1 canonical preimage bytes (the decision record).
    pub canonical_preimage: &'a [u8],
    /// The provenance identity `{endpoint_id, org_id, event_sequence, event_class, captured_at}`.
    pub identity: Value,
}

/// Build the next SIGNED, hash-linked decision row from a [`DecisionInput`]. `signing_key`/`key_id`
/// are the ADR-062 enrolled per-agent identity (#1736) — NEVER the fixture key in production. The new
/// tip is `row.chain_hash`.
pub fn append_decision(
    input: DecisionInput<'_>,
    signing_key: &ed25519_dalek::SigningKey,
    key_id: impl Into<String>,
) -> DecisionChainRow {
    let leaf = build_commitment_leaf(input.source_kind, input.canonical_preimage, input.identity);
    let signed = sign_leaf(leaf, signing_key, key_id);
    row_from_signed(input.seq, input.prev_tip, &signed)
}

/// Every way independent re-derivation of a decision chain can fail. Each carries the offending `seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionChainError {
    /// No rows supplied.
    Empty,
    /// `seq` is not strictly `previous + 1` (a duplicate, gap, or out-of-order row).
    NotContiguous { seq: u64 },
    /// The row's `content_hash` != `sha256(base64-decode(canonical_preimage_b64))` — the preimage was
    /// edited, or the hash was forged.
    ContentHashMismatch { seq: u64 },
    /// The row's `chain_hash` != `decision_chain_hash(prev_tip, content_hash)` — the link is broken
    /// (reorder / deletion / edit).
    BrokenLink { seq: u64 },
    /// `sig_b64` / `key_id` is present but does not decode to a 64-byte signature.
    BadSignatureEncoding { seq: u64 },
    /// The leaf signature did not verify against the trust store (tamper / forgery / wrong key).
    SignatureUntrusted { seq: u64 },
    /// A row is unsigned (empty `sig_b64`) but signatures were REQUIRED for this verification.
    MissingSignature { seq: u64 },
    /// The row's `source_kind` is not a decision domain ([`crate::decision_record::DECISION_SOURCE_KINDS`])
    /// — a FOREIGN / cross-type leaf (e.g. an offline-cache telemetry-batch WAL leaf) spliced onto the
    /// decision chain. Rejected fail-closed EVEN IF validly signed by the same enrolled key: the generic
    /// record-chain's envelope-domain separation is only sound because the decision verifier pins here.
    ForeignSourceKind { seq: u64, source_kind: String },
}

impl std::fmt::Display for DecisionChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use DecisionChainError::*;
        match self {
            Empty => write!(f, "empty decision chain"),
            NotContiguous { seq } => {
                write!(f, "seq {seq} is not contiguous (dup/gap/out-of-order)")
            }
            ContentHashMismatch { seq } => {
                write!(
                    f,
                    "seq {seq}: content_hash != sha256(preimage) (preimage edited)"
                )
            }
            BrokenLink { seq } => write!(f, "seq {seq}: broken hash-link (reorder/delete/edit)"),
            BadSignatureEncoding { seq } => {
                write!(f, "seq {seq}: signature is not 64 bytes base64")
            }
            SignatureUntrusted { seq } => write!(f, "seq {seq}: leaf signature did not verify"),
            MissingSignature { seq } => {
                write!(f, "seq {seq}: unsigned row but signatures required")
            }
            ForeignSourceKind { seq, source_kind } => {
                write!(
                    f,
                    "seq {seq}: foreign source_kind {source_kind:?} on a decision chain (cross-type leaf)"
                )
            }
        }
    }
}

impl std::error::Error for DecisionChainError {}

/// Independently RE-DERIVE and verify a decision chain from the leaf PREIMAGES — the acceptance
/// contract. Recomputes `content_hash` from each preimage, recomputes `chain_hash` down the spine from
/// `expected_first_prev` (genesis or a trusted checkpoint), checks `seq` contiguity, and — when
/// `require_signatures` — verifies each leaf's Ed25519 signature against `trust` at `at_time`. Returns
/// the re-derived final TIP on success (the value the lake's asserted tip must equal — the lake tip is
/// only a POINTER, never trusted). Detects tamper (byte flip), rewind/truncation (dropped rows), and
/// forged signatures — mirroring `evchain-verify.py`.
///
/// # SECURITY — the caller MUST pin BOTH endpoints
/// This function proves the rows form a self-consistent hash-linked chain FROM `expected_first_prev`
/// TO the returned tip. It does NOT, by itself, prove that chain is the endpoint's REAL history — an
/// attacker who owns the box can fabricate a fully self-consistent chain from any genesis (and, with
/// the enrolled key, even validly-signed rows). So the caller MUST (a) pin `expected_first_prev` to the
/// true genesis ([`DECISION_CHAIN_GENESIS`]) or a TRUSTED co-anchored checkpoint — never a value taken
/// from the same untrusted file; and (b) compare the returned tip against an INDEPENDENTLY-pinned
/// expected tip — the external anchor (increment 2, RFC-3161 / Rekor) or a monotonic/TPM rewind counter,
/// NOT the lake's asserted tip. This is exactly the honesty tier banked with MESHLOGIC03: 1a is
/// tamper-evident WITHIN a trusted-boot session; robustness ACROSS host compromise gates on those pins.
/// GENERIC record-chain verify — the SAME linkage + content-hash + signature checks as
/// [`verify_decision_chain`], with the DOMAIN PIN injected as `is_expected_source_kind`. Any leaf type on
/// the shared generic chain (decisions, the ADR-025 offline-cache telemetry-batch WAL, a future record
/// type) is verified through ONE primitive rather than a forked copy of the crypto — the only way the
/// canon/hash/signature discipline can't drift between chains (ADR-176). The pin is the chain's domain
/// gate: a row whose `source_kind` fails `is_expected_source_kind` is a cross-type splice, rejected
/// FAIL-CLOSED INDEPENDENT of `require_signatures` (such a leaf may be validly signed by the SAME enrolled
/// key — `source_kind` rides the signature but NOT the chain-link, so without the pin a signed foreign
/// leaf would re-derive and pass (2)-(4)). Returns the verified tip. `expected_first_prev` is
/// [`DECISION_CHAIN_GENESIS`] (the shared, record-agnostic genesis) for a from-genesis walk, or a trusted
/// co-anchored checkpoint tip when an auditor walks forward.
///
/// # SECURITY
/// `is_expected_source_kind` MUST be a TIGHT ALLOWLIST of exactly the domain(s) this chain carries
/// (e.g. [`crate::decision_record::is_decision_source_kind`], or a cache-WAL's `is_offline_cache_leaf`).
/// A permissive pin — above all `|_| true` — silently disables ALL cross-type replay protection while
/// every other check stays green: a leaf of ANY domain, validly signed by the same enrolled key, would
/// then re-derive and pass. The pin is the ONLY thing standing between two chains sharing this primitive.
pub fn verify_record_chain<F: Fn(&str) -> bool>(
    rows: &[DecisionChainRow],
    expected_first_prev: &str,
    trust: &EnrolledAgentTrustStore,
    at_time: u64,
    require_signatures: bool,
    is_expected_source_kind: F,
) -> Result<String, DecisionChainError> {
    use base64::Engine as _;
    if rows.is_empty() {
        return Err(DecisionChainError::Empty);
    }
    let mut prev_tip = expected_first_prev.to_string();
    for (i, row) in rows.iter().enumerate() {
        // (0) DOMAIN PIN — the chain carries ONLY its own domain's leaves. A row whose `source_kind` fails
        // the injected pin (a foreign leaf of another record type sharing the generic chain primitive) is a
        // cross-type splice, rejected FAIL-CLOSED — independent of `require_signatures`, because such a leaf
        // may be validly signed by the SAME enrolled key. This is the verifier pin the generic
        // `record_chain`'s envelope-domain separation depends on: source_kind rides the signature but NOT
        // the chain-link, so without this check a signed foreign leaf would re-derive and pass (2)-(4).
        if !is_expected_source_kind(&row.source_kind) {
            return Err(DecisionChainError::ForeignSourceKind {
                seq: row.seq,
                source_kind: row.source_kind.clone(),
            });
        }
        // (1) contiguity — a gap or reorder is a possible silently-deleted decision.
        if row.seq != i as u64 {
            return Err(DecisionChainError::NotContiguous { seq: row.seq });
        }
        // (2) content_hash is the sha256 of the actual preimage (not an asserted value).
        let preimage = base64::engine::general_purpose::STANDARD
            .decode(row.canonical_preimage_b64.as_bytes())
            .map_err(|_| DecisionChainError::ContentHashMismatch { seq: row.seq })?;
        if sha256_hex(&preimage) != row.content_hash {
            return Err(DecisionChainError::ContentHashMismatch { seq: row.seq });
        }
        // (3) the hash-link re-derives from the previous tip.
        let expect = decision_chain_hash(&prev_tip, &row.content_hash);
        if expect != row.chain_hash {
            return Err(DecisionChainError::BrokenLink { seq: row.seq });
        }
        // (4) the leaf signature verifies (domain-separated full-leaf preimage) — when required.
        if require_signatures && row.sig_b64.is_empty() {
            return Err(DecisionChainError::MissingSignature { seq: row.seq });
        }
        if !row.sig_b64.is_empty() {
            let signed = row.to_signed_leaf()?;
            match verify_leaf_signature(&signed, trust, at_time) {
                LeafSigStatus::Signed { .. } => {}
                LeafSigStatus::Untrusted(_) => {
                    return Err(DecisionChainError::SignatureUntrusted { seq: row.seq })
                }
            }
        }
        prev_tip = row.chain_hash.clone();
    }
    Ok(prev_tip)
}

/// The decision chain is ONE domain on the generic [`verify_record_chain`]: it pins the decision source
/// kinds ([`crate::decision_record::is_decision_source_kind`]) and is otherwise byte-identical to the
/// pre-extraction verify (a foreign — e.g. offline-cache telemetry — leaf is rejected fail-closed).
pub fn verify_decision_chain(
    rows: &[DecisionChainRow],
    expected_first_prev: &str,
    trust: &EnrolledAgentTrustStore,
    at_time: u64,
    require_signatures: bool,
) -> Result<String, DecisionChainError> {
    verify_record_chain(
        rows,
        expected_first_prev,
        trust,
        at_time,
        require_signatures,
        crate::decision_record::is_decision_source_kind,
    )
}

// ---------------------------------------------------------------------------------------------
// On-disk chain file (the `cooperation-decisions.jsonl` the deployed reader consumes).
// ---------------------------------------------------------------------------------------------

/// Load the existing decision-chain rows from a `decisions.jsonl` file. A missing file is an EMPTY
/// chain (not an error) — the first decision on a fresh box starts the chain. Blank lines are skipped.
/// A malformed line is a hard error (a corrupt chain must not be silently continued).
pub fn load_chain_file(path: &std::path::Path) -> std::io::Result<Vec<DecisionChainRow>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let row: DecisionChainRow = serde_json::from_str(line).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                // Line context so an operator can locate the corruption, not just "invalid data".
                format!("corrupt decision-chain line {}: {e}", rows.len() + 1),
            )
        })?;
        rows.push(row);
    }
    Ok(rows)
}

/// The next `(seq, prev_tip)` to append to a chain of `existing_len` rows with the given current tip.
/// Pulled out so the caller can compute the append position without re-reading the whole file when it
/// already tracks the tail.
pub fn next_position(existing_rows: &[DecisionChainRow]) -> (u64, String) {
    (existing_rows.len() as u64, tip(existing_rows))
}

/// Process-wide per-path append locks. The read-derive-append below is a strict data dependency (each
/// row's `seq`/`prev_tip` derive from the current tail), so two threads racing it would both compute the
/// SAME `seq`/`prev_tip` and write a divergent pair the verifier rejects at the contiguity gate — AFTER
/// the corruption is on disk. This serialises appends to a given chain file WITHIN the process. The
/// single-agent-per-box deployment invariant covers the cross-PROCESS case; a genuine multi-instance
/// producer would additionally need an OS advisory lock (`flock`/`fs2`) — tracked for that day, not 1a.
static APPEND_LOCKS: std::sync::LazyLock<
    std::sync::Mutex<
        std::collections::HashMap<std::path::PathBuf, std::sync::Arc<std::sync::Mutex<()>>>,
    >,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn append_lock_for(path: &std::path::Path) -> std::sync::Arc<std::sync::Mutex<()>> {
    APPEND_LOCKS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .entry(path.to_path_buf())
        .or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(())))
        .clone()
}

/// The locked, durable read-derive-BUILD-sign-append shared by the signed + unsigned entry points.
/// Holds the per-path append lock across load → derive `seq` → build → sign → write so no second
/// producer can interleave. Building INSIDE the lock is what lets us inject the chain position:
/// `identity.event_sequence = seq` is set atomically, so the SIGNED leaf's identity always matches the
/// row's `seq` (they cannot be derived independently — `seq` only exists once the tail is read).
fn locked_build_append(
    path: &std::path::Path,
    source_kind: &str,
    canon_spec_version: &str,
    canonical_preimage: &[u8],
    mut identity: Value,
    signer: Option<(&ed25519_dalek::SigningKey, &str)>,
) -> std::io::Result<DecisionChainRow> {
    let lock = append_lock_for(path);
    let _guard = lock.lock().unwrap_or_else(|p| p.into_inner());
    let existing = load_chain_file(path)?;
    let (seq, prev_tip) = next_position(&existing);
    // Stamp the chain position into the SIGNED identity (frozen schema: identity.event_sequence =
    // chain_index). Only meaningful once `seq` is known, i.e. under the lock.
    if let Value::Object(map) = &mut identity {
        map.insert("event_sequence".to_string(), Value::from(seq));
    }
    let leaf = build_commitment_leaf_with_spec(
        source_kind,
        canon_spec_version,
        canonical_preimage,
        identity,
    );
    let signed = match signer {
        Some((signing_key, key_id)) => sign_leaf(leaf, signing_key, key_id),
        None => SignedCommitmentLeaf::new(leaf, None),
    };
    let row = row_from_signed(seq, &prev_tip, &signed);
    write_row_line(path, &row)?;
    Ok(row)
}

/// Append ONE signed decision to the on-disk chain file, returning the new row (whose `chain_hash` is
/// the new tip). Reads the existing chain to derive `seq` + `prev_tip`, stamps `event_sequence = seq`
/// into the identity, builds+signs the leaf, and durably appends a single JSON line under the per-path
/// append lock. `signing_key`/`key_id` are the ADR-062 enrolled per-agent identity — an UN-ENROLLED box
/// uses [`append_unsigned_decision_to_file`] instead of a fixture (never fixture-sign a prod proof).
pub fn append_decision_to_file(
    path: &std::path::Path,
    source_kind: &str,
    canonical_preimage: &[u8],
    identity: Value,
    signing_key: &ed25519_dalek::SigningKey,
    key_id: &str,
) -> std::io::Result<DecisionChainRow> {
    // Decision leaves are canonicalized under MLCH-1 (the frozen decision-record spec). Delegates to the
    // spec-aware generic append; the "MLCH-1" here keeps decision rows byte-identical to pre-generic.
    locked_build_append(
        path,
        source_kind,
        "MLCH-1",
        canonical_preimage,
        identity,
        Some((signing_key, key_id)),
    )
}

/// GENERIC signed-leaf append — the ONE shared tamper-evidence primitive (ADR-025 / ADR-176) under both
/// the decision chain and the offline-cache WAL. Same lock/seq-derivation/`event_sequence`-stamp/fsync
/// durability as [`append_decision_to_file`], but the caller supplies the record's STAMPED
/// `canon_spec_version` (so a verifier re-derives each leaf under its own spec) and the signed-ENVELOPE
/// `source_kind` domain tag (the cross-type replay boundary — a verifier MUST pin its expected value).
/// The typed, trait-based entry point is [`crate::record_chain::append_record_to_file`]. Returns the new
/// row whose `chain_hash` is the tip.
///
/// LAYOUT: write each `source_kind`'s records to their OWN chain file (a decision file, a telemetry-WAL
/// file — distinct lifecycles). A foreign `source_kind` spliced onto a DECISION-chain file is rejected by
/// [`verify_decision_chain`]'s domain pin, so this cannot silently corrupt decision verification — but
/// one-domain-per-file is the intended layout, not a suggestion.
pub fn append_leaf_to_file(
    path: &std::path::Path,
    source_kind: &str,
    canon_spec_version: &str,
    canonical_preimage: &[u8],
    identity: Value,
    signing_key: &ed25519_dalek::SigningKey,
    key_id: &str,
) -> std::io::Result<DecisionChainRow> {
    locked_build_append(
        path,
        source_kind,
        canon_spec_version,
        canonical_preimage,
        identity,
        Some((signing_key, key_id)),
    )
}

/// The honest UN-ENROLLED generic append (mirror of [`append_unsigned_decision_to_file`]): re-derivable
/// chain, no signature, so `tamper_evident` stays honestly false upstream. Never fixture-signs.
pub fn append_unsigned_leaf_to_file(
    path: &std::path::Path,
    source_kind: &str,
    canon_spec_version: &str,
    canonical_preimage: &[u8],
    identity: Value,
) -> std::io::Result<DecisionChainRow> {
    locked_build_append(
        path,
        source_kind,
        canon_spec_version,
        canonical_preimage,
        identity,
        None,
    )
}

/// Append ONE UNSIGNED decision (honest un-enrolled path): the chain still re-derives, but the row
/// carries no signature so `tamper_evident` stays honestly false upstream. Never fixture-signs.
pub fn append_unsigned_decision_to_file(
    path: &std::path::Path,
    source_kind: &str,
    canonical_preimage: &[u8],
    identity: Value,
) -> std::io::Result<DecisionChainRow> {
    locked_build_append(
        path,
        source_kind,
        "MLCH-1",
        canonical_preimage,
        identity,
        None,
    )
}

/// Append a single row as one JSON line (with a trailing newline), then `fsync` so a power loss cannot
/// leave a torn or lost tail on the PROOF chain. Creates the file + parent dir if absent.
/// `serde_json::to_string` cannot emit an interior newline for a `DecisionChainRow` (all string fields
/// are hex/base64/JSON-escaped), so one line == one record holds.
fn write_row_line(path: &std::path::Path, row: &DecisionChainRow) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let line = serde_json::to_string(row)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?; // durability: the evidence tail must survive power loss
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_leaf::{fixture_signing_key, EnrolledAgentKey, EnrolledAgentTrustStore};
    use ed25519_dalek::Signer;
    use serde_json::json;

    const KEY_ID: &str = "test-agent-key-1";

    fn trust_store() -> EnrolledAgentTrustStore {
        let sk = fixture_signing_key();
        EnrolledAgentTrustStore::new(vec![EnrolledAgentKey {
            key_id: KEY_ID.to_string(),
            verifying_key: sk.verifying_key(),
            not_before: None,
            not_after: None,
        }])
    }

    fn identity(seq: u64) -> Value {
        json!({
            "endpoint_id": "ep-1",
            "org_id": "org-1",
            "event_sequence": seq,
            "event_class": "CooperationDecision",
            "captured_at": 116_444_736_000_000_000u64 + seq,
        })
    }

    /// Build a signed N-row chain from a deterministic set of decisions.
    fn build_chain(n: u64) -> Vec<DecisionChainRow> {
        let sk = fixture_signing_key();
        let mut rows = Vec::new();
        let mut prev = DECISION_CHAIN_GENESIS.to_string();
        for seq in 0..n {
            let preimage = format!("{{\"decision\":\"block\",\"seq\":{seq}}}");
            let source_kind = if seq % 2 == 0 {
                "enforcement_decision"
            } else {
                "cooperation_decision"
            };
            let row = append_decision(
                DecisionInput {
                    seq,
                    prev_tip: &prev,
                    source_kind,
                    canonical_preimage: preimage.as_bytes(),
                    identity: identity(seq),
                },
                &sk,
                KEY_ID,
            );
            prev = row.chain_hash.clone();
            rows.push(row);
        }
        rows
    }

    #[test]
    fn clean_chain_re_derives_and_verifies() {
        let rows = build_chain(5);
        let asserted_tip = tip(&rows);
        let re_derived = verify_decision_chain(
            &rows,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            true,
        )
        .expect("clean chain must verify");
        // The independently re-derived tip equals the asserted tip — the acceptance's core assertion.
        assert_eq!(re_derived, asserted_tip);
        assert!(!asserted_tip.is_empty());
        // Distinct rows → distinct chain hashes (no collision / no all-zero decorative tip).
        assert_ne!(rows[0].chain_hash, rows[1].chain_hash);
    }

    #[test]
    fn tamper_one_preimage_byte_diverges_and_sig_fails() {
        let mut rows = build_chain(4);
        // Flip a byte in row 2's preimage (re-encode a mutated preimage) WITHOUT updating hashes.
        use base64::Engine as _;
        let mut p = base64::engine::general_purpose::STANDARD
            .decode(rows[2].canonical_preimage_b64.as_bytes())
            .unwrap();
        p[0] ^= 0x01;
        rows[2].canonical_preimage_b64 = base64::engine::general_purpose::STANDARD.encode(&p);
        // content_hash no longer matches the (mutated) preimage → caught at the content-hash gate.
        let err = verify_decision_chain(
            &rows,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            true,
        )
        .unwrap_err();
        assert_eq!(err, DecisionChainError::ContentHashMismatch { seq: 2 });
    }

    #[test]
    fn forged_content_hash_breaks_the_link() {
        let mut rows = build_chain(4);
        // Attacker rewrites row 2's preimage AND its content_hash consistently, but can't re-sign
        // (no key) and can't fix the downstream chain_hash of row 3 → link breaks at row 3.
        use base64::Engine as _;
        let new_preimage = b"{\"decision\":\"allow\",\"seq\":2,\"evil\":true}";
        rows[2].canonical_preimage_b64 =
            base64::engine::general_purpose::STANDARD.encode(new_preimage);
        rows[2].content_hash = sha256_hex(new_preimage);
        rows[2].chain_hash = decision_chain_hash(&rows[1].chain_hash, &rows[2].content_hash);
        // The attacker cannot re-sign (no enrolled key), so they strip the now-invalid signature and
        // make row 2 internally self-consistent. The INDEPENDENT hash-link is what still catches it:
        // row 3's chain_hash was linked to the ORIGINAL row-2 tip, so the spine diverges at seq 3.
        rows[2].sig_b64 = String::new();
        rows[2].key_id = String::new();
        let err = verify_decision_chain(
            &rows,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            false, // even ignoring signatures, the hash-link alone catches it
        )
        .unwrap_err();
        assert_eq!(err, DecisionChainError::BrokenLink { seq: 3 });
    }

    #[test]
    fn rewind_dropped_tail_row_changes_tip() {
        let full = build_chain(5);
        let full_tip = tip(&full);
        let truncated = &full[..4];
        let trunc_tip = verify_decision_chain(
            truncated,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            true,
        )
        .expect("prefix is itself a valid chain");
        // A truncated (rewound) chain re-derives to a DIFFERENT tip — detectable against a pinned tip.
        assert_ne!(trunc_tip, full_tip);
    }

    #[test]
    fn dropped_middle_row_is_not_contiguous() {
        let full = build_chain(5);
        let mut rows = full.clone();
        rows.remove(2); // seq now 0,1,3,4 → contiguity gate fires at the old row 3 (index 2).
        let err = verify_decision_chain(
            &rows,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            true,
        )
        .unwrap_err();
        assert_eq!(err, DecisionChainError::NotContiguous { seq: 3 });
    }

    #[test]
    fn forged_signature_is_rejected() {
        let mut rows = build_chain(3);
        // Replace row 1's signature with a signature by a DIFFERENT (attacker) key over the same msg.
        use base64::Engine as _;
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let signed = rows[1].to_signed_leaf().unwrap();
        let msg = [
            crate::signed_leaf::LEAF_SIG_DOMAIN,
            &[0x00u8],
            &crate::signed_leaf::canonical_leaf_bytes(&signed.leaf),
        ]
        .concat();
        let forged = attacker.sign(&msg).to_bytes();
        rows[1].sig_b64 = base64::engine::general_purpose::STANDARD.encode(forged);
        let err = verify_decision_chain(
            &rows,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            true,
        )
        .unwrap_err();
        assert_eq!(err, DecisionChainError::SignatureUntrusted { seq: 1 });
    }

    #[test]
    fn unsigned_row_is_honest_when_signatures_not_required() {
        // Un-enrolled box: emit an unsigned row (signature None) — chain still re-derives, but a
        // signatures-required verification refuses it (no false "signed" claim).
        let sk = fixture_signing_key();
        let leaf = build_commitment_leaf("enforcement_decision", b"{\"d\":1}", identity(0));
        let unsigned = SignedCommitmentLeaf::new(leaf, None);
        let row = row_from_signed(0, DECISION_CHAIN_GENESIS, &unsigned);
        assert!(row.sig_b64.is_empty() && row.key_id.is_empty());
        // re-derives fine without signatures…
        assert!(verify_decision_chain(
            std::slice::from_ref(&row),
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            1,
            false
        )
        .is_ok());
        // …but a signatures-REQUIRED check honestly rejects it.
        assert_eq!(
            verify_decision_chain(
                std::slice::from_ref(&row),
                DECISION_CHAIN_GENESIS,
                &trust_store(),
                1,
                true
            )
            .unwrap_err(),
            DecisionChainError::MissingSignature { seq: 0 }
        );
        let _ = sk;
    }

    #[test]
    fn foreign_source_kind_is_rejected_even_when_validly_signed() {
        // A telemetry (offline-cache WAL) leaf VALIDLY SIGNED BY THE ENROLLED KEY, spliced onto a decision
        // chain: it re-derives (content_hash + hash-link) and its signature is TRUSTED — yet the domain pin
        // rejects it FAIL-CLOSED for BOTH require_signatures values. This is the cross-type replay the
        // generic record_chain's envelope-domain separation relies on the decision verifier to catch; the
        // MED an independent review flagged (documented obligation vs. enforced check).
        let sk = fixture_signing_key();
        let leaf = crate::signed_leaf::build_commitment_leaf_with_spec(
            "meshlogic.offline-cache.telemetry-batch",
            "MLCH-1",
            b"[{\"e\":1}]",
            identity(0),
        );
        let signed = sign_leaf(leaf, &sk, KEY_ID);
        let row = row_from_signed(0, DECISION_CHAIN_GENESIS, &signed);
        assert!(
            !row.sig_b64.is_empty(),
            "row is validly signed by the enrolled key"
        );
        for require_sig in [false, true] {
            assert_eq!(
                verify_decision_chain(
                    std::slice::from_ref(&row),
                    DECISION_CHAIN_GENESIS,
                    &trust_store(),
                    116_444_736_000_000_100,
                    require_sig,
                )
                .unwrap_err(),
                DecisionChainError::ForeignSourceKind {
                    seq: 0,
                    source_kind: "meshlogic.offline-cache.telemetry-batch".to_string(),
                },
                "require_signatures={require_sig}: foreign source_kind must be rejected"
            );
        }
    }

    #[test]
    fn verify_record_chain_pins_its_own_domain_symmetrically() {
        // The generic verify accepts a NON-decision domain when the injected pin matches, and rejects a
        // foreign leaf fail-closed — the mirror of `foreign_source_kind_is_rejected...`, proving the pin
        // works in BOTH directions (a telemetry-pinned verify rejects a decision leaf just as the
        // decision-pinned verify rejects a telemetry leaf). This is the property the offline-cache WAL
        // verifier relies on: cross-type replay resistance on the SHARED chain primitive.
        const WAL_KIND: &str = "meshlogic.offline-cache.telemetry-batch";
        let sk = fixture_signing_key();

        // Build a 2-row WAL (telemetry) chain, validly signed by the enrolled key.
        let mut wal = Vec::new();
        let mut prev = DECISION_CHAIN_GENESIS.to_string();
        for seq in 0..2u64 {
            let preimage = format!("[{{\"event_id\":{seq}}}]");
            let leaf = crate::signed_leaf::build_commitment_leaf_with_spec(
                WAL_KIND,
                "MLCH-1",
                preimage.as_bytes(),
                identity(seq),
            );
            let signed = sign_leaf(leaf, &sk, KEY_ID);
            let row = row_from_signed(seq, &prev, &signed);
            prev = row.chain_hash.clone();
            wal.push(row);
        }

        // (1) POSITIVE: the WAL-pinned generic verify accepts its own domain and re-derives the tip.
        let tip = verify_record_chain(
            &wal,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            true,
            |sk| sk == WAL_KIND,
        )
        .expect("WAL chain must verify under its own domain pin");
        assert_eq!(
            tip,
            wal.last().unwrap().chain_hash,
            "re-derived tip == asserted tip"
        );

        // (2) NEGATIVE (the new symmetric direction): a DECISION chain, validly signed, is rejected
        //     FAIL-CLOSED by a WAL-pinned verify — a decision leaf can never replay onto the WAL chain.
        let decision = build_chain(2);
        for require_sig in [false, true] {
            assert_eq!(
                verify_record_chain(
                    &decision,
                    DECISION_CHAIN_GENESIS,
                    &trust_store(),
                    116_444_736_000_000_100,
                    require_sig,
                    |sk| sk == WAL_KIND,
                )
                .unwrap_err(),
                DecisionChainError::ForeignSourceKind {
                    seq: 0,
                    source_kind: "enforcement_decision".to_string(),
                },
                "require_signatures={require_sig}: a decision leaf must be rejected by the WAL pin"
            );
        }

        // (3) And the delegating decision verify still rejects the WAL chain — symmetry both ways.
        assert!(matches!(
            verify_decision_chain(
                &wal,
                DECISION_CHAIN_GENESIS,
                &trust_store(),
                116_444_736_000_000_100,
                true,
            )
            .unwrap_err(),
            DecisionChainError::ForeignSourceKind { .. }
        ));
    }

    fn temp_chain_path(tag: &str) -> std::path::PathBuf {
        // Unique-per-RUN path: the process id keeps parallel `cargo test` invocations (separate test
        // binaries) from colliding on the same file; the tag keeps tests within a run distinct. (Date/
        // random are unavailable in this crate's build, so pid + tag give uniqueness without them.)
        let mut p = std::env::temp_dir();
        p.push(format!("mlc-m6c-tests-{}", std::process::id()));
        p.push(tag);
        p.push("cooperation-decisions.jsonl");
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn append_to_file_builds_a_re_derivable_on_disk_chain() {
        let path = temp_chain_path("append_rederive");
        let sk = fixture_signing_key();
        // Fresh box: file absent → first append starts the chain at seq 0 / empty genesis.
        for seq in 0..4u64 {
            let preimage = format!("{{\"decision\":\"block\",\"seq\":{seq}}}");
            let row = append_decision_to_file(
                &path,
                "enforcement_decision",
                preimage.as_bytes(),
                identity(seq),
                &sk,
                KEY_ID,
            )
            .expect("append must succeed");
            assert_eq!(row.seq, seq);
        }
        // Re-load from disk and independently verify — proves what read_decision_chain would consume.
        let loaded = load_chain_file(&path).expect("load");
        assert_eq!(loaded.len(), 4);
        let disk_tip = tip(&loaded);
        let re_derived = verify_decision_chain(
            &loaded,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            true,
        )
        .expect("on-disk chain must re-derive");
        assert_eq!(re_derived, disk_tip);
        assert!(!disk_tip.is_empty());
        // The deployed reader takes the LAST line's "hash" as the tip — assert the wire shape matches.
        let last_line = std::fs::read_to_string(&path).unwrap();
        let last: Value = serde_json::from_str(last_line.lines().last().unwrap()).unwrap();
        assert_eq!(last["hash"], disk_tip);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unsigned_append_is_honest_and_still_links() {
        let path = temp_chain_path("append_unsigned");
        let r0 = append_unsigned_decision_to_file(
            &path,
            "cooperation_decision",
            b"{\"decision\":\"allow\",\"seq\":0}",
            identity(0),
        )
        .unwrap();
        assert!(r0.sig_b64.is_empty() && r0.key_id.is_empty());
        let loaded = load_chain_file(&path).unwrap();
        // Re-derives without signatures (honest un-enrolled), but a signatures-required check rejects.
        assert!(
            verify_decision_chain(&loaded, DECISION_CHAIN_GENESIS, &trust_store(), 1, false)
                .is_ok()
        );
        assert!(
            verify_decision_chain(&loaded, DECISION_CHAIN_GENESIS, &trust_store(), 1, true)
                .is_err()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_stamps_event_sequence_equal_to_seq_and_signs_over_it() {
        let path = temp_chain_path("event_seq");
        let sk = fixture_signing_key();
        for expected in 0..3u64 {
            let row = append_decision_to_file(
                &path,
                "enforcement_decision",
                b"{\"d\":1}",
                // identity WITHOUT event_sequence — the crate stamps it under the lock.
                json!({"endpoint_id":"ep","org_id":"org","event_class":"CooperationDecision","captured_at":1u64}),
                &sk,
                KEY_ID,
            )
            .unwrap();
            assert_eq!(row.seq, expected);
            // The SIGNED identity carries event_sequence == the row's seq (stamped atomically).
            assert_eq!(row.identity["event_sequence"], json!(expected));
        }
        // The signature is over the leaf INCL. the injected event_sequence, so the whole chain still
        // re-derives + verifies — proving the stamp is inside the signed envelope, not bolted on after.
        let loaded = load_chain_file(&path).unwrap();
        verify_decision_chain(
            &loaded,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            true,
        )
        .expect("stamped chain must verify");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_is_empty_chain() {
        let path = temp_chain_path("missing");
        assert!(load_chain_file(&path).unwrap().is_empty());
        assert_eq!(next_position(&[]), (0, DECISION_CHAIN_GENESIS.to_string()));
    }

    #[test]
    fn concurrent_appends_produce_a_contiguous_verifiable_chain() {
        // Proves the per-path append lock: N threads racing append_*_to_file must NOT produce duplicate
        // seq / divergent chain_hash. Without the lock they'd both read tip T, compute seq=k, and write a
        // pair the verifier rejects. With it, the on-disk chain is a clean 0..N that re-derives.
        let path = std::sync::Arc::new(temp_chain_path("concurrent"));
        let n = 16u64;
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let path = std::sync::Arc::clone(&path);
                std::thread::spawn(move || {
                    let sk = fixture_signing_key();
                    let preimage = format!("{{\"decision\":\"block\",\"t\":{i}}}");
                    append_decision_to_file(
                        &path,
                        "enforcement_decision",
                        preimage.as_bytes(),
                        identity(i),
                        &sk,
                        KEY_ID,
                    )
                    .expect("threaded append must succeed");
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let loaded = load_chain_file(&path).unwrap();
        assert_eq!(loaded.len() as u64, n, "every append landed exactly once");
        // seq is a clean contiguous 0..N (no dup/gap from a race) and the chain re-derives end-to-end.
        for (i, row) in loaded.iter().enumerate() {
            assert_eq!(row.seq, i as u64);
        }
        verify_decision_chain(
            &loaded,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            true,
        )
        .expect("concurrently-built chain must re-derive contiguously");
        let _ = std::fs::remove_file(&*path);
    }

    #[test]
    fn wire_field_is_hash_to_match_deployed_reader() {
        // The deployed incident_evidence.rs::read_decision_chain reads each record's "hash" as the tip.
        // The serialized row MUST carry "hash" (not "chain_hash") or the deployed reader finds no tip.
        let rows = build_chain(1);
        let json: Value = serde_json::from_str(&serde_json::to_string(&rows[0]).unwrap()).unwrap();
        assert!(json.get("hash").is_some(), "wire key must be 'hash'");
        assert!(
            json.get("chain_hash").is_none(),
            "must NOT emit 'chain_hash'"
        );
        assert_eq!(json["hash"], rows[0].chain_hash);
        // Round-trips back to the same row (serde rename is symmetric).
        let back: DecisionChainRow = serde_json::from_value(json).unwrap();
        assert_eq!(back, rows[0]);
    }

    #[test]
    fn fixture_signed_rows_rejected_by_a_prod_trust_store() {
        // Enforces the "never fixture-sign in prod" guarantee: a chain signed with the fixture key MUST
        // fail against a production trust store that does not enrol that key — so a leaked fixture key
        // can never forge accepted evidence in the field.
        let rows = build_chain(3);
        let prod_store = EnrolledAgentTrustStore::new(vec![]); // no fixture key enrolled
        let err = verify_decision_chain(
            &rows,
            DECISION_CHAIN_GENESIS,
            &prod_store,
            116_444_736_000_000_100,
            true,
        )
        .unwrap_err();
        assert_eq!(err, DecisionChainError::SignatureUntrusted { seq: 0 });
    }

    #[test]
    fn bad_signature_encoding_is_caught() {
        let mut rows = build_chain(2);
        rows[1].sig_b64 = "not-base64-and-not-64-bytes!!".to_string();
        let err = verify_decision_chain(
            &rows,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            true,
        )
        .unwrap_err();
        assert_eq!(err, DecisionChainError::BadSignatureEncoding { seq: 1 });
    }

    #[test]
    fn forged_from_scratch_chain_re_derives_but_to_a_different_tip() {
        // MEDIUM AI-review (the pinning point): a box-owning attacker can fabricate a FULLY
        // self-consistent, validly-signed chain from genesis. It re-derives CLEANLY — so re-derivation
        // alone is insufficient; the tip must be pinned against an EXTERNAL anchor. This proves the
        // forged chain's tip differs from the real one, which is exactly what tip-pinning catches.
        let real = build_chain(4);
        let real_tip = tip(&real);

        let sk = fixture_signing_key();
        let mut forged = Vec::new();
        let mut prev = DECISION_CHAIN_GENESIS.to_string();
        for seq in 0..4u64 {
            let preimage = format!("{{\"decision\":\"allow\",\"seq\":{seq},\"fabricated\":true}}");
            let row = append_decision(
                DecisionInput {
                    seq,
                    prev_tip: &prev,
                    source_kind: "cooperation_decision",
                    canonical_preimage: preimage.as_bytes(),
                    identity: identity(seq),
                },
                &sk,
                KEY_ID,
            );
            prev = row.chain_hash.clone();
            forged.push(row);
        }
        // The forged chain is itself internally valid (re-derives + signatures verify)…
        let forged_tip = verify_decision_chain(
            &forged,
            DECISION_CHAIN_GENESIS,
            &trust_store(),
            116_444_736_000_000_100,
            true,
        )
        .expect("a fabricated chain is still internally self-consistent");
        // …but its tip differs from the real one — only an EXTERNAL pin (anchor / rewind counter)
        // distinguishes the true history from a plausible forgery.
        assert_ne!(forged_tip, real_tip);
    }

    #[test]
    fn kat_content_hash_is_cross_language_anchored() {
        // Cross-language parity anchor for evchain-verify.py: the EMPTY preimage MUST hash to the
        // well-known SHA-256 of the empty string. If a port's content_hash differs here, its canon /
        // hashing is wrong before any chain logic runs. (The full sig / canonical-bytes vector is handed
        // to the Python harness as the sample when 1a emits; this pins the base convention in-repo.)
        const SHA256_EMPTY: &str =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let leaf = build_commitment_leaf("enforcement_decision", b"", identity(0));
        assert_eq!(leaf.content_hash, SHA256_EMPTY);
        // The genesis chain-link over it is deterministic, 64-hex, and NOT a trivial/zero tip.
        let ch = decision_chain_hash(DECISION_CHAIN_GENESIS, &leaf.content_hash);
        assert_eq!(ch.len(), 64);
        assert_ne!(ch, SHA256_EMPTY);
        assert_ne!(ch, "0".repeat(64));
    }
}
