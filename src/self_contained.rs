//! R7 — self-contained proof-bundle types (Task 1 of 6, `docs/superpowers/plans/
//! 2026-07-25-r7-proof-bundle.md`).
//!
//! Unit 1 (the bundle-assembly endpoint, `cloud-backend-rs/src/routes/proof_bundle.rs`, a later
//! task) packages one compliance export's evidence into a zip a customer can verify **offline,
//! without trusting MeshLogic** — the wedge named in the R7 design spec. This module defines the
//! bundle's serde-round-trippable shape only: no assembly logic, no verification logic. It wraps
//! (never re-derives) the crate's already-proven primitives — `proof_gen::ProofBundle` per
//! evidence record, `coanchor::RekorReceipt` per anchored period — into one JSON document a
//! customer downloads alongside the TST DER blobs.
//!
//! [`RecordVerdict`] / [`BundleVerdict`] are the later verifier task's (Unit 2, `meshlogic_verify`)
//! output shape, defined here so bundle producer and offline verifier share one type and can never
//! drift on the ≥5 fail-closed grades the design spec requires (PROVEN / ALTERED /
//! NOT_YET_WITNESSED / NOT_YET_ANCHORED / UNTRUSTED_KEY / MALFORMED).

use crate::anchor::verify_tst_full;
use crate::coanchor::{verify_coanchored_at, CoAnchorStatus, RekorReceipt, RekorTrustStore};
use crate::commitment_leaf::sha256_hex;
use crate::proof_gen::ProofBundle;
use base64::Engine as _;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
// `EncodePublicKey`/`Sha256`/`Digest` are only needed by the POV fixture functions below (AI-review
// round-3 MED-3: `pov_bundle_signing_key`/`pov_bundle_trust_store` are now
// `#[cfg(any(debug_assertions, feature = "pov-fixtures"))]`) — gated identically so a production
// (release, no `pov-fixtures`) build does not fail on unused imports.
#[cfg(any(debug_assertions, feature = "pov-fixtures"))]
use p256::pkcs8::EncodePublicKey;
#[cfg(any(debug_assertions, feature = "pov-fixtures"))]
use sha2::{Digest, Sha256};

/// The same STANDARD (padded) base64 engine `commitment_leaf`/`coanchor` use internally — kept
/// local because their own `B64` constants are module-private.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Schema tag stamped into every bundle's `schema` field — a verifier's first sanity check before
/// trusting anything else in the document.
///
/// Bumped to v2 by the R7 signing-key workstream (`docs/superpowers/sdd/2026-07-26-r7-signing-key`):
/// adds the [`BundleSignature`]-carrying `signature` field, now the verifier's ONLY trust gate
/// (task 3, [`verify_self_contained`] + [`BundleTrustStore`]). `signer_fingerprint_sha256` is kept
/// for now (a later task in that workstream removes it once the producer moves to KMS signing).
pub const BUNDLE_SCHEMA: &str = "meshlogic.proof-bundle.v2";

/// A4 remediation: the allow-list of bundle schema versions THIS verifier understands.
/// [`verify_self_contained`] fails the WHOLE bundle closed (`Malformed`) for anything else — a
/// forward/unknown `schema` is NEVER graded as if its fields carried the current version's semantics
/// (version-confusion). The `schema` field is already inside [`SelfContainedBundle::canonical_signing_bytes`]
/// (so a signed bundle can't flip it), but that only stops external forgery — it does NOT make a
/// genuine future-schema bundle safe to grade under today's field assumptions. Extend this list
/// deliberately, only when a new schema's field semantics are actually supported here.
pub const KNOWN_BUNDLE_SCHEMAS: &[&str] = &[BUNDLE_SCHEMA];

/// Domain-separation tag for [`SelfContainedBundle::canonical_signing_bytes`] — the same hygiene as
/// `signed_leaf::LEAF_SIG_DOMAIN`: binds the signature to THIS protocol so it can never be replayed as
/// a signature over some other MeshLogic message. FROZEN once a later task's producer/verifier both
/// depend on it.
const BUNDLE_SIG_DOMAIN: &[u8] = b"meshlogic.proof-bundle.sig.v2\x00";

/// SECURITY (R7 signing-key task 3): the POV (proof-of-value) demo's fixed, deterministic P-256
/// signing key — a FIXTURE key, NOT a production KMS key. There is no production bundle-signing
/// key wired up yet (TODO(R7 signing-key task 6): replace this whole function's body once one
/// exists, mirroring `meshlogic_verify`'s POV fixture gate). Deterministic (fixed seed) so a bundle
/// signed with this key always verifies against [`pov_bundle_trust_store`]'s pinned SPKI without
/// threading key material between callers.
///
/// Supersedes the old AI-review HIGH-2 `pov_signer_fingerprint` fixture (a bare
/// `sha256_hex(b"kat-pinned-signer-der")` string both producer and verifier hardcoded as a
/// string-equality "trust gate") — removed once `verify_self_contained` moved to real ECDSA-P256
/// verification (R7 signing-key task 3) and the producer moved to real KMS signing (task 4), which
/// left that function with no caller on either side.
///
/// SECURITY (AI-review round-3 MED-3): gated `#[cfg(any(debug_assertions, feature = "pov-fixtures"))]`
/// — this used to be `pub` UNCONDITIONALLY on the library surface, so ANY downstream crate merely
/// linking `meshlogic-merkle` in a RELEASE build could reach this demo key and sign or trust with it,
/// directly undermining R7's "never silently trust demo keys" thesis. The gate deliberately MIRRORS
/// `meshlogic_verify`'s own binary gate (`all(not(debug_assertions), not(feature = "pov-fixtures"))`
/// on its production path) — exactly as the review asked ("the library surface should mirror the
/// binary's release gate"): in a production (release) build with no `pov-fixtures`, `debug_assertions`
/// is false, so these functions do not exist and a downstream consumer's release binary cannot reach
/// the demo key. `debug_assertions` (not `test`) is required, not merely cleaner: the demo binary
/// reaches these across a crate boundary (`meshlogic_merkle::self_contained::...`), and `cfg(test)` is
/// true ONLY while THIS crate's own `--lib` unit-test harness compiles — it never applies to the
/// `[[bin]]`'s view of the library, so a `test`-only gate would make `meshlogic_verify` (and the CI
/// `--features offline-verify` clippy/test steps that build it in the debug profile) fail to compile.
/// A release downstream build is the real "silently ships a demo key" threat this closes; a downstream
/// *debug* build reaching a fixture is a dev-only exposure the binary's own gate already accepts by the
/// same reasoning. `pov-fixtures` stays the explicit, loud opt-in for building the POV demo in release.
#[cfg(any(debug_assertions, feature = "pov-fixtures"))]
pub fn pov_bundle_signing_key() -> p256::ecdsa::SigningKey {
    let seed = Sha256::digest(b"meshlogic.proof-bundle.pov-signing-key.v1");
    p256::ecdsa::SigningKey::from_slice(&seed).expect("fixed seed is a valid P-256 scalar")
}

/// The [`BundleTrustStore`] pinning [`pov_bundle_signing_key`]'s public SPKI — the ONE place both
/// the POV demo verifier (`meshlogic_verify`, gated `pov-fixtures`) and this crate's own tests derive
/// that pin, so producer/verifier fixtures can never silently diverge. NOT a production trust root.
///
/// Gated identically to [`pov_bundle_signing_key`] (AI-review round-3 MED-3) — see that function's
/// doc for why.
#[cfg(any(debug_assertions, feature = "pov-fixtures"))]
pub fn pov_bundle_trust_store() -> BundleTrustStore {
    let vk = pov_bundle_signing_key().verifying_key().to_owned();
    let der = vk
        .to_public_key_der()
        .expect("encode POV bundle-signer SPKI DER")
        .into_vec();
    let spki_sha256 = sha256_hex(&der);
    BundleTrustStore::from_pinned(vec![BundleTrustKey {
        spki_der: der,
        spki_sha256,
        not_before: None,
        not_after: None,
    }])
}

/// The whole self-contained bundle: one compliance export's evidence records, pinned to a single
/// as-of roots-chain checkpoint (`pinned_period_id`, design spec §4 "coherence") so every record's
/// proof re-derives against the same fixed root set.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SelfContainedBundle {
    /// Always [`BUNDLE_SCHEMA`] — a verifier rejects anything else before parsing further.
    pub schema: String,
    pub org_id: String,
    pub export_id: String,
    /// The roots-chain period the bundle's checkpoint was pinned at (design spec §4).
    pub pinned_period_id: u64,
    /// SHA-256 fingerprint of the MeshLogic collection-signing key — a CONVENIENCE copy only; the
    /// verifier trusts its own out-of-band-pinned root, never this field (design spec §5).
    ///
    /// NO LONGER the verifier's trust gate as of R7 signing-key task 3: [`verify_self_contained`]
    /// now checks [`Self::signature`] (real ECDSA-P256) against a [`BundleTrustStore`], never this
    /// string. Kept for now — the producer (`cloud-backend-rs/src/routes/proof_bundle.rs`, task 4)
    /// still stamps it; a later task removes the field once that producer moves to KMS signing.
    pub signer_fingerprint_sha256: String,
    /// Schema-v2 field (R7 signing-key workstream): the bundle's ECDSA-P256 signature over its own
    /// [`Self::canonical_signing_bytes`]. `None` for a not-yet-signed bundle (or one produced before
    /// the schema bump, or by a producer that has not yet wired up KMS signing — R7 signing-key
    /// task 4) — [`verify_self_contained`] (task 3) treats a missing signature as fail-closed
    /// `UNTRUSTED_KEY`, never a softer grade.
    ///
    /// `#[serde(default)]` (AI-review Minor, task 1): a bundle JSON that predates this field (or
    /// simply omits it) deserialises to `None` rather than a hard serde parse error, so an absent
    /// signature is graded by the fail-closed `UNTRUSTED_KEY` path above, not rejected before the
    /// schema tag is even read.
    #[serde(default)]
    pub signature: Option<BundleSignature>,
    /// Whether this bundle is deliberately narrowed to committed-only (provable) records — see
    /// [`BundleScope`]. A machine-readable, SIGNED counterpart to the README's human-readable scope
    /// line: it is part of [`Self::canonical_signing_bytes`], so a programmatic consumer of
    /// bundle.json can distinguish a deliberately-narrowed bundle from a full export that merely
    /// happens to have every record committed — without trusting any server-side log. Omitted on
    /// the wire when `FullExport` (via `skip_serializing_if`) so existing full-export bundles
    /// serialise byte-identically (no signature / frozen-corpus break); a predating bundle without
    /// the field deserialises to `FullExport`.
    #[serde(default, skip_serializing_if = "BundleScope::is_full_export")]
    pub scope: BundleScope,
    pub records: Vec<BundleRecord>,
    /// RFC 3161 timestamp-token DER, one per anchored period the bundle's records span.
    pub tst_der_by_period: Vec<PeriodTst>,
    /// Graded Sigstore/Rekor co-anchor receipt, one per period (absent = not yet witnessed).
    pub rekor_by_period: Vec<PeriodRekor>,
}

/// The bundle's evidence scope. `CommittedOnly` = deliberately includes ONLY records that resolve
/// to a committed WORM leaf (dropping un-anchored control-evidence) so the overall verdict is a
/// clean `PROVEN`; `FullExport` (default) = every exported record, mixed verdicts. Because this is
/// part of [`SelfContainedBundle::canonical_signing_bytes`], the narrowing is a tamper-evident,
/// machine-readable attestation, not just a README line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleScope {
    /// Every exported record is present (mixed per-record verdicts expected). The default, and
    /// omitted on the wire so full-export bundles serialise exactly as before this field existed.
    #[default]
    FullExport,
    /// Only committed (anchored) records — a deliberately-narrowed, PoV-ready bundle.
    CommittedOnly,
}

impl BundleScope {
    /// Serde `skip_serializing_if` predicate — keeps `FullExport` off the wire for byte-identity.
    pub fn is_full_export(&self) -> bool {
        matches!(self, BundleScope::FullExport)
    }

    /// One-line human description for the offline verifier's report.
    pub fn describe(&self) -> &'static str {
        match self {
            BundleScope::FullExport => {
                "full export (every exported record; mixed per-record verdicts expected)"
            }
            BundleScope::CommittedOnly => {
                "committed-only (deliberately narrowed to provable records; un-anchored evidence \
                 excluded by request)"
            }
        }
    }
}

impl SelfContainedBundle {
    /// RFC 8785 canonical bytes of this bundle with [`Self::signature`] EXCLUDED, prefixed with
    /// [`BUNDLE_SIG_DOMAIN`] — the exact preimage a producer's KMS signature (later task) is computed
    /// over and a verifier's p256 check (later task) re-derives.
    ///
    /// `signature` MUST be excluded from its own signed bytes: a bundle has to sign identically
    /// whether or not it is yet signed (populating `signature` can never change what was signed over,
    /// or signing would be circular), so this clones `self`, clears `signature`, and canonicalises
    /// that — never the bundle as received.
    ///
    /// SECURITY (R7 signing-key critical fix): `signer_fingerprint_sha256` is ALSO normalised out
    /// (cleared to `""`) here, for the same reason. It is documented as a convenience copy the
    /// verifier never trusts (the real key reference lives in `signature.spki_sha256`), so it has no
    /// business affecting the signed preimage — the producer
    /// (`cloud-backend-rs/src/routes/proof_bundle.rs::sign_bundle`) signs while the field is empty,
    /// then overwrites it with the real key's SPKI hash AFTER signing, so leaving it in the preimage
    /// made every real bundle sign under one value and verify under another, failing
    /// `UNTRUSTED_KEY` deterministically. Excluding it makes producer and verifier agree regardless
    /// of WHEN the field is set.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        unsigned.signer_fingerprint_sha256 = String::new();
        let value = serde_json::to_value(&unsigned)
            .expect("SelfContainedBundle serializes to a JSON value (no non-string map keys)");
        let mut bytes = BUNDLE_SIG_DOMAIN.to_vec();
        bytes.extend_from_slice(&crate::jcs::canonical_json_bytes(&value));
        bytes
    }
}

/// The bundle's ECDSA-P256 signature over [`SelfContainedBundle::canonical_signing_bytes`] — added in
/// schema v2 (R7 signing-key workstream). A later task's producer populates this via a real KMS sign;
/// another later task's verifier p256-checks it against a pinned key, replacing the placeholder
/// `signer_fingerprint_sha256` gate `verify_self_contained` still uses today.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BundleSignature {
    /// The KMS key identifier (e.g. an ARN) that produced [`Self::sig_der_b64`] — a CONVENIENCE
    /// label only, never itself trusted: the verifier trusts its own out-of-band-pinned key/root,
    /// the same rule [`SelfContainedBundle::signer_fingerprint_sha256`] documents.
    pub key_id: String,
    /// Lowercase-hex SHA-256 of the signing key's DER-encoded SubjectPublicKeyInfo — lets the
    /// verifier pin against the key's fingerprint (mirrors `coanchor`'s Rekor log-id pinning).
    pub spki_sha256: String,
    /// STANDARD (padded) base64 of the DER-encoded ECDSA signature.
    pub sig_der_b64: String,
    /// Signature algorithm identifier, e.g. `"ecdsa-p256-sha256"`.
    pub alg: String,
}

/// One pinned, trusted bundle-signer key with an optional validity window (Unix seconds) — the
/// ECDSA-P256 analog of `coanchor::RekorTrustKey`, so a rotated-out signer can still be pinned for
/// the window it was genuinely valid in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleTrustKey {
    /// DER-encoded SubjectPublicKeyInfo of the pinned signer key — the input to
    /// [`p256::ecdsa::VerifyingKey::from_public_key_der`].
    pub spki_der: Vec<u8>,
    /// Lowercase-hex SHA-256 of `spki_der`, matched against [`BundleSignature::spki_sha256`] to
    /// select this key ([`BundleTrustStore::select`]) — MUST equal `sha256_hex(&spki_der)`, the same
    /// self-consistency invariant `coanchor::RekorTrustKey::log_id` documents for its own key hash.
    pub spki_sha256: String,
    /// Inclusive lower bound of the key's validity (Unix seconds); `None` = open-ended.
    pub not_before: Option<u64>,
    /// Inclusive upper bound of the key's validity (Unix seconds); `None` = open-ended.
    pub not_after: Option<u64>,
}

/// The offline verifier's pinned bundle-signer trust store (design spec §5, R7 signing-key task 3)
/// — the ONLY trust anchor for [`SelfContainedBundle::signature`]. Never resolved from the bundle's
/// own `key_id`/`signer_fingerprint_sha256` convenience copies, which an attacker fully controls;
/// the caller (verifier) pins this out-of-band, exactly like `coanchor::RekorTrustStore` pins the
/// Sigstore log key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BundleTrustStore {
    keys: Vec<BundleTrustKey>,
}

impl BundleTrustStore {
    /// Build a trust store from an explicit set of pinned keys.
    pub fn from_pinned(keys: Vec<BundleTrustKey>) -> Self {
        Self { keys }
    }

    /// Resolve the pinned key matching `spki_sha256`, if any — the ONLY lookup path (never trusts
    /// [`BundleSignature::key_id`], a convenience label the signer — or an attacker — fully
    /// controls). Validity-window enforcement happens at the call site
    /// ([`verify_self_contained`]'s signature gate), not here, so `select` stays a pure lookup.
    pub fn select(&self, spki_sha256: &str) -> Option<&BundleTrustKey> {
        self.keys.iter().find(|k| k.spki_sha256 == spki_sha256)
    }
}

/// One evidence record's entry: its committed identity plus everything needed to re-verify it, or
/// an honest reason why it cannot be (never a fabricated proof — design spec §4/§5).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BundleRecord {
    pub record_id: String,
    pub content_hash: String,
    /// The record's canonical preimage, base64, if the export chose to include it (verifier
    /// recomputes `content_hash` from this to catch alteration; absent for preimage-withheld bundles).
    pub preimage_b64: Option<String>,
    /// `proof_gen::ProofBundle::to_json` — carried as an opaque value here so this crate's serde
    /// core stays decoupled from `ProofBundle`'s own (de)serialization; the later assembly task
    /// converts, this module never re-derives.
    pub proof: Option<serde_json::Value>,
    pub status: RecordStatus,
}

/// Whether a record has a Merkle leaf at the pinned checkpoint. Never inferred — set by the
/// assembly task from an actual roots-chain lookup (design spec §4: "Never fabricate a proof").
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Anchored,
    NotYetAnchored { reason: String },
}

/// One period's RFC 3161 timestamp-token DER, base64-encoded for the JSON carrier.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeriodTst {
    pub period_id: u64,
    pub tst_der_b64: String,
}

/// One period's graded Rekor co-anchor receipt (`coanchor::RekorReceipt`, opaque `serde_json::Value`
/// for the same decoupling reason as [`BundleRecord::proof`]); `None` means not yet witnessed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeriodRekor {
    pub period_id: u64,
    pub receipt: Option<serde_json::Value>,
}

/// A single record's (or the bundle's overall) fail-closed grade (design spec §5, §7 verdict
/// states). `PROVEN` requires inclusion + TST + the EXTERNAL Rekor witness — never MeshLogic's
/// signature alone; ambiguity/incompleteness must never grade here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordVerdict {
    Proven,
    Altered,
    NotYetWitnessed,
    NotYetAnchored,
    UntrustedKey,
    Malformed,
}

/// The verifier's (Unit 2, later task) full report shape: an overall grade, the per-record
/// breakdown, and the honest-boundary notes the design spec (§5) requires stating verbatim
/// (proves inclusion + non-alteration + external witness; NOT completeness/correctness).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BundleVerdict {
    pub overall: RecordVerdict,
    pub per_record: Vec<(String, RecordVerdict)>,
    pub notes: Vec<String>,
}

// -------------------------------------------------------------------------------------------
// Task 2 (this task, R7 plan) — `verify_self_contained`: the PROVEN / ALTERED / MALFORMED core
// (inclusion + TST + leaf re-derive). `UntrustedKey` and the external Rekor co-anchor gate that
// final-grades `Proven` are Task 3's — this task's `Proven` is provisional (TST-verified only).
// -------------------------------------------------------------------------------------------

/// Grade ONE [`BundleRecord`] against the checks this task owns: anchoring honesty, proof
/// parseability, the leaf re-derivation (`sha256_hex(base64_decode(preimage_b64)) ==
/// record.content_hash`), the proof's own structural inclusion + roots-chain-linkage verify, a full
/// RFC 3161 crypto verify of its period's timestamp token, and (Task 3) the external Rekor co-anchor
/// witness. The first failing check wins per record (design spec §5/§7 grading precedence) — see
/// [`verify_self_contained`].
fn grade_record(
    record: &BundleRecord,
    bundle: &SelfContainedBundle,
    trusted_tsa_roots: &[Vec<u8>],
    rekor_trust: &RekorTrustStore,
) -> (RecordVerdict, String) {
    // 1. Anchoring honesty: a record the assembler never anchored can never grade PROVEN — never
    //    inferred, the assembler's own `RecordStatus` decides this (design spec §4).
    if let RecordStatus::NotYetAnchored { reason } = &record.status {
        return (
            RecordVerdict::NotYetAnchored,
            format!("{}: not yet anchored ({reason})", record.record_id),
        );
    }

    // 2. The carried proof must at least parse. An anchored record with no proof, or one that
    //    does not parse as a `ProofBundle`, is a MALFORMED bundle — never softened to a lesser grade.
    let proof_json = match &record.proof {
        Some(v) => v,
        None => {
            return (
                RecordVerdict::Malformed,
                format!("{}: anchored record carries no proof", record.record_id),
            )
        }
    };
    let parsed = match ProofBundle::from_json(proof_json) {
        Ok(p) => p,
        Err(e) => {
            return (
                RecordVerdict::Malformed,
                format!("{}: proof does not parse: {e}", record.record_id),
            )
        }
    };

    // 2.5 ANTI-SWAP BINDING (round-2 review Critical): the parsed proof must prove inclusion for
    //     THIS record's OWN declared content_hash — never some other, validly-anchored record's.
    //     Without this, an attacker could substitute a different record's individually-valid proof
    //     (structurally sound, TST-verified, just for the WRONG leaf) and it would grade PROVEN
    //     undetected, defeating the "verify non-alteration without trusting MeshLogic" guarantee
    //     (design spec §5: ALTERED means content_hash does not match ITS COMMITTED LEAF).
    //     `parsed.content_hash` is the leaf identity the inclusion path was re-derived for
    //     (proof_gen.rs `ProofBundle::content_hash`).
    if parsed.content_hash != record.content_hash {
        return (
            RecordVerdict::Altered,
            format!(
                "{}: proof is for content_hash {} but the record declares {} — proof/record \
                 binding broken (swapped or substituted proof)",
                record.record_id, parsed.content_hash, record.content_hash
            ),
        );
    }

    // 2.6 ORG COHERENCE (A4-ii remediation): the carried proof must be for the SAME org the bundle
    //     declares. Because the roots chain can aggregate multiple orgs (and, pre-A1, `org_id` is not
    //     yet folded into the committed root), a validly-anchored leaf from a DIFFERENT org would
    //     otherwise grade PROVEN inside a bundle labelled `org_id = A` — genuine cross-org confusion.
    //     This is the verifier-side coherence check the R7 "verify without trusting MeshLogic's
    //     assembly" thesis requires; the cryptographic org-in-root binding it complements is the A1
    //     MAC-2 committed digest (`committed_chain`, NEEDS windows-master concurrence).
    if parsed.org_id != bundle.org_id {
        return (
            RecordVerdict::Altered,
            format!(
                "{}: proof is for org {:?} but the bundle declares {:?} — cross-org proof (coherence \
                 violation)",
                record.record_id, parsed.org_id, bundle.org_id
            ),
        );
    }

    // 2.7 PERIOD COHERENCE (A4-ii remediation): the bundle pins ONE as-of checkpoint
    //     (`pinned_period_id`); every record must be provable as-of that checkpoint, i.e. anchored at
    //     a period <= the pin. A record whose proof is anchored at a LATER period than the declared
    //     checkpoint cannot be witnessed by it — the "every record provable as-of ONE fixed
    //     checkpoint" guarantee is violated, so grade `Malformed` rather than let it pass silently.
    if parsed.period_id > bundle.pinned_period_id {
        return (
            RecordVerdict::Malformed,
            format!(
                "{}: proof period {} is beyond the bundle's pinned checkpoint period {} — the \
                 as-of checkpoint cannot witness it (coherence violation)",
                record.record_id, parsed.period_id, bundle.pinned_period_id
            ),
        );
    }

    // 3. Leaf re-derive: the auditor re-derivation `commitment_leaf` performs
    //    (`sha256_hex(base64_decode(preimage))` must equal the declared content_hash). Applied
    //    directly here rather than via `commitment_leaf::load_and_verify_leaf`, because that
    //    function additionally requires the decoded preimage to itself be a parseable
    //    CommitmentLeaf JSON envelope — an invariant this bundle's carried `preimage_b64` (the raw
    //    evidence preimage) does not make. The cryptographic re-derivation is identical (same
    //    `sha256_hex` primitive, never reimplemented); only the wrapping differs.
    if let Some(b64) = &record.preimage_b64 {
        match B64.decode(b64) {
            Ok(preimage) => {
                let recomputed = sha256_hex(&preimage);
                if recomputed != record.content_hash {
                    return (
                        RecordVerdict::Altered,
                        format!(
                            "{}: preimage re-derives to {recomputed}, expected {}",
                            record.record_id, record.content_hash
                        ),
                    );
                }
            }
            Err(e) => {
                return (
                    RecordVerdict::Altered,
                    format!(
                        "{}: preimage_b64 is not valid base64: {e}",
                        record.record_id
                    ),
                )
            }
        }
    }
    // A withheld preimage (design spec: `preimage_b64` is optional) has nothing to re-derive
    // against — this task does not treat absence alone as alteration.

    // 4. Structural verification: inclusion + roots-chain linkage, reusing the frozen SEAM
    //    unchanged (never re-implemented).
    if let Err(e) = parsed.verify() {
        return (
            RecordVerdict::Malformed,
            format!("{}: proof fails structural verify: {e}", record.record_id),
        );
    }

    // 5. RFC 3161 timestamp: locate the period's TST DER and fully crypto-verify it against the
    //    proof's own re-derived period root.
    let tst_der_b64 = match bundle
        .tst_der_by_period
        .iter()
        .find(|t| t.period_id == parsed.period_id)
    {
        Some(t) => &t.tst_der_b64,
        None => {
            return (
                RecordVerdict::NotYetWitnessed,
                format!(
                    "{}: no TST carried for period {}",
                    record.record_id, parsed.period_id
                ),
            )
        }
    };
    let der = match B64.decode(tst_der_b64) {
        Ok(d) => d,
        Err(e) => {
            return (
                RecordVerdict::NotYetWitnessed,
                format!(
                    "{}: tst_der_b64 for period {} is not valid base64: {e}",
                    record.record_id, parsed.period_id
                ),
            )
        }
    };
    let verified_tst = match verify_tst_full(&der, parsed.inclusion.period_root, trusted_tsa_roots)
    {
        Ok(v) => v,
        Err(e) => {
            // This task does not split WHICH TST failures are MALFORMED vs merely not-yet-witnessed
            // (design spec defers that finer grading); NotYetWitnessed here is the fail-CLOSED
            // choice — a TST that fails to verify never grades PROVEN.
            return (
                RecordVerdict::NotYetWitnessed,
                format!(
                    "{}: TST for period {} did not verify ({e})",
                    record.record_id, parsed.period_id
                ),
            );
        }
    };

    // 6. External Rekor co-anchor witness (Task 3): inclusion + chain-linkage + a genuinely-verified
    //    TST is MeshLogic's OWN signature on its OWN copy of the evidence — it never rules out
    //    MeshLogic unilaterally rewriting that copy. PROVEN additionally requires the roots-chain
    //    root to be independently witnessed in the public Sigstore Rekor log
    //    (`coanchor::verify_coanchored`, never re-implemented here). A record that is TST-verified
    //    but not (yet) Rekor-witnessed grades the honest `NotYetWitnessed`, never a softened PROVEN.
    let receipt = bundle
        .rekor_by_period
        .iter()
        .find(|r| r.period_id == parsed.period_id)
        .and_then(|r| r.receipt.as_ref())
        // The bundle carries the COMPACT persisted receipt shape (coanchor::RekorReceipt::
        // to_receipt_json — what the roots-chain row's `coanchor_receipt` attr stores), NOT the raw
        // Rekor entries-response. Parse it with the matching inverse; a parse failure yields None →
        // graded the honest NotYetWitnessed below, never a softened Proven.
        .and_then(|v| RekorReceipt::from_receipt_json(v).ok());
    // A2 remediation: bind the Rekor receipt's attacker-chosen `integrated_time` to the AUTHENTICATED
    // RFC 3161 TST `gen_time` we JUST cryptographically verified for this same period root (step 5).
    // `integrated_time` is not part of the signed checkpoint text, so on its own it must not select
    // which pinned key validates the receipt; cross-checking it against the verified TST time refuses
    // a fabricated old-looking time chosen to land inside a retired key's window
    // (`verify_coanchored_at` → `IntegratedTimeUnauthenticated`, graded the honest NotYetWitnessed).
    match verify_coanchored_at(
        parsed.inclusion.period_root,
        parsed.period_id,
        receipt.as_ref(),
        rekor_trust,
        verified_tst.gen_time_unix,
    ) {
        CoAnchorStatus::CoAnchored { .. } => (
            RecordVerdict::Proven,
            format!(
                "{}: inclusion + chain-linkage + TST + Rekor co-anchor witness all verified",
                record.record_id
            ),
        ),
        // AnchoredOnly covers every reason (missing receipt, unparseable/invalid receipt, or a
        // receipt we do not hold a trusted key for) — all grade the same honest NotYetWitnessed;
        // the reason string is carried in the note for the auditor, never in the verdict itself.
        CoAnchorStatus::AnchoredOnly { reason } => (
            RecordVerdict::NotYetWitnessed,
            format!(
                "{}: RFC 3161-anchored but not yet Rekor co-anchored ({reason:?})",
                record.record_id
            ),
        ),
    }
}

/// Worst-first rank (design spec §5/§7 precedence): `Malformed > UntrustedKey > Altered >
/// NotYetAnchored > NotYetWitnessed > Proven`. The WORST grade gets the HIGHEST rank so
/// `Iterator::max_by_key` picks it as the bundle's overall verdict.
fn verdict_rank(v: &RecordVerdict) -> u8 {
    match v {
        RecordVerdict::Malformed => 5,
        RecordVerdict::UntrustedKey => 4,
        RecordVerdict::Altered => 3,
        RecordVerdict::NotYetAnchored => 2,
        RecordVerdict::NotYetWitnessed => 1,
        RecordVerdict::Proven => 0,
    }
}

/// H1 (AI review round-2, R7 signing-key hardening): establish the bundle's own "as-of" anchor time
/// for [`verify_bundle_signature`]'s validity-window check. An OFFLINE verifier can run YEARS after a
/// bundle was produced, so wall-clock "now" is the wrong question for whether the pinned signer key
/// was valid AT SIGNING TIME — checking against wall-clock wrongly retires a formerly-valid key
/// purely because time has since passed, for a bundle that was genuinely signed inside the key's
/// window.
///
/// The anchor is the MINIMUM cryptographically-VERIFIED RFC 3161 TST `gen_time_unix` across every
/// period the bundle carries a proof + TST for — never an unverified/merely-extracted time. Using an
/// unverified time would let an attacker holding a compromised (rightly-retired) key embed a
/// fabricated old-looking TST purely to dodge a closed validity window, defeating the whole point of
/// the window. Reuses the same `verify_tst_full` crypto [`grade_record`] runs per record (never
/// re-implemented) rather than trusting any bundle-carried timestamp field directly.
///
/// Returns `None` if not even one TST in the bundle cryptographically verifies — the caller
/// (`verify_bundle_signature`) must then fail CLOSED for any window-bounded key rather than silently
/// falling back to wall-clock or `0`.
fn establish_bundle_anchor_time(
    bundle: &SelfContainedBundle,
    trusted_tsa_roots: &[Vec<u8>],
) -> Option<u64> {
    let mut earliest: Option<u64> = None;
    for record in &bundle.records {
        let Some(proof_json) = &record.proof else {
            continue;
        };
        let Ok(parsed) = ProofBundle::from_json(proof_json) else {
            continue;
        };
        let Some(tst) = bundle
            .tst_der_by_period
            .iter()
            .find(|t| t.period_id == parsed.period_id)
        else {
            continue;
        };
        let Ok(der) = B64.decode(&tst.tst_der_b64) else {
            continue;
        };
        if let Ok(verified) = verify_tst_full(&der, parsed.inclusion.period_root, trusted_tsa_roots)
        {
            earliest = Some(match earliest {
                Some(e) => e.min(verified.gen_time_unix),
                None => verified.gen_time_unix,
            });
        }
    }
    earliest
}

/// The whole-bundle signature gate (R7 signing-key task 3, replacing the old fingerprint-equality
/// placeholder): verify [`SelfContainedBundle::signature`] is a genuine ECDSA-P256 signature over
/// [`SelfContainedBundle::canonical_signing_bytes`] by a key `bundle_trust` pins — the ONLY trust
/// anchor (never the bundle's own convenience `key_id`/`signer_fingerprint_sha256` copies, which an
/// attacker fully controls). `Ok` means the gate passed; `Err` carries the whole-bundle verdict +
/// note [`verify_self_contained`] applies to EVERY record before any per-record grading ever runs
/// (design spec: a bundle failing this gate proves nothing about any individual record either).
///
/// Grading, matching the `signed_leaf::verify_leaf_signature` fail-closed shape (adapted
/// Ed25519→ECDSA-P256): no signature, no matching pinned key, an expired/not-yet-valid pinned key,
/// or a signature that fails to verify all grade `UntrustedKey`; a signature/key that does not even
/// PARSE (bad base64/DER) grades the stricter `Malformed` — mirrors [`grade_record`]'s own
/// parse-vs-verify split.
fn verify_bundle_signature(
    bundle: &SelfContainedBundle,
    bundle_trust: &BundleTrustStore,
    trusted_tsa_roots: &[Vec<u8>],
) -> Result<(), (RecordVerdict, String)> {
    let sig = bundle.signature.as_ref().ok_or_else(|| {
        (
            RecordVerdict::UntrustedKey,
            "bundle carries no signature — untrusted key, whole bundle rejected fail-closed"
                .to_string(),
        )
    })?;

    let key = bundle_trust.select(&sig.spki_sha256).ok_or_else(|| {
        (
            RecordVerdict::UntrustedKey,
            format!(
                "bundle signature key {} is not in the caller-pinned trust store — untrusted key, \
                 whole bundle rejected fail-closed",
                sig.spki_sha256
            ),
        )
    })?;

    // Validity window: an expired or not-yet-valid pinned key must not vouch for a signature either
    // — the same rotation-window discipline `coanchor::RekorTrustKey` enforces for the Rekor log
    // key. H1 (AI review round-2): wall-clock "now" is the WRONG question here — an OFFLINE verifier
    // is routinely run years after a bundle was produced, and checking a fixed validity window
    // against the CURRENT moment wrongly retires a key that was genuinely valid when the bundle was
    // signed. There is no "signed-at" timestamp carried directly on `BundleSignature` (unlike
    // Rekor's receipt-carried `integrated_time`), so the honest "as-of" time is instead the bundle's
    // OWN verified RFC 3161 anchor time ([`establish_bundle_anchor_time`]) — never wall-clock, never
    // a bundle-carried-but-unverified field. Only computed when a window is actually set: when both
    // bounds are `None` (true of every pinned key today — see the field docs) this is a no-op, byte-
    // for-byte the same as before this fix.
    if key.not_before.is_some() || key.not_after.is_some() {
        let anchor = establish_bundle_anchor_time(bundle, trusted_tsa_roots).ok_or_else(|| {
            (
                RecordVerdict::UntrustedKey,
                format!(
                    "bundle signature key {} carries a pinned validity window (not_before {:?}, \
                     not_after {:?}) but no verified RFC 3161 TST anchor time could be established \
                     from the bundle's own carried timestamps — cannot honestly evaluate the window, \
                     untrusted key, whole bundle rejected fail-closed",
                    sig.spki_sha256, key.not_before, key.not_after
                ),
            )
        })?;
        if key.not_before.is_some_and(|nb| anchor < nb)
            || key.not_after.is_some_and(|na| anchor > na)
        {
            return Err((
                RecordVerdict::UntrustedKey,
                format!(
                    "bundle signature key {} is outside its pinned validity window as of the \
                     bundle's own verified anchor time (not_before {:?}, not_after {:?}, bundle \
                     anchor time {anchor}) — untrusted key, whole bundle rejected fail-closed",
                    sig.spki_sha256, key.not_before, key.not_after
                ),
            ));
        }
    }

    let vk = VerifyingKey::from_public_key_der(&key.spki_der).map_err(|e| {
        (
            RecordVerdict::Malformed,
            format!(
                "bundle trust store's pinned SPKI for {} does not parse: {e}",
                sig.spki_sha256
            ),
        )
    })?;
    let der = B64.decode(&sig.sig_der_b64).map_err(|e| {
        (
            RecordVerdict::Malformed,
            format!("bundle signature base64 does not parse: {e}"),
        )
    })?;
    let signature = Signature::from_der(&der).map_err(|e| {
        (
            RecordVerdict::Malformed,
            format!("bundle signature DER does not parse: {e}"),
        )
    })?;

    vk.verify(&bundle.canonical_signing_bytes(), &signature)
        .map_err(|_| {
            (
                RecordVerdict::UntrustedKey,
                "bundle signature does NOT verify against the pinned key — untrusted key, whole \
                 bundle rejected fail-closed"
                    .to_string(),
            )
        })
}

/// Verify a [`SelfContainedBundle`] OFFLINE, without trusting MeshLogic — the customer-facing
/// entry point (design spec §5). First enforces the bundle-signature gate
/// ([`verify_bundle_signature`], task 3, fail-closed, whole-bundle), then grades every record via
/// [`grade_record`] (inclusion + roots-chain linkage + leaf re-derivation + RFC 3161 timestamp +
/// external Rekor co-anchor witness) and aggregates worst-of into one [`BundleVerdict`]; `overall`
/// is `Proven` only if every record is.
///
/// `bundle_trust` is the caller's OUT-OF-BAND-pinned [`BundleTrustStore`] (design spec §5) — the
/// bundle's OWN `signature.key_id`/`signer_fingerprint_sha256` are convenience copies an attacker
/// fully controls, never themselves a trust anchor. A signature that does not verify against a
/// pinned key grades the WHOLE bundle `UntrustedKey` (or `Malformed` on a parse failure) before any
/// per-record grading runs (design spec: ambiguity/incompleteness must never grade here — a bundle
/// claiming an untrusted key proves nothing about any individual record either).
pub fn verify_self_contained(
    bundle: &SelfContainedBundle,
    trusted_tsa_roots: &[Vec<u8>],
    rekor_trust: &RekorTrustStore,
    bundle_trust: &BundleTrustStore,
) -> BundleVerdict {
    // A4 remediation: FAIL-CLOSED schema gate — the verifier's documented "first sanity check"
    // (`BUNDLE_SCHEMA` / the `schema` field doc), now actually enforced. An unknown/unsupported
    // `schema` grades the WHOLE bundle `Malformed` BEFORE the signature gate or any per-record work,
    // so a future bundle whose field semantics changed is never silently mis-graded under this
    // verifier's assumptions. (`schema` is inside the signed bytes, so this is version-confusion
    // defence, not external-forgery defence — see `KNOWN_BUNDLE_SCHEMAS`.)
    if !KNOWN_BUNDLE_SCHEMAS.contains(&bundle.schema.as_str()) {
        let note = format!(
            "unsupported bundle schema {:?} (known: {:?}) — whole bundle rejected fail-closed",
            bundle.schema, KNOWN_BUNDLE_SCHEMAS
        );
        let per_record = bundle
            .records
            .iter()
            .map(|r| (r.record_id.clone(), RecordVerdict::Malformed))
            .collect();
        return BundleVerdict {
            overall: RecordVerdict::Malformed,
            per_record,
            notes: vec![note],
        };
    }

    if let Err((verdict, note)) = verify_bundle_signature(bundle, bundle_trust, trusted_tsa_roots) {
        let per_record = bundle
            .records
            .iter()
            .map(|r| (r.record_id.clone(), verdict))
            .collect();
        return BundleVerdict {
            overall: verdict,
            per_record,
            notes: vec![note],
        };
    }

    let mut notes = Vec::with_capacity(bundle.records.len());
    let mut per_record = Vec::with_capacity(bundle.records.len());
    for record in &bundle.records {
        let (verdict, note) = grade_record(record, bundle, trusted_tsa_roots, rekor_trust);
        notes.push(note);
        per_record.push((record.record_id.clone(), verdict));
    }
    // An empty bundle proves nothing about anything — fail closed rather than vacuously PROVEN.
    let overall = per_record
        .iter()
        .map(|(_, v)| *v)
        .max_by_key(verdict_rank)
        .unwrap_or(RecordVerdict::Malformed);
    BundleVerdict {
        overall,
        per_record,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, valid [`SelfContainedBundle`] fixture shared by the schema round-trip tests below.
    fn sample_bundle() -> SelfContainedBundle {
        SelfContainedBundle {
            schema: BUNDLE_SCHEMA.to_string(),
            org_id: "org-acme".into(),
            export_id: "exp-1".into(),
            pinned_period_id: 0,
            signer_fingerprint_sha256: "ab".repeat(32),
            signature: None,
            scope: BundleScope::FullExport,
            records: vec![BundleRecord {
                record_id: "r1".into(),
                content_hash: "cd".repeat(32),
                preimage_b64: Some("Zm9v".into()),
                proof: None,
                status: RecordStatus::NotYetAnchored {
                    reason: "no_leaf".into(),
                },
            }],
            tst_der_by_period: vec![],
            rekor_by_period: vec![],
        }
    }

    #[test]
    fn bundle_round_trips_and_carries_schema_tag() {
        let b = sample_bundle();
        let json = serde_json::to_vec(&b).unwrap();
        let back: SelfContainedBundle = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.schema, BUNDLE_SCHEMA);
        assert_eq!(back.records[0].record_id, "r1");
    }

    #[test]
    fn scope_is_backward_compatible_and_part_of_the_signed_bytes() {
        // FullExport (default) is OMITTED on the wire → byte-identical to pre-scope bundles, so no
        // existing signature / frozen corpus breaks.
        let full = sample_bundle();
        let full_json = serde_json::to_string(&full).unwrap();
        assert!(
            !full_json.contains("scope"),
            "FullExport must be omitted: {full_json}"
        );
        // A bundle JSON with no scope field deserialises to FullExport (predating-bundle safety).
        let back: SelfContainedBundle = serde_json::from_str(&full_json).unwrap();
        assert_eq!(back.scope, BundleScope::FullExport);

        // CommittedOnly IS serialised, round-trips, and — because it is inside
        // canonical_signing_bytes — signs DIFFERENTLY from a full export (tamper-evident attestation).
        let mut committed = sample_bundle();
        committed.scope = BundleScope::CommittedOnly;
        let committed_json = serde_json::to_string(&committed).unwrap();
        assert!(
            committed_json.contains("\"scope\":\"committed_only\""),
            "{committed_json}"
        );
        let rt: SelfContainedBundle = serde_json::from_str(&committed_json).unwrap();
        assert_eq!(rt.scope, BundleScope::CommittedOnly);
        assert_ne!(
            full.canonical_signing_bytes(),
            committed.canonical_signing_bytes(),
            "scope must be inside the signed preimage so a downstream consumer can trust it"
        );
    }

    #[test]
    fn v2_bundle_round_trips_and_canonical_bytes_exclude_signature() {
        let mut b = sample_bundle();
        let bytes_unsigned = b.canonical_signing_bytes();
        b.signature = Some(BundleSignature {
            key_id: "arn:...".into(),
            spki_sha256: "ab".repeat(32),
            sig_der_b64: "Zm9v".into(),
            alg: "ecdsa-p256-sha256".into(),
        });
        // canonical signing bytes MUST be identical whether or not the signature field is populated
        assert_eq!(
            bytes_unsigned,
            b.canonical_signing_bytes(),
            "signature must be excluded from its own signed bytes"
        );
        let j = serde_json::to_vec(&b).unwrap();
        let back: SelfContainedBundle = serde_json::from_slice(&j).unwrap();
        assert_eq!(back.schema, BUNDLE_SCHEMA);
        assert_eq!(back.signature.unwrap().alg, "ecdsa-p256-sha256");
    }
}
