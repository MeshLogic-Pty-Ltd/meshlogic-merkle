//! ADR-043 C1 M6-a — the SIGNED commitment-leaf verifier (the "signed collection boundary").
//!
//! Closes the moat gap the anchor half leaves open: [`commitment_leaf`](crate::commitment_leaf)
//! proves each leaf's preimage byte-faithfully hashes to its `content_hash` and that the leaf is
//! INCLUDED under a genuinely-anchored Merkle root — but it does NOT prove the leaf was collected by
//! an enrolled agent. Anything with write access to the commitment-leaf store could therefore inject
//! a self-consistent FABRICATED leaf (a preimage it made up, hashed correctly) and have it anchored
//! under a real root. This module adds the collection-boundary signature: each leaf is signed with a
//! per-agent enrolled Ed25519 identity, and verification FAILS CLOSED against a pinned fleet-identity
//! trust store — an unknown / unenrolled `key_id` is never accepted.
//!
//! mac-lead's RATIFIED format (ADR-043 design authority):
//! - **Q1 KEY = IDENTITY-DIRECT** — each leaf is signed with the per-agent enrolled Ed25519 identity
//!   DIRECTLY (ADR-062 fleet identity), not a derived key. The signature carrier records the signer's
//!   `key_id` (the identifier of the enrolled public key).
//! - **Q2 BINDS = the FULL canonical leaf ENVELOPE** — the signature is Ed25519 over the WHOLE
//!   canonical leaf envelope ([`canonical_leaf_bytes`]), not just `content_hash`, so no field
//!   (`identity`, `source_kind`, `canonical_preimage_b64`, …) stays mutable under a valid signature.
//! - **Q3 TRUST STORE = the L2 fleet-identity registry** — [`EnrolledAgentTrustStore`] is the
//!   authoritative pinned Ed25519 pubkey set, keyed by `key_id`, with rotation-capable validity
//!   windows (mirrors the P3 [`RekorTrustStore`](crate::coanchor::RekorTrustStore) pattern). An
//!   unknown / out-of-window `key_id` grades untrusted; it is NEVER accepted.
//!
//! CLAIM BOUNDARY: a `Signed` result attests only that the FULL canonical leaf envelope was signed by
//! an agent whose Ed25519 identity is pinned+enrolled in the supplied trust store and valid at the
//! supplied time. It does NOT by itself establish inclusion (that is the anchor half) or make any
//! tamper-proof / immutability claim. It does NOT attest correctness of the enforcement decision.
//!
//! # FROZEN canon (mac-lead-ratified 2026-07-10)
//! The exact byte layout produced by [`canonical_leaf_bytes`] is the LOAD-BEARING contract the M6-c
//! agent-side signer (windows-master's lane) MUST reproduce byte-for-byte. It is documented on that
//! function. It is **FROZEN** and stable as of the mac-lead canon-spec ratification (2026-07-10,
//! windows-tertiary co-verified): JCS-over-envelope, domain tag `"MeshLogic/CommitmentLeaf/v1" || 0x00
//! || canonical_leaf_bytes`, `key_id` carrier-only. M6-c builds against this FROZEN contract; any
//! future change to the byte layout is a breaking change that MUST bump [`LEAF_CANON_SPEC_VERSION`].
//!
//! # SIGNING SPEC — domain separation (mac-lead FROZEN spec)
//! The Ed25519 signature is NOT over the bare canonical leaf bytes. The signed/verified message is the
//! EXACT frozen preimage:
//!
//! ```text
//!   "MeshLogic/CommitmentLeaf/v1"  ||  0x00  ||  JCS(envelope)
//! ```
//!
//! i.e. `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes(leaf)` — the domain-separation tag
//! ([`LEAF_SIG_DOMAIN`], ASCII `MeshLogic/CommitmentLeaf/v1`) followed by a single `0x00` NULL-byte
//! SEPARATOR, then the JCS canonical envelope bytes. This is standard signature hygiene: the tag binds
//! every leaf signature to THIS protocol (no cross-protocol reuse), and the `0x00` separator removes
//! all tag/message boundary ambiguity — no crafted envelope can shift the split point because `0x00`
//! never appears in the ASCII tag.
//!
//! CRITICAL: the tag AND the separator live ONLY at the SIGNING layer (the message handed to
//! sign/verify). They are **NOT** part of the JCS leaf canon — [`canonical_leaf_bytes`] and the
//! ADR-042 MLCH-1 `content_hash` are byte-untouched, so the frozen canon KAT and cross-platform
//! `content_hash` compatibility are unaffected. The M6-c agent-side signer MUST reproduce this exact
//! 3-part preimage byte-for-byte.

use serde_json::{Map, Value};

/// Canonicalization spec version of the LEAF-ENVELOPE signing canon (distinct from the record-level
/// MLCH-1 `content_hash` canon, though it uses the SAME RFC 8785 rules — see [`canonical_leaf_bytes`]).
///
/// FROZEN/STABLE as of the mac-lead canon-spec ratification (2026-07-10). `MLLS-1` now denotes a
/// frozen contract, NOT a draft — M6-c signs against it as-is. Bump this on ANY change to the byte
/// layout (a canon change is a breaking wire change and MUST carry a new version discriminator).
pub const LEAF_CANON_SPEC_VERSION: &str = "MLLS-1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedLeafError(pub String);
impl std::fmt::Display for SignedLeafError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signed-leaf error: {}", self.0)
    }
}
impl std::error::Error for SignedLeafError {}

fn err<T>(msg: impl Into<String>) -> Result<T, SignedLeafError> {
    Err(SignedLeafError(msg.into()))
}

// ---------------------------------------------------------------------------------------------
// The commitment-leaf ENVELOPE (the object that is signed).
// ---------------------------------------------------------------------------------------------

/// The canonical commitment-leaf ENVELOPE — the exact field set the capture-at-stamp producer emits
/// (cloud-backend `telemetry_forward.rs` `CommitmentLeaf::to_json_bytes`) and the object the
/// collection-boundary signature binds. The Ed25519 signature carried by [`LeafSignature`] is over
/// [`canonical_leaf_bytes`] of THIS whole envelope (mac-lead Q2), so every field below is bound.
///
/// The `identity` object is carried as an opaque [`Value`] (its keys are canonicalized recursively),
/// matching the producer's `{endpoint_id, org_id, event_sequence, event_class, captured_at}` shape
/// without freezing that inner shape into this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentLeaf {
    /// Leaf-envelope format version (producer emits `"1"`).
    pub leaf_version: String,
    /// The ADR-042 `content_hash` (64-char lowercase hex SHA-256 of the canonical preimage).
    pub content_hash: String,
    /// The record-level canonicalization spec version (`"MLCH-1"`).
    pub canon_spec_version: String,
    /// Leaf source kind (`"enforcement"` for the File-deny slice-1a).
    pub source_kind: String,
    /// STANDARD base64 of the RAW canonicalize() preimage bytes.
    pub canonical_preimage_b64: String,
    /// The provenance `identity` object, verbatim (canonicalized recursively when signed).
    pub identity: Value,
}

impl CommitmentLeaf {
    /// Parse a producer leaf-blob JSON [`Value`] (the on-disk `commitment-leaves/…​.json` shape) into
    /// a [`CommitmentLeaf`]. Missing optional strings default to empty; `identity` defaults to `Null`.
    /// `content_hash` and `canonical_preimage_b64` are REQUIRED (a leaf without them cannot be a
    /// meaningful signing subject).
    pub fn from_leaf_json(v: &Value) -> Result<Self, SignedLeafError> {
        let obj = match v.as_object() {
            Some(o) => o,
            None => return err("leaf blob is not a JSON object"),
        };
        let s = |k: &str| -> String {
            obj.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let content_hash = match obj.get("content_hash").and_then(Value::as_str) {
            Some(h) => h.to_string(),
            None => return err("leaf blob missing string `content_hash`"),
        };
        if obj
            .get("canonical_preimage_b64")
            .and_then(Value::as_str)
            .is_none()
        {
            return err("leaf blob missing string `canonical_preimage_b64`");
        }
        Ok(CommitmentLeaf {
            leaf_version: s("leaf_version"),
            content_hash,
            canon_spec_version: s("canon_spec_version"),
            source_kind: s("source_kind"),
            canonical_preimage_b64: s("canonical_preimage_b64"),
            identity: obj.get("identity").cloned().unwrap_or(Value::Null),
        })
    }

    /// Build the envelope as a [`Value`] object carrying every signed field. Key ORDER here is
    /// irrelevant: [`canonical_leaf_bytes`] sorts keys per RFC 8785, so this is the logical envelope,
    /// not the byte layout.
    fn to_envelope_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "leaf_version".into(),
            Value::String(self.leaf_version.clone()),
        );
        m.insert(
            "content_hash".into(),
            Value::String(self.content_hash.clone()),
        );
        m.insert(
            "canon_spec_version".into(),
            Value::String(self.canon_spec_version.clone()),
        );
        m.insert(
            "source_kind".into(),
            Value::String(self.source_kind.clone()),
        );
        m.insert(
            "canonical_preimage_b64".into(),
            Value::String(self.canonical_preimage_b64.clone()),
        );
        m.insert("identity".into(), self.identity.clone());
        Value::Object(m)
    }
}

// ---------------------------------------------------------------------------------------------
// LOAD-BEARING CANON — the exact byte layout the M6-c agent signer MUST reproduce byte-for-byte.
// ---------------------------------------------------------------------------------------------

/// Deterministic canonical bytes of the FULL commitment-leaf envelope — the exact preimage the
/// Ed25519 collection-boundary signature is computed over (mac-lead Q2). This is the LOAD-BEARING
/// contract: the M6-c agent-side signer (windows-master) and the Phase-2 verify Lambda MUST reproduce
/// these bytes byte-for-byte, or a genuine signature will fail to verify.
///
/// # Exact byte layout (FROZEN — mac-lead-ratified 2026-07-10)
/// The envelope is serialized as **RFC 8785 (JCS) canonical JSON** — the SAME rule family as the
/// ADR-042 §4 record-level `content_hash` canon (MLCH-1), applied to the leaf ENVELOPE instead of the
/// record, so the leaf canon is cross-platform (mac-ESF / mac-NE / Windows) and the verify Lambda
/// agrees. Concretely:
/// 1. **Object members are sorted by key, compared as UTF-16 code units** (RFC 8785 §3.2.3) — NOT
///    Rust's native `&str`/UTF-8 order, and NOT `str::cmp`/Unicode-scalar order (all three AGREE for
///    BMP-only keys but DIVERGE once a key contains an astral-plane char > U+FFFF, whose surrogate-pair
///    first code unit `0xD800..=0xDBFF` sorts BELOW a BMP char in `0xE000..=0xFFFF`). A reimplementation
///    that sorts by `k.as_bytes()` / `k.cmp(k2)` is therefore WRONG above the BMP. This divergence is
///    pinned by the `canon_sort_is_utf16_code_units_not_utf8_astral` KAT. Applied recursively to
///    `identity`.
/// 2. **Strings** use RFC 8785 §3.2.2.2 escaping: escape only `"` `\` and control chars, with the
///    short forms `\b \t \n \f \r`, otherwise `\u00xx` (lowercase hex); every other code point is
///    emitted literally as UTF-8.
/// 3. **Numbers**: integers whose MAGNITUDE exceeds `2^53-1` are emitted as JSON STRINGS
///    (the MLCH-1 big-integer rule, ADR-042 §6.1) so a large `event_sequence` u64 survives losslessly;
///    smaller integers are their plain decimal. **No floats are expected** in a leaf envelope; a
///    (spec-violating) finite float is rendered via the ES6 `Number::toString` layout for determinism.
/// 4. No insignificant whitespace; members joined by `,`, `key:value` joined by `:`.
///
/// The TOP-LEVEL envelope keys, in canonical (sorted) order, are:
/// `canon_spec_version`, `canonical_preimage_b64`, `content_hash`, `identity`, `leaf_version`,
/// `source_kind`. The `identity` sub-object's keys are likewise sorted.
///
/// This function is TOTAL and never panics: `serde_json` numbers are always finite, so the number
/// path always yields a deterministic string.
///
/// NOTE (signing vs canon): the Ed25519 signature is computed over
/// `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes(leaf)`, but the domain tag ([`LEAF_SIG_DOMAIN`])
/// and the `0x00` separator are SIGNING-layer only — they are NEVER emitted by this function and are
/// NOT part of the JCS canon. These bytes (and hence the frozen canon KAT / MLCH-1 `content_hash`) are
/// untouched by domain separation.
pub fn canonical_leaf_bytes(leaf: &CommitmentLeaf) -> Vec<u8> {
    crate::jcs::canonical_json_bytes(&leaf.to_envelope_value())
}

// ---------------------------------------------------------------------------------------------
// Signature carrier + signed-leaf wrapper.
// ---------------------------------------------------------------------------------------------

/// Domain-separation tag for the collection-boundary signature (mac-lead FROZEN spec). ASCII bytes
/// `MeshLogic/CommitmentLeaf/v1` (note: SLASHES, not hyphens).
///
/// The Ed25519 signature is computed over the frozen 3-part preimage
/// `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes(leaf)` — the tag, a single `0x00` NULL-byte
/// separator, then the JCS canonical envelope — NOT the bare canonical bytes. This is standard
/// signature hygiene: the tag binds every signature to THIS protocol so a leaf signature can never be
/// replayed as a signature over some other MeshLogic message (cross-protocol reuse), and the `0x00`
/// separator makes the tag/message boundary unambiguous (`0x00` never occurs in the ASCII tag, so no
/// crafted envelope can shift the split).
///
/// CRITICAL — the tag AND the separator live ONLY at the SIGNING layer (the message handed to
/// sign/verify). They are **NOT** part of the JCS leaf canon: [`canonical_leaf_bytes`] and the
/// ADR-042 MLCH-1 `content_hash` are byte-untouched, so the frozen canon KAT and cross-platform
/// `content_hash` compatibility are unaffected. The M6-c agent-side signer (windows-master) MUST
/// reproduce this exact 3-part preimage byte-for-byte.
pub const LEAF_SIG_DOMAIN: &[u8] = b"MeshLogic/CommitmentLeaf/v1";

/// The collection-boundary signature carried ALONGSIDE a leaf (a wrapper, not a leaf field — so it
/// never perturbs the leaf envelope / its `content_hash`). `key_id` identifies the enrolled Ed25519
/// public key (ADR-062 fleet identity) that produced `sig`; `sig` is the 64-byte Ed25519 signature
/// over `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes(leaf)` (domain-separated — see
/// [`LEAF_SIG_DOMAIN`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafSignature {
    /// Identifier of the enrolled Ed25519 signing identity (resolved against the trust store).
    pub key_id: String,
    /// Ed25519 signature (64 bytes) over `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes(leaf)`.
    pub sig: [u8; 64],
}

/// A commitment leaf together with its (optional) collection-boundary signature. A wrapper is used
/// deliberately (mac-lead / task guidance): editing the frozen leaf envelope to carry the signature
/// would perturb its `content_hash` / the frozen anchor vectors. `signature == None` models an
/// UNSIGNED leaf (graded [`UntrustedReason::NoSignature`], fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommitmentLeaf {
    pub leaf: CommitmentLeaf,
    pub signature: Option<LeafSignature>,
}

impl SignedCommitmentLeaf {
    pub fn new(leaf: CommitmentLeaf, signature: Option<LeafSignature>) -> Self {
        Self { leaf, signature }
    }
}

// ---------------------------------------------------------------------------------------------
// Q3 TRUST STORE — the pinned L2 fleet-identity registry (rotation-capable; mirrors RekorTrustStore).
// ---------------------------------------------------------------------------------------------

/// One pinned, enrolled agent Ed25519 identity with an optional validity window (Unix seconds).
///
/// Agent identities rotate (ADR-062 fleet identity). Pinning the key together with the window it was
/// valid for lets an OLD leaf verify against the identity that was live WHEN THE LEAF WAS COLLECTED,
/// not against today's key — mirroring the P3 [`RekorTrustKey`](crate::coanchor::RekorTrustKey)
/// rotation model.
#[derive(Debug, Clone)]
pub struct EnrolledAgentKey {
    /// The enrolled key identifier a [`LeafSignature`] names.
    pub key_id: String,
    /// The enrolled Ed25519 public key.
    pub verifying_key: ed25519_dalek::VerifyingKey,
    /// Inclusive lower bound of validity (Unix seconds); `None` = open-ended.
    pub not_before: Option<u64>,
    /// Inclusive upper bound of validity (Unix seconds); `None` = open-ended.
    pub not_after: Option<u64>,
}

impl EnrolledAgentKey {
    /// True iff `at_time` falls within this key's validity window.
    fn valid_at(&self, at_time: u64) -> bool {
        self.not_before.is_none_or(|nb| at_time >= nb)
            && self.not_after.is_none_or(|na| at_time <= na)
    }
}

/// A rotation-capable store of pinned, enrolled agent Ed25519 identities — the authoritative L2
/// fleet-identity registry for the collection boundary (mac-lead Q3). [`resolve`](Self::resolve)
/// returns the key to verify a signature against iff its `key_id` matches AND `at_time` is within its
/// validity window. An unknown / out-of-window `key_id` resolves to `None` → FAIL CLOSED.
#[derive(Debug, Clone, Default)]
pub struct EnrolledAgentTrustStore {
    keys: Vec<EnrolledAgentKey>,
}

impl EnrolledAgentTrustStore {
    /// Build a trust store from an explicit set of pinned enrolled identities.
    pub fn new(keys: Vec<EnrolledAgentKey>) -> Self {
        Self { keys }
    }

    /// Add a pinned key (builder-style), returning `self` for chaining.
    pub fn with_key(mut self, key: EnrolledAgentKey) -> Self {
        self.keys.push(key);
        self
    }

    /// The pinned keys, in insertion order.
    pub fn keys(&self) -> &[EnrolledAgentKey] {
        &self.keys
    }

    /// True iff SOME pinned key carries this `key_id` (irrespective of validity window). Lets the
    /// verifier distinguish an UNKNOWN key_id (never enrolled) from a KNOWN one used outside its
    /// window (rotation lag) — two distinct fail-closed grades.
    pub fn contains_key_id(&self, key_id: &str) -> bool {
        self.keys.iter().any(|k| k.key_id == key_id)
    }

    /// Resolve the full pinned [`EnrolledAgentKey`] whose `key_id` matches AND whose validity window
    /// contains `at_time`. `None` if no such key. FIRST match (insertion order) wins on overlap.
    pub fn resolve_key(&self, key_id: &str, at_time: u64) -> Option<&EnrolledAgentKey> {
        self.keys
            .iter()
            .find(|k| k.key_id == key_id && k.valid_at(at_time))
    }

    /// Resolve the [`VerifyingKey`](ed25519_dalek::VerifyingKey) to verify a signature against:
    /// `key_id` matches AND `at_time` ∈ its validity window, else `None` (fail-closed).
    pub fn resolve(&self, key_id: &str, at_time: u64) -> Option<&ed25519_dalek::VerifyingKey> {
        self.resolve_key(key_id, at_time).map(|k| &k.verifying_key)
    }

    /// The `key_id` of the bundled deterministic test identity (see [`Self::from_fixture`]).
    pub const FIXTURE_KEY_ID: &'static str = "enrolled-agent-fixture-ed25519-v1";

    /// A deterministic fixture trust store pinning ONE enrolled identity ([`Self::FIXTURE_KEY_ID`])
    /// with open-ended validity — for tests and as a reproducible reference. The key is derived from a
    /// fixed 32-byte seed (see [`fixture_signing_key`]) so the same public key is pinned every build.
    pub fn from_fixture() -> Self {
        Self::new(vec![EnrolledAgentKey {
            key_id: Self::FIXTURE_KEY_ID.to_string(),
            verifying_key: fixture_signing_key().verifying_key(),
            not_before: None,
            not_after: None,
        }])
    }
}

/// The fixed 32-byte Ed25519 seed backing the deterministic fixture identity. NOT a production key —
/// a build-reproducible identity so [`EnrolledAgentTrustStore::from_fixture`] pins a stable pubkey and
/// tests can sign real leaves with the matching private key.
pub const FIXTURE_SEED: [u8; 32] = [
    0x4d, 0x45, 0x53, 0x48, 0x4c, 0x4f, 0x47, 0x49, 0x43, 0x2d, 0x43, 0x31, 0x2d, 0x4d, 0x36, 0x61,
    0x2d, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x2d, 0x30, 0x31,
];

/// The deterministic fixture Ed25519 signing key (from [`FIXTURE_SEED`]). Exposed so the M6-c
/// signer's conformance tests and this crate's tests can produce a REAL signature over a leaf that
/// [`EnrolledAgentTrustStore::from_fixture`] verifies.
pub fn fixture_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&FIXTURE_SEED)
}

// ---------------------------------------------------------------------------------------------
// VERIFY — fail-closed graded status.
// ---------------------------------------------------------------------------------------------

/// Why a leaf signature is NOT trusted. Every variant is a FAIL-CLOSED grade (never accepted):
/// `NoSignature` (leaf carries no signature), `UnknownKeyId` (the `key_id` is not enrolled in the
/// trust store at all), `KeyNotValidAtTime` (the `key_id` IS enrolled but its validity window
/// excludes the leaf's time — e.g. a rotation lag), `SigInvalid` (the Ed25519 signature does not
/// verify over the canonical leaf bytes — the tamper / forgery finding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UntrustedReason {
    /// The leaf carries no collection-boundary signature.
    NoSignature,
    /// The signature's `key_id` is not enrolled in the trust store.
    UnknownKeyId,
    /// The `key_id` is enrolled but its validity window excludes the leaf's time (rotation lag).
    KeyNotValidAtTime,
    /// The Ed25519 signature does not verify over
    /// `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes(leaf)` (tamper / forgery).
    SigInvalid,
}

/// The graded collection-boundary status of a commitment leaf. Produced by
/// [`verify_leaf_signature`], which NEVER panics and only returns [`Signed`](Self::Signed) for a
/// valid signature by an ENROLLED, IN-WINDOW enrolled identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafSigStatus {
    /// A valid Ed25519 signature over the full canonical leaf envelope by an enrolled, in-window
    /// identity — the collection boundary is proven.
    Signed {
        /// The enrolled `key_id` that signed the leaf.
        key_id: String,
    },
    /// The signature is not trusted, with the fail-closed reason.
    Untrusted(UntrustedReason),
}

/// Verify a leaf's collection-boundary signature against the pinned fleet-identity trust store —
/// FAIL CLOSED, graded, never panics (mac-lead Q1/Q2/Q3).
///
/// `at_time` is the instant (Unix seconds) at which the signer's enrollment window is evaluated —
/// the leaf's COLLECTION time (its `identity.captured_at`), supplied by the caller. (Explicit rather
/// than parsed from the RFC 3339 `captured_at` string here so this core stays free of a datetime
/// dependency; the anchor/verify caller already holds the leaf's capture instant.)
///
/// Steps: (1) no signature → [`UntrustedReason::NoSignature`]; (2) `key_id` not enrolled at all →
/// [`UntrustedReason::UnknownKeyId`]; (3) enrolled but out-of-window at `at_time` →
/// [`UntrustedReason::KeyNotValidAtTime`]; (4) Ed25519-verify the sig over
/// `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes(leaf)` (domain-separated — see
/// [`LEAF_SIG_DOMAIN`]) with the resolved key — failure → [`UntrustedReason::SigInvalid`]. Only a
/// valid signature by an
/// enrolled, in-window key → [`LeafSigStatus::Signed`]. Uses `verify_strict` (rejects malleable /
/// non-canonical signatures and small-order public keys).
pub fn verify_leaf_signature(
    signed_leaf: &SignedCommitmentLeaf,
    trust: &EnrolledAgentTrustStore,
    at_time: u64,
) -> LeafSigStatus {
    let signature = match &signed_leaf.signature {
        None => return LeafSigStatus::Untrusted(UntrustedReason::NoSignature),
        Some(s) => s,
    };

    // Distinguish "never enrolled" (UnknownKeyId) from "enrolled but out-of-window"
    // (KeyNotValidAtTime) — both fail closed, but they are different operational states (mirrors the
    // coanchor rotation-lag grading; rotation lag != a crypto/tamper finding).
    let key = match trust.resolve_key(&signature.key_id, at_time) {
        Some(k) => k,
        None => {
            if trust.contains_key_id(&signature.key_id) {
                return LeafSigStatus::Untrusted(UntrustedReason::KeyNotValidAtTime);
            }
            return LeafSigStatus::Untrusted(UntrustedReason::UnknownKeyId);
        }
    };

    // Domain separation (mac-lead frozen spec): verify over the exact 3-part preimage
    // `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes(leaf)`, NOT the bare canon. The tag and the
    // 0x00 separator are SIGNING-layer only — never part of the JCS leaf canon.
    let message = [
        LEAF_SIG_DOMAIN,
        &[0x00u8],
        &canonical_leaf_bytes(&signed_leaf.leaf),
    ]
    .concat();
    let sig = ed25519_dalek::Signature::from_bytes(&signature.sig);
    match key.verifying_key.verify_strict(&message, &sig) {
        Ok(()) => LeafSigStatus::Signed {
            key_id: signature.key_id.clone(),
        },
        Err(_) => LeafSigStatus::Untrusted(UntrustedReason::SigInvalid),
    }
}

/// M6-c ENVELOPE PRODUCER (windows-master lane): build a [`CommitmentLeaf`] from a decision/enforcement
/// record's ALREADY-JCS-CANONICALIZED preimage bytes. Sets `content_hash = sha256_hex(preimage)` and
/// `canonical_preimage_b64 = STANDARD base64(preimage)`, so the leaf satisfies the invariant the offline
/// verifier + backend re-derivation enforce: `sha256(base64_decode(canonical_preimage_b64)) ==
/// content_hash`. `identity` is the caller's (agent's) ADR-062 enrolled-identity descriptor — carried
/// opaque and canonicalized recursively when the leaf is signed. Pairs with [`sign_leaf`]:
/// `sign_leaf(build_commitment_leaf(kind, preimage, id), key, key_id)` yields a leaf that
/// [`verify_leaf_signature`] grades `Signed` (see the round-trip test). The caller JCS-canonicalizes the
/// record (so producer and verifier canon match byte-for-byte) BEFORE calling this.
pub fn build_commitment_leaf(
    source_kind: impl Into<String>,
    canonical_preimage: &[u8],
    identity: Value,
) -> CommitmentLeaf {
    // MLCH-1 shorthand for the decision-chain path — byte-identical to the frozen v=1 leaf. The generic
    // record-chain path (ADR-025 / ADR-176) calls `build_commitment_leaf_with_spec` so each record carries
    // its own STAMPED canon spec rather than this hardcoded default.
    build_commitment_leaf_with_spec(source_kind, "MLCH-1", canonical_preimage, identity)
}

/// Generalized leaf builder: `canon_spec_version` is the RECORD's stamped canonicalization spec (e.g.
/// "MLCH-1"), not a hardcoded constant — so ONE chain primitive can carry records under different
/// canonicalizations and an independent verifier re-derives EACH leaf under its own stamped spec
/// (canonicalize-by-stamped-version). Identical to [`build_commitment_leaf`] in every other respect
/// (`content_hash = sha256(canonical_preimage)`, raw preimage carried base64 for re-derivation); the
/// caller JCS-canonicalizes the record BEFORE calling this. `source_kind` is the signed-ENVELOPE domain
/// tag — the cross-type replay boundary a verifier pins its expected value against.
pub fn build_commitment_leaf_with_spec(
    source_kind: impl Into<String>,
    canon_spec_version: impl Into<String>,
    canonical_preimage: &[u8],
    identity: Value,
) -> CommitmentLeaf {
    use base64::Engine as _;
    CommitmentLeaf {
        leaf_version: "1".to_string(),
        content_hash: crate::commitment_leaf::sha256_hex(canonical_preimage),
        canon_spec_version: canon_spec_version.into(),
        source_kind: source_kind.into(),
        canonical_preimage_b64: base64::engine::general_purpose::STANDARD
            .encode(canonical_preimage),
        identity,
    }
}

/// M6-c PRODUCER (windows-master lane / ADR-043 C1): sign a [`CommitmentLeaf`] with the per-agent
/// enrolled Ed25519 identity (ADR-062, mac-lead Q1 identity-direct), producing a
/// [`SignedCommitmentLeaf`] that [`verify_leaf_signature`] accepts as [`LeafSigStatus::Signed`] under
/// the enrolled trust store. Reproduces the frozen 3-part preimage
/// `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes(leaf)` BYTE-FOR-BYTE — the SAME construction
/// [`verify_leaf_signature`] verifies over — so producer and verifier can never drift (the round-trip
/// test is the acceptance gate). `key_id` names the signer's enrolled public key in the L2
/// fleet-identity trust store; it is a signature-carrier field only, never part of the leaf canon.
pub fn sign_leaf(
    leaf: CommitmentLeaf,
    signing_key: &ed25519_dalek::SigningKey,
    key_id: impl Into<String>,
) -> SignedCommitmentLeaf {
    use ed25519_dalek::Signer;
    // Domain-separated message — MUST match verify_leaf_signature's preimage exactly.
    let message = [LEAF_SIG_DOMAIN, &[0x00u8], &canonical_leaf_bytes(&leaf)].concat();
    let sig = signing_key.sign(&message).to_bytes();
    SignedCommitmentLeaf::new(
        leaf,
        Some(LeafSignature {
            key_id: key_id.into(),
            sig,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use serde_json::json;

    /// A fixture leaf with ALL-ASCII fields so its canonical byte layout is exactly predictable
    /// (used as a frozen canon KAT below).
    fn fixture_leaf() -> CommitmentLeaf {
        CommitmentLeaf {
            leaf_version: "1".into(),
            content_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            canon_spec_version: "MLCH-1".into(),
            source_kind: "enforcement".into(),
            canonical_preimage_b64: "eyJhIjoxfQ==".into(),
            identity: json!({
                "endpoint_id": "EP-aaaaaaaaaaaaaaaa",
                "org_id": "org-acme",
                "event_sequence": 7,
                "event_class": "File",
                "captured_at": "2026-07-05T00:00:00+00:00"
            }),
        }
    }

    /// FROZEN canon vector: the exact RFC 8785 (JCS) byte layout of the fixture leaf envelope. If the
    /// canon serializer drifts, this fails — protecting the M6-c byte-for-byte contract.
    const FROZEN_CANON: &str = concat!(
        "{",
        "\"canon_spec_version\":\"MLCH-1\",",
        "\"canonical_preimage_b64\":\"eyJhIjoxfQ==\",",
        "\"content_hash\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",",
        "\"identity\":{",
        "\"captured_at\":\"2026-07-05T00:00:00+00:00\",",
        "\"endpoint_id\":\"EP-aaaaaaaaaaaaaaaa\",",
        "\"event_class\":\"File\",",
        "\"event_sequence\":7,",
        "\"org_id\":\"org-acme\"",
        "},",
        "\"leaf_version\":\"1\",",
        "\"source_kind\":\"enforcement\"",
        "}"
    );

    fn sign_fixture(leaf: &CommitmentLeaf) -> LeafSignature {
        let sk = fixture_signing_key();
        // Domain-separated message (mac-lead frozen 3-part preimage, same as verify):
        // LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes(leaf).
        let message = [LEAF_SIG_DOMAIN, &[0x00u8], &canonical_leaf_bytes(leaf)].concat();
        let sig = sk.sign(&message);
        LeafSignature {
            key_id: EnrolledAgentTrustStore::FIXTURE_KEY_ID.to_string(),
            sig: sig.to_bytes(),
        }
    }

    #[test]
    fn canonical_bytes_match_frozen_jcs_layout() {
        let got = String::from_utf8(canonical_leaf_bytes(&fixture_leaf())).unwrap();
        assert_eq!(got, FROZEN_CANON, "leaf canon byte layout drifted");
    }

    #[test]
    fn signed_leaf_by_enrolled_key_grades_signed() {
        let leaf = fixture_leaf();
        let signed = SignedCommitmentLeaf::new(leaf.clone(), Some(sign_fixture(&leaf)));
        let trust = EnrolledAgentTrustStore::from_fixture();
        assert_eq!(
            verify_leaf_signature(&signed, &trust, 1_751_673_600),
            LeafSigStatus::Signed {
                key_id: EnrolledAgentTrustStore::FIXTURE_KEY_ID.to_string()
            },
            "a real signature by the enrolled fixture identity MUST grade Signed"
        );
    }

    #[test]
    fn m6c_sign_leaf_output_verifies_against_the_m6a_verifier() {
        // ACCEPTANCE GATE: the M6-c PRODUCER (`sign_leaf`) must produce a leaf that the M6-a VERIFIER
        // grades `Signed` under the enrolled identity — byte-for-byte proof that the producer
        // reproduces the frozen `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes` preimage. If the two
        // ever drift, this fails.
        let signed = sign_leaf(
            fixture_leaf(),
            &fixture_signing_key(),
            EnrolledAgentTrustStore::FIXTURE_KEY_ID,
        );
        assert_eq!(
            verify_leaf_signature(
                &signed,
                &EnrolledAgentTrustStore::from_fixture(),
                1_751_673_600
            ),
            LeafSigStatus::Signed {
                key_id: EnrolledAgentTrustStore::FIXTURE_KEY_ID.to_string()
            },
            "M6-c sign_leaf output MUST verify as Signed under the enrolled fixture identity"
        );
    }

    #[test]
    fn m6c_build_commitment_leaf_re_derives_and_signs_and_verifies() {
        use base64::Engine as _;
        // Stand-in for a JCS-canonicalized decision record (the caller canonicalizes before calling).
        let preimage = br#"{"actor":"x","decision":"deny"}"#;
        let leaf = build_commitment_leaf(
            "enforcement",
            preimage,
            serde_json::json!({ "agent": "fixture" }),
        );
        // Invariant the offline verifier + backend re-derivation enforce.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&leaf.canonical_preimage_b64)
            .expect("canonical_preimage_b64 must be valid base64");
        assert_eq!(decoded, preimage, "preimage must round-trip through base64");
        assert_eq!(
            leaf.content_hash,
            crate::commitment_leaf::sha256_hex(preimage),
            "content_hash must be sha256_hex of the preimage"
        );
        // End-to-end producer path: build -> sign -> verify == Signed.
        let signed = sign_leaf(
            leaf,
            &fixture_signing_key(),
            EnrolledAgentTrustStore::FIXTURE_KEY_ID,
        );
        assert!(
            matches!(
                verify_leaf_signature(
                    &signed,
                    &EnrolledAgentTrustStore::from_fixture(),
                    1_751_673_600
                ),
                LeafSigStatus::Signed { .. }
            ),
            "a built + signed commitment leaf MUST verify Signed"
        );
    }

    #[test]
    fn signature_is_domain_separated_bare_canon_sig_rejected() {
        // The frozen signing preimage is `LEAF_SIG_DOMAIN || 0x00 || canonical_leaf_bytes(leaf)`.
        // Prove BOTH the tag AND the 0x00 separator are load-bearing: a signature over any OTHER
        // preimage MUST be rejected.
        let leaf = fixture_leaf();
        let sk = fixture_signing_key();
        let trust = EnrolledAgentTrustStore::from_fixture();

        // (a) BARE canon (no tag, no separator) — must NOT verify.
        let bare_sig = sk.sign(&canonical_leaf_bytes(&leaf));
        let signed_bare = SignedCommitmentLeaf::new(
            leaf.clone(),
            Some(LeafSignature {
                key_id: EnrolledAgentTrustStore::FIXTURE_KEY_ID.to_string(),
                sig: bare_sig.to_bytes(),
            }),
        );
        assert_eq!(
            verify_leaf_signature(&signed_bare, &trust, 1_751_673_600),
            LeafSigStatus::Untrusted(UntrustedReason::SigInvalid),
            "a signature over bare canonical bytes (no tag, no separator) MUST NOT verify"
        );

        // (b) tag || canon but WITHOUT the 0x00 separator — must NOT verify (separator is load-bearing).
        let no_sep_msg = [LEAF_SIG_DOMAIN, &canonical_leaf_bytes(&leaf)].concat();
        let no_sep_sig = sk.sign(&no_sep_msg);
        let signed_no_sep = SignedCommitmentLeaf::new(
            leaf,
            Some(LeafSignature {
                key_id: EnrolledAgentTrustStore::FIXTURE_KEY_ID.to_string(),
                sig: no_sep_sig.to_bytes(),
            }),
        );
        assert_eq!(
            verify_leaf_signature(&signed_no_sep, &trust, 1_751_673_600),
            LeafSigStatus::Untrusted(UntrustedReason::SigInvalid),
            "a signature over `tag || canon` WITHOUT the 0x00 separator MUST NOT verify"
        );

        // The tag + separator are NOT in the canon (frozen KAT unchanged) — signing-layer only.
        assert_eq!(
            String::from_utf8(canonical_leaf_bytes(&fixture_leaf())).unwrap(),
            FROZEN_CANON,
            "domain separation MUST NOT perturb the frozen JCS canon"
        );
    }

    #[test]
    fn tampered_leaf_grades_sig_invalid() {
        let leaf = fixture_leaf();
        let sig = sign_fixture(&leaf);
        // Tamper a field AFTER signing → canonical bytes change → signature no longer matches.
        let mut tampered = leaf.clone();
        tampered.content_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".into();
        let signed = SignedCommitmentLeaf::new(tampered, Some(sig));
        let trust = EnrolledAgentTrustStore::from_fixture();
        assert_eq!(
            verify_leaf_signature(&signed, &trust, 1_751_673_600),
            LeafSigStatus::Untrusted(UntrustedReason::SigInvalid),
            "a leaf altered after signing MUST grade SigInvalid"
        );
    }

    #[test]
    fn tampering_any_identity_field_grades_sig_invalid() {
        // Q2: the WHOLE envelope is bound, incl. the nested identity — flip an identity field.
        let leaf = fixture_leaf();
        let sig = sign_fixture(&leaf);
        let mut tampered = leaf.clone();
        tampered.identity["endpoint_id"] = json!("EP-bbbbbbbbbbbbbbbb");
        let signed = SignedCommitmentLeaf::new(tampered, Some(sig));
        let trust = EnrolledAgentTrustStore::from_fixture();
        assert_eq!(
            verify_leaf_signature(&signed, &trust, 1_751_673_600),
            LeafSigStatus::Untrusted(UntrustedReason::SigInvalid),
            "altering a bound identity field MUST break the signature"
        );
    }

    #[test]
    fn unknown_key_id_grades_untrusted_fail_closed() {
        let leaf = fixture_leaf();
        let mut sig = sign_fixture(&leaf);
        sig.key_id = "some-unenrolled-agent-key".into(); // not in the trust store
        let signed = SignedCommitmentLeaf::new(leaf, Some(sig));
        let trust = EnrolledAgentTrustStore::from_fixture();
        assert_eq!(
            verify_leaf_signature(&signed, &trust, 1_751_673_600),
            LeafSigStatus::Untrusted(UntrustedReason::UnknownKeyId),
            "an unenrolled key_id MUST fail closed as UnknownKeyId"
        );
    }

    #[test]
    fn empty_trust_store_grades_unknown_key_id() {
        let leaf = fixture_leaf();
        let signed = SignedCommitmentLeaf::new(leaf.clone(), Some(sign_fixture(&leaf)));
        let empty = EnrolledAgentTrustStore::default();
        assert_eq!(
            verify_leaf_signature(&signed, &empty, 1_751_673_600),
            LeafSigStatus::Untrusted(UntrustedReason::UnknownKeyId),
            "an empty trust store trusts NObody (fail closed)"
        );
    }

    #[test]
    fn key_out_of_window_grades_key_not_valid_at_time() {
        let leaf = fixture_leaf();
        let signed = SignedCommitmentLeaf::new(leaf.clone(), Some(sign_fixture(&leaf)));
        // Pin the fixture identity to a window that EXCLUDES at_time (models a rotation lag).
        let trust = EnrolledAgentTrustStore::new(vec![EnrolledAgentKey {
            key_id: EnrolledAgentTrustStore::FIXTURE_KEY_ID.to_string(),
            verifying_key: fixture_signing_key().verifying_key(),
            not_before: Some(2_000_000_000),
            not_after: Some(2_100_000_000),
        }]);
        assert_eq!(
            verify_leaf_signature(&signed, &trust, 1_751_673_600),
            LeafSigStatus::Untrusted(UntrustedReason::KeyNotValidAtTime),
            "an enrolled key used outside its window MUST grade KeyNotValidAtTime, not UnknownKeyId"
        );
        // And INSIDE the window the same signature verifies → Signed.
        assert_eq!(
            verify_leaf_signature(&signed, &trust, 2_050_000_000),
            LeafSigStatus::Signed {
                key_id: EnrolledAgentTrustStore::FIXTURE_KEY_ID.to_string()
            },
            "inside the validity window the signature MUST verify"
        );
    }

    #[test]
    fn no_signature_grades_no_signature() {
        let signed = SignedCommitmentLeaf::new(fixture_leaf(), None);
        let trust = EnrolledAgentTrustStore::from_fixture();
        assert_eq!(
            verify_leaf_signature(&signed, &trust, 1_751_673_600),
            LeafSigStatus::Untrusted(UntrustedReason::NoSignature),
            "an unsigned leaf MUST grade NoSignature (fail closed)"
        );
    }

    #[test]
    fn canon_is_field_order_independent() {
        // The SAME logical leaf built with the identity object's keys inserted in DIFFERENT orders
        // MUST canonicalize to byte-identical output (RFC 8785 sorts keys).
        let a = CommitmentLeaf {
            identity: json!({
                "captured_at": "2026-07-05T00:00:00+00:00",
                "endpoint_id": "EP-aaaaaaaaaaaaaaaa",
                "event_class": "File",
                "event_sequence": 7,
                "org_id": "org-acme"
            }),
            ..fixture_leaf()
        };
        let b = CommitmentLeaf {
            identity: json!({
                "org_id": "org-acme",
                "event_sequence": 7,
                "event_class": "File",
                "endpoint_id": "EP-aaaaaaaaaaaaaaaa",
                "captured_at": "2026-07-05T00:00:00+00:00"
            }),
            ..fixture_leaf()
        };
        assert_eq!(
            canonical_leaf_bytes(&a),
            canonical_leaf_bytes(&b),
            "canon MUST be independent of input field order"
        );
    }

    #[test]
    fn big_event_sequence_is_stringified() {
        // MLCH-1 big-integer rule: a u64 event_sequence > 2^53-1 canonicalizes as a JSON string.
        let leaf = CommitmentLeaf {
            identity: json!({ "event_sequence": 18446744073709551615u64 }),
            ..fixture_leaf()
        };
        let s = String::from_utf8(canonical_leaf_bytes(&leaf)).unwrap();
        assert!(
            s.contains("\"event_sequence\":\"18446744073709551615\""),
            "a > 2^53-1 event_sequence MUST be a JSON string, got: {s}"
        );
    }

    #[test]
    fn canon_sort_is_utf16_code_units_not_utf8_astral() {
        // RFC 8785 §3.2.3 sorts object member names by UTF-16 CODE UNITS. For a key containing an
        // astral-plane char (> U+FFFF, encoded as a surrogate PAIR whose FIRST unit is in
        // 0xD800..=0xDBFF) this DIVERGES from a naive UTF-8-byte / Rust `str::cmp` (Unicode-scalar)
        // sort. This KAT pins the divergence so an M6-c reimplementation that (wrongly) sorts by
        // `k.as_bytes()` / `k.cmp(k2)` FAILS instead of silently producing a different canon.
        //
        // Compare identity keys "a\u{1F600}" (astral 😀, U+1F600) vs "a\u{E000}" (BMP private-use,
        // ABOVE the surrogate range):
        //   * UTF-16 code-unit order: 😀's first unit 0xD83D  <  0xE000  → "a\u{1F600}" sorts FIRST.
        //   * str::cmp / codepoint order: 0x1F600  >  0xE000  → would sort "a\u{1F600}" LAST (WRONG).
        // So the correct RFC 8785 output places the astral key BEFORE the U+E000 key.
        let leaf = CommitmentLeaf {
            identity: json!({
                "a\u{1F600}": 1,
                "a\u{E000}": 2,
            }),
            ..fixture_leaf()
        };
        let s = String::from_utf8(canonical_leaf_bytes(&leaf)).unwrap();
        let astral_pos = s.find('\u{1F600}').expect("astral key present in canon");
        let bmp_pos = s.find('\u{E000}').expect("U+E000 key present in canon");
        assert!(
            astral_pos < bmp_pos,
            "RFC 8785 UTF-16-code-unit sort MUST place the astral-plane key BEFORE the U+E000 key \
             (a UTF-8/str::cmp sort would INVERT this); got: {s}"
        );
    }

    #[test]
    fn from_leaf_json_roundtrips_producer_blob() {
        // The producer's on-disk blob shape parses into a CommitmentLeaf whose canon signs+verifies.
        let blob = json!({
            "leaf_version": "1",
            "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "canon_spec_version": "MLCH-1",
            "source_kind": "enforcement",
            "canonical_preimage_b64": "eyJhIjoxfQ==",
            "identity": {
                "endpoint_id": "EP-aaaaaaaaaaaaaaaa",
                "org_id": "org-acme",
                "event_sequence": 7,
                "event_class": "File",
                "captured_at": "2026-07-05T00:00:00+00:00"
            }
        });
        let leaf = CommitmentLeaf::from_leaf_json(&blob).expect("parse producer blob");
        assert_eq!(canonical_leaf_bytes(&leaf), FROZEN_CANON.as_bytes());
        let signed = SignedCommitmentLeaf::new(leaf.clone(), Some(sign_fixture(&leaf)));
        assert_eq!(
            verify_leaf_signature(
                &signed,
                &EnrolledAgentTrustStore::from_fixture(),
                1_751_673_600
            ),
            LeafSigStatus::Signed {
                key_id: EnrolledAgentTrustStore::FIXTURE_KEY_ID.to_string()
            }
        );
    }

    #[test]
    fn from_leaf_json_rejects_missing_required_fields() {
        assert!(CommitmentLeaf::from_leaf_json(&json!({ "content_hash": "x" })).is_err());
        assert!(CommitmentLeaf::from_leaf_json(&json!({ "canonical_preimage_b64": "x" })).is_err());
        assert!(CommitmentLeaf::from_leaf_json(&json!([1, 2, 3])).is_err());
    }
}
