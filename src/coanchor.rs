//! ADR-043 C1 P3 — production OFFLINE co-anchor VERIFIER for the Sigstore Rekor public
//! transparency log (`docs/adrs/ADR-043-merkle-rfc3161-anchoring.md`).
//!
//! PROMOTES the proven `spike/c1-p3-rekor-coanchor` implementation. The hard-crypto core
//! (`RekorReceipt` / `RekorInclusionProof` / [`verify_coanchor_receipt`] / [`parse_checkpoint`] /
//! `verify_checkpoint_signature`) is kept intact and byte-identical to the spike — it is proven
//! against a real live-captured Rekor fixture plus adversarial tests. This module ADDS the
//! production layer on top: a GRADED status ([`CoAnchorStatus`]) and a rotation-capable pinned-key
//! trust store ([`RekorTrustStore`]). The live publish path (`publish_root_to_rekor` /
//! `rekor-client`) is deliberately NOT ported — publishing is the producer PR's concern; this
//! module is the NETWORK-FREE offline verifier only (deps: serde_json / base64 / p256 / sha2 / hex).
//!
//! WHY: P1b RFC 3161-anchors each roots-chain root, but MeshLogic holds every copy of that
//! evidence — it is tamper-EVIDENT, not yet independently witnessed. P3 publishes the daily
//! roots-chain HEAD to a PUBLIC append-only log (Rekor) that MeshLogic cannot unilaterally rewrite.
//! Because the roots chain is hash-linked (P1b `prev_root_hash`), witnessing head@P transitively
//! witnesses every period <= P.
//!
//! GRADED, NOT BINARY (mac-lead ratified Q4): a missing or invalid receipt is NOT a verification
//! FAILURE — it is simply "not yet independently witnessed". [`verify_coanchored`] therefore never
//! returns `Err` and never panics; it GRADES a root as either [`CoAnchorStatus::CoAnchored`] (a
//! Rekor receipt verified end-to-end) or [`CoAnchorStatus::AnchoredOnly`] (RFC 3161-anchored but
//! not co-anchored — with the reason). No "tamper-proof" claim is unlocked here; that language is
//! gated on a later claim PR.
//!
//! HONEST BOUNDARY: Rekor witnesses that the entry (hence our root) was in the log at the checkpoint
//! tree size; it does NOT attest WHO submitted it (the embedded key is submitter-chosen).

use crate::{hash_leaf, verify_inclusion, Hash};
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoanchorError(pub String);
impl std::fmt::Display for CoanchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rekor co-anchor error: {}", self.0)
    }
}
impl std::error::Error for CoanchorError {}

fn err(msg: impl Into<String>) -> CoanchorError {
    CoanchorError(msg.into())
}

/// A Rekor RFC 6962 inclusion proof for one entry, decoded from the entry's `inclusionProof` JSON.
/// `leaf_index`/`tree_size` are the entry's position and the tree size WITHIN its (active) shard —
/// the exact inputs [`crate::verify_inclusion`] expects (NOT the top-level global `logIndex`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekorInclusionProof {
    /// 0-based leaf index within the shard tree (`inclusionProof.logIndex`).
    pub leaf_index: u64,
    /// Number of leaves in the shard tree the proof is against (`inclusionProof.treeSize`).
    pub tree_size: u64,
    /// The shard Merkle root the proof reproduces (`inclusionProof.rootHash`, 32 bytes).
    pub root_hash: Hash,
    /// RFC 6962 audit path (`inclusionProof.hashes`, each 32 bytes).
    pub hashes: Vec<Hash>,
}

/// The co-anchor RECEIPT persisted alongside the roots-chain row for later OFFLINE re-verification.
///
/// It is exactly what an auditor needs with NO further Rekor calls: the canonical entry body (the
/// RFC 6962 leaf preimage), the inclusion proof, and the SIGNED checkpoint (which an auditor checks
/// against Rekor's published public key). `log_index`/`entry_uuid`/`integrated_time` are provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekorReceipt {
    /// Rekor log/shard identifier (SHA-256 of the log's DER public key, hex) — which key signs the checkpoint.
    pub log_id: String,
    /// Global virtual log index of the entry (provenance / lookup; NOT the inclusion-proof leaf index).
    pub log_index: u64,
    /// The entry's UUID (Merkle-leaf-hash-derived id) — stable handle for a later Rekor GET.
    pub entry_uuid: String,
    /// Rekor-asserted integration time (Unix seconds).
    pub integrated_time: u64,
    /// Base64 of the CANONICAL entry body. Base64-decoding it yields the RFC 6962 leaf DATA
    /// (`hash_leaf(body) = SHA-256(0x00 || body)`), and its JSON commits to our root.
    pub body_b64: String,
    /// The entry's inclusion proof (decoded).
    pub inclusion: RekorInclusionProof,
    /// The signed tree head (C2SP checkpoint / sumdb-note): origin, tree size, base64 root, and an
    /// ECDSA-P256 signature line. Verified offline against Rekor's log public key.
    pub checkpoint: String,
}

/// Lower-case-hex a 64-char string into a 32-byte [`Hash`].
fn hex32(s: &str, field: &str) -> Result<Hash, CoanchorError> {
    let v = hex::decode(s).map_err(|e| err(format!("{field}: bad hex: {e}")))?;
    v.try_into()
        .map_err(|_| err(format!("{field}: expected 32-byte hash")))
}

impl RekorReceipt {
    /// Parse a single Rekor `LogEntry` JSON object (the value under the UUID key of a
    /// `GET/POST /api/v1/log/entries` response) into a persisted receipt. Requires the entry to
    /// carry `verification.inclusionProof` (a freshly created entry may need a read-back by UUID).
    pub fn from_log_entry(uuid: &str, entry: &Value) -> Result<Self, CoanchorError> {
        let body_b64 = entry["body"]
            .as_str()
            .ok_or_else(|| err("entry missing `body`"))?
            .to_string();
        let log_id = entry["logID"].as_str().unwrap_or_default().to_string();
        let log_index = entry["logIndex"].as_u64().unwrap_or_default();
        let integrated_time = entry["integratedTime"].as_u64().unwrap_or_default();

        let ip = entry
            .get("verification")
            .and_then(|v| v.get("inclusionProof"))
            .ok_or_else(|| err("entry has no verification.inclusionProof yet (retry read-back)"))?;

        let leaf_index = ip["logIndex"]
            .as_u64()
            .ok_or_else(|| err("inclusionProof.logIndex missing"))?;
        let tree_size = ip["treeSize"]
            .as_u64()
            .ok_or_else(|| err("inclusionProof.treeSize missing"))?;
        let root_hash = hex32(
            ip["rootHash"]
                .as_str()
                .ok_or_else(|| err("inclusionProof.rootHash missing"))?,
            "inclusionProof.rootHash",
        )?;
        let hashes = ip["hashes"]
            .as_array()
            .ok_or_else(|| err("inclusionProof.hashes missing"))?
            .iter()
            .map(|h| {
                hex32(
                    h.as_str()
                        .ok_or_else(|| err("inclusionProof.hashes[] not a string"))?,
                    "inclusionProof.hashes[]",
                )
            })
            .collect::<Result<Vec<Hash>, CoanchorError>>()?;
        let checkpoint = ip["checkpoint"]
            .as_str()
            .ok_or_else(|| err("inclusionProof.checkpoint missing"))?
            .to_string();

        Ok(RekorReceipt {
            log_id,
            log_index,
            entry_uuid: uuid.to_string(),
            integrated_time,
            body_b64,
            inclusion: RekorInclusionProof {
                leaf_index,
                tree_size,
                root_hash,
                hashes,
            },
            checkpoint,
        })
    }

    /// Parse a whole `entries` response body (`{ "<uuid>": { <entry> } }`) into `(uuid, receipt)`.
    pub fn from_entries_response(body: &str) -> Result<Self, CoanchorError> {
        let v: Value =
            serde_json::from_str(body).map_err(|e| err(format!("parse entries response: {e}")))?;
        let obj = v
            .as_object()
            .ok_or_else(|| err("entries response is not a JSON object"))?;
        let (uuid, entry) = obj
            .iter()
            .next()
            .ok_or_else(|| err("entries response is empty"))?;
        RekorReceipt::from_log_entry(uuid, entry)
    }

    /// Serialize to the COMPACT persisted receipt JSON — the shape the tamper-evidence-builder
    /// writes to the roots-chain row's `coanchor_receipt` attribute, and the shape a proof bundle
    /// carries for OFFLINE re-verification (there is no further Rekor call). This is the canonical
    /// on-the-row / in-the-bundle shape; [`Self::from_receipt_json`] is its exact inverse.
    ///
    /// FROZEN round-trip (see `receipt_json_round_trips`): `from_receipt_json(&to_receipt_json(r))
    /// == r`. `hex::encode` here is byte-identical to the builder's historical `bytes_to_hex`
    /// (both lowercase `{:02x}`), so rows persisted before this method existed parse unchanged.
    pub fn to_receipt_json(&self) -> Value {
        serde_json::json!({
            "log_id": self.log_id,
            "log_index": self.log_index,
            "entry_uuid": self.entry_uuid,
            "integrated_time": self.integrated_time,
            "body_b64": self.body_b64,
            "checkpoint": self.checkpoint,
            "inclusion": {
                "leaf_index": self.inclusion.leaf_index,
                "tree_size": self.inclusion.tree_size,
                "root_hash": hex::encode(self.inclusion.root_hash),
                "hashes": self
                    .inclusion
                    .hashes
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
            },
        })
    }

    /// Parse the COMPACT persisted receipt JSON ([`Self::to_receipt_json`]'s shape) — the exact
    /// inverse of that method, and what the offline verifier uses to reconstruct a receipt from a
    /// bundle. Strict on every field (this is OUR own canonical format, so any missing/mistyped
    /// field is corruption, not an optional-provenance case): a parse failure surfaces as `Err`,
    /// which the caller grades as the honest NotYetWitnessed — never a softened Proven.
    pub fn from_receipt_json(v: &Value) -> Result<Self, CoanchorError> {
        let s = |k: &str| -> Result<String, CoanchorError> {
            Ok(v[k]
                .as_str()
                .ok_or_else(|| err(format!("receipt missing/!string `{k}`")))?
                .to_string())
        };
        let u = |k: &str| -> Result<u64, CoanchorError> {
            v[k].as_u64()
                .ok_or_else(|| err(format!("receipt missing/!u64 `{k}`")))
        };
        let inc = v
            .get("inclusion")
            .ok_or_else(|| err("receipt missing `inclusion`"))?;
        let iu = |k: &str| -> Result<u64, CoanchorError> {
            inc[k]
                .as_u64()
                .ok_or_else(|| err(format!("inclusion missing/!u64 `{k}`")))
        };
        let root_hash = hex32(
            inc["root_hash"]
                .as_str()
                .ok_or_else(|| err("inclusion.root_hash missing"))?,
            "inclusion.root_hash",
        )?;
        let hashes = inc["hashes"]
            .as_array()
            .ok_or_else(|| err("inclusion.hashes missing"))?
            .iter()
            .map(|h| {
                hex32(
                    h.as_str()
                        .ok_or_else(|| err("inclusion.hashes[] not a string"))?,
                    "inclusion.hashes[]",
                )
            })
            .collect::<Result<Vec<Hash>, CoanchorError>>()?;
        Ok(RekorReceipt {
            log_id: s("log_id")?,
            log_index: u("log_index")?,
            entry_uuid: s("entry_uuid")?,
            integrated_time: u("integrated_time")?,
            body_b64: s("body_b64")?,
            inclusion: RekorInclusionProof {
                leaf_index: iu("leaf_index")?,
                tree_size: iu("tree_size")?,
                root_hash,
                hashes,
            },
            checkpoint: s("checkpoint")?,
        })
    }
}

/// Parsed fields of a C2SP checkpoint / sumdb-note: the signed TEXT, the asserted tree size + root,
/// and the raw ECDSA signature bytes (DER) from the first signature line.
struct ParsedCheckpoint {
    signed_text: Vec<u8>,
    tree_size: u64,
    root_hash: Hash,
    sig_der: Vec<u8>,
}

/// Split a checkpoint note into its signed text + first signature, and parse the size/root header.
///
/// Note format (Go sumdb-note / C2SP): `<origin>\n<treeSize>\n<base64(rootHash)>\n[extra...]\n` is
/// the signed TEXT (ending in a newline), followed by a BLANK line (a lone `\n`, the separator, NOT
/// signed), followed by one or more `— <name> <base64sig>` signature lines. The signature blob is
/// `base64` decoding to a 4-byte key hint followed by a DER ECDSA signature (verified over SHA-256
/// of the text). Getting the boundary right matters: including the blank-line separator in the
/// signed message makes a valid checkpoint signature fail to verify.
fn parse_checkpoint(checkpoint: &str) -> Result<ParsedCheckpoint, CoanchorError> {
    // The origin line uses an ASCII hyphen; the em-dash (U+2014) only ever starts a signature line.
    let sig_pos = checkpoint
        .find('\u{2014}')
        .ok_or_else(|| err("checkpoint has no signature line"))?;
    // Signed text = everything before the signature block MINUS the single blank-line separator
    // immediately preceding it (the text keeps its own trailing newline).
    let mut text_end = sig_pos;
    if checkpoint.as_bytes().get(text_end.wrapping_sub(1)) == Some(&b'\n') {
        text_end -= 1;
    }
    let signed_text = checkpoint.as_bytes()[..text_end].to_vec();

    let header: Vec<&str> = checkpoint[..sig_pos].split('\n').collect();
    if header.len() < 3 {
        return Err(err("checkpoint header too short (want origin/size/root)"));
    }
    // header[0] is the log/shard ORIGIN (identity). The trust layer binds it to the pinned key's
    // expected origin via the raw checkpoint's first line (see `verify_coanchored`); the signature
    // check below then authenticates that same signed text end-to-end.
    let tree_size = header[1]
        .trim()
        .parse::<u64>()
        .map_err(|e| err(format!("checkpoint tree size: {e}")))?;
    let root_b64 = header[2].trim();
    let root_bytes = B64
        .decode(root_b64)
        .map_err(|e| err(format!("checkpoint root base64: {e}")))?;
    let root_hash: Hash = root_bytes
        .try_into()
        .map_err(|_| err("checkpoint root is not 32 bytes"))?;

    // First signature line: "— <name> <base64(keyhint||DERsig)>".
    let sig_line = checkpoint[sig_pos..]
        .lines()
        .next()
        .ok_or_else(|| err("empty signature line"))?;
    let blob_b64 = sig_line
        .rsplit(' ')
        .next()
        .ok_or_else(|| err("signature line has no blob"))?;
    let blob = B64
        .decode(blob_b64.trim())
        .map_err(|e| err(format!("signature base64: {e}")))?;
    if blob.len() <= 4 {
        return Err(err("signature blob too short (want 4-byte hint + DER sig)"));
    }
    let sig_der = blob[4..].to_vec(); // drop the 4-byte key hint

    Ok(ParsedCheckpoint {
        signed_text,
        tree_size,
        root_hash,
        sig_der,
    })
}

/// Verify the checkpoint's ECDSA-P256 signature over its signed text against Rekor's log public key.
fn verify_checkpoint_signature(
    parsed: &ParsedCheckpoint,
    rekor_pubkey_pem: &str,
) -> Result<(), CoanchorError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let vk = VerifyingKey::from_public_key_pem(rekor_pubkey_pem)
        .map_err(|e| err(format!("parse Rekor public key PEM: {e}")))?;
    let sig = Signature::from_der(&parsed.sig_der)
        .map_err(|e| err(format!("parse checkpoint DER signature: {e}")))?;
    vk.verify(&parsed.signed_text, &sig)
        .map_err(|_| err("checkpoint signature does NOT verify against Rekor's log key"))
}

/// The 32-byte content-hash digest a `hashedrekord` for `root` must carry: `SHA-256(root)`.
fn root_data_hash_hex(root: &Hash) -> String {
    hex::encode(Sha256::digest(root))
}

/// Extract the raw SPKI DER bytes from a SubjectPublicKeyInfo PEM (`-----BEGIN PUBLIC KEY-----`).
///
/// We hash exactly the pinned/submitted DER (the base64 body between the armor lines) rather than
/// re-encoding through a key parser, so the computed log id is byte-identical to how Rekor derives
/// it — `logID = SHA-256(DER(SubjectPublicKeyInfo))`. Re-encoding could canonicalise differently and
/// silently change the hash.
fn spki_der_from_pem(pem: &str) -> Result<Vec<u8>, CoanchorError> {
    let mut body = String::new();
    let mut in_body = false;
    for line in pem.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN") {
            in_body = true;
            continue;
        }
        if t.starts_with("-----END") {
            break;
        }
        if in_body {
            body.push_str(t);
        }
    }
    if body.is_empty() {
        return Err(err("public key PEM has no SPKI body"));
    }
    B64.decode(body)
        .map_err(|e| err(format!("public key PEM base64: {e}")))
}

/// The Rekor log id a given log public key implies: `SHA-256(DER(SubjectPublicKeyInfo))`, lower-hex.
///
/// This is THE cryptographic bind between a checkpoint-verifying key and a receipt's claimed
/// `log_id`: because the log id IS the key hash, comparing this against `receipt.log_id` proves the
/// key we are about to verify the signed checkpoint with genuinely belongs to the log the receipt
/// names — closing the cross-log confusion where a receipt names log A (so log A's key is selected)
/// while the pinned key material does not actually correspond to A.
fn log_id_for_pubkey_pem(pem: &str) -> Result<String, CoanchorError> {
    Ok(hex::encode(Sha256::digest(spki_der_from_pem(pem)?)))
}

/// PURE / OFFLINE co-anchor verification (no network).
///
/// Given the roots-chain HEAD `root` we published, its persisted [`RekorReceipt`], and Rekor's log
/// public key (PEM, pinned by the auditor), prove ALL of:
///   0. the supplied `rekor_pubkey_pem` IS the key named by `receipt.log_id`
///      (`SHA-256(DER(pubkey)) == receipt.log_id`) — the key↔log_id cryptographic bind. Without this
///      a caller could verify a checkpoint against a pinned key that does not actually correspond to
///      the log the receipt claims (cross-log confusion);
///   1. the entry body's RFC 6962 leaf hash + inclusion proof reproduce the inclusion-proof root
///      (via this crate's own [`crate::verify_inclusion`] — no second Merkle implementation);
///   2. that inclusion-proof root == the root in the SIGNED checkpoint, the checkpoint tree size
///      matches, AND the checkpoint's ECDSA-P256 signature verifies against Rekor's key;
///   3. the entry commits to OUR `root` (`hashedrekord data.hash.value == SHA-256(root)`).
///
/// Any failure returns `Err`. Requires only `serde_json`/`base64`/`p256` — NO network, NO AWS.
///
/// This is the low-level BINARY primitive: for production grading use [`verify_coanchored`], which
/// wraps this in the graded [`CoAnchorStatus`], selects the pinned key from a [`RekorTrustStore`],
/// and additionally binds the checkpoint ORIGIN to the pinned key (see there). The key↔log_id bind
/// (step 0) is enforced HERE so every direct caller of the primitive gets it too.
pub fn verify_coanchor_receipt(
    root: Hash,
    receipt: &RekorReceipt,
    rekor_pubkey_pem: &str,
) -> Result<(), CoanchorError> {
    // (0) KEY↔LOG_ID BIND: the log id IS the SHA-256 of the log's DER public key, so the pinned key
    // we are handed MUST hash to the log id the receipt claims. This rejects verifying a checkpoint
    // against a key that does not belong to the named log — the core cross-log-confusion guard.
    let key_log_id = log_id_for_pubkey_pem(rekor_pubkey_pem)?;
    if !key_log_id.eq_ignore_ascii_case(receipt.log_id.trim()) {
        return Err(err(
            "checkpoint key hash != receipt.log_id (key does not belong to the claimed Rekor log)",
        ));
    }

    // (1) RFC 6962 leaf hash from the canonical body, then reproduce the inclusion proof.
    let body = B64
        .decode(receipt.body_b64.trim())
        .map_err(|e| err(format!("decode entry body base64: {e}")))?;
    let leaf_hash = hash_leaf(&body);
    let ip = &receipt.inclusion;
    let leaf_index: usize = ip
        .leaf_index
        .try_into()
        .map_err(|_| err("leaf_index exceeds usize"))?;
    let tree_size: usize = ip
        .tree_size
        .try_into()
        .map_err(|_| err("tree_size exceeds usize"))?;
    if !verify_inclusion(leaf_index, tree_size, leaf_hash, &ip.hashes, ip.root_hash) {
        return Err(err(
            "inclusion proof does NOT reproduce the inclusion-proof root",
        ));
    }

    // (2) Checkpoint binds the SAME root + size, and its signature verifies against Rekor's key.
    let cp = parse_checkpoint(&receipt.checkpoint)?;
    if cp.root_hash != ip.root_hash {
        return Err(err(
            "checkpoint root != inclusion-proof root (proof not against the signed tree head)",
        ));
    }
    if cp.tree_size != ip.tree_size {
        return Err(err("checkpoint tree size != inclusion-proof tree size"));
    }
    verify_checkpoint_signature(&cp, rekor_pubkey_pem)?;

    // (3) The entry commits to OUR root: the hashedrekord data hash is SHA-256(root).
    let entry: Value =
        serde_json::from_slice(&body).map_err(|e| err(format!("parse entry body JSON: {e}")))?;
    let kind = entry["kind"].as_str().unwrap_or_default();
    if kind != "hashedrekord" {
        return Err(err(format!(
            "unexpected entry kind `{kind}` (expected hashedrekord)"
        )));
    }
    let committed = entry["spec"]["data"]["hash"]["value"]
        .as_str()
        .ok_or_else(|| err("entry has no spec.data.hash.value"))?;
    let want = root_data_hash_hex(&root);
    if !committed.eq_ignore_ascii_case(&want) {
        return Err(err(
            "entry does NOT commit to our root (data.hash.value != SHA-256(root))",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// PRODUCTION LAYER — graded status + rotation-capable pinned-Rekor-key trust store.
// ---------------------------------------------------------------------------------------------

/// Reason a root is only RFC 3161-anchored and not yet independently co-anchored to Rekor.
///
/// This is NOT an error — it is a graded outcome. `NoReceipt` means we simply have no Rekor receipt
/// for this root yet (publishing may be pending, rate-limited, or the log was unavailable);
/// `RekorKeyUntrusted` means we DO hold a receipt but no pinned key in our trust store covers its
/// `log_id`/`integrated_time` (e.g. a key-rotation lag) — a CONFIG/trust-store state, not a crypto
/// finding; `ReceiptInvalid` carries the specific CRYPTO verification failure (inclusion proof,
/// checkpoint signature, root-commit) so an auditor can see WHY a receipt we DID trust the key for
/// did not stand up (mac-lead ratification: rotation-lag != tamper — the two must not be conflated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchoredOnlyReason {
    /// No Rekor receipt was supplied for this root.
    NoReceipt,
    /// A receipt was supplied but did not verify; the string is the underlying reason.
    ReceiptInvalid(String),
    /// A receipt was supplied but our trust store does NOT self-consistently trust the log it names.
    /// These trust/config states, all NOT crypto failures, are graded here (distinct from
    /// [`ReceiptInvalid`](Self::ReceiptInvalid), which implies possible tamper):
    ///
    /// - no pinned key covers its `log_id` at its `integrated_time` (e.g. a key-rotation lag);
    /// - the selected pinned key does not actually belong to that `log_id`
    ///   (`SHA-256(DER(pinned key)) != log_id`) — a mis-pinned trust store;
    /// - the checkpoint's ORIGIN line does not match the pinned key's expected `origin` — the
    ///   checkpoint declares a different log/shard than the one we pinned trust for (cross-log /
    ///   cross-shard confusion).
    RekorKeyUntrusted,
}

/// The GRADED co-anchor status of a roots-chain root (mac-lead ratified Q4 — graded, not binary).
///
/// A missing or invalid receipt is NOT a verification failure; it is "RFC 3161-anchored but not yet
/// independently witnessed". Produced by [`verify_coanchored`], which never returns `Err` and never
/// panics — it always GRADES.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoAnchorStatus {
    /// A Rekor receipt verified end-to-end against a pinned log key: the root is independently
    /// witnessed in the public transparency log.
    CoAnchored {
        /// The roots-chain period this root is the HEAD of (caller-supplied provenance).
        covered_period_id: u64,
        /// The entry's global virtual Rekor log index (provenance / lookup).
        log_index: u64,
        /// Rekor-asserted integration time (Unix seconds).
        integrated_time: u64,
    },
    /// RFC 3161-anchored but not co-anchored to Rekor, with the reason.
    AnchoredOnly {
        /// Why the root is not (yet) co-anchored.
        reason: AnchoredOnlyReason,
    },
}

/// One pinned, trusted Rekor log key with an optional validity window (Unix seconds).
///
/// Rekor log keys rotate. Pinning the key together with the window it was valid for lets an OLD
/// receipt verify against the key that was live WHEN THE ENTRY WAS INTEGRATED, not against today's
/// key — which is exactly what a long-lived audit trail needs (mac-lead SPIKE-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekorTrustKey {
    /// Rekor log id this key signs (SHA-256 of the log's DER public key, hex) — matched against a
    /// receipt's `log_id`. MUST equal `SHA-256(DER(pubkey_pem))`: the Rekor log id IS the key hash,
    /// so a self-consistent pin cryptographically binds the claimed log identity to the key we verify
    /// the checkpoint against. That bind is ENFORCED at verify time (see [`verify_coanchored`] /
    /// [`log_id_for_pubkey_pem`]) — a store that pins a key under the wrong `log_id` is rejected
    /// rather than silently trusted.
    pub log_id: String,
    /// The log's public key, PEM (SPKI) — the input to the checkpoint-signature verifier.
    pub pubkey_pem: String,
    /// The exact checkpoint ORIGIN string this log signs — the C2SP / Go-sumdb-note checkpoint's
    /// FIRST line, i.e. the log's/shard's self-declared identity (e.g.
    /// `"rekor.sigstore.dev - <shardTreeId>"`). `Some(origin)` binds a verified checkpoint to THIS
    /// log/shard: a receipt that selected this key by `log_id` but whose checkpoint origin line
    /// differs is rejected — closing the cross-log / cross-shard CONFUSION surface once the store
    /// holds more than one log (a single Rekor signing key can front several shard origins, so the
    /// signature check alone does not pin WHICH tree the checkpoint is for). `None` = do not enforce
    /// the origin bind (legacy/custom pins that rely on the `log_id`↔key-hash bind only); prefer
    /// `Some`.
    pub origin: Option<String>,
    /// Inclusive lower bound of the key's validity (Unix seconds); `None` = open-ended (no lower bound).
    pub not_before: Option<u64>,
    /// Inclusive upper bound of the key's validity (Unix seconds); `None` = open-ended (no upper bound).
    pub not_after: Option<u64>,
}

impl RekorTrustKey {
    /// True iff this key signs `log_id` AND `integrated_time` falls within its validity window.
    fn covers(&self, log_id: &str, integrated_time: u64) -> bool {
        self.log_id == log_id
            && self.not_before.is_none_or(|nb| integrated_time >= nb)
            && self.not_after.is_none_or(|na| integrated_time <= na)
    }
}

/// The fixture Rekor log id (public good `rekor.sigstore.dev` instance at fixture-capture time):
/// SHA-256 of the log's DER public key. Kept in lock-step with `tests/fixtures/rekor_pubkey.pem`.
pub const FIXTURE_REKOR_LOG_ID: &str =
    "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d";

/// The checkpoint ORIGIN string of the fixture-capture Rekor shard — the first line of the fixture
/// entry's signed checkpoint. Pinned alongside [`FIXTURE_REKOR_LOG_ID`] so the default trust store
/// binds a verified checkpoint to THIS shard's identity (cross-log/-shard confusion guard).
pub const FIXTURE_REKOR_ORIGIN: &str = "rekor.sigstore.dev - 1193050959916656506";

/// The bundled Rekor log public key (PEM) matching [`FIXTURE_REKOR_LOG_ID`].
const FIXTURE_REKOR_PUBKEY_PEM: &str = include_str!("../tests/fixtures/rekor_pubkey.pem");

/// A rotation-capable store of pinned, trusted Rekor log keys (mac-lead SPIKE-3).
///
/// Holds one or more [`RekorTrustKey`]s. [`select_key`](Self::select_key) resolves the PEM to verify
/// a given receipt against by matching the receipt's `log_id` AND honoring each key's validity
/// window — so a receipt is always checked against the key that was valid when it was issued.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RekorTrustStore {
    keys: Vec<RekorTrustKey>,
}

impl RekorTrustStore {
    /// Build a trust store from an explicit set of pinned keys.
    pub fn new(keys: Vec<RekorTrustKey>) -> Self {
        Self { keys }
    }

    /// The default trust store pinned to the bundled fixture key (public good `rekor.sigstore.dev`),
    /// open-ended validity. Suitable for tests and as a shipped default pin for that instance.
    pub fn from_fixture() -> Self {
        Self::new(vec![RekorTrustKey {
            log_id: FIXTURE_REKOR_LOG_ID.to_string(),
            pubkey_pem: FIXTURE_REKOR_PUBKEY_PEM.to_string(),
            // Bind the fixture shard's real origin (verified: SHA-256(DER(pubkey)) == log_id, and
            // this origin is the first line of the fixture checkpoint).
            origin: Some(FIXTURE_REKOR_ORIGIN.to_string()),
            not_before: None,
            not_after: None,
        }])
    }

    /// Add a pinned key (builder-style), returning `self` for chaining.
    pub fn with_key(mut self, key: RekorTrustKey) -> Self {
        self.keys.push(key);
        self
    }

    /// The pinned keys, in insertion order.
    pub fn keys(&self) -> &[RekorTrustKey] {
        &self.keys
    }

    /// Resolve the full pinned [`RekorTrustKey`] that signs `log_id` AND whose validity window
    /// contains `integrated_time`. Returns `None` if no pinned key matches the log id, or none is
    /// valid at that time. The FIRST matching key (insertion order) wins when windows overlap.
    ///
    /// Prefer this over [`select_key`](Self::select_key) in the verify path: it carries the pinned
    /// key's `origin` (for the checkpoint-origin bind) and its `log_id` (for the key↔log_id-hash
    /// bind) alongside the PEM.
    pub fn select_trust_key(&self, log_id: &str, integrated_time: u64) -> Option<&RekorTrustKey> {
        self.keys.iter().find(|k| k.covers(log_id, integrated_time))
    }

    /// Resolve the PEM of the pinned key that signs `log_id` AND whose validity window contains
    /// `integrated_time`. Returns `None` if no pinned key matches the log id, or none is valid at
    /// that time. The FIRST matching key (insertion order) wins when windows overlap.
    pub fn select_key(&self, log_id: &str, integrated_time: u64) -> Option<&str> {
        self.select_trust_key(log_id, integrated_time)
            .map(|k| k.pubkey_pem.as_str())
    }
}

/// GRADED production co-anchor verification (mac-lead Q4). Never returns `Err`, never panics — it
/// GRADES a root as [`CoAnchorStatus::CoAnchored`] or [`CoAnchorStatus::AnchoredOnly`].
///
/// `receipt == None` grades [`AnchoredOnly`](CoAnchorStatus::AnchoredOnly) with
/// [`AnchoredOnlyReason::NoReceipt`].
///
/// `receipt == Some(r)` selects the pinned Rekor key from `trust` by `r.log_id` (honoring validity
/// windows at `r.integrated_time`), then makes the trust decision SELF-CONSISTENT before grading
/// `CoAnchored`. Any of these trust/config states grades [`AnchoredOnly`] with
/// [`AnchoredOnlyReason::RekorKeyUntrusted`] (a trust/config finding, distinct from a crypto one),
/// each checked UP FRONT before any signature work:
///
/// - NO pinned key covers the receipt (e.g. a key-rotation lag);
/// - the selected pinned key does not actually belong to `r.log_id`
///   (`SHA-256(DER(key)) != r.log_id`) — a mis-pinned store;
/// - the checkpoint's ORIGIN line does not match the pinned key's expected `origin` — the checkpoint
///   declares a different log/shard than the one we pinned (cross-log / cross-shard confusion).
///
/// Otherwise it runs the proven [`verify_coanchor_receipt`] against the selected key: `Ok` grades
/// [`CoAnchored`](CoAnchorStatus::CoAnchored); `Err(e)` grades [`AnchoredOnly`] with
/// [`AnchoredOnlyReason::ReceiptInvalid`] (a crypto/tamper finding — e.g. the checkpoint signature
/// does not verify, or the entry does not commit to `root`).
///
/// The graded split is deliberate (mac-lead: rotation-lag / mis-config != tamper): binds about WHICH
/// log/key we trust grade `RekorKeyUntrusted`; the signature / inclusion / root-commitment crypto
/// grades `ReceiptInvalid`.
///
/// `covered_period_id` is carried through into a `CoAnchored` result as provenance — the roots-chain
/// period whose HEAD `root` is.
pub fn verify_coanchored(
    root: Hash,
    covered_period_id: u64,
    receipt: Option<&RekorReceipt>,
    trust: &RekorTrustStore,
) -> CoAnchorStatus {
    let receipt = match receipt {
        None => {
            return CoAnchorStatus::AnchoredOnly {
                reason: AnchoredOnlyReason::NoReceipt,
            }
        }
        Some(r) => r,
    };

    let untrusted = CoAnchorStatus::AnchoredOnly {
        reason: AnchoredOnlyReason::RekorKeyUntrusted,
    };

    // (a) No pinned key covers this receipt's log_id/integrated_time (e.g. rotation lag): a
    // trust/config gap, graded RekorKeyUntrusted BEFORE any crypto verify — a receipt we don't trust
    // the key for must not be conflated with ReceiptInvalid (which implies possible tamper).
    let key = match trust.select_trust_key(&receipt.log_id, receipt.integrated_time) {
        Some(k) => k,
        None => return untrusted,
    };

    // (b) KEY↔LOG_ID BIND: the pinned key we selected must actually be the key named by the log_id
    // (log_id == SHA-256(DER(pubkey))). A store that pins the wrong key under this log_id is a
    // trust/config error, NOT tamper of the receipt → RekorKeyUntrusted. (verify_coanchor_receipt
    // re-checks this as a hard crypto precondition for its direct callers; we grade it here first so
    // a mis-pinned store is reported as the config state it is.)
    match log_id_for_pubkey_pem(&key.pubkey_pem) {
        Ok(kid) if kid.eq_ignore_ascii_case(receipt.log_id.trim()) => {}
        _ => return untrusted,
    }

    // (c) ORIGIN BIND: if the pinned key declares an expected checkpoint origin, the receipt's
    // checkpoint must declare that SAME log/shard identity. A mismatch means the checkpoint is for a
    // log/shard we have NOT pinned trust for (cross-log / cross-shard confusion) — a trust/config
    // state → RekorKeyUntrusted, checked before the crypto verify. (A checkpoint whose origin MATCHES
    // but whose signed text was otherwise altered still fails the signature check inside
    // verify_coanchor_receipt → ReceiptInvalid; the two cases stay distinct.)
    if let Some(expected_origin) = key.origin.as_deref() {
        let cp_origin = receipt.checkpoint.lines().next().unwrap_or_default();
        if cp_origin != expected_origin {
            return untrusted;
        }
    }

    match verify_coanchor_receipt(root, receipt, &key.pubkey_pem) {
        Ok(()) => CoAnchorStatus::CoAnchored {
            covered_period_id,
            log_index: receipt.log_index,
            integrated_time: receipt.integrated_time,
        },
        Err(e) => CoAnchorStatus::AnchoredOnly {
            reason: AnchoredOnlyReason::ReceiptInvalid(e.to_string()),
        },
    }
}

// ---------------------------------------------------------------------------------------------
// PRODUCER — signer abstraction + live Rekor publish (ADR-043 C1 P3 phase-2b, feature `rekor-client`).
// ---------------------------------------------------------------------------------------------
//
// This is the PUBLISH half (the producer PR's concern) layered on top of the always-on offline
// verifier above. It is deliberately SIGNER-AGNOSTIC: this crate stays AWS-free, so the producer
// injects a [`CoAnchorSigner`] (e.g. a KMS-backed signer in the tamper-evidence-builder Lambda, or
// an in-process [`EphemeralSigner`] for the live round-trip test). The signature is ECDSA-P256 over
// the raw 32-byte root, hashed with SHA-256 (`ECDSA_SHA_256`) — matching Rekor's `hashedrekord`
// `data.hash = SHA-256(root)` semantics and the offline verifier's expectation.

/// Signs a roots-chain root for Rekor `hashedrekord` submission. Injected by the producer so this
/// crate never links an AWS/KMS SDK. Both methods are FALLIBLE (KMS/HSM calls can fail); the
/// producer wraps the whole publish in its own fail-open block.
///
/// `sign_root` MUST return a **DER-encoded ECDSA-P256 signature** computed as `ECDSA_SHA_256` over
/// the raw 32 root bytes (i.e. sign `SHA-256(root)`) — the exact input Rekor verifies against the
/// submitted public key, and the same semantics the spike's `sk.sign(&root)` produced.
/// `public_key_pem` MUST return the signer's SPKI public key in PEM (`-----BEGIN PUBLIC KEY-----`).
pub trait CoAnchorSigner {
    /// The signer's SPKI public key, PEM-encoded. Submitted (base64) as the entry's `publicKey`.
    fn public_key_pem(&self) -> Result<String, CoanchorError>;
    /// DER-encoded ECDSA-P256 (`ECDSA_SHA_256`) signature over the raw 32-byte `root`.
    fn sign_root(&self, root: &Hash) -> Result<Vec<u8>, CoanchorError>;
}

/// PRODUCTION co-anchor PUBLISH: sign `root` via the injected `signer`, submit a `hashedrekord`
/// entry to Rekor, then read the entry back BY UUID to capture the inclusion proof + signed
/// checkpoint, returning the persistable [`RekorReceipt`].
///
/// Ported from `spike/c1-p3-rekor-coanchor` but refactored to use a [`CoAnchorSigner`] instead of
/// generating an ephemeral key inline — so the builder can drive it with a KMS-managed key whose
/// private material never leaves KMS. Same wire flow: `data.hash = SHA-256(root)` hex,
/// `signature.content = base64(DER sig)`, `publicKey.content = base64(PEM)`; POST to
/// `{rekor_url}/api/v1/log/entries`; if the POST response lacks the inclusion proof, GET the entry
/// back by UUID. Pure-Rust HTTP (`ureq` + rustls), 30 s timeout, 4 MiB response cap. `rekor_url` is
/// the instance base, e.g. `https://rekor.sigstore.dev`.
#[cfg(feature = "rekor-client")]
pub fn publish_root_to_rekor(
    root: Hash,
    rekor_url: &str,
    signer: &dyn CoAnchorSigner,
) -> Result<RekorReceipt, CoanchorError> {
    use std::time::Duration;

    // Signature (DER ECDSA-P256 over SHA-256(root)) + SPKI public key PEM come from the injected
    // signer — the private key material is the signer's concern (KMS-resident in production).
    let sig_der = signer.sign_root(&root)?;
    let sig_b64 = B64.encode(&sig_der);
    let pub_pem = signer.public_key_pem()?;
    let pub_b64 = B64.encode(pub_pem.as_bytes());
    let data_hash = root_data_hash_hex(&root);

    let proposed = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": { "hash": { "algorithm": "sha256", "value": data_hash } },
            "signature": {
                "content": sig_b64,
                "publicKey": { "content": pub_b64 }
            }
        }
    });

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build();
    let base = rekor_url.trim_end_matches('/');

    // POST the proposed entry. Serialize the JSON ourselves + `send_string` so we don't need ureq's
    // optional `json` feature.
    let proposed_str =
        serde_json::to_string(&proposed).map_err(|e| err(format!("serialize entry: {e}")))?;
    let post_resp = agent
        .post(&format!("{base}/api/v1/log/entries"))
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .send_string(&proposed_str)
        .map_err(|e| err(format!("Rekor POST failed: {}", rekor_ureq_msg(e))))?;
    let post_body = read_capped(post_resp.into_reader())?;

    // The POST response may already carry the inclusion proof; if so, use it directly.
    if let Ok(receipt) = RekorReceipt::from_entries_response(&post_body) {
        return Ok(receipt);
    }

    // Otherwise extract the UUID and read the entry back (proof is attached once integrated).
    let posted: Value =
        serde_json::from_str(&post_body).map_err(|e| err(format!("parse POST response: {e}")))?;
    let uuid = posted
        .as_object()
        .and_then(|o| o.keys().next())
        .cloned()
        .ok_or_else(|| err("POST response carried no entry UUID"))?;

    let get_resp = agent
        .get(&format!("{base}/api/v1/log/entries/{uuid}"))
        .set("Accept", "application/json")
        .call()
        .map_err(|e| err(format!("Rekor GET-by-uuid failed: {}", rekor_ureq_msg(e))))?;
    let get_body = read_capped(get_resp.into_reader())?;
    RekorReceipt::from_entries_response(&get_body)
}

/// Read a ureq response body with a 4 MiB cap so a hostile/broken server cannot OOM the caller.
#[cfg(feature = "rekor-client")]
fn read_capped(reader: impl std::io::Read) -> Result<String, CoanchorError> {
    use std::io::Read as _;
    const MAX: u64 = 4 << 20;
    let mut buf = Vec::new();
    reader
        .take(MAX)
        .read_to_end(&mut buf)
        .map_err(|e| err(format!("reading Rekor response: {e}")))?;
    String::from_utf8(buf).map_err(|e| err(format!("Rekor response not UTF-8: {e}")))
}

/// Extract a readable message from a ureq error, including the server body on a 4xx/5xx status.
#[cfg(feature = "rekor-client")]
fn rekor_ureq_msg(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            format!("HTTP {code}: {body}")
        }
        other => other.to_string(),
    }
}

/// An in-process ECDSA-P256 [`CoAnchorSigner`] backed by a random ephemeral key. FOR TESTS / the
/// `#[ignore]` live round-trip only — production signs with a KMS-resident key (the builder's
/// `KmsCoAnchorSigner`). Mirrors the spike's inline ephemeral key so the wire format stays proven.
#[cfg(feature = "rekor-client")]
pub struct EphemeralSigner {
    sk: p256::ecdsa::SigningKey,
}

#[cfg(feature = "rekor-client")]
impl EphemeralSigner {
    /// Generate a fresh random P-256 signing key (retry until 32 random bytes form a valid scalar).
    pub fn generate() -> Result<Self, CoanchorError> {
        use p256::ecdsa::SigningKey;
        loop {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| err(format!("key rng: {e}")))?;
            if let Ok(sk) = SigningKey::from_slice(&seed) {
                return Ok(Self { sk });
            }
        }
    }
}

#[cfg(feature = "rekor-client")]
impl CoAnchorSigner for EphemeralSigner {
    fn public_key_pem(&self) -> Result<String, CoanchorError> {
        use p256::pkcs8::{EncodePublicKey, LineEnding};
        self.sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| err(format!("encode public key PEM: {e}")))
    }

    fn sign_root(&self, root: &Hash) -> Result<Vec<u8>, CoanchorError> {
        use p256::ecdsa::{signature::Signer, Signature};
        // `Signer<Signature>` for `SigningKey` hashes the message with SHA-256, so this is
        // ECDSA_SHA_256 over the raw root — identical semantics to KMS RAW + EcdsaSha256.
        let sig: Signature = self.sk.sign(root.as_slice());
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Offline fixture: a REAL Rekor entries response (`{uuid: {entry}}`) captured from a live publish,
    // plus the Rekor log public key at capture time. Proves the OFFLINE verify path with NO network.
    const FIXTURE_ENTRY: &str = include_str!("../tests/fixtures/rekor_coanchor_entry.json");
    const FIXTURE_PUBKEY: &str = include_str!("../tests/fixtures/rekor_pubkey.pem");
    // The exact 32-byte root that was co-anchored to produce FIXTURE_ENTRY (hex).
    const FIXTURE_ROOT_HEX: &str = include_str!("../tests/fixtures/rekor_coanchor_root.hex");

    fn fixture_root() -> Hash {
        hex32(FIXTURE_ROOT_HEX.trim(), "fixture root").expect("valid 32-byte fixture root")
    }

    fn fixture_receipt() -> RekorReceipt {
        RekorReceipt::from_entries_response(FIXTURE_ENTRY).expect("parse fixture receipt")
    }

    // ----- PROVEN spike adversarial tests (ported verbatim) -------------------------------------

    #[test]
    fn parses_fixture_receipt() {
        let r = fixture_receipt();
        assert!(!r.entry_uuid.is_empty(), "uuid present");
        assert!(!r.checkpoint.is_empty(), "checkpoint present");
        assert!(r.inclusion.tree_size >= 1, "tree size present");
        assert!(!r.inclusion.hashes.is_empty() || r.inclusion.tree_size == 1);
    }

    #[test]
    fn offline_verify_accepts_the_real_fixture_receipt() {
        verify_coanchor_receipt(fixture_root(), &fixture_receipt(), FIXTURE_PUBKEY)
            .expect("captured real Rekor receipt MUST verify offline");
    }

    #[test]
    fn offline_verify_rejects_a_one_bit_altered_root() {
        let mut wrong = fixture_root();
        wrong[0] ^= 0x01;
        assert!(
            verify_coanchor_receipt(wrong, &fixture_receipt(), FIXTURE_PUBKEY).is_err(),
            "a root the entry does not commit to MUST be rejected"
        );
    }

    #[test]
    fn offline_verify_rejects_a_tampered_inclusion_proof() {
        let mut receipt = fixture_receipt();
        if let Some(h) = receipt.inclusion.hashes.first_mut() {
            h[0] ^= 0x01;
        } else {
            // Single-leaf tree: corrupt the body so the leaf hash no longer reproduces the root.
            receipt.body_b64.push('A');
        }
        assert!(
            verify_coanchor_receipt(fixture_root(), &receipt, FIXTURE_PUBKEY).is_err(),
            "a tampered inclusion proof MUST be rejected"
        );
    }

    #[test]
    fn offline_verify_rejects_a_forged_checkpoint_signature() {
        let mut receipt = fixture_receipt();
        // Flip a byte inside the signed text so the ECDSA signature no longer matches.
        receipt.checkpoint = receipt.checkpoint.replacen("rekor", "Rekor", 1);
        assert!(
            verify_coanchor_receipt(fixture_root(), &receipt, FIXTURE_PUBKEY).is_err(),
            "a checkpoint whose signed text was altered MUST be rejected"
        );
    }

    // ----- ADDED production-layer tests: graded status --------------------------------------------

    #[test]
    fn verify_coanchored_grades_real_fixture_as_coanchored() {
        let receipt = fixture_receipt();
        let trust = RekorTrustStore::from_fixture();
        let status = verify_coanchored(fixture_root(), 42, Some(&receipt), &trust);
        assert_eq!(
            status,
            CoAnchorStatus::CoAnchored {
                covered_period_id: 42,
                log_index: receipt.log_index,
                integrated_time: receipt.integrated_time,
            },
            "the real fixture receipt against its pinned key MUST grade as CoAnchored"
        );
    }

    #[test]
    fn receipt_json_round_trips_through_compact_shape() {
        // to_receipt_json ∘ from_receipt_json is identity — the FROZEN contract that lets a
        // roots-chain row / a proof bundle carry a receipt losslessly for offline re-verification.
        let r = fixture_receipt();
        let back = RekorReceipt::from_receipt_json(&r.to_receipt_json())
            .expect("compact receipt round-trips");
        assert_eq!(r, back);
    }

    #[test]
    fn compact_shape_receipt_still_grades_coanchored() {
        // THE load-bearing property for finding-A live PROVEN: a receipt reconstructed from the
        // COMPACT (persisted/bundled) shape must drive the SAME CoAnchored verdict as the raw
        // fixture — otherwise a real bundle could never reach Proven through the compact shape it
        // actually carries.
        let compact = RekorReceipt::from_receipt_json(&fixture_receipt().to_receipt_json())
            .expect("parse compact");
        let trust = RekorTrustStore::from_fixture();
        let status = verify_coanchored(fixture_root(), 42, Some(&compact), &trust);
        assert!(
            matches!(status, CoAnchorStatus::CoAnchored { .. }),
            "compact-shape receipt must still grade CoAnchored, got {status:?}"
        );
    }

    #[test]
    fn from_receipt_json_parses_a_frozen_historic_on_disk_row() {
        // A receipt EXACTLY as the pre-#2650 builder persisted it to the roots-chain row's
        // `coanchor_receipt` attribute (compact shape, snake_case fields, lowercase hex). Freezing a
        // historic on-disk sample here means a future field-name / structure / hex-casing drift in
        // from_receipt_json that would fail to parse ALREADY-PERSISTED rows is caught (AI-review
        // #2650 MED — that class silently degrades Proven -> NotYetWitnessed at scale). Parsing is
        // by key, so key order / whitespace in the stored bytes is irrelevant — only the field
        // CONTRACT is frozen.
        let ab = "ab".repeat(32); // root_hash bytes
        let cd = "cd".repeat(32); // one audit-path hash
        let historic = format!(
            r#"{{"log_id":"Lx","log_index":7,"entry_uuid":"Ux","integrated_time":100,"body_b64":"Ym9keQ==","checkpoint":"cp\n","inclusion":{{"leaf_index":2,"tree_size":4,"root_hash":"{ab}","hashes":["{cd}"]}}}}"#
        );
        let r = RekorReceipt::from_receipt_json(&serde_json::from_str(&historic).unwrap())
            .expect("a historic on-disk coanchor_receipt row MUST still parse");
        assert_eq!(r.log_id, "Lx");
        assert_eq!(r.log_index, 7);
        assert_eq!(r.entry_uuid, "Ux");
        assert_eq!(r.integrated_time, 100);
        assert_eq!(r.body_b64, "Ym9keQ==");
        assert_eq!(r.inclusion.leaf_index, 2);
        assert_eq!(r.inclusion.tree_size, 4);
        assert_eq!(r.inclusion.root_hash, [0xab; 32]);
        assert_eq!(r.inclusion.hashes, vec![[0xcd; 32]]);
        // ...and a re-serialize round-trips (to_receipt_json <-> from_receipt_json stay inverses).
        assert_eq!(
            RekorReceipt::from_receipt_json(&r.to_receipt_json()).unwrap(),
            r
        );
    }

    #[test]
    fn verify_coanchored_grades_none_receipt_as_anchored_only_no_receipt() {
        let trust = RekorTrustStore::from_fixture();
        let status = verify_coanchored(fixture_root(), 42, None, &trust);
        assert_eq!(
            status,
            CoAnchorStatus::AnchoredOnly {
                reason: AnchoredOnlyReason::NoReceipt
            },
            "a missing receipt MUST grade as AnchoredOnly{{NoReceipt}}, not fail"
        );
    }

    #[test]
    fn verify_coanchored_grades_tampered_receipt_as_receipt_invalid_without_panic() {
        // Tamper the committed root: the entry no longer commits to it.
        let mut wrong = fixture_root();
        wrong[0] ^= 0x01;
        let receipt = fixture_receipt();
        let trust = RekorTrustStore::from_fixture();
        let status = verify_coanchored(wrong, 42, Some(&receipt), &trust);
        match status {
            CoAnchorStatus::AnchoredOnly {
                reason: AnchoredOnlyReason::ReceiptInvalid(_),
            } => {}
            other => panic!("tampered receipt MUST grade as ReceiptInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_coanchored_grades_unknown_log_id_as_rekor_key_untrusted() {
        // Empty trust store → no pinned key for the receipt's log id → graded, not a panic/err, and
        // NOT conflated with a crypto failure: this is a trust/config gap (RekorKeyUntrusted), not
        // ReceiptInvalid.
        let receipt = fixture_receipt();
        let empty = RekorTrustStore::default();
        let status = verify_coanchored(fixture_root(), 42, Some(&receipt), &empty);
        assert_eq!(
            status,
            CoAnchorStatus::AnchoredOnly {
                reason: AnchoredOnlyReason::RekorKeyUntrusted
            },
            "no pinned key for the receipt's log id MUST grade as RekorKeyUntrusted, not ReceiptInvalid"
        );
    }

    #[test]
    fn verify_coanchored_grades_out_of_window_integrated_time_as_rekor_key_untrusted() {
        // The pinned key exists for the fixture log id, but its validity window EXCLUDES the
        // fixture receipt's integrated_time — modeling a key-rotation lag. This MUST grade as
        // RekorKeyUntrusted (a trust/config state), NOT ReceiptInvalid (which would imply a
        // possible crypto/tamper finding).
        let receipt = fixture_receipt();
        let trust = RekorTrustStore::new(vec![RekorTrustKey {
            log_id: FIXTURE_REKOR_LOG_ID.to_string(),
            pubkey_pem: FIXTURE_PUBKEY.to_string(),
            origin: Some(FIXTURE_REKOR_ORIGIN.to_string()),
            not_before: Some(2_000_000_000),
            not_after: Some(2_100_000_000),
        }]);
        let status = verify_coanchored(fixture_root(), 42, Some(&receipt), &trust);
        assert_eq!(
            status,
            CoAnchorStatus::AnchoredOnly {
                reason: AnchoredOnlyReason::RekorKeyUntrusted
            },
            "a receipt outside every pinned key's validity window (rotation lag) MUST grade as \
             RekorKeyUntrusted, not ReceiptInvalid"
        );
    }

    // ----- ADDED: cross-log / cross-shard confusion binds (AI-review MEDIUM on #2031) -------------

    #[test]
    fn log_id_for_pubkey_pem_reproduces_the_fixture_log_id() {
        // The whole bind rests on: Rekor log id == SHA-256(DER(SubjectPublicKeyInfo)). Prove our
        // hasher reproduces the fixture log id from the pinned PEM (and that the fixture receipt
        // claims that same id) — if this drifts, the binds below would silently over/under-reject.
        let kid = log_id_for_pubkey_pem(FIXTURE_PUBKEY).expect("hash fixture pubkey");
        assert_eq!(
            kid, FIXTURE_REKOR_LOG_ID,
            "SHA-256(DER(fixture pubkey)) MUST equal the pinned fixture log id"
        );
        assert_eq!(
            kid,
            fixture_receipt().log_id,
            "and MUST equal the fixture receipt's claimed log id"
        );
    }

    #[test]
    fn offline_verify_rejects_a_key_that_is_not_the_receipts_log_id() {
        // The PRIMITIVE binds key↔log_id: hand it the genuine fixture receipt/root + the correct
        // fixture key, but with the receipt claiming a DIFFERENT log id than the key hashes to. The
        // primitive MUST reject up front (cross-log confusion), before any Merkle/signature work.
        let mut receipt = fixture_receipt();
        receipt.log_id =
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
        assert!(
            verify_coanchor_receipt(fixture_root(), &receipt, FIXTURE_PUBKEY).is_err(),
            "a key that does not hash to the receipt's log_id MUST be rejected by the primitive"
        );
    }

    #[test]
    fn verify_coanchored_grades_key_not_matching_log_id_hash_as_rekor_key_untrusted() {
        // A trust store that MIS-PINS the fixture PEM under a log id that is NOT its key hash.
        // select_trust_key still resolves it (matched by the claimed log id), the origin bind would
        // pass, but the key↔log_id-hash bind FAILS → graded RekorKeyUntrusted (a trust/config state),
        // never CoAnchored, and NOT conflated with ReceiptInvalid (which implies tamper).
        const WRONG_LOG_ID: &str =
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let mut receipt = fixture_receipt();
        receipt.log_id = WRONG_LOG_ID.to_string();
        let trust = RekorTrustStore::new(vec![RekorTrustKey {
            log_id: WRONG_LOG_ID.to_string(),
            pubkey_pem: FIXTURE_PUBKEY.to_string(),
            origin: Some(FIXTURE_REKOR_ORIGIN.to_string()),
            not_before: None,
            not_after: None,
        }]);
        let status = verify_coanchored(fixture_root(), 42, Some(&receipt), &trust);
        assert_eq!(
            status,
            CoAnchorStatus::AnchoredOnly {
                reason: AnchoredOnlyReason::RekorKeyUntrusted
            },
            "a pinned key whose hash != the receipt's log id MUST grade RekorKeyUntrusted, \
             not CoAnchored or ReceiptInvalid"
        );
    }

    #[test]
    fn verify_coanchored_grades_altered_checkpoint_origin_as_rekor_key_untrusted() {
        // Rewrite the checkpoint's ORIGIN line to claim a DIFFERENT shard. The receipt still selects
        // the pinned fixture key by log_id and the key↔log_id-hash bind holds, but the checkpoint now
        // declares a log/shard we have NOT pinned trust for → cross-log/-shard confusion →
        // RekorKeyUntrusted (a trust/config state), NOT CoAnchored.
        let mut receipt = fixture_receipt();
        receipt.checkpoint = receipt.checkpoint.replacen(
            FIXTURE_REKOR_ORIGIN,
            "rekor.sigstore.dev - 9999999999999999999",
            1,
        );
        let trust = RekorTrustStore::from_fixture();
        let status = verify_coanchored(fixture_root(), 42, Some(&receipt), &trust);
        assert_eq!(
            status,
            CoAnchorStatus::AnchoredOnly {
                reason: AnchoredOnlyReason::RekorKeyUntrusted
            },
            "a checkpoint whose origin claims a different log/shard MUST grade RekorKeyUntrusted, \
             not CoAnchored"
        );
    }

    // ----- ADDED production-layer tests: rotation-capable trust store -----------------------------

    #[test]
    fn select_key_returns_pinned_pem_for_fixture_log_id_and_time() {
        let receipt = fixture_receipt();
        let trust = RekorTrustStore::from_fixture();
        let pem = trust
            .select_key(&receipt.log_id, receipt.integrated_time)
            .expect("fixture log id + time MUST resolve a pinned key");
        assert_eq!(pem, FIXTURE_PUBKEY, "resolves the bundled fixture PEM");
    }

    #[test]
    fn select_key_returns_none_for_unknown_log_id() {
        let trust = RekorTrustStore::from_fixture();
        assert!(
            trust.select_key("deadbeef", 1_783_376_686).is_none(),
            "an unknown log id MUST NOT resolve a key"
        );
    }

    #[test]
    fn select_key_returns_none_for_out_of_window_time() {
        // Pin the fixture key to a window that EXCLUDES the fixture integrated_time (1783376686).
        let trust = RekorTrustStore::new(vec![RekorTrustKey {
            log_id: FIXTURE_REKOR_LOG_ID.to_string(),
            pubkey_pem: FIXTURE_PUBKEY.to_string(),
            origin: Some(FIXTURE_REKOR_ORIGIN.to_string()),
            not_before: Some(2_000_000_000),
            not_after: Some(2_100_000_000),
        }]);
        assert!(
            trust
                .select_key(FIXTURE_REKOR_LOG_ID, 1_783_376_686)
                .is_none(),
            "a time before the key's not_before MUST NOT resolve the key"
        );
        // A time INSIDE the window resolves it.
        assert!(
            trust
                .select_key(FIXTURE_REKOR_LOG_ID, 2_050_000_000)
                .is_some(),
            "a time inside the window MUST resolve the key"
        );
    }

    #[test]
    fn select_key_picks_the_key_valid_when_the_receipt_was_issued() {
        // Two keys for the SAME log id: an OLD one (valid up to T) and a NEW one (valid from T).
        // A receipt integrated before T must resolve the OLD key, not today's key (rotation).
        const OLD_PEM: &str = "-----BEGIN PUBLIC KEY-----\nOLDKEY\n-----END PUBLIC KEY-----\n";
        let boundary = 1_800_000_000u64;
        let trust = RekorTrustStore::new(vec![
            RekorTrustKey {
                log_id: FIXTURE_REKOR_LOG_ID.to_string(),
                pubkey_pem: OLD_PEM.to_string(),
                origin: Some(FIXTURE_REKOR_ORIGIN.to_string()),
                not_before: None,
                not_after: Some(boundary),
            },
            RekorTrustKey {
                log_id: FIXTURE_REKOR_LOG_ID.to_string(),
                pubkey_pem: FIXTURE_PUBKEY.to_string(),
                origin: Some(FIXTURE_REKOR_ORIGIN.to_string()),
                not_before: Some(boundary + 1),
                not_after: None,
            },
        ]);
        // Fixture integrated_time (1783376686) < boundary → OLD key.
        assert_eq!(
            trust.select_key(FIXTURE_REKOR_LOG_ID, 1_783_376_686),
            Some(OLD_PEM),
            "an old receipt MUST verify against the key valid WHEN IT WAS ISSUED"
        );
        // A later time → the rotated-in key.
        assert_eq!(
            trust.select_key(FIXTURE_REKOR_LOG_ID, boundary + 100),
            Some(FIXTURE_PUBKEY),
            "a later receipt MUST verify against the rotated-in key"
        );
    }

    // ----- PRODUCER live round-trip (ported from the spike, refactored onto CoAnchorSigner) -------

    // LIVE end-to-end round-trip against the public Rekor instance via the injected EphemeralSigner.
    // #[ignore]'d — hits the network, so NOT run in CI (rate limits / availability). Run manually to
    // (re)generate the fixture:
    //   cargo test -p meshlogic-merkle --features rekor-client -- --ignored --nocapture
    #[cfg(feature = "rekor-client")]
    #[test]
    #[ignore = "live network call to the public Rekor transparency log"]
    fn live_rekor_publish_via_ephemeral_signer_then_offline_verify() {
        use sha2::{Digest, Sha256};
        // A unique-per-run "roots-chain head" so we never collide with an existing log entry.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root: Hash = Sha256::digest(format!("meshlogic-p3-producer-{nonce}").as_bytes()).into();

        let signer = EphemeralSigner::generate().expect("generate ephemeral signer");
        let receipt = publish_root_to_rekor(root, "https://rekor.sigstore.dev", &signer)
            .expect("live Rekor publish");
        println!(
            "log_index={} uuid={}",
            receipt.log_index, receipt.entry_uuid
        );
        println!("checkpoint=\n{}", receipt.checkpoint);

        // The offline verifier must accept the live receipt against Rekor's published key.
        let pubkey = FIXTURE_PUBKEY; // pinned at fixture-capture time; refresh if Rekor rotates.
        verify_coanchor_receipt(root, &receipt, pubkey).expect("live receipt MUST verify offline");
    }
}
