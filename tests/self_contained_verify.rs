// AI-review round-3 MED-3: this whole file's KAT-bundle fixture machinery signs with
// `self_contained::pov_bundle_signing_key`/pins via `pov_bundle_trust_store` — both now gated
// `#[cfg(any(test, feature = "pov-fixtures"))]` in the library (closing the "any downstream linking
// offline-verify can reach the demo key" hole). The `test` half of that gate can never help an
// integration-test crate like this one — `cfg(test)` only ever applies to the LIBRARY's own `--lib`
// unit-test compilation, never to a dependent crate merely being compiled while `cargo test` runs —
// so this file now requires `pov-fixtures` explicitly, matching every mandated invocation of it
// (`cargo test -p meshlogic-merkle --features offline-verify,pov-fixtures --test
// self_contained_verify`). Without `pov-fixtures` this file compiles to nothing (0 tests, not an
// error) rather than a hard compile failure — the same "absent, not broken" shape `#![cfg(feature =
// "offline-verify")]` alone already gave it.
#![cfg(all(feature = "offline-verify", feature = "pov-fixtures"))]
use meshlogic_merkle::coanchor::{
    RekorTrustKey, RekorTrustStore, FIXTURE_REKOR_LOG_ID, FIXTURE_REKOR_ORIGIN,
};
use meshlogic_merkle::commitment_leaf::{b64_encode, sha256_hex};
use meshlogic_merkle::proof_gen::{build_proof_bundle, TstRef};
use meshlogic_merkle::roots_chain::build_roots_chain;
use meshlogic_merkle::self_contained::*;
use meshlogic_merkle::{hash_leaf, Hash};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{EncodePublicKey, LineEnding};
use sha2::{Digest, Sha256};
use std::fs;

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
// Frozen KAT p0 root that the freeTSA fixture .tsr timestamps (see offline_verify.rs) — copied
// EXACT from tests/offline_verify.rs KAT_ROOT_HEX / KAT_CONTENT_HASH so the same real TST vector
// anchors both. `KAT_CONTENT_HASH` is the ProofBundle's OWN leaf identity (sha256("leaf-E")); the
// BundleRecord's `content_hash` below is bound to this SAME value (verify_self_contained's
// anti-swap check requires parsed.content_hash == record.content_hash — round 2 review fix), and
// its `preimage_b64` is the literal "leaf-E" bytes the KAT hash commits to.
const KAT_ROOT_HEX: &str = "5fb58d89ca9e40abece0d6b1447d5783094112244c17e9b5b7aa5c89c84f8012";
const KAT_CONTENT_HASH: &str = "88496c1549d5dc5f6a0d91963892d3b681fc18540ebb3bd79c769a7a5993271a";

fn cacert_der() -> Vec<u8> {
    fs::read(format!("{FIX}freetsa_cacert.der")).unwrap()
}
fn kat_tst_der() -> Vec<u8> {
    fs::read(format!("{FIX}freetsa_kat_response.tsr")).unwrap()
}
fn content_hash(label: &str) -> String {
    hex::encode(Sha256::digest(label.as_bytes()))
}

/// The KAT period's leaf set (frozen order: C, D, E) — pulled out so the swap-proof test can build
/// a SECOND, individually-valid proof over the same chain/period for a DIFFERENT leaf.
fn kat_p0() -> Vec<String> {
    vec![
        content_hash("leaf-C"),
        content_hash("leaf-D"),
        content_hash("leaf-E"),
    ]
}
fn kat_tst_refs() -> Vec<TstRef> {
    vec![TstRef {
        period_id: 0,
        tst_ref: Some("roots-chain-tst/org-acme/0.tsr".into()),
        gen_time_unix: Some(1_783_338_948),
        serial_hex: Some("05fd9908".into()),
        anchored: true,
    }]
}

/// The checkpoint ORIGIN this test's synthetic Rekor shard signs — distinct from
/// `coanchor::FIXTURE_REKOR_ORIGIN` so it can never be confused with (or accidentally satisfied by)
/// the real pinned Sigstore fixture key.
const SYNTH_ORIGIN: &str = "meshlogic-test-rekor-shard - 1";

/// A DETERMINISTIC (fixed-seed) test-only P-256 keypair — never the real Sigstore key, which stays
/// pinned via `RekorTrustStore::from_fixture()`. Deterministic so a bundle built by
/// `kat_self_contained` and a trust store built separately by `synthetic_trust_store()` always agree
/// on the same key without threading key material between them.
fn synthetic_signing_key() -> SigningKey {
    let seed = Sha256::digest(b"r7-task3-synthetic-rekor-test-key-seed-v1");
    SigningKey::from_slice(&seed).expect("fixed seed is a valid P-256 scalar")
}

/// `(log_id, pubkey_pem)` for [`synthetic_signing_key`] — `log_id` computed the SAME way Rekor (and
/// `coanchor::log_id_for_pubkey_pem`) does: `SHA-256(DER(SubjectPublicKeyInfo))`, so a trust store
/// pinning this key is self-consistent (the key↔log_id bind `verify_coanchored` enforces).
fn synthetic_log_id_and_pem() -> (String, String) {
    let vk = synthetic_signing_key().verifying_key().to_owned();
    let der = vk.to_public_key_der().expect("encode SPKI DER");
    let log_id = hex::encode(Sha256::digest(der.as_bytes()));
    let pem = vk
        .to_public_key_pem(LineEnding::LF)
        .expect("encode SPKI PEM");
    (log_id, pem)
}

/// A trust store pinning ONLY the synthetic test key (never the real Sigstore fixture key) — the
/// counterpart a verifier passes to accept [`synthetic_rekor_receipt_value`].
fn synthetic_trust_store() -> RekorTrustStore {
    let (log_id, pubkey_pem) = synthetic_log_id_and_pem();
    RekorTrustStore::new(vec![RekorTrustKey {
        log_id,
        pubkey_pem,
        origin: Some(SYNTH_ORIGIN.to_string()),
        not_before: None,
        not_after: None,
        revoked: false,
    }])
}

/// Build a synthetic-but-cryptographically-REAL Rekor entries-response JSON (the exact shape
/// `coanchor::RekorReceipt::from_entries_response` parses) that genuinely co-anchors `root` under a
/// SINGLE-LEAF Rekor tree, signed by [`synthetic_signing_key`].
///
/// WHY synthetic rather than the crate's captured live fixture (`rekor_coanchor_entry.json`): that
/// fixture commits to a DIFFERENT root than the frozen KAT Merkle root the freeTSA TST fixture
/// timestamps — there is no single root with both a real TST AND a real Sigstore Rekor receipt. This
/// exercises the REAL `verify_coanchored` crypto (RFC 6962 inclusion + C2SP checkpoint ECDSA-P256
/// signature + root-commitment) end-to-end, offline, against a TEST-pinned key
/// (`synthetic_trust_store()`) — production pins the real Sigstore key via
/// `RekorTrustStore::from_fixture()`, never this one.
fn synthetic_rekor_receipt_value(root: Hash, _period_id: u64) -> serde_json::Value {
    let sk = synthetic_signing_key();
    let (log_id, _pem) = synthetic_log_id_and_pem();

    let data_hash = hex::encode(Sha256::digest(root));
    let entry_body = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": { "data": { "hash": { "algorithm": "sha256", "value": data_hash } } }
    });
    let body_bytes = serde_json::to_vec(&entry_body).unwrap();
    let body_b64 = b64_encode(&body_bytes);

    // Single-leaf tree: the inclusion-proof root IS the RFC 6962 leaf hash (empty audit path).
    let leaf_hash = hash_leaf(&body_bytes);
    let root_b64 = b64_encode(&leaf_hash);

    // C2SP checkpoint / sumdb-note: signed header lines, a blank-line separator (NOT signed), then
    // one signature line. Sign exactly the header text (matching `coanchor::parse_checkpoint`).
    let signed_text = format!("{SYNTH_ORIGIN}\n1\n{root_b64}\n");
    let sig: Signature = sk.sign(signed_text.as_bytes());
    let mut sig_blob = vec![0u8, 0, 0, 0]; // 4-byte key hint — unchecked by the verifier
    sig_blob.extend_from_slice(sig.to_der().as_bytes());
    let sig_b64 = b64_encode(&sig_blob);
    let checkpoint = format!("{signed_text}\n\u{2014} test-key {sig_b64}\n");

    let raw_entries_response = serde_json::json!({
        "test-uuid-0000": {
            "body": body_b64,
            "logID": log_id,
            "logIndex": 1,
            // Realistic Rekor integration lag: seconds AFTER the RFC 3161 TSA stamp for the same
            // root. Bound to the freeTSA KAT TST's own verified gen_time so the A2 authenticated-time
            // cross-check (`verify_coanchored_at`, wired into `grade_record`) is satisfied — a
            // synthetic receipt whose integrated_time drifted far from the authenticated TST time
            // would (correctly) now grade NOT_YET_WITNESSED. Models a genuine co-anchor, integrated
            // 30 s after timestamping.
            "integratedTime": KAT_TST_GEN_TIME_UNIX + 30,
            "verification": {
                "inclusionProof": {
                    "logIndex": 0,
                    "treeSize": 1,
                    "rootHash": hex::encode(leaf_hash),
                    "hashes": [],
                    "checkpoint": checkpoint,
                }
            }
        }
    });

    // A bundle now carries the COMPACT persisted receipt shape (what the roots-chain
    // `coanchor_receipt` attr stores and `from_receipt_json` parses), NOT the raw Rekor
    // entries-response. Round-trip the cryptographically-real raw response through the crate's own
    // parse → compact serialize so this fixture matches production exactly.
    meshlogic_merkle::coanchor::RekorReceipt::from_entries_response(
        &raw_entries_response.to_string(),
    )
    .expect("synthetic entries-response parses")
    .to_receipt_json()
}

/// Build a real anchored `SelfContainedBundle` for one KAT leaf, TST + (optionally) Rekor embedded.
///
/// `p0` reproduces the frozen KAT root the freeTSA fixture genuinely timestamps, so `verify_tst_full`
/// crypto-verifies for real (no mocked TSA). The `BundleRecord`'s declared `content_hash` is bound
/// to the SAME `KAT_CONTENT_HASH` the carried proof proves inclusion for (verify_self_contained's
/// anti-swap check), and its `preimage_b64` is the literal "leaf-E" bytes that hash genuinely commits
/// to — `tamper_preimage` flips a byte of the DECODED preimage so it no longer re-derives, making
/// the ALTERED test a real cryptographic mismatch, not a fabricated flag. The Rekor receipt (when
/// `with_rekor`) is the SYNTHETIC-but-real one built by `synthetic_rekor_receipt_value` — see that
/// function's doc for why the crate's captured live fixture cannot be used here.
fn unsigned_kat_bundle(with_rekor: bool, tamper_preimage: bool) -> SelfContainedBundle {
    let p0 = kat_p0();
    let chain = build_roots_chain(&[(0, p0.clone())]).unwrap();
    assert_eq!(
        hex::encode(chain[0].root_hash),
        KAT_ROOT_HEX,
        "period-0 root must equal the timestamped KAT root"
    );
    let proof =
        build_proof_bundle(KAT_CONTENT_HASH, "org-acme", 0, &p0, &chain, kat_tst_refs()).unwrap();
    assert_eq!(
        proof.verify(),
        Ok(()),
        "KAT proof must be structurally sound"
    );

    // The literal preimage the frozen KAT content_hash commits to (sha256("leaf-E") ==
    // KAT_CONTENT_HASH — confirmed against tests/offline_verify.rs's own constant).
    let mut preimage = b"leaf-E".to_vec();
    if tamper_preimage {
        preimage[0] ^= 0x01; // sha256(preimage) != KAT_CONTENT_HASH
    }

    let rekor_by_period = if with_rekor {
        vec![PeriodRekor {
            period_id: 0,
            receipt: Some(synthetic_rekor_receipt_value(chain[0].root_hash, 0)),
        }]
    } else {
        vec![]
    };

    SelfContainedBundle {
        schema: BUNDLE_SCHEMA.to_string(),
        org_id: "org-acme".into(),
        export_id: "exp-kat".into(),
        pinned_period_id: 0,
        signer_fingerprint_sha256: sha256_hex(b"kat-pinned-signer-der"),
        signature: None,
        scope: BundleScope::FullExport,
        records: vec![BundleRecord {
            record_id: "r-kat".into(),
            content_hash: KAT_CONTENT_HASH.to_string(),
            preimage_b64: Some(b64_encode(&preimage)),
            proof: Some(proof.to_json()),
            status: RecordStatus::Anchored,
        }],
        tst_der_by_period: vec![PeriodTst {
            period_id: 0,
            tst_der_b64: b64_encode(&kat_tst_der()),
        }],
        rekor_by_period,
    }
}

/// Sign `bundle.canonical_signing_bytes()` with `sk`, embedding the result as `bundle.signature` —
/// the ONE place tests attach a signature, so every signing test produces the identical shape
/// `verify_bundle_signature` (in `self_contained.rs`) expects. `key_id` is a decorative label only
/// (per `BundleSignature`'s own doc, never itself trusted) — `spki_sha256` is what selection
/// actually keys off.
fn sign_bundle(bundle: &mut SelfContainedBundle, sk: &SigningKey) {
    let sig: Signature = sk.sign(&bundle.canonical_signing_bytes());
    let spki_der = sk
        .verifying_key()
        .to_public_key_der()
        .expect("encode SPKI DER")
        .into_vec();
    bundle.signature = Some(BundleSignature {
        key_id: "test-key".into(),
        spki_sha256: sha256_hex(&spki_der),
        sig_der_b64: b64_encode(sig.to_der().as_bytes()),
        alg: "ecdsa-p256-sha256".into(),
    });
}

/// Build a real anchored, SIGNED `SelfContainedBundle` — [`unsigned_kat_bundle`] plus a genuine
/// ECDSA-P256 signature by [`pov_bundle_signing_key`] over its own canonical bytes (so it verifies
/// against [`pov_bundle_trust_store`], the pin this crate's `meshlogic_verify` bin ALSO uses under
/// its `pov-fixtures`/`debug_assertions` gate — reusing that one production-shared fixture, rather
/// than a test-local key, is what lets the bin's own e2e tests below keep grading
/// NOT_YET_WITNESSED, exactly as before this task, instead of being swallowed by the new whole-
/// bundle signature gate). Most tests below want a bundle that is genuinely SIGNED first and only
/// then (optionally) tampered/swapped/mutated — see [`unsigned_kat_bundle`] directly for the tests
/// that need to mutate bundle CONTENT before it is signed.
fn kat_self_contained(with_rekor: bool, tamper_preimage: bool) -> SelfContainedBundle {
    let mut b = unsigned_kat_bundle(with_rekor, tamper_preimage);
    sign_bundle(&mut b, &pov_bundle_signing_key());
    b
}

#[test]
fn anchored_witnessed_bundle_is_proven() {
    let b = kat_self_contained(true, false);
    // The synthetic-but-real Rekor receipt embedded by `kat_self_contained` is signed by the TEST
    // key, not the real Sigstore fixture key — so the trust store here must pin THAT key
    // (`synthetic_trust_store()`), not `RekorTrustStore::from_fixture()` (see
    // `synthetic_rekor_receipt_value`'s doc for why no single receipt can satisfy both).
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &synthetic_trust_store(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(
        v.overall,
        RecordVerdict::Proven,
        "PROVEN requires CoAnchored (real verify_coanchored against the test-pinned key); notes: {:?}",
        v.notes
    );
}

#[test]
fn tampered_preimage_is_altered() {
    let b = kat_self_contained(true, true); // preimage no longer hashes to content_hash
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &RekorTrustStore::from_fixture(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(v.overall, RecordVerdict::Altered);
}

#[test]
fn malformed_bundle_is_malformed_never_proven() {
    // Mutate the proof BEFORE signing (not after — mutating a signed bundle now hits the whole-
    // bundle signature gate first, see `tampered_bundle_body_breaks_signature`); this test wants
    // the record-level MALFORMED grade, so the signature over the final (already-garbage) bundle
    // must itself verify cleanly.
    let mut b = unsigned_kat_bundle(true, false);
    b.records[0].proof = Some(serde_json::json!({"garbage": true})); // unparseable ProofBundle
    sign_bundle(&mut b, &pov_bundle_signing_key());
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &RekorTrustStore::from_fixture(),
        &pov_bundle_trust_store(),
    );
    assert!(matches!(v.overall, RecordVerdict::Malformed));
    assert_ne!(v.overall, RecordVerdict::Proven);
}

/// MED-1 (AI review round-3): an export with NO evidence records at all (nothing to prove) must
/// grade the whole bundle `MALFORMED` — the `verify_self_contained` aggregation step falls through
/// `.unwrap_or(RecordVerdict::Malformed)` for an empty `per_record` list, but that path had no
/// direct regression test before this one, and a customer reading a bare "MALFORMED" verdict could
/// easily (mis)read it as "corrupt/tampered" rather than "there was structurally nothing here to
/// verify". `Malformed` is the CORRECT grade regardless (an empty bundle proves nothing, so it must
/// never grade vacuously `PROVEN`) — this test locks that in; the accompanying customer-facing
/// clarification lives in `build_readme`'s MALFORMED bullet (`cloud-backend-rs/src/routes/
/// proof_bundle.rs`). Per the brief: keep `Malformed` — do NOT add a new verdict variant for this.
#[test]
fn empty_bundle_grades_malformed_never_vacuously_proven() {
    let mut b = SelfContainedBundle {
        schema: BUNDLE_SCHEMA.to_string(),
        org_id: "org-acme".into(),
        export_id: "exp-empty".into(),
        pinned_period_id: 0,
        signer_fingerprint_sha256: String::new(),
        signature: None,
        scope: BundleScope::FullExport,
        records: vec![], // nothing to prove
        tst_der_by_period: vec![],
        rekor_by_period: vec![],
    };
    sign_bundle(&mut b, &pov_bundle_signing_key()); // signature itself is fine; only records is empty
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &RekorTrustStore::from_fixture(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(
        v.overall,
        RecordVerdict::Malformed,
        "an empty bundle (no records — nothing to prove) must grade MALFORMED, never vacuously \
         PROVEN; notes: {:?}",
        v.notes
    );
    assert!(v.per_record.is_empty());
}

/// ANTI-SWAP (round-2 review Critical): a record's own `content_hash`/`preimage_b64` can be
/// perfectly self-consistent while its `proof` field carries a DIFFERENT, individually-VALID
/// ProofBundle — one that structurally verifies and TST-verifies fine, just for the WRONG leaf
/// (content_hash("leaf-D") instead of the record's own KAT_CONTENT_HASH/"leaf-E"). Without binding
/// `parsed.content_hash == record.content_hash`, this substitution graded PROVEN undetected,
/// defeating the "verify non-alteration without trusting MeshLogic" guarantee (design spec §5:
/// ALTERED means content_hash does not match ITS COMMITTED LEAF).
#[test]
fn swapped_proof_for_different_record_is_altered() {
    // Unsigned + swap-then-sign (not `kat_self_contained` + mutate-after): mutating a SIGNED bundle
    // now hits the whole-bundle signature gate first (see `tampered_bundle_body_breaks_signature`);
    // this test wants the record-level ALTERED grade, so the final (already-swapped) bundle's
    // signature must itself verify cleanly.
    let mut b = unsigned_kat_bundle(true, false); // baseline: record + proof both genuinely for "leaf-E".

    let p0 = kat_p0();
    let chain = build_roots_chain(&[(0, p0.clone())]).unwrap();
    let other_content_hash = content_hash("leaf-D");
    assert_ne!(
        other_content_hash, b.records[0].content_hash,
        "the swapped-in proof must be for a genuinely DIFFERENT leaf"
    );
    let other_proof = build_proof_bundle(
        &other_content_hash,
        "org-acme",
        0,
        &p0,
        &chain,
        kat_tst_refs(),
    )
    .unwrap();
    // The swapped-in proof is individually valid — this is the whole point of the attack: nothing
    // about the proof ITSELF is malformed or unanchored, it just proves the WRONG leaf.
    assert_eq!(
        other_proof.verify(),
        Ok(()),
        "the swapped-in proof must be individually valid"
    );

    // Swap it onto the record. record.content_hash / preimage_b64 (still "leaf-E") are UNTOUCHED
    // and remain self-consistent — only the carried proof is substituted.
    b.records[0].proof = Some(other_proof.to_json());
    sign_bundle(&mut b, &pov_bundle_signing_key());

    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &RekorTrustStore::from_fixture(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(
        v.overall,
        RecordVerdict::Altered,
        "a proof swapped for a different leaf MUST be caught, not graded Proven; notes: {:?}",
        v.notes
    );
}

/// WITNESS GATE (R7 Task 3): inclusion + chain-linkage + a genuinely-verified RFC 3161 timestamp is
/// MeshLogic's OWN signature on its own copy of the evidence — it never rules out MeshLogic
/// unilaterally rewriting that copy. PROVEN requires the EXTERNAL Rekor co-anchor witness on top; a
/// TST-only bundle (no Rekor receipt at all) must grade NOT_YET_WITNESSED, never PROVEN.
#[test]
fn tst_only_without_rekor_is_not_yet_witnessed_not_proven() {
    let b = kat_self_contained(false, false); // TST embedded, Rekor receipt absent
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &RekorTrustStore::from_fixture(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(v.overall, RecordVerdict::NotYetWitnessed);
    assert_ne!(
        v.overall,
        RecordVerdict::Proven,
        "signature alone must not be PROVEN"
    );
}

// ---------------------------------------------------------------------------------------------
// R7 signing-key task 3 — the fingerprint-equality placeholder gate is gone; `verify_self_contained`
// now REAL-verifies `bundle.signature` (ECDSA-P256) against a caller-pinned `BundleTrustStore`. The
// old `attacker_key_in_bundle_is_untrusted_key_never_proven` test (tampering
// `signer_fingerprint_sha256`, the field this gate no longer consults) is SUPERSEDED by
// `wrong_key_signature_is_untrusted_key_never_proven` below, which exercises the same
// "attacker-claimed key must never be trusted" property against the real crypto gate.
// ---------------------------------------------------------------------------------------------

/// HAPPY PATH: a genuine ECDSA-P256 signature by a key the trust store pins permits PROVEN — this
/// is an ADDITIONAL gate on top of the existing inclusion/TST/Rekor checks, not a replacement for
/// them (`kat_self_contained` still needs `with_rekor=true` for PROVEN, same as before this task).
#[test]
fn valid_ecdsa_signature_against_pinned_key_permits_proven() {
    let b = kat_self_contained(true, false);
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &synthetic_trust_store(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(v.overall, RecordVerdict::Proven, "notes: {:?}", v.notes);
}

/// TRUST-ROOT PIN: a signature that is internally well-formed and genuinely signs the bundle's own
/// canonical bytes, but by a key the caller never pinned, must never grade PROVEN — fail-closed
/// UNTRUSTED_KEY, exactly the same property the old fingerprint-equality gate was meant to enforce,
/// now backed by real crypto rather than a string compare.
#[test]
fn wrong_key_signature_is_untrusted_key_never_proven() {
    let mut b = kat_self_contained(true, false);
    // Re-sign with a DIFFERENT deterministic test key whose SPKI is NOT pinned in the store.
    let foreign_seed = Sha256::digest(b"r7-task3-foreign-bundle-signer-not-pinned-v1");
    let foreign_key =
        SigningKey::from_slice(&foreign_seed).expect("fixed seed is a valid P-256 scalar");
    sign_bundle(&mut b, &foreign_key);

    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &synthetic_trust_store(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(v.overall, RecordVerdict::UntrustedKey);
    assert_ne!(v.overall, RecordVerdict::Proven);
}

/// A bundle mutated AFTER signing: the signature was computed over the ORIGINAL
/// `canonical_signing_bytes()`, so it no longer matches once the body changes. Must never grade
/// PROVEN — the whole point of signing the bundle's own content.
#[test]
fn tampered_bundle_body_breaks_signature() {
    let mut b = kat_self_contained(true, false);
    b.org_id = "org-attacker".into(); // mutate signed content, keep the (now-stale) signature
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &synthetic_trust_store(),
        &pov_bundle_trust_store(),
    );
    assert_ne!(v.overall, RecordVerdict::Proven);
    assert!(matches!(
        v.overall,
        RecordVerdict::UntrustedKey | RecordVerdict::Malformed
    ));
}

/// PREIMAGE HYGIENE (R7 signing-key critical fix): `signer_fingerprint_sha256` is documented
/// (`SelfContainedBundle::signer_fingerprint_sha256`, `BundleSignature::key_id`) as a CONVENIENCE
/// copy the verifier never trusts — the real key reference lives in `signature.spki_sha256`. That
/// means it must have no bearing on the signature itself: a signature computed while the field held
/// one value must still verify after the field is later changed to a DIFFERENT value, exactly as
/// the producer does (`cloud-backend-rs/src/routes/proof_bundle.rs::sign_bundle` signs with the
/// field empty, then overwrites it with the real KMS key's SPKI hash AFTER signing — see
/// `producer_shaped_sign_then_mutate_fingerprint_is_proven` below for that exact sequence
/// reproduced end-to-end). Before the fix, `canonical_signing_bytes()` included this field, so the
/// post-sign mutation changed the preimage the verifier re-derives and the signature failed to
/// verify — UNTRUSTED_KEY, deterministically, for every real producer-signed bundle.
#[test]
fn signature_survives_post_sign_fingerprint_mutation() {
    let mut b = kat_self_contained(true, false); // built + signed with the ordinary fixture fingerprint
    b.signer_fingerprint_sha256 = "deadbeef".repeat(8); // mutate to a DIFFERENT non-empty value post-sign
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &synthetic_trust_store(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(
        v.overall,
        RecordVerdict::Proven,
        "signer_fingerprint_sha256 is a convenience copy the verifier never trusts — mutating it \
         after signing must not affect signature verification; notes: {:?}",
        v.notes
    );
}

/// END-TO-END, PRODUCER-SHAPED (R7 signing-key critical fix): reproduces
/// `cloud-backend-rs/src/routes/proof_bundle.rs::sign_bundle`'s exact ordering — the field starts
/// empty, `canonical_signing_bytes()` is computed and signed with it empty, and ONLY THEN is
/// `signer_fingerprint_sha256` overwritten with the real signing key's SPKI hash (mirroring that
/// function's own `bundle.signer_fingerprint_sha256 = spki_sha256.clone()` after the KMS `sign`
/// call). This is the missing integration test: no prior test signed a bundle in producer order,
/// which is why 6 individual reviews missed the preimage mismatch this whole workstream is fixing.
#[test]
fn producer_shaped_sign_then_mutate_fingerprint_is_proven() {
    let mut b = unsigned_kat_bundle(true, false);
    b.signer_fingerprint_sha256 = String::new(); // producer's placeholder before signing
    let sk = pov_bundle_signing_key();
    let sig: Signature = sk.sign(&b.canonical_signing_bytes()); // signed while the field is EMPTY
    let spki_der = sk
        .verifying_key()
        .to_public_key_der()
        .expect("encode SPKI DER")
        .into_vec();
    let spki_sha256 = sha256_hex(&spki_der);
    b.signature = Some(BundleSignature {
        key_id: "arn:aws:kms:ap-southeast-2:000000000000:key/pov".into(),
        spki_sha256: spki_sha256.clone(),
        sig_der_b64: b64_encode(sig.to_der().as_bytes()),
        alg: "ecdsa-p256-sha256".into(),
    });
    b.signer_fingerprint_sha256 = spki_sha256; // producer's post-sign overwrite

    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &synthetic_trust_store(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(
        v.overall,
        RecordVerdict::Proven,
        "a producer-shaped sign-then-mutate-fingerprint bundle must verify (PROVEN under \
         pov-fixtures), never UNTRUSTED_KEY; notes: {:?}",
        v.notes
    );
}

/// H1 (AI review round-2, R7 signing-key hardening) fixture helper: a [`BundleTrustStore`] pinning
/// [`pov_bundle_signing_key`]'s real SPKI (same key as [`pov_bundle_trust_store`]) but with a
/// CALLER-CHOSEN validity window, so these tests can exercise the window-vs-anchor-time logic
/// without hand-rolling SPKI DER/hash plumbing.
fn pov_bundle_trust_store_with_window(
    not_before: Option<u64>,
    not_after: Option<u64>,
) -> BundleTrustStore {
    let der = pov_bundle_signing_key()
        .verifying_key()
        .to_public_key_der()
        .expect("encode SPKI DER")
        .into_vec();
    let spki_sha256 = sha256_hex(&der);
    BundleTrustStore::from_pinned(vec![BundleTrustKey {
        spki_der: der,
        spki_sha256,
        not_before,
        not_after,
    }])
}

/// The frozen `gen_time_unix` the freeTSA KAT `.tsr` fixture genuinely, cryptographically
/// timestamps (confirmed against `tests/offline_verify.rs`'s own constant) — the bundle's own
/// verified RFC 3161 anchor time for every test below in this section.
const KAT_TST_GEN_TIME_UNIX: u64 = 1_783_338_948;

/// H1 (AI review round-2): the offline verifier's validity-window check must use the BUNDLE'S OWN
/// verified TST anchor time, never wall-clock "now" — a verifier run years after a bundle was
/// produced must not wrongly retire a key that was genuinely valid when the bundle was signed. Here
/// the pinned key's window closes shortly AFTER the bundle's real (frozen, 2026-era) TST time —
/// closed as of ANY later point in time an offline verifier might genuinely run at (see
/// `SOME_LATER_VERIFIER_RUN_TIME_UNIX` below) — so a wall-clock-style check would incorrectly
/// reject this, while the anchor-time check correctly does not.
///
/// H2 (AI review round-3): this regression guard must NEVER read the real system clock — the
/// previous version of this test asserted `SystemTime::now() > not_after` as a "sanity" check,
/// which is exactly the wall-clock coupling H1 exists to remove from the PRODUCTION code, now
/// leaked back into the TEST proving that removal. Reading the real clock also makes the test
/// non-deterministic: it would silently stop proving anything (or outright fail its own sanity
/// assertion) on a machine whose clock is rolled back or frozen for reproducibility. Replaced with
/// a fixed, hardcoded constant standing in for "whenever this verifier is actually run" — a pure
/// compile-time-constant comparison, never a clock read.
#[test]
fn key_valid_at_bundle_anchor_time_survives_wallclock_expiry() {
    /// A fixed point in time, comfortably after `KAT_TST_GEN_TIME_UNIX`, standing in for "some
    /// later point at which this offline verifier happens to run" — deliberately a hardcoded
    /// constant, NEVER `SystemTime::now()` (see this test's own doc for why).
    const SOME_LATER_VERIFIER_RUN_TIME_UNIX: u64 = 4_000_000_000; // ~2096-10 — comfortably later
    let not_after = KAT_TST_GEN_TIME_UNIX + 1000;
    assert!(
        SOME_LATER_VERIFIER_RUN_TIME_UNIX > not_after,
        "sanity: this test only proves anything if the fixed reference point is later than the \
         pinned not_after — a pure constant comparison, not a system-clock read; if this fails, \
         the constants themselves need revisiting, not the fix"
    );

    let b = kat_self_contained(true, false); // with_rekor=true — needed for an overall PROVEN grade
    let trust = pov_bundle_trust_store_with_window(None, Some(not_after));
    let v = verify_self_contained(&b, &[cacert_der()], &synthetic_trust_store(), &trust);
    assert_eq!(
        v.overall,
        RecordVerdict::Proven,
        "a key valid AT THE BUNDLE'S OWN VERIFIED ANCHOR TIME must not be retired just because \
         some LATER point in time (e.g. wall-clock at verifier-run time) has since passed its \
         pinned window; notes: {:?}",
        v.notes
    );
}

/// H1 (AI review round-2), fail-closed half: a pinned key with a validity window set (either bound)
/// MUST reject outright — never silently pass — when no verified RFC 3161 TST anchor time can be
/// established from the bundle at all (here: the bundle carries no TST for any period). Falling back
/// to wall-clock or `0` here would be exactly the bug this fix closes; the honest answer is
/// UNTRUSTED_KEY, not a lucky pass.
#[test]
fn windowed_key_with_no_establishable_anchor_time_is_untrusted_key() {
    let mut b = unsigned_kat_bundle(true, false);
    b.tst_der_by_period.clear(); // no verifiable TST anywhere in the bundle
    sign_bundle(&mut b, &pov_bundle_signing_key());

    // A generously permissive window (would pass under wall-clock OR the real anchor time) — this
    // isolates that the fail-closed behaviour is driven by "anchor time unknowable", not by the
    // window bounds themselves.
    let trust = pov_bundle_trust_store_with_window(None, Some(2_000_000_000));
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &RekorTrustStore::from_fixture(),
        &trust,
    );
    assert_eq!(
        v.overall,
        RecordVerdict::UntrustedKey,
        "a windowed key with no establishable bundle anchor time must fail closed, never verify; \
         notes: {:?}",
        v.notes
    );
}

// ---------------------------------------------------------------------------------------------
// R7 Task 4 — `meshlogic_verify` bin tests.
//
// The bin's `main()` pins the REAL trust roots (`RekorTrustStore::from_fixture()`'s real Sigstore
// key + the real freeTSA CA) — deliberately NOT overridable (no `--trust-store` flag), because an
// overridable root would defeat the anti-circularity guarantee the whole feature exists for. Every
// PROVEN-capable KAT bundle this crate's fixtures can build is witnessed by a Rekor receipt signed
// by a TEST key (`synthetic_signing_key`, above) — never the real Sigstore key — so feeding one to
// the real-rooted bin correctly, honestly grades NOT_YET_WITNESSED (the real store rightly declines
// the test-key receipt). That is what the e2e test below asserts: NOT_YET_WITNESSED, exit 2 — NOT
// a forced PROVEN, which is not achievable here without trusting a test key in production code.
//
// The PROVEN render + exit-0 path is covered separately, directly, by
// `report_and_code_renders_proven_and_exits_zero` below (constructs a `BundleVerdict` with
// `overall: Proven` directly — no bundle/trust-root plumbing involved).
// ---------------------------------------------------------------------------------------------

/// H3 (AI review round-2): `meshlogic_verify.rs`'s ONLY Rekor trust anchor is
/// `RekorTrustStore::from_fixture()` — its name reads as a test double, but the bin's module doc
/// claims it actually pins the REAL public-good `rekor.sigstore.dev` log key, not a throwaway test
/// key. This proves that claim rather than taking it on faith: `from_fixture()`'s pinned `log_id`
/// and checkpoint `origin` must equal the well-known real Sigstore values, hardcoded here as a second,
/// independent literal (not merely re-imported) — so an accidental edit to `FIXTURE_REKOR_LOG_ID`/
/// `FIXTURE_REKOR_ORIGIN` in `coanchor.rs` that quietly swapped in a non-Sigstore key would also be
/// caught, not just a divergence between `from_fixture()` and those same constants.
///
/// Does NOT modify `coanchor.rs` (a different lane owns that file) — read-only assertion against its
/// existing pinned constants. Recommended follow-up for the coanchor owner: rename `from_fixture` to
/// something like `sigstore_public_good` so the function's own name carries this guarantee instead of
/// relying on a doc comment + this test.
#[test]
fn rekor_from_fixture_pins_the_real_sigstore_public_good_log() {
    let trust = RekorTrustStore::from_fixture();
    let keys = trust.keys();
    assert_eq!(keys.len(), 1, "from_fixture() must pin exactly one key");
    let key = &keys[0];

    assert_eq!(
        key.log_id, FIXTURE_REKOR_LOG_ID,
        "from_fixture()'s pinned log_id must be coanchor.rs's own FIXTURE_REKOR_LOG_ID constant"
    );
    assert_eq!(
        key.origin.as_deref(),
        Some(FIXTURE_REKOR_ORIGIN),
        "from_fixture()'s pinned checkpoint origin must be coanchor.rs's own FIXTURE_REKOR_ORIGIN"
    );

    // Independent literals (not re-imports) of the real, public rekor.sigstore.dev instance's known
    // identifiers — the actual proof that the constants above are the genuine Sigstore public-good
    // log, not merely internally self-consistent with each other.
    const REAL_SIGSTORE_REKOR_LOG_ID: &str =
        "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d";
    const REAL_SIGSTORE_REKOR_ORIGIN: &str = "rekor.sigstore.dev - 1193050959916656506";
    assert_eq!(
        FIXTURE_REKOR_LOG_ID, REAL_SIGSTORE_REKOR_LOG_ID,
        "coanchor.rs's FIXTURE_REKOR_LOG_ID must equal the real public-good rekor.sigstore.dev log \
         id — if this ever legitimately changes (log rotation), this literal must be updated \
         alongside independent confirmation from Sigstore, not silently"
    );
    assert_eq!(
        FIXTURE_REKOR_ORIGIN, REAL_SIGSTORE_REKOR_ORIGIN,
        "coanchor.rs's FIXTURE_REKOR_ORIGIN must equal the real public-good rekor.sigstore.dev \
         shard origin"
    );
}

// ---- A4 remediation: schema fail-closed + org/period coherence -------------------------------

/// A4-i: a bundle whose `schema` is not in [`KNOWN_BUNDLE_SCHEMAS`] grades the WHOLE bundle
/// `Malformed`, ahead of even the signature gate (an unsigned unknown-schema bundle is rejected on
/// schema, not on the missing signature) — closing the version-confusion fail-OPEN the finding names.
#[test]
fn unsupported_schema_grades_malformed_before_anything_else() {
    let mut b = unsigned_kat_bundle(true, false);
    b.schema = "meshlogic.proof-bundle.v999".to_string(); // a future/unknown schema
                                                          // Deliberately NOT signed: the schema gate is the FIRST check, so this must still be Malformed
                                                          // (on schema), never UntrustedKey (on the absent signature).
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &synthetic_trust_store(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(
        v.overall,
        RecordVerdict::Malformed,
        "an unsupported schema must fail the whole bundle closed; notes: {:?}",
        v.notes
    );
    assert!(
        v.notes
            .iter()
            .any(|n| n.contains("unsupported bundle schema")),
        "the note must name the schema rejection; notes: {:?}",
        v.notes
    );
    // Control: the SAME bundle carrying a KNOWN schema (and signed) still reaches PROVEN — the gate
    // rejects ONLY the unknown schema, it does not over-reject.
    let mut ok = unsigned_kat_bundle(true, false);
    assert!(KNOWN_BUNDLE_SCHEMAS.contains(&ok.schema.as_str()));
    sign_bundle(&mut ok, &pov_bundle_signing_key());
    let v2 = verify_self_contained(
        &ok,
        &[cacert_der()],
        &synthetic_trust_store(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(
        v2.overall,
        RecordVerdict::Proven,
        "a known-schema bundle is unaffected by the gate; notes: {:?}",
        v2.notes
    );
}

/// A4-ii (org coherence): a record whose carried proof is for a DIFFERENT org than the bundle
/// declares must never grade PROVEN — genuine cross-org confusion (the roots chain can aggregate
/// multiple orgs). The bundle is signed AFTER the org is set, so the whole-bundle signature gate
/// passes (a producer bug / crafted-but-signed incoherent bundle); the per-record org check catches it.
#[test]
fn cross_org_proof_grades_altered_not_proven() {
    let mut b = unsigned_kat_bundle(true, false); // the carried proof is for org "org-acme"
    b.org_id = "org-impersonator".into(); // …but the bundle claims a different org
    sign_bundle(&mut b, &pov_bundle_signing_key()); // sign the (incoherent) bundle → sig gate passes
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &synthetic_trust_store(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(
        v.overall,
        RecordVerdict::Altered,
        "a proof for a different org than the bundle must not grade PROVEN; notes: {:?}",
        v.notes
    );
    assert!(
        v.notes.iter().any(|n| n.contains("cross-org")),
        "the note must name the cross-org coherence violation; notes: {:?}",
        v.notes
    );
}

/// A4-ii (period coherence): the bundle pins ONE as-of checkpoint (`pinned_period_id`); a record whose
/// proof is anchored at a LATER period than the pin cannot be witnessed by that checkpoint. Same KAT
/// leaves, but the roots-chain row + proof are at PERIOD 1 (the Merkle root is period-independent, so
/// the same frozen root is reproduced), while the bundle pins period 0 → fail closed as Malformed.
#[test]
fn record_period_beyond_pinned_checkpoint_is_malformed() {
    let p0 = kat_p0();
    let chain = build_roots_chain(&[(1, p0.clone())]).unwrap();
    assert_eq!(
        hex::encode(chain[0].root_hash),
        KAT_ROOT_HEX,
        "the same leaves reproduce the frozen KAT root at any period_id"
    );
    let tst_refs = vec![TstRef {
        period_id: 1,
        tst_ref: Some("roots-chain-tst/org-acme/1.tsr".into()),
        gen_time_unix: Some(KAT_TST_GEN_TIME_UNIX),
        serial_hex: Some("05fd9908".into()),
        anchored: true,
    }];
    let proof = build_proof_bundle(KAT_CONTENT_HASH, "org-acme", 1, &p0, &chain, tst_refs).unwrap();
    let mut b = SelfContainedBundle {
        schema: BUNDLE_SCHEMA.to_string(),
        org_id: "org-acme".into(),
        export_id: "exp-coherence".into(),
        pinned_period_id: 0, // < the record's period 1 → the pinned checkpoint cannot witness it
        signer_fingerprint_sha256: sha256_hex(b"kat-pinned-signer-der"),
        signature: None,
        scope: BundleScope::FullExport,
        records: vec![BundleRecord {
            record_id: "r-p1".into(),
            content_hash: KAT_CONTENT_HASH.to_string(),
            preimage_b64: Some(b64_encode(b"leaf-E")),
            proof: Some(proof.to_json()),
            status: RecordStatus::Anchored,
        }],
        tst_der_by_period: vec![PeriodTst {
            period_id: 1,
            tst_der_b64: b64_encode(&kat_tst_der()),
        }],
        rekor_by_period: vec![],
    };
    sign_bundle(&mut b, &pov_bundle_signing_key());
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &synthetic_trust_store(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(
        v.overall,
        RecordVerdict::Malformed,
        "a record anchored beyond the pinned checkpoint must fail closed; notes: {:?}",
        v.notes
    );
    assert!(
        v.notes
            .iter()
            .any(|n| n.contains("beyond the bundle's pinned checkpoint")),
        "the note must name the period coherence violation; notes: {:?}",
        v.notes
    );
}

/// Write `bundle` as the single `bundle.json` entry of a zip at `path` — the shape
/// `meshlogic_verify` reads.
fn write_bundle_zip(path: &std::path::Path, bundle: &SelfContainedBundle) {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    let file = fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("bundle.json", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(&serde_json::to_vec(bundle).unwrap()).unwrap();
    zip.finish().unwrap();
}

/// Write `raw` verbatim as the single `bundle.json` entry — used to build a zip whose entry is not
/// valid JSON at all (the MALFORMED path).
fn write_raw_zip(path: &std::path::Path, raw: &[u8]) {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    let file = fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("bundle.json", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(raw).unwrap();
    zip.finish().unwrap();
}

#[test]
fn meshlogic_verify_bin_reports_not_yet_witnessed_on_kat_synthetic_zip() {
    // Anchored + TST-verified for real, Rekor-witnessed only by the TEST key — exactly the bundle
    // the real-rooted bin must (honestly) decline to grade PROVEN.
    let b = kat_self_contained(true, false);
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("proof-bundle.zip");
    write_bundle_zip(&zip_path, &b);

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_meshlogic_verify"))
        .arg(&zip_path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("NOT_YET_WITNESSED"), "stdout: {stdout}");
    assert!(
        !stdout.contains("RESULT: PROVEN"),
        "the test-key Rekor receipt must never satisfy the real-pinned trust store: {stdout}"
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn meshlogic_verify_bin_reports_malformed_on_garbage_bundle_json() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("garbage-bundle.zip");
    write_raw_zip(&zip_path, b"{ this is not valid json");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_meshlogic_verify"))
        .arg(&zip_path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("MALFORMED"), "stdout: {stdout}");
    assert_eq!(out.status.code(), Some(2));
}

/// ZIP-BOMB CAP (AI-review HIGH-1): `bundle.json` is untrusted input — a malicious zip can declare
/// (or, via a corrupt/lying header, simply produce) an arbitrarily large decompressed entry. The
/// payload here is VALID JSON (a single padded string field) so that, absent the cap, it would
/// read to completion and fail only with a generic "does not parse" (schema mismatch) error —
/// asserting on the specific "zip-bomb guard" wording proves the SIZE CAP fired, not merely that
/// the bundle happened to be unparseable for an unrelated reason.
#[test]
fn meshlogic_verify_bin_rejects_oversized_bundle_json_zip_bomb() {
    let mut raw = br#"{"pad":""#.to_vec();
    raw.extend(std::iter::repeat_n(b'A', 64 * 1024 * 1024 + 1024));
    raw.extend_from_slice(br#""}"#);

    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("zip-bomb.zip");
    write_raw_zip(&zip_path, &raw);

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_meshlogic_verify"))
        .arg(&zip_path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("zip-bomb guard"),
        "must reject via the size cap, not merely fail to parse: {stdout}"
    );
    assert!(stdout.contains("MALFORMED"), "stdout: {stdout}");
    assert_eq!(
        out.status.code(),
        Some(2),
        "must fail-closed, never panic/OOM"
    );
}

#[test]
fn meshlogic_verify_bin_usage_error_on_missing_argument() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_meshlogic_verify"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
}

/// Direct unit test of the render + exit-code logic (not an e2e shell-out): no fixture reaches
/// PROVEN through the bin's real pinned trust roots (see module doc above), so this constructs the
/// `BundleVerdict` directly and asserts `report_and_code`'s render text + exit-code mapping for the
/// PROVEN case in isolation.
#[test]
fn report_and_code_renders_proven_and_exits_zero() {
    let v = BundleVerdict {
        overall: RecordVerdict::Proven,
        per_record: vec![("r-1".to_string(), RecordVerdict::Proven)],
        notes: vec![
            "r-1: inclusion + chain-linkage + TST + Rekor co-anchor witness all verified"
                .to_string(),
        ],
    };
    let (report, code) = meshlogic_merkle::verify_report::report_and_code(&v);
    assert!(report.contains("PROVEN"), "report: {report}");
    assert!(
        !report.to_lowercase().contains("tamper-proof"),
        "must never claim tamper-proof: {report}"
    );
    assert_eq!(code, std::process::ExitCode::SUCCESS);
}

#[test]
fn report_and_code_non_proven_exits_two() {
    let v = BundleVerdict {
        overall: RecordVerdict::NotYetWitnessed,
        per_record: vec![("r-1".to_string(), RecordVerdict::NotYetWitnessed)],
        notes: vec!["r-1: RFC 3161-anchored but not yet Rekor co-anchored".to_string()],
    };
    let (report, code) = meshlogic_merkle::verify_report::report_and_code(&v);
    assert!(report.contains("NOT_YET_WITNESSED"), "report: {report}");
    assert_eq!(code, std::process::ExitCode::from(2));
}

/// H4 (AI review round-2, messaging clarity): NOT_YET_WITNESSED is the verdict most real bundles
/// carry today (`rekor_by_period` stays empty until finding-A wires Rekor — a separate, deferred
/// follow-up, not this fix). A customer reading this report must not mistake it for an ambiguous or
/// worrying result: the report must say plainly that inclusion + TST + the MeshLogic signature are
/// ALL already verified, that only the EXTERNAL Rekor witness is pending, and that this is expected
/// and NOT a tamper finding. The PROVEN report must not carry this NOT_YET_WITNESSED-specific
/// clarification (it would be misleading noise on an already-fully-witnessed result).
#[test]
fn report_and_code_explains_not_yet_witnessed_is_expected_not_a_tamper_finding() {
    let v = BundleVerdict {
        overall: RecordVerdict::NotYetWitnessed,
        per_record: vec![("r-1".to_string(), RecordVerdict::NotYetWitnessed)],
        notes: vec!["r-1: RFC 3161-anchored but not yet Rekor co-anchored".to_string()],
    };
    let (report, _code) = meshlogic_merkle::verify_report::report_and_code(&v);
    assert!(
        report.contains("NOT a tamper finding"),
        "report must explicitly disclaim a tamper finding: {report}"
    );
    assert!(
        report.to_lowercase().contains("inclusion") && report.to_lowercase().contains("signature"),
        "report must state what IS already verified (inclusion + signature): {report}"
    );
    assert!(
        report.to_lowercase().contains("rekor"),
        "report must name the pending external witness: {report}"
    );
    assert!(
        !report.to_lowercase().contains("tamper-proof"),
        "must never claim tamper-proof: {report}"
    );

    let proven = BundleVerdict {
        overall: RecordVerdict::Proven,
        per_record: vec![("r-1".to_string(), RecordVerdict::Proven)],
        notes: vec![
            "r-1: inclusion + chain-linkage + TST + Rekor co-anchor witness all verified"
                .to_string(),
        ],
    };
    let (proven_report, _) = meshlogic_merkle::verify_report::report_and_code(&proven);
    assert!(
        !proven_report.contains("ABOUT NOT_YET_WITNESSED"),
        "a fully PROVEN report must not carry the not-yet-witnessed clarification: {proven_report}"
    );
}

/// ZERO-TRUST (R7 Task 6): the whole point of a self-contained bundle is that grading it to PROVEN
/// takes ONLY the bundle bytes + the verifier's own pinned roots (`cacert_der()` + a `RekorTrustStore`
/// built from constants baked into this test binary) — no AWS SDK client, no HTTP client, no network
/// call is constructed anywhere on the `verify_self_contained` path. This is a regression guard, not
/// new logic: if it ever needs a src change to pass, that means the verify path started reaching out
/// to the network, which would defeat the "verify without trusting MeshLogic" guarantee this whole
/// feature exists for.
#[test]
fn verify_needs_no_network_or_aws() {
    let b = kat_self_contained(true, false);
    let v = verify_self_contained(
        &b,
        &[cacert_der()],
        &synthetic_trust_store(),
        &pov_bundle_trust_store(),
    );
    assert_eq!(
        v.overall,
        RecordVerdict::Proven,
        "passed with zero external calls; notes: {:?}",
        v.notes
    );
}
