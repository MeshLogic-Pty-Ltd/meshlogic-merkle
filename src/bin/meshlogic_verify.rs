//! `meshlogic_verify` — the customer-facing zero-trust OFFLINE proof-bundle verifier (R7 Task 4,
//! design spec Unit 2). Reads a proof-bundle zip, parses its `bundle.json` entry as a
//! `self_contained::SelfContainedBundle`, grades it via `verify_self_contained`, and prints a
//! graded human report.
//!
//! ZERO-TRUST BY CONSTRUCTION: the trust roots below are PINNED CONSTANTS. There is deliberately
//! no `--trust-store` flag or environment-variable override of any kind — an overridable root
//! would let the bundle (or its packaging) choose what the verifier trusts, defeating the whole
//! anti-circularity guarantee this feature exists to provide (a customer must be able to verify
//! WITHOUT trusting MeshLogic). This binary constructs NO AWS client and NO network client.
//!
//! Exit codes: 0 = every record grades PROVEN, 2 = any record grades worse (or the bundle is
//! unreadable/malformed), 64 = usage error (missing argument).
//!
//! TRUST ROOTS: the RFC 3161 TSA root (the real freeTSA CA, [`TSA_ROOT`]) and the Rekor
//! transparency-log key (`RekorTrustStore::from_fixture()` — despite the name, this pins the real
//! public-good `rekor.sigstore.dev` key, not a test fixture) are real and used unconditionally in
//! every build. The one root that WAS a placeholder — the bundle-signer key
//! [`BundleSignature`](meshlogic_merkle::self_contained::BundleSignature) is checked against — is
//! now a real ECDSA-P256 pin too (R7 signing-key task 6): production release builds pin the KMS
//! bundle-signing key's public SPKI via `MESHLOGIC_BUNDLE_SPKI_DER_B64`, injected at release-build
//! time (see the release step documented in `docs/superpowers/specs/
//! 2026-07-25-r7-proof-bundle-offline-verifier-design.md`). POV/dev builds instead pin the crate's
//! shared test signing key ([`pov_bundle_trust_store`](meshlogic_merkle::self_contained::pov_bundle_trust_store))
//! so the bin's own e2e tests keep exercising a bundle whose signature genuinely verifies (the real
//! Sigstore Rekor store still declines the KAT bundle's test-key receipt, so those tests correctly
//! grade `NOT_YET_WITNESSED`, never a forced `PROVEN`).
//!
//! POV (proof-of-value) FIXTURE GATE (AI-review HIGH-2): gated behind `debug_assertions` (dev/test
//! builds — `cargo build`/`cargo test` need no extra flag) OR the `pov-fixtures` feature (an
//! explicit, loud opt-in for the POV demo). Building the demo binary: `cargo build --release -p
//! meshlogic-merkle --features offline-verify,pov-fixtures --bin meshlogic_verify`. A bare
//! `--release` build without `pov-fixtures` AND without `MESHLOGIC_BUNDLE_SPKI_DER_B64` fails to
//! compile (see [`PROD_BUNDLE_SPKI_DER_B64`]) rather than silently shipping the POV fixture key as
//! if it were a real trust anchor.

use meshlogic_merkle::coanchor::RekorTrustStore;
use meshlogic_merkle::self_contained::{BundleTrustStore, SelfContainedBundle};
use meshlogic_merkle::verify_report::report_and_code;
use std::io::Read;
use std::process::ExitCode;

#[cfg(all(not(debug_assertions), not(feature = "pov-fixtures")))]
use base64::Engine as _;
#[cfg(all(not(debug_assertions), not(feature = "pov-fixtures")))]
use meshlogic_merkle::commitment_leaf::sha256_hex;
#[cfg(all(not(debug_assertions), not(feature = "pov-fixtures")))]
use meshlogic_merkle::self_contained::BundleTrustKey;

/// The real, pinned RFC 3161 TSA root — freeTSA's genuine CA cert (`tests/fixtures/
/// freetsa_cacert.der`), used unconditionally (not a POV-only fixture; freeTSA is a real,
/// independently-operated timestamp authority).
const TSA_ROOT: &[u8] = include_bytes!("../../tests/fixtures/freetsa_cacert.der");

/// Base64 engine matching the producer's `STANDARD.encode` of the KMS key's SPKI DER (same STANDARD
/// engine `commitment_leaf`/`self_contained` use internally). Only needed by the production
/// [`bundle_trust_store`] path — a POV/dev build never decodes a base64 SPKI here.
#[cfg(all(not(debug_assertions), not(feature = "pov-fixtures")))]
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// PRODUCTION release gate (R7 signing-key task 6): the KMS bundle-signing key's public SPKI DER,
/// base64-encoded, injected at release-build time via `MESHLOGIC_BUNDLE_SPKI_DER_B64` — fetched
/// with `aws kms get-public-key --key-id alias/meshlogic-proof-bundle-signer` AFTER the key exists
/// (it does not exist yet at the time this task is written; the KMS key's Terraform applies on
/// merge — see the release step in `docs/superpowers/specs/
/// 2026-07-25-r7-proof-bundle-offline-verifier-design.md`). `env!`'s custom-message form is this
/// binary's compile-time release gate: a naked `cargo build --release` (no `debug_assertions`, no
/// `pov-fixtures`, no env var) fails to compile with the message below instead of silently shipping
/// without a real pinned trust anchor — the compile-time analogue of the crate's other fail-closed
/// gates.
#[cfg(all(not(debug_assertions), not(feature = "pov-fixtures")))]
const PROD_BUNDLE_SPKI_DER_B64: &str = env!(
    "MESHLOGIC_BUNDLE_SPKI_DER_B64",
    "meshlogic_verify: production release build requires MESHLOGIC_BUNDLE_SPKI_DER_B64 — base64 \
     of the KMS bundle-signing key's public SPKI DER, fetched via `aws kms get-public-key --key-id \
     alias/meshlogic-proof-bundle-signer` once that key exists (see the release step in \
     docs/superpowers/specs/2026-07-25-r7-proof-bundle-offline-verifier-design.md). Enable the \
     `pov-fixtures` feature only for the POV demo; a naked `cargo build --release` must never \
     silently ship the POV test-signing-key fixture as if it were a real trust anchor."
);

/// Build the offline verifier's pinned bundle-signer trust store for this build configuration —
/// see the module doc and [`PROD_BUNDLE_SPKI_DER_B64`].
#[cfg(all(not(debug_assertions), not(feature = "pov-fixtures")))]
fn bundle_trust_store() -> BundleTrustStore {
    let spki_der = B64.decode(PROD_BUNDLE_SPKI_DER_B64).unwrap_or_else(|e| {
        panic!(
            "MESHLOGIC_BUNDLE_SPKI_DER_B64 is not valid base64 (checked at release-build time): {e}"
        )
    });
    let spki_sha256 = sha256_hex(&spki_der);
    BundleTrustStore::from_pinned(vec![BundleTrustKey {
        spki_der,
        spki_sha256,
        not_before: None,
        not_after: None,
    }])
}

/// POV/dev build of the bundle-signer trust store — the crate's shared test signing key (see the
/// module doc).
#[cfg(any(debug_assertions, feature = "pov-fixtures"))]
fn bundle_trust_store() -> BundleTrustStore {
    meshlogic_merkle::self_contained::pov_bundle_trust_store()
}

/// Zip-bomb guard (AI-review HIGH-1): the largest `bundle.json` this verifier will decompress.
/// `bundle.json` is untrusted input — a malicious zip could declare (or, via a corrupt/lying
/// header, simply produce) an arbitrarily large decompressed entry to OOM the verifier before it
/// ever gets to parse anything. 64 MiB comfortably covers any real proof bundle (the per-record
/// proofs + TST DER + Rekor receipts are all small) with headroom to spare.
const MAX_BUNDLE_JSON_BYTES: u64 = 64 * 1024 * 1024;

/// Print the base64 SPKI DER this binary is pinned to, then nothing else — so an auditor can
/// confirm in ONE command that the verifier they downloaded is pinned to MeshLogic's real
/// signing key (compare the output to `aws kms get-public-key --key-id
/// alias/meshlogic-proof-bundle-signer --query PublicKey --output text`, or MeshLogic's
/// published key), and the release workflow can assert the built binary embedded the key it
/// fetched. Release build: the pinned prod SPKI. POV/dev build: a loud non-key marker, since
/// that binary is pinned to the shared TEST key and its verdicts are NOT a trust anchor.
#[cfg(all(not(debug_assertions), not(feature = "pov-fixtures")))]
fn print_pinned_spki() {
    println!("{PROD_BUNDLE_SPKI_DER_B64}");
}
#[cfg(any(debug_assertions, feature = "pov-fixtures"))]
fn print_pinned_spki() {
    // Deliberately NOT the real base64 SPKI: a POV/dev binary must never be mistaken for a
    // trust anchor, and its --print-pinned-spki must never match a real key comparison.
    println!("POV-DEV-TEST-KEY-NOT-A-TRUST-ANCHOR");
    eprintln!(
        "meshlogic_verify: POV/dev build — pinned to the shared TEST signing key, not a real \
         trust anchor; its verdicts are not independently trustworthy."
    );
}

fn main() -> ExitCode {
    let arg1 = std::env::args().nth(1);
    // Self-report the pinned key (auditor key-confirmation + the release workflow's pin check).
    if arg1.as_deref() == Some("--print-pinned-spki") {
        print_pinned_spki();
        return ExitCode::SUCCESS;
    }
    let path = match arg1 {
        Some(p) if !p.starts_with('-') => p,
        _ => {
            eprintln!("usage: meshlogic_verify <bundle.zip> | --print-pinned-spki");
            return ExitCode::from(64);
        }
    };

    let bundle = match load_bundle(&path) {
        Ok(b) => b,
        Err(reason) => {
            println!("RESULT: MALFORMED");
            println!("{reason}");
            return ExitCode::from(2);
        }
    };

    // R7 signing-key task 3+6: `verify_self_contained` real-verifies `bundle.signature`
    // (ECDSA-P256) against a pinned `BundleTrustStore` — `bundle_trust_store()` resolves to the
    // real KMS-key SPKI pin in a production release build, or the crate's shared test signing key
    // in a POV/dev build (see the module doc + that function's two `#[cfg]`-gated definitions
    // above). The TSA root and Rekor log key are real and unconditional in every build.
    let verdict = meshlogic_merkle::self_contained::verify_self_contained(
        &bundle,
        &[TSA_ROOT.to_vec()],
        &RekorTrustStore::from_fixture(),
        &bundle_trust_store(),
    );
    // Surface the SIGNED scope attestation: a committed-only bundle deliberately excludes
    // un-anchored evidence (so its overall verdict can be a clean PROVEN); a full export includes
    // everything. `scope` is part of canonical_signing_bytes, so tampering with it fails the
    // signature — this line is trustworthy exactly when the verdict confirms the signature verified.
    println!("SCOPE: {}", bundle.scope.describe());
    let (report, code) = report_and_code(&verdict);
    print!("{report}");
    code
}

/// Open the zip at `path`, read its `bundle.json` entry, and parse it as a `SelfContainedBundle`.
/// Every failure mode (unreadable file, corrupt zip, missing entry, non-UTF8, bad JSON) is
/// returned as `Err`, never a panic — a proof-bundle zip is untrusted input and malformed input
/// must fail closed, not crash the verifier.
fn load_bundle(path: &str) -> Result<SelfContainedBundle, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("cannot open '{path}': {e}"))?;
    let mut zip =
        zip::ZipArchive::new(f).map_err(|e| format!("'{path}' is not a valid zip: {e}"))?;
    let mut entry = zip
        .by_name("bundle.json")
        .map_err(|e| format!("zip has no 'bundle.json' entry: {e}"))?;

    // Zip-bomb guard, signal 1: reject on the DECLARED (zip-header) uncompressed size before
    // reading a single byte. Cheap, and catches the honest case outright.
    if entry.size() > MAX_BUNDLE_JSON_BYTES {
        return Err(format!(
            "'bundle.json' declares {} uncompressed bytes, exceeding the {MAX_BUNDLE_JSON_BYTES}-byte \
             cap — refusing (zip-bomb guard)",
            entry.size()
        ));
    }
    // Zip-bomb guard, signal 2: a corrupt or deliberately-lying header cannot be trusted on its
    // own, so the actual read is ALSO hard-capped — `take(MAX + 1)` bounds worst-case memory to
    // one byte over the cap regardless of what the header claims, and reading exactly `MAX + 1`
    // bytes back (rather than erroring inside `take`, which never happens) is how the true size
    // is distinguished from a legitimately cap-sized entry.
    let mut s = String::new();
    let read = entry
        .by_ref()
        .take(MAX_BUNDLE_JSON_BYTES + 1)
        .read_to_string(&mut s)
        .map_err(|e| format!("'bundle.json' is not valid UTF-8: {e}"))?;
    if read as u64 > MAX_BUNDLE_JSON_BYTES {
        return Err(format!(
            "'bundle.json' decompresses to more than the {MAX_BUNDLE_JSON_BYTES}-byte cap — \
             refusing (zip-bomb guard; declared size did not match actual)"
        ));
    }
    serde_json::from_str(&s).map_err(|e| format!("'bundle.json' does not parse: {e}"))
}
