//! R7 Task 4 — the `meshlogic_verify` bin's render + exit-code logic, pulled into the library so it
//! is unit-testable WITHOUT a bundle that actually achieves PROVEN through the real pinned trust
//! roots (no fixture does — see `tests/self_contained_verify.rs`'s KAT bundles, all signed by a
//! TEST key). `main()` stays a thin wrapper: read the zip, call `verify_self_contained`, call
//! [`report_and_code`], print, exit.

use crate::self_contained::{BundleVerdict, RecordVerdict};

/// Render the full human report — per-record verdicts, notes, the overall RESULT line, the honest
/// boundary statement, and a machine `JSON:` line — and map the verdict to this binary's exit code
/// (0 = every record PROVEN, 2 = anything else). Split out from `main` so both the render text and
/// the exit-code mapping are directly unit-testable.
pub fn report_and_code(v: &BundleVerdict) -> (String, std::process::ExitCode) {
    let mut out = String::new();
    out.push_str("MeshLogic offline proof-bundle verification\n");
    for (record_id, verdict) in &v.per_record {
        out.push_str(&format!("  {record_id}: {}\n", verdict_label(*verdict)));
    }
    out.push_str("\nnotes:\n");
    for note in &v.notes {
        out.push_str(&format!("  - {note}\n"));
    }
    out.push_str(&format!("\nRESULT: {}\n", verdict_label(v.overall)));
    // H4 (AI review round-2, messaging clarity): real bundles today grade NOT_YET_WITNESSED (Rekor
    // wiring is a separate, deferred follow-up — see finding-A) — that must never read as an
    // ambiguous or worrying result. Spell out exactly what already verified (inclusion + TST +
    // signature, all independently, offline, right now) versus what is merely pending (the
    // EXTERNAL Rekor transparency-log witness), so a customer reading this report cannot mistake
    // "not yet witnessed" for "not yet trustworthy".
    if v.overall == RecordVerdict::NotYetWitnessed {
        out.push_str(
            "\nABOUT NOT_YET_WITNESSED: every record above is PROVEN-INCLUDED, RFC 3161 \
             timestamped, and signed by a genuine MeshLogic KMS key — all independently verified \
             OFFLINE, right now, by this run. What is not yet present is the EXTERNAL public-\
             transparency-log (Sigstore/Rekor) witness — a further, independent confirmation that \
             MeshLogic itself cannot unilaterally rewrite this evidence. This is EXPECTED during \
             the current phase and is NOT a tamper finding: the evidence's integrity and \
             MeshLogic's signature are fully verified today; only the additional external witness \
             is pending.\n",
        );
    }
    // The honest boundary (design spec §5): PROVEN is a strong but bounded claim, stated regardless
    // of the actual verdict above (an auditor reading a NOT_YET_WITNESSED report should still see
    // exactly what a PROVEN verdict would and would not have established). Never say
    // "tamper-proof" — that overclaims what inclusion + TST + Rekor witness actually establish.
    out.push_str(
        "\nEvery verdict above proves inclusion + non-alteration since the anchor + a genuine \
         MeshLogic signature; PROVEN additionally requires an independent Rekor witness. No \
         verdict proves completeness (that no evidence was withheld from this bundle) or \
         correctness (that the underlying evidence is accurate).\n",
    );
    out.push_str(&format!(
        "JSON: {}\n",
        serde_json::to_string(&v.per_record).unwrap_or_else(|_| "[]".into())
    ));
    let code = if v.overall == RecordVerdict::Proven {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(2)
    };
    (out, code)
}

/// The upper-snake-case label printed for each [`RecordVerdict`] — matches the design spec's
/// verdict names verbatim (PROVEN / ALTERED / NOT_YET_WITNESSED / NOT_YET_ANCHORED /
/// UNTRUSTED_KEY / MALFORMED).
pub fn verdict_label(v: RecordVerdict) -> &'static str {
    match v {
        RecordVerdict::Proven => "PROVEN",
        RecordVerdict::Altered => "ALTERED",
        RecordVerdict::NotYetWitnessed => "NOT_YET_WITNESSED",
        RecordVerdict::NotYetAnchored => "NOT_YET_ANCHORED",
        RecordVerdict::UntrustedKey => "UNTRUSTED_KEY",
        RecordVerdict::Malformed => "MALFORMED",
    }
}

// Unit-tested from `tests/self_contained_verify.rs` (not here as `#[cfg(test)] mod tests`): this
// crate's mandated test invocation is `cargo test -p meshlogic-merkle --features offline-verify
// --test self_contained_verify` (narrowed to that one integration-test binary — bare `cargo test`
// is banned on this Windows toolchain, see that file's module doc), which does not run `--lib`
// unit tests. Keeping the direct render/exit-code test there too means one command runs
// everything R7 Task 4 needs.
