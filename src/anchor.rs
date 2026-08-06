//! RFC 3161 timestamp anchoring over a MAC-1 Merkle root (ADR-043 P1a Task 2).
//!
//! Pure-Rust RustCrypto stack (mac-lead P1a Q3): `x509-tsp` (RFC 3161 TSP ASN.1) + `der` + `spki`
//! + `const-oid` + `cms`. NO OpenSSL FFI. The Merkle `root` (an RFC 6962 tree hash = a SHA-256
//! digest) is used directly as the `hashedMessage` of a SHA-256 `MessageImprint`; the TSA
//! countersigns that digest together with a trusted time T.
//!
//! HONEST BOUNDARY (ADR-043 §6): [`extract_tst_facts_matching_root`] confirms a returned token's
//! imprint IS our root and reads its asserted time — it does NOT verify the TSA's CMS signature /
//! certificate chain. That full cryptographic verification is the P4 offline verifier. The
//! function is named to make that boundary syntactically obvious (it is `extract…`, not `verify…`).
//! Production TSA selection is a P2 sign-off item (ADR-043 §7).

use crate::Hash;
use cms::signed_data::SignedData;
use const_oid::db::rfc5912::ID_SHA_256;
use der::asn1::{Int, OctetString};
use der::{Any, Decode, Encode};
use spki::AlgorithmIdentifier;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorError(pub String);
impl std::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rfc3161 anchor error: {}", self.0)
    }
}
impl std::error::Error for AnchorError {}

/// Build a DER-encoded RFC 3161 `TimeStampReq` with NO nonce — a deterministic builder for unit
/// tests. Live callers should use [`build_timestamp_request_with_nonce`] with a random nonce.
pub fn build_timestamp_request(root: Hash) -> Result<Vec<u8>, AnchorError> {
    build_timestamp_request_with_nonce(root, None)
}

/// Build a DER-encoded RFC 3161 `TimeStampReq` that timestamps the Merkle `root`, optionally
/// carrying a `nonce`.
///
/// The root IS a SHA-256 digest (RFC 6962 tree hash), so it is the `hashedMessage` of a SHA-256
/// imprint directly — no re-hash. `cert_req = true` asks the TSA to embed its signing certificate
/// so the returned token can be verified OFFLINE by an auditor (the P1a goal). A `nonce` binds the
/// request to its response: with a fresh random nonce, an on-path attacker cannot replay an older
/// TSA response for the same root (RFC 3161 §2.4.1 anti-replay).
pub fn build_timestamp_request_with_nonce(
    root: Hash,
    nonce: Option<u64>,
) -> Result<Vec<u8>, AnchorError> {
    let hash_algorithm: AlgorithmIdentifier<Any> = AlgorithmIdentifier {
        oid: ID_SHA_256,
        parameters: None,
    };
    let hashed_message = OctetString::new(root.to_vec()).map_err(|e| AnchorError(e.to_string()))?;
    let nonce = match nonce {
        // Minimal DER INTEGER encoding: strip leading zero bytes, then prepend 0x00 if the top bit
        // is set so it stays positive. Handles any u64 (der rejects non-canonical INTEGERs).
        Some(n) => {
            let be = n.to_be_bytes();
            let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
            let mut bytes = be[start..].to_vec();
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, 0x00);
            }
            Some(Int::new(&bytes).map_err(|e| AnchorError(e.to_string()))?)
        }
        None => None,
    };
    let req = TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm,
            hashed_message,
        },
        req_policy: None,
        nonce,
        cert_req: true,
        extensions: None,
    };
    req.to_der().map_err(|e| AnchorError(e.to_string()))
}

/// Facts extracted from a Time-Stamp Token whose imprint covers our root. HONEST BOUNDARY
/// (ADR-043 §6): `extract_tst_facts_matching_root` confirms the TSA timestamped exactly our root and
/// extracts the asserted time — it does NOT yet verify the TSA's CMS signature / certificate
/// chain. That full cryptographic verification is the P4 offline-verifier's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TstFacts {
    /// TSA-asserted token creation time, seconds since the Unix epoch.
    pub gen_time_unix: u64,
    /// TSA-assigned token serial number.
    pub serial: Vec<u8>,
}

/// Parse an RFC 3161 `TimeStampResp` (DER) and confirm its Time-Stamp Token's message imprint IS
/// the Merkle `expected_root` — i.e. the TSA timestamped exactly our root. `Ok(TstFacts)` on match
/// (with the token's time + serial), `Err` on any parse failure or imprint mismatch. Navigation per
/// RFC 3161 / RFC 5652: `TimeStampResp` → `ContentInfo` → CMS `SignedData` → eContent → `TstInfo`.
///
/// NOT A FULL VERIFIER (ADR-043 §6): this checks imprint-coverage + reads the time. It does NOT
/// verify the TSA's CMS signature or certificate chain — a malformed token carrying the right
/// imprint would pass. Full cryptographic verification is the P4 offline verifier. Named `extract…`
/// (not `verify…`) so callers cannot mistake it for cryptographic proof.
pub fn extract_tst_facts_matching_root(
    resp_der: &[u8],
    expected_root: Hash,
) -> Result<TstFacts, AnchorError> {
    let resp = TimeStampResp::from_der(resp_der).map_err(|e| AnchorError(e.to_string()))?;
    let token = resp
        .time_stamp_token
        .ok_or_else(|| AnchorError("response carries no time_stamp_token".into()))?;
    let content_der = token
        .content
        .to_der()
        .map_err(|e| AnchorError(e.to_string()))?;
    let sd = SignedData::from_der(&content_der).map_err(|e| AnchorError(e.to_string()))?;
    let encap = sd
        .encap_content_info
        .econtent
        .ok_or_else(|| AnchorError("SignedData has no eContent (TSTInfo)".into()))?;
    let tst = TstInfo::from_der(encap.value()).map_err(|e| AnchorError(e.to_string()))?;
    if tst.message_imprint.hashed_message.as_bytes() != expected_root.as_slice() {
        return Err(AnchorError(
            "TST message imprint does not cover the expected Merkle root".into(),
        ));
    }
    Ok(TstFacts {
        gen_time_unix: tst.gen_time.to_unix_duration().as_secs(),
        serial: tst.serial_number.as_bytes().to_vec(),
    })
}

/// Timestamp a Merkle `root` against a live RFC 3161 TSA over HTTP and return the raw
/// `TimeStampResp` DER (feed it straight to [`extract_tst_facts_matching_root`]). Feature-gated
/// (`tsa-client`) so the shared verify/producer core stays dependency-light. Pure-Rust HTTP
/// (`ureq` + rustls) — no OpenSSL FFI (mac-lead P1a Q3). Sends a fresh random nonce (anti-replay),
/// bounds the call with a 30s timeout, caps the response at 1 MiB, and rejects a response whose
/// Content-Type is not `application/timestamp-reply`. Production TSA selection is a P2 sign-off item.
#[cfg(feature = "tsa-client")]
pub fn timestamp_root_via_tsa(root: Hash, tsa_url: &str) -> Result<Vec<u8>, AnchorError> {
    use std::io::Read;
    use std::time::Duration;

    // Fresh random nonce so a replayed older TSA response cannot pass verification.
    let mut nb = [0u8; 8];
    getrandom::getrandom(&mut nb).map_err(|e| AnchorError(format!("nonce rng: {e}")))?;
    let req_der = build_timestamp_request_with_nonce(root, Some(u64::from_be_bytes(nb)))?;

    // Overall timeout so a slow/hostile TSA cannot hang the caller indefinitely.
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build();
    let resp = agent
        .post(tsa_url)
        .set("Content-Type", "application/timestamp-query")
        .send_bytes(&req_der)
        .map_err(|e| AnchorError(format!("TSA POST to {tsa_url} failed: {e}")))?;

    // Reject a non-TSA response (e.g. an HTML proxy error page) before the DER parser sees it.
    let ctype = resp.content_type().to_string();
    if !ctype.starts_with("application/timestamp-reply") {
        return Err(AnchorError(format!(
            "TSA returned unexpected Content-Type '{ctype}' (want application/timestamp-reply)"
        )));
    }

    // Cap the body so a hostile/broken TSA cannot OOM the caller (a real TST is a few KB).
    const MAX_TSA_RESP_BYTES: u64 = 1 << 20;
    let mut body = Vec::new();
    resp.into_reader()
        .take(MAX_TSA_RESP_BYTES)
        .read_to_end(&mut body)
        .map_err(|e| AnchorError(format!("reading TSA response: {e}")))?;
    Ok(body)
}

/// ADR-043 C1 P4 — re-export the FULL RFC 3161 TST cryptographic verifier (CMS signature + X.509
/// chain) at `anchor::` so it reads as the zero-trust counterpart to [`extract_tst_facts_matching_root`].
/// The implementation is the peer module [`crate::tst_verify`] (declared in `lib.rs`, feature-gated
/// `offline-verify` so the shared Merkle/producer core stays dependency-light).
#[cfg(feature = "offline-verify")]
pub use crate::tst_verify::{verify_tst_full, TstVerifyError, VerifiedTst};

/// ADR-043 C1 P2 — re-export the PRODUCER-side anchor authenticity check (`verify_tst_pinned`) + the
/// PEM→DER helper (`cert_pem_to_der`) at `anchor::` alongside [`extract_tst_facts_matching_root`] and
/// [`verify_tst_full`]. `verify_tst_pinned` closes the `extract_` ≠ `verify_` gap: it authenticates a
/// token's CMS signature against a PINNED TSA signer cert (not the token's embedded cert), reusing the
/// SAME `verify_signature` primitive P4 uses. Returns [`TstFacts`] so it is a drop-in for the
/// producer that currently records `extract_tst_facts_matching_root`'s facts. Feature-gated
/// `offline-verify` (the RustCrypto x509/rsa/ecdsa stack) like the P4 verifier.
#[cfg(feature = "offline-verify")]
pub use crate::tst_verify::{cert_pem_to_der, verify_tst_pinned};

/// ADR-043 C1 P2 — re-export the producer's INIT-TIME pinned-cert inspection ([`inspect_pinned_cert`]
/// returning [`PinnedCertInfo`]): non-cryptographic facts (timeStamping-EKU presence, CA flag,
/// `notAfter`) the builder uses to WARN on a mis-pinned cert (e.g. the CA root instead of the TSA
/// signer) and to monitor expiry lead-time. Not a verification (mac-lead scoped hard cert-validity to
/// P4); a config guard. Feature-gated `offline-verify`.
#[cfg(feature = "offline-verify")]
pub use crate::tst_verify::{inspect_pinned_cert, PinnedCertInfo};

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    #[test]
    fn timestamp_request_carries_the_root_as_sha256_imprint() {
        let root: Hash = [0xAB; 32];
        let bytes = build_timestamp_request(root).expect("build req");
        let req = TimeStampReq::from_der(&bytes).expect("decode req");
        assert_eq!(req.version, TspVersion::V1);
        assert!(
            req.cert_req,
            "cert_req must be set for offline verification"
        );
        assert_eq!(
            req.message_imprint.hashed_message.as_bytes(),
            &root,
            "the imprint must be exactly the Merkle root"
        );
        assert_eq!(req.message_imprint.hash_algorithm.oid, ID_SHA_256);
    }

    #[test]
    fn nonce_round_trips_into_the_request() {
        let root: Hash = [0x11; 32];
        let n: u64 = 0x0102_0304_0506_0708;
        let bytes = build_timestamp_request_with_nonce(root, Some(n)).expect("build req");
        let req = TimeStampReq::from_der(&bytes).expect("decode req");
        let raw = req
            .nonce
            .expect("nonce must be present")
            .as_bytes()
            .to_vec();
        let mut buf = [0u8; 8];
        buf[8 - raw.len()..].copy_from_slice(&raw);
        assert_eq!(u64::from_be_bytes(buf), n, "nonce must round-trip");
    }

    // A REAL openssl-generated TST fixture, verbatim from x509-tsp's own test vectors: a
    // TimeStampResp whose token covers imprint SHA-256("abc") = ba7816bf…15ad, genTime 1686137186,
    // serial 04. Verifying our code against a genuine TSA response, not a self-constructed one.
    const FIXTURE_RESP_HEX: &str = "3082028430030201003082027B06092A864886F70D010702A082026C30820268020103310F300D060960864801650304020105003081C9060B2A864886F70D0109100104A081B90481B63081B302010106042A0304013031300D060960864801650304020105000420BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD020104180F32303233303630373131323632365A300A020101800201F48101640101FF0208314CFCE4E0651827A048A4463044310B30090603550406130255533113301106035504080C0A536F6D652D5374617465310D300B060355040A0C04546573743111300F06035504030C0854657374205453413182018430820180020101305C3044310B30090603550406130255533113301106035504080C0A536F6D652D5374617465310D300B060355040A0C04546573743111300F06035504030C08546573742054534102146A0DCC59137C11D1C2B092042B4BC51C0D634D24300D06096086480165030402010500A08198301A06092A864886F70D010903310D060B2A864886F70D0109100104301C06092A864886F70D010905310F170D3233303630373131323632365A302B060B2A864886F70D010910020C311C301A3018301604142F36B1B52456F5AC3A1CA09794AE3D0D64AD38C2302F06092A864886F70D01090431220420BAF4CCF82E9B5B3956EADCC87346B407684F26D82B68D0E7DE0D31EA79AF648C300A06082A8648CE3D0403020467306502305A6E1C175B20A93FAB25D14CC5F5A2836D726D6D4A964B66FFBFFCE46276A96475F1408728B3385DCA37C2BA46BE17E1023100C46B7F08D03409A8ECCFD7637765412C3C5EC050E0D39CF48F0F5015950342CB18D8434FF331BA4463C086297C37D07B";

    #[test]
    fn extract_tst_facts_matching_root_matches_real_fixture_and_extracts_time() {
        let resp = hex::decode(FIXTURE_RESP_HEX).expect("decode fixture");
        // the fixture's imprint is SHA-256("abc"); treat that digest as our Merkle "root".
        let root = crate::leaf_bytes_from_content_hash(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .unwrap();
        let facts = extract_tst_facts_matching_root(&resp, root).expect("TST must cover the root");
        assert_eq!(facts.gen_time_unix, 1686137186);
        assert_eq!(facts.serial, vec![0x04]);
        // a one-bit-different root MUST be rejected (no false accept).
        let mut wrong = root;
        wrong[0] ^= 0x01;
        assert!(
            extract_tst_facts_matching_root(&resp, wrong).is_err(),
            "non-covering root MUST reject"
        );
    }

    // Live end-to-end round-trip against a real public TSA. #[ignore]'d — it hits the network,
    // so it is NOT run in CI (external TSAs flake / rate-limit); run manually:
    //   cargo test -p meshlogic-merkle --features tsa-client -- --ignored --nocapture
    #[cfg(feature = "tsa-client")]
    #[test]
    #[ignore = "live network call to a public TSA"]
    fn live_tsa_roundtrip_covers_root() {
        use sha2::{Digest, Sha256};
        let root: Hash = Sha256::digest(b"meshlogic-p1a-live-tsa-smoke").into();
        let resp =
            timestamp_root_via_tsa(root, "https://freetsa.org/tsr").expect("live TSA round-trip");
        let facts = extract_tst_facts_matching_root(&resp, root).expect("TST must cover our root");
        assert!(
            facts.gen_time_unix > 1_700_000_000,
            "genTime should be recent (a real TSA timestamp)"
        );
    }
}
