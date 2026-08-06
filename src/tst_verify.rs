//! FULL RFC 3161 Time-Stamp Token cryptographic verification (ADR-043 C1 P4, the offline verifier).
//!
//! [`crate::anchor::extract_tst_facts_matching_root`] deliberately does NOT verify the TSA's CMS
//! signature or certificate chain — it only confirms the imprint covers our root and reads the time.
//! THIS module closes that gap: [`verify_tst_full`] does the cryptographic work an auditor needs to
//! trust a token WITHOUT trusting MeshLogic — it verifies
//!
//!   1. the CMS `SignerInfo` signature over the DER of the signed attributes, using the signer
//!      certificate's public key (RSA-PKCS1 or ECDSA P-256/P-384, dispatched on the signature OID);
//!   2. that the `messageDigest` signed-attribute equals the digest of the eContent (the `TSTInfo`)
//!      and the `contentType` attribute is `id-ct-TSTInfo` (binds the signature to THIS token);
//!   3. that the token's `MessageImprint` IS the caller's expected Merkle root;
//!   4. that the signer certificate is an END-ENTITY (CA:FALSE) leaf carrying the id-kp-timeStamping
//!      EKU (RFC 3161 §2.3), is valid at the token's `genTime`, and chains to one of the
//!      caller-supplied `trusted_roots`.
//!
//! HONEST SCOPE (read before trusting a "VERIFIED"):
//! * Chain building verifies each certificate's signature under its issuer's key up to a supplied
//!   trusted root (the freeTSA topology — signer issued directly by the trusted root — is the DIRECT
//!   case; embedded intermediates are walked with bounded-depth BACKTRACKING, trying alternative
//!   candidates rather than committing to the first that signs). Issuer selection is disambiguated by
//!   the Authority/Subject Key Identifier (AKI/SKI) when present, then decided by the signature. It
//!   checks `basicConstraints` CA:TRUE on issuers and the validity window on every cert in the path.
//! * The trusted anchor MUST be SELF-SIGNED (subject==issuer and its self-signature verifies) — a
//!   non-self-signed cert (e.g. an intermediate) supplied as `--trusted-root` is rejected, so the
//!   zero-trust story rests on a cert that proves possession of the key for its own SPKI.
//! * A trusted root that matches the signer's issuer IDENTITY (DN + AKI/SKI) but does NOT actually
//!   sign it is surfaced as an explicit `ChainInvalid` — never silently skipped (guards against a
//!   substituted / DN-colliding anchor).
//! * It does NOT do revocation (CRL/OCSP), name-constraints, policy-constraints, or path-length
//!   enforcement beyond the CA flag. Those are the remaining RFC 5280 hardening (flagged, not silently
//!   skipped) — an auditor supplies the trusted root out-of-band, which is the load-bearing anchor.
//! * The trusted anchor is ALWAYS one of the caller's `trusted_roots`. A root certificate the TSA
//!   embeds in the token is NEVER trusted as an anchor (zero-trust) — embedded certs serve only as
//!   candidate intermediates.
//! * Any signature/curve/hash algorithm not in the supported set FAILS CLOSED ([`TstVerifyError::Unsupported`])
//!   — it is never treated as a passing verification.
//!
//! This is NOT the whole tamper-evidence claim: P4 proves the anchor's cryptographic authenticity;
//! the customer WORM co-anchor (P3) is still required before "tamper-evident" can be asserted.

use crate::Hash;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::OctetString;
use der::{Any, Decode, Encode};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashSet;
use x509_cert::certificate::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage};
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_tsp::{TimeStampResp, TstInfo};

// ---- OID constants (literal, so the mapping is auditable in one place) ---------------------------

/// CMS `contentType` signed-attribute type (RFC 5652 §11.1) — 1.2.840.113549.1.9.3.
const ATTR_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// CMS `messageDigest` signed-attribute type (RFC 5652 §11.2) — 1.2.840.113549.1.9.4.
const ATTR_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// eContentType for a Time-Stamp Token: id-ct-TSTInfo — 1.2.840.113549.1.9.16.1.4.
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
/// id-kp-timeStamping EKU (RFC 3161 §2.3) — 1.3.6.1.5.5.7.3.8. RFC 3161 requires the TSA signing
/// cert to carry EXACTLY this EKU, in an EKU extension marked CRITICAL, as the SOLE purpose.
const ID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

// ---- chain-search work limits (F1 — DoS work-budget) ---------------------------------------------
//
// A hostile token can embed many mutually-signing / same-key CA certificates; the BACKTRACKING chain
// walk would otherwise explore a combinatorial number of candidate paths (up to K^MAX_DEPTH issuer
// signature verifications) — an availability DoS (an auditor sees a HANG, not a false VERIFIED). The
// walk is bounded three independent ways, each of which fails CLOSED with `ChainSearchExhausted`:
//   1. `MAX_EMBEDDED_CERTS` — the number of token-embedded candidate intermediates considered;
//   2. `MAX_ISSUER_SIG_VERIFS` — a GLOBAL cap on issuer-signature verifications across the whole walk;
//   3. a (subject DN, SKI) visited-set — the same candidate identity is never re-walked (also breaks
//      issuer cycles). See [`ChainBudget`].
/// Reject a token embedding more than this many candidate certificates outright (a real TSA token
/// carries 1–3). Generous headroom over any legitimate topology.
const MAX_EMBEDDED_CERTS: usize = 64;
/// Global ceiling on issuer-signature verifications performed by a single chain walk. Any legitimate
/// path is ≤ MAX_DEPTH verifications; this backstops adversarial branching that slips under the other
/// two limits.
const MAX_ISSUER_SIG_VERIFS: u32 = 256;

// Digest algorithm OIDs.
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

// Signature algorithm OIDs.
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

// Public-key + curve OIDs.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Distinct failure modes of [`verify_tst_full`]. Each is a HARD reject — there is no "warning that
/// still verifies". Anything we cannot check with confidence maps to [`Self::Unsupported`] and fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TstVerifyError {
    /// The DER did not parse as a `TimeStampResp` / CMS `SignedData` / `TstInfo`, or a required field
    /// (signer info, signed attributes, embedded signer cert, SPKI) was absent/malformed.
    ParseError(String),
    /// The token's `MessageImprint` is NOT the caller's expected Merkle root.
    ImprintMismatch,
    /// The CMS `SignerInfo` signature did not verify, OR the `messageDigest`/`contentType` signed
    /// attributes did not bind to this token's eContent.
    SigInvalid,
    /// The signer certificate does not chain to any supplied trusted root (or none was supplied).
    ChainInvalid(String),
    /// The signer certificate lacks the id-kp-timeStamping Extended Key Usage.
    EkuMissing,
    /// The signer certificate HAS an Extended Key Usage extension but it violates RFC 3161 §2.3: the
    /// EKU extension is not marked CRITICAL, or id-kp-timeStamping is not the SOLE purpose (extra
    /// purposes present). Distinguished from [`Self::EkuMissing`] (no EKU extension at all).
    EkuNotCriticalOrNotSole,
    /// The signer certificate is not an end-entity cert (basicConstraints CA:TRUE). RFC 3161 §2.3
    /// requires the TSA signing cert to be a leaf — a CA cert must not double as the TSA signer.
    SignerNotLeaf,
    /// A certificate in the path was not valid at the token's `genTime`.
    Expired,
    /// A signature/curve/hash algorithm outside the implemented set — FAILS CLOSED (never VERIFIED).
    Unsupported(String),
    /// The certificate-chain search hit a work limit (embedded-cert count, global issuer-signature
    /// verification budget, or a re-walk of an already-visited identity) before terminating — a
    /// hostile token trying to exhaust the verifier. FAILS CLOSED (an availability guard, never a
    /// false VERIFIED). See the `MAX_EMBEDDED_CERTS` / `MAX_ISSUER_SIG_VERIFS` limits.
    ChainSearchExhausted(String),
}

impl std::fmt::Display for TstVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TstVerifyError::ParseError(s) => write!(f, "TST parse error: {s}"),
            TstVerifyError::ImprintMismatch => {
                write!(
                    f,
                    "TST message imprint does not equal the expected Merkle root"
                )
            }
            TstVerifyError::SigInvalid => {
                write!(f, "TST CMS signature / signed-attributes invalid")
            }
            TstVerifyError::ChainInvalid(s) => {
                write!(
                    f,
                    "TST signer certificate does not chain to a trusted root: {s}"
                )
            }
            TstVerifyError::EkuMissing => {
                write!(f, "TST signer certificate lacks the id-kp-timeStamping EKU")
            }
            TstVerifyError::EkuNotCriticalOrNotSole => write!(
                f,
                "TST signer certificate EKU is not critical, or id-kp-timeStamping is not the sole \
                 purpose (RFC 3161 §2.3)"
            ),
            TstVerifyError::SignerNotLeaf => write!(
                f,
                "TST signer certificate is a CA (basicConstraints CA:TRUE), not an end-entity leaf \
                 (RFC 3161 §2.3)"
            ),
            TstVerifyError::Expired => {
                write!(
                    f,
                    "a certificate in the chain was not valid at the token genTime"
                )
            }
            TstVerifyError::Unsupported(s) => write!(f, "unsupported algorithm (fail-closed): {s}"),
            TstVerifyError::ChainSearchExhausted(s) => {
                write!(
                    f,
                    "certificate-chain search exhausted a work limit (fail-closed): {s}"
                )
            }
        }
    }
}
impl std::error::Error for TstVerifyError {}

/// What [`verify_tst_full`] returns on success — the facts an auditor records plus WHICH signer /
/// root / algorithms were actually used, so the verdict is self-describing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTst {
    /// TSA-asserted token creation time, seconds since the Unix epoch.
    pub gen_time_unix: u64,
    /// TSA-assigned token serial number (raw big-endian bytes).
    pub serial: Vec<u8>,
    /// The signer certificate's Subject DN (RFC 4514 string).
    pub signer_subject: String,
    /// The trusted-root Subject DN the chain terminated at.
    pub trusted_root_subject: String,
    /// The CMS `SignerInfo` signature algorithm OID that was verified (dotted).
    pub cms_sig_alg: String,
}

// ---- signature primitives ------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashKind {
    Sha256,
    Sha384,
    Sha512,
}

fn digest(kind: HashKind, msg: &[u8]) -> Vec<u8> {
    match kind {
        HashKind::Sha256 => Sha256::digest(msg).to_vec(),
        HashKind::Sha384 => Sha384::digest(msg).to_vec(),
        HashKind::Sha512 => Sha512::digest(msg).to_vec(),
    }
}

fn digest_kind_from_oid(oid: &ObjectIdentifier) -> Option<HashKind> {
    match *oid {
        OID_SHA256 => Some(HashKind::Sha256),
        OID_SHA384 => Some(HashKind::Sha384),
        OID_SHA512 => Some(HashKind::Sha512),
        _ => None,
    }
}

/// The hash a signature-algorithm OID IMPLIES (RSA-with-SHAn and ECDSA-with-SHAn both name their
/// digest in the OID). `None` for an unrecognised signature algorithm (its verification path then
/// fails closed as [`TstVerifyError::Unsupported`]).
fn hash_kind_from_sig_oid(sig_alg: &ObjectIdentifier) -> Option<HashKind> {
    match *sig_alg {
        OID_RSA_SHA256 | OID_ECDSA_SHA256 => Some(HashKind::Sha256),
        OID_RSA_SHA384 | OID_ECDSA_SHA384 => Some(HashKind::Sha384),
        OID_RSA_SHA512 | OID_ECDSA_SHA512 => Some(HashKind::Sha512),
        _ => None,
    }
}

/// SHARED signed-attrs helper (F2 — the open AI MEDIUM, RFC 5652 §5.3): resolve the SignerInfo
/// `digestAlgorithm` to a [`HashKind`] AND cross-check that it names the SAME hash the
/// `signatureAlgorithm` implies. Without this cross-check a token could name one hash in
/// `digestAlgorithm` (used to compute/compare `messageDigest` over the eContent) while its signature
/// binds a different hash — RFC 5652 §5.3 requires them to agree. Confirmed NOT exploitable in the
/// current token shape (fixed eContent, imprint-checked, both hashes strong, the signature binds the
/// attributes) — closed for correctness so EVERY caller of the signed-attrs path (verify_tst_full now,
/// the P2 producer-verify that will reuse this) is covered.
///
/// * `Ok(HashKind)` — digestAlgorithm is supported and consistent with the signature algorithm.
/// * `Err(Unsupported)` — digestAlgorithm is outside the implemented set (fail-closed).
/// * `Err(SigInvalid)` — digestAlgorithm and signatureAlgorithm name DIFFERENT hashes (§5.3 violation).
fn require_consistent_digest_alg(
    digest_alg: &ObjectIdentifier,
    sig_alg: &ObjectIdentifier,
) -> Result<HashKind, TstVerifyError> {
    let digest_kind = digest_kind_from_oid(digest_alg)
        .ok_or_else(|| TstVerifyError::Unsupported(format!("digest algorithm {digest_alg}")))?;
    if let Some(sig_hash) = hash_kind_from_sig_oid(sig_alg) {
        if sig_hash != digest_kind {
            return Err(TstVerifyError::SigInvalid);
        }
    }
    // An unrecognised `sig_alg` (hash_kind == None) is intentionally NOT rejected here — the signature
    // verification step is the single fail-closed authority for unsupported signature algorithms
    // ([`TstVerifyError::Unsupported`]); duplicating that verdict here would only blur the error.
    Ok(digest_kind)
}

/// Verify `signature` over `message` using the public key in `spki`, dispatching on the signature
/// algorithm OID `sig_alg`. Returns `Ok(())` iff the signature is cryptographically valid.
///
/// Supported: RSA-PKCS1v1.5 with SHA-256/384/512, and ECDSA over P-256/P-384 with SHA-256/384/512
/// (the hash comes from the signature OID; the curve from the SPKI). ANY other algorithm is
/// [`TstVerifyError::Unsupported`] — we never approximate crypto we cannot perform.
fn verify_signature(
    spki: &SubjectPublicKeyInfoOwned,
    sig_alg: &ObjectIdentifier,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TstVerifyError> {
    let spki_der = spki
        .to_der()
        .map_err(|e| TstVerifyError::ParseError(format!("re-encode SPKI: {e}")))?;

    // RSA PKCS#1 v1.5.
    let rsa_hash = match *sig_alg {
        OID_RSA_SHA256 => Some(HashKind::Sha256),
        OID_RSA_SHA384 => Some(HashKind::Sha384),
        OID_RSA_SHA512 => Some(HashKind::Sha512),
        _ => None,
    };
    if let Some(hk) = rsa_hash {
        return verify_rsa(&spki_der, hk, message, signature);
    }

    // ECDSA (hash from the signature OID, curve from the SPKI).
    let ecdsa_hash = match *sig_alg {
        OID_ECDSA_SHA256 => Some(HashKind::Sha256),
        OID_ECDSA_SHA384 => Some(HashKind::Sha384),
        OID_ECDSA_SHA512 => Some(HashKind::Sha512),
        _ => None,
    };
    if let Some(hk) = ecdsa_hash {
        if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
            return Err(TstVerifyError::Unsupported(format!(
                "ECDSA signature but non-EC public key {}",
                spki.algorithm.oid
            )));
        }
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
            .ok_or_else(|| TstVerifyError::ParseError("EC SPKI missing named-curve OID".into()))?;
        return verify_ecdsa(&spki_der, curve, hk, message, signature);
    }

    Err(TstVerifyError::Unsupported(format!(
        "signature algorithm {sig_alg}"
    )))
}

fn verify_rsa(
    spki_der: &[u8],
    hk: HashKind,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TstVerifyError> {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::RsaPublicKey;

    let key = RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|e| TstVerifyError::ParseError(format!("RSA SPKI: {e}")))?;
    let hashed = digest(hk, message);
    let scheme = match hk {
        HashKind::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        HashKind::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        HashKind::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    };
    key.verify(scheme, &hashed, signature)
        .map_err(|_| TstVerifyError::SigInvalid)
}

fn verify_ecdsa(
    spki_der: &[u8],
    curve: ObjectIdentifier,
    hk: HashKind,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TstVerifyError> {
    let prehash = digest(hk, message);
    match curve {
        OID_SECP256R1 => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            use p256::ecdsa::{Signature, VerifyingKey};
            use p256::pkcs8::DecodePublicKey;
            let vk = VerifyingKey::from_public_key_der(spki_der)
                .map_err(|e| TstVerifyError::ParseError(format!("P-256 SPKI: {e}")))?;
            let sig = Signature::from_der(signature).map_err(|_| TstVerifyError::SigInvalid)?;
            vk.verify_prehash(&prehash, &sig)
                .map_err(|_| TstVerifyError::SigInvalid)
        }
        OID_SECP384R1 => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            use p384::ecdsa::{Signature, VerifyingKey};
            use p384::pkcs8::DecodePublicKey;
            let vk = VerifyingKey::from_public_key_der(spki_der)
                .map_err(|e| TstVerifyError::ParseError(format!("P-384 SPKI: {e}")))?;
            let sig = Signature::from_der(signature).map_err(|_| TstVerifyError::SigInvalid)?;
            vk.verify_prehash(&prehash, &sig)
                .map_err(|_| TstVerifyError::SigInvalid)
        }
        other => Err(TstVerifyError::Unsupported(format!("EC curve {other}"))),
    }
}

// ---- certificate helpers -------------------------------------------------------------------------

fn cert_not_before_unix(cert: &Certificate) -> u64 {
    cert.tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs()
}
fn cert_not_after_unix(cert: &Certificate) -> u64 {
    cert.tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs()
}

fn cert_is_ca(cert: &Certificate) -> bool {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts.iter() {
            if ext.extn_id == BasicConstraints::OID {
                if let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                    return bc.ca;
                }
            }
        }
    }
    false
}

/// RFC 3161 §2.3 (F3): the TSA signing certificate MUST carry an Extended Key Usage extension that is
/// (a) marked CRITICAL and (b) has id-kp-timeStamping as its SOLE purpose. Presence-only is NOT enough
/// — a cert whose EKU permits other purposes (or is non-critical) is not an RFC-3161-conformant TSA
/// signer. Returns:
/// * `Ok(())` — a critical EKU whose only purpose is id-kp-timeStamping.
/// * `Err(EkuMissing)` — no EKU extension at all.
/// * `Err(EkuNotCriticalOrNotSole)` — EKU present but non-critical, or timeStamping is not the sole
///   purpose (extra or wrong purposes).
fn check_timestamping_eku(cert: &Certificate) -> Result<(), TstVerifyError> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts.iter() {
            if ext.extn_id == ExtendedKeyUsage::OID {
                if !ext.critical {
                    return Err(TstVerifyError::EkuNotCriticalOrNotSole);
                }
                let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| TstVerifyError::ParseError(format!("EKU: {e}")))?;
                // SOLE purpose: exactly one entry, and it is id-kp-timeStamping.
                if eku.0.len() != 1 || eku.0[0] != ID_KP_TIME_STAMPING {
                    return Err(TstVerifyError::EkuNotCriticalOrNotSole);
                }
                return Ok(());
            }
        }
    }
    Err(TstVerifyError::EkuMissing)
}

/// The 20-byte (or other-length) SubjectKeyIdentifier extension value of `cert`, if present.
fn cert_subject_key_id(cert: &Certificate) -> Option<Vec<u8>> {
    cert_ski(cert)
}

/// The keyIdentifier of the AuthorityKeyIdentifier extension of `cert`, if present.
fn cert_authority_key_id(cert: &Certificate) -> Option<Vec<u8>> {
    use x509_cert::ext::pkix::AuthorityKeyIdentifier;
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id == AuthorityKeyIdentifier::OID {
            if let Ok(aki) = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()) {
                return aki.key_identifier.map(|k| k.as_bytes().to_vec());
            }
        }
    }
    None
}

/// Does `cand` PLAUSIBLY claim to be the issuer of `child`? Requires the child's issuer DN to equal
/// the candidate's subject DN AND, when BOTH the child's Authority Key Identifier and the candidate's
/// Subject Key Identifier are present, that they match. The AKI/SKI gate (HIGH-1) disambiguates DN
/// collisions BEFORE any signature check, so a substituted same-DN cert with a different key is
/// filtered here rather than only at the crypto step. When either identifier is absent we fall back
/// to the DN match alone (and the signature check remains the load-bearing decision).
fn is_candidate_issuer(child: &Certificate, cand: &Certificate) -> bool {
    if child.tbs_certificate.issuer != cand.tbs_certificate.subject {
        return false;
    }
    match (cert_authority_key_id(child), cert_subject_key_id(cand)) {
        (Some(aki), Some(ski)) => aki == ski,
        _ => true,
    }
}

/// Cryptographically verify that `child`'s signature was produced by `issuer`'s key — `child`'s own
/// signatureAlgorithm over its TBSCertificate DER. Does NOT check the DN (pair with
/// [`is_candidate_issuer`]). `Err(SigInvalid)` = wrong key; `Err(Unsupported)`/`Err(ParseError)` are
/// fail-closed conditions the caller must NOT treat as "just not the issuer".
fn verify_issuer_signature(
    child: &Certificate,
    issuer: &Certificate,
) -> Result<(), TstVerifyError> {
    let tbs_der = child
        .tbs_certificate
        .to_der()
        .map_err(|e| TstVerifyError::ParseError(format!("re-encode TBSCertificate: {e}")))?;
    let sig = child.signature.as_bytes().ok_or_else(|| {
        TstVerifyError::ParseError("certificate signature not byte-aligned".into())
    })?;
    verify_signature(
        &issuer.tbs_certificate.subject_public_key_info,
        &child.signature_algorithm.oid,
        &tbs_der,
        sig,
    )
}

/// A supplied cert is a usable trust ANCHOR only if it is SELF-SIGNED (subject==issuer AND its own
/// self-signature verifies — proof of possession of the private key for its SPKI), is a CA, and is
/// valid at `gen_time`. Requiring a self-signature (HIGH-2) stops an intermediate or attacker-chosen
/// non-self-signed cert (CA:TRUE, chosen SPKI) from being accepted as a trust anchor.
fn validate_trust_anchor(root: &Certificate, gen_time: u64) -> Result<(), TstVerifyError> {
    if root.tbs_certificate.subject != root.tbs_certificate.issuer {
        return Err(TstVerifyError::ChainInvalid(
            "trusted anchor is not self-signed (subject != issuer) — not a valid trust root".into(),
        ));
    }
    verify_issuer_signature(root, root).map_err(|e| match e {
        TstVerifyError::SigInvalid => {
            TstVerifyError::ChainInvalid("trusted anchor self-signature did not verify".into())
        }
        other => other, // Unsupported / ParseError propagate (fail closed)
    })?;
    if !cert_is_ca(root) {
        return Err(TstVerifyError::ChainInvalid(
            "trusted anchor is not a CA (basicConstraints CA:FALSE)".into(),
        ));
    }
    if gen_time < cert_not_before_unix(root) || gen_time > cert_not_after_unix(root) {
        return Err(TstVerifyError::Expired);
    }
    Ok(())
}

/// A stable identity key for the chain-walk visited-set (F1): (Subject DN DER, SubjectKeyIdentifier).
/// Two certificates with the same subject AND the same SKI are the "same node" for walk purposes — a
/// re-walk is redundant (the outcome does not depend on the parent it was reached from) and, for a
/// hostile same-key cluster, the source of combinatorial blow-up.
fn node_key(cert: &Certificate) -> (Vec<u8>, Vec<u8>) {
    let subject = cert.tbs_certificate.subject.to_der().unwrap_or_default();
    let ski = cert_ski(cert).unwrap_or_default();
    (subject, ski)
}

/// Work budget threaded through the BACKTRACKING chain walk (F1). Bounds the search so a hostile
/// token cannot turn it into an availability DoS: a GLOBAL issuer-signature verification counter plus
/// a (subject, SKI) visited-set. Both fail CLOSED with [`TstVerifyError::ChainSearchExhausted`] /
/// dedup — never a false VERIFIED.
struct ChainBudget {
    /// Remaining issuer-signature verifications for the WHOLE walk (see `MAX_ISSUER_SIG_VERIFS`).
    verifs_remaining: u32,
    /// Node identities already explored as `current` — re-entry is skipped (memoisation + cycle break).
    visited: HashSet<(Vec<u8>, Vec<u8>)>,
}

impl ChainBudget {
    fn new() -> Self {
        ChainBudget {
            verifs_remaining: MAX_ISSUER_SIG_VERIFS,
            visited: HashSet::new(),
        }
    }
    /// Charge ONE issuer-signature verification against the global budget; fail closed at zero.
    fn charge_verification(&mut self) -> Result<(), TstVerifyError> {
        match self.verifs_remaining.checked_sub(1) {
            Some(n) => {
                self.verifs_remaining = n;
                Ok(())
            }
            None => Err(TstVerifyError::ChainSearchExhausted(format!(
                "exceeded the global issuer-signature verification budget ({MAX_ISSUER_SIG_VERIFS})"
            ))),
        }
    }
}

/// Chain `signer` to one of `trusted_roots`, using `intermediates` (the token-embedded certs) as
/// candidate intermediate CAs. Returns the terminating trusted root's Subject DN on success. The
/// trusted anchor is ALWAYS one of `trusted_roots` (an embedded root is never an anchor) and must be
/// a self-signed CA valid at `gen_time` ([`validate_trust_anchor`]). The search is bounded (F1):
/// at most `MAX_EMBEDDED_CERTS` candidate intermediates, `MAX_ISSUER_SIG_VERIFS` total signature
/// verifications, and no identity re-walked — each overflow is a fail-closed `ChainSearchExhausted`.
fn build_chain_to_root(
    signer: &Certificate,
    intermediates: &[Certificate],
    trusted_roots: &[Certificate],
    gen_time: u64,
) -> Result<String, TstVerifyError> {
    if trusted_roots.is_empty() {
        return Err(TstVerifyError::ChainInvalid(
            "no trusted roots supplied".into(),
        ));
    }
    // F1(c): cap the number of token-embedded candidate certificates BEFORE the walk. A real TSA
    // token embeds 1–3; a token stuffing dozens of candidate CAs is adversarial — reject outright.
    if intermediates.len() > MAX_EMBEDDED_CERTS {
        return Err(TstVerifyError::ChainSearchExhausted(format!(
            "token embeds {} candidate certificates, over the limit of {MAX_EMBEDDED_CERTS}",
            intermediates.len()
        )));
    }
    const MAX_DEPTH: usize = 8;
    let mut budget = ChainBudget::new();
    chain_to_root(
        signer,
        intermediates,
        trusted_roots,
        gen_time,
        MAX_DEPTH,
        &mut budget,
    )?
    .ok_or_else(|| {
        TstVerifyError::ChainInvalid(
            "signer certificate does not chain to any supplied trusted root".into(),
        )
    })
}

/// Recursive, BACKTRACKING chain builder (MEDIUM-2: tries alternative embedded intermediates rather
/// than committing to the first that signs `current`). Returns:
/// * `Ok(Some(root_dn))` — `current` chains to a valid trust anchor.
/// * `Ok(None)` — no path within `depth_left` (caller reports "does not chain").
/// * `Err(..)` — a HARD, fail-closed condition: a trusted root matched the issuer identity but did
///   NOT sign `current` (HIGH-1 — never a silent fall-through), an unsupported algorithm, or a
///   parse error.
fn chain_to_root(
    current: &Certificate,
    intermediates: &[Certificate],
    trusted_roots: &[Certificate],
    gen_time: u64,
    depth_left: usize,
    budget: &mut ChainBudget,
) -> Result<Option<String>, TstVerifyError> {
    if depth_left == 0 {
        return Ok(None);
    }
    // F1(b): if we have already explored THIS identity as `current`, do not re-walk it. The result of
    // "does `current` chain to a root?" is independent of the parent it was reached from, so this is a
    // sound memoisation that also breaks issuer cycles and collapses same-key candidate clusters.
    if !budget.visited.insert(node_key(current)) {
        return Ok(None);
    }

    // 1. TERMINAL: is `current` directly issued by one of the trusted roots?
    let dn_matching: Vec<&Certificate> = trusted_roots
        .iter()
        .filter(|r| is_candidate_issuer(current, r))
        .collect();
    if !dn_matching.is_empty() {
        for root in &dn_matching {
            budget.charge_verification()?;
            match verify_issuer_signature(current, root) {
                Ok(()) => {
                    validate_trust_anchor(root, gen_time)?;
                    return Ok(Some(dn(&root.tbs_certificate.subject)));
                }
                // Wrong key for THIS candidate — try the next DN-matching root.
                Err(TstVerifyError::SigInvalid) => continue,
                // Unsupported / ParseError → fail closed, never keep walking.
                Err(e) => return Err(e),
            }
        }
        // HIGH-1: a trusted root matched `current`'s issuer identity (DN + AKI/SKI) but NONE of them
        // actually signed it. Surface the cryptographic failure EXPLICITLY — do NOT fall through to
        // the intermediate walk. A DN-collision / substituted trust anchor must not be masked.
        return Err(TstVerifyError::ChainInvalid(
            "a supplied trusted root matched the certificate's issuer identity but did not sign it \
             (substituted or mismatched trust anchor)"
                .into(),
        ));
    }

    // 2. STEP UP through an embedded intermediate CA, with backtracking over all candidates.
    for inter in intermediates {
        if inter.tbs_certificate.subject == current.tbs_certificate.subject {
            continue; // never step onto self
        }
        if !cert_is_ca(inter) || !is_candidate_issuer(current, inter) {
            continue;
        }
        budget.charge_verification()?;
        match verify_issuer_signature(current, inter) {
            Ok(()) => {
                // The intermediate must itself be time-valid to sit in the path; if not, backtrack.
                if gen_time < cert_not_before_unix(inter) || gen_time > cert_not_after_unix(inter) {
                    continue;
                }
                if let Some(root_dn) = chain_to_root(
                    inter,
                    intermediates,
                    trusted_roots,
                    gen_time,
                    depth_left - 1,
                    budget,
                )? {
                    return Ok(Some(root_dn));
                }
                // Dead end via this intermediate — backtrack and try the next candidate.
            }
            Err(TstVerifyError::SigInvalid) => continue, // not the real issuer; keep looking
            Err(e) => return Err(e),                     // Unsupported / ParseError → fail closed
        }
    }
    Ok(None)
}

/// RFC 3161 §2.3: the TSA signing certificate MUST be an end-entity certificate. Reject a CA cert
/// (even one carrying the timeStamping EKU) presented as the signer (HIGH-3).
fn require_end_entity(signer: &Certificate) -> Result<(), TstVerifyError> {
    if cert_is_ca(signer) {
        return Err(TstVerifyError::SignerNotLeaf);
    }
    Ok(())
}

fn dn(name: &x509_cert::name::Name) -> String {
    name.to_string()
}

// ---- shared parse + signed-attributes core (P2 ⇄ P4, no fork) ------------------------------------

/// Everything [`parse_and_verify_signed_attrs`] extracts once so BOTH the P4 full verifier
/// ([`verify_tst_full`]) and the P2 producer authenticity check ([`verify_tst_pinned`]) run ONE parse
/// and ONE signed-attributes path — the CMS `SignerInfo` signature is then checked by the caller with
/// its chosen verifying key (the token's embedded cert for P4; the PINNED cert for P2). That verifying
/// key is the ONLY difference between the two, so they can never drift in how they read a token.
struct SignedAttrsChecked {
    /// TSA-asserted token creation time, seconds since the Unix epoch.
    gen_time_unix: u64,
    /// TSA-assigned token serial number (raw big-endian bytes).
    serial: Vec<u8>,
    /// DER of the SignedAttributes as an explicit SET OF (tag 0x31) — the bytes the CMS signature
    /// covers (RFC 5652 §5.4).
    signed_attrs_der: Vec<u8>,
    /// The `SignerInfo` signature algorithm OID (the dispatch key for [`verify_signature`]).
    cms_sig_alg: ObjectIdentifier,
    /// The `SignerInfo` signature bytes.
    cms_signature: Vec<u8>,
    /// The `SignerIdentifier` — lets the P4 path resolve WHICH embedded cert is the signer.
    sid: SignerIdentifier,
    /// Every certificate embedded in the token (P4 chain candidates; the pinned path ignores these —
    /// it authenticates against the PINNED cert, never a token-supplied one).
    embedded: Vec<Certificate>,
}

/// Parse `resp_der` (`TimeStampResp` → CMS `SignedData` → `TstInfo`), confirm the token's
/// `MessageImprint` IS `expected_root`, and verify the CMS signed attributes bind the signature to
/// THIS token (`contentType` == id-ct-TSTInfo AND `messageDigest` == digest(eContent)). Does NOT
/// verify the `SignerInfo` signature itself — the caller supplies the verifying key. Imprint is
/// checked BEFORE anything signature-related, so a wrong root surfaces as [`TstVerifyError::ImprintMismatch`]
/// rather than a signature error.
fn parse_and_verify_signed_attrs(
    resp_der: &[u8],
    expected_root: Hash,
) -> Result<SignedAttrsChecked, TstVerifyError> {
    // --- parse: TimeStampResp -> CMS SignedData -> TstInfo -------------------------------------
    let resp = TimeStampResp::from_der(resp_der)
        .map_err(|e| TstVerifyError::ParseError(format!("TimeStampResp: {e}")))?;
    let token = resp
        .time_stamp_token
        .ok_or_else(|| TstVerifyError::ParseError("response carries no time_stamp_token".into()))?;
    // The token is a CMS ContentInfo wrapping SignedData.
    let ci = ContentInfo::from_der(
        &token
            .to_der()
            .map_err(|e| TstVerifyError::ParseError(format!("re-encode token: {e}")))?,
    )
    .map_err(|e| TstVerifyError::ParseError(format!("ContentInfo: {e}")))?;
    let sd = ci
        .content
        .decode_as::<SignedData>()
        .map_err(|e| TstVerifyError::ParseError(format!("SignedData: {e}")))?;

    let encap =
        sd.encap_content_info.econtent.as_ref().ok_or_else(|| {
            TstVerifyError::ParseError("SignedData has no eContent (TSTInfo)".into())
        })?;
    // eContent OCTET STRING contents == the TSTInfo DER (what messageDigest hashes and what parses).
    let tst_info_der = encap.value();
    let tst = TstInfo::from_der(tst_info_der)
        .map_err(|e| TstVerifyError::ParseError(format!("TstInfo: {e}")))?;

    // --- (3) imprint IS our expected root (checked first) --------------------------------------
    if tst.message_imprint.hashed_message.as_bytes() != expected_root.as_slice() {
        return Err(TstVerifyError::ImprintMismatch);
    }
    let gen_time_unix = tst.gen_time.to_unix_duration().as_secs();
    let serial = tst.serial_number.as_bytes().to_vec();

    // --- locate the single SignerInfo ----------------------------------------------------------
    let signer_info: &SignerInfo = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| TstVerifyError::ParseError("SignedData has no SignerInfo".into()))?;

    // --- (2) signed attributes: contentType + messageDigest bind the sig to THIS token ---------
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| TstVerifyError::ParseError("SignerInfo has no signed attributes".into()))?;

    // F2 / RFC 5652 §5.3: resolve digestAlgorithm to a HashKind AND cross-check it names the same
    // hash the signatureAlgorithm implies (SigInvalid on mismatch; Unsupported on an unknown digest).
    let digest_kind = require_consistent_digest_alg(
        &signer_info.digest_alg.oid,
        &signer_info.signature_algorithm.oid,
    )?;

    // contentType == id-ct-TSTInfo
    let ct = get_attr_value(signed_attrs, &ATTR_CONTENT_TYPE)
        .ok_or_else(|| TstVerifyError::ParseError("missing contentType signed attribute".into()))?;
    let ct_oid = ct
        .decode_as::<ObjectIdentifier>()
        .map_err(|e| TstVerifyError::ParseError(format!("contentType value: {e}")))?;
    if ct_oid != ID_CT_TST_INFO {
        return Err(TstVerifyError::SigInvalid);
    }

    // messageDigest == digest(eContent)
    let md = get_attr_value(signed_attrs, &ATTR_MESSAGE_DIGEST).ok_or_else(|| {
        TstVerifyError::ParseError("missing messageDigest signed attribute".into())
    })?;
    let md_octets = md
        .decode_as::<OctetString>()
        .map_err(|e| TstVerifyError::ParseError(format!("messageDigest value: {e}")))?;
    let econtent_digest = digest(digest_kind, tst_info_der);
    if md_octets.as_bytes() != econtent_digest.as_slice() {
        return Err(TstVerifyError::SigInvalid);
    }

    // RFC 5652 §5.4: the signature is over the DER of the SignedAttributes as an explicit SET OF
    // (tag 0x31), NOT the [0] IMPLICIT tag they carry inside SignerInfo. `SetOfVec::to_der()` emits
    // exactly that SET-OF encoding.
    let signed_attrs_der = signed_attrs
        .to_der()
        .map_err(|e| TstVerifyError::ParseError(format!("re-encode signed attributes: {e}")))?;

    Ok(SignedAttrsChecked {
        gen_time_unix,
        serial,
        signed_attrs_der,
        cms_sig_alg: signer_info.signature_algorithm.oid,
        cms_signature: signer_info.signature.as_bytes().to_vec(),
        sid: signer_info.sid.clone(),
        embedded: collect_certificates(&sd),
    })
}

// ---- the public entry points ---------------------------------------------------------------------

/// FULLY verify an RFC 3161 `TimeStampResp` (DER) against an `expected_root` and a set of
/// caller-supplied `trusted_roots` (each a DER-encoded X.509 CA certificate). See the module docs for
/// exactly what is and is NOT checked. `Ok(VerifiedTst)` iff EVERY check passes; otherwise a specific
/// [`TstVerifyError`]. Offline, deterministic, no network, no AWS.
pub fn verify_tst_full(
    resp_der: &[u8],
    expected_root: Hash,
    trusted_roots: &[Vec<u8>],
) -> Result<VerifiedTst, TstVerifyError> {
    // Shared parse + imprint + signed-attributes path (same core P2 uses — see the note above).
    let checked = parse_and_verify_signed_attrs(resp_der, expected_root)?;

    // --- locate the signer certificate embedded in the token -----------------------------------
    let signer_cert = find_signer_cert(&checked.embedded, &checked.sid).ok_or_else(|| {
        TstVerifyError::ParseError("signer certificate not embedded in the token".into())
    })?;

    // --- (1) CMS signature over the signed attributes, keyed on the token's EMBEDDED signer cert --
    // In P4 the embedded cert is only a CHAIN CANDIDATE — its authenticity is decided by (4), chaining
    // it to a caller-trusted root. (P2 instead keys this same check on a PINNED cert — verify_tst_pinned.)
    verify_signature(
        &signer_cert.tbs_certificate.subject_public_key_info,
        &checked.cms_sig_alg,
        &checked.signed_attrs_der,
        &checked.cms_signature,
    )?;

    let gen_time_unix = checked.gen_time_unix;

    // --- (4) EKU + end-entity + validity + chain to a trusted root -----------------------------
    // F3 / RFC 3161 §2.3: the EKU extension MUST be critical and id-kp-timeStamping its SOLE purpose.
    check_timestamping_eku(&signer_cert)?;
    // HIGH-3 / RFC 3161 §2.3: the signer MUST be a leaf, not a CA (even one with the timeStamping EKU).
    require_end_entity(&signer_cert)?;
    if gen_time_unix < cert_not_before_unix(&signer_cert)
        || gen_time_unix > cert_not_after_unix(&signer_cert)
    {
        return Err(TstVerifyError::Expired);
    }

    let roots: Vec<Certificate> = trusted_roots
        .iter()
        .map(|d| {
            Certificate::from_der(d)
                .map_err(|e| TstVerifyError::ParseError(format!("trusted root: {e}")))
        })
        .collect::<Result<_, _>>()?;
    let trusted_root_subject =
        build_chain_to_root(&signer_cert, &checked.embedded, &roots, gen_time_unix)?;

    Ok(VerifiedTst {
        gen_time_unix,
        serial: checked.serial,
        signer_subject: dn(&signer_cert.tbs_certificate.subject),
        trusted_root_subject,
        cms_sig_alg: checked.cms_sig_alg.to_string(),
    })
}

/// ADR-043 C1 **P2** (mac-lead ratified, msg-b2baf7f0) — the PRODUCER-side anchor **authenticity**
/// check the builder runs before it may mark a root `anchored=true`.
///
/// Verify that an RFC 3161 `TimeStampResp` (DER) covers `expected_root` AND that its CMS `SignerInfo`
/// signature was produced by the private key of a PINNED, out-of-band-configured TSA signing
/// certificate (`pinned_signer_cert_der`, a DER X.509 cert). Unlike [`verify_tst_full`] (P4) — which
/// trusts the token's OWN embedded signer cert as a chain candidate and decides authenticity by
/// chaining it to a trusted root — THIS verifies the signature DIRECTLY against the pinned cert's
/// public key. So a forger who re-signs the token with their own key and swaps in their own embedded
/// cert does NOT pass: the pinned key never signed their `SignerInfo`. That is the load-bearing point
/// closing the `extract_` ≠ `verify_` gap (imprint-only [`crate::anchor::extract_tst_facts_matching_root`]
/// would accept such a forgery; this rejects it).
///
/// Shares the SAME parse + signed-attributes path ([`parse_and_verify_signed_attrs`]) and the SAME
/// [`verify_signature`] primitive as P4 — only the verifying key differs (pinned here, embedded there)
/// — so the two never fork. Returns the [`crate::anchor::TstFacts`] the producer records. Errors:
/// [`TstVerifyError::ImprintMismatch`] (root ≠ imprint — checked FIRST),
/// [`TstVerifyError::SigInvalid`] (signed-attrs don't bind, OR the signature does not verify under the
/// pinned key), [`TstVerifyError::ParseError`] / [`TstVerifyError::Unsupported`] (fail-closed).
///
/// SCOPE (P2): authenticity of the SIGNER via a pinned key. It does NOT walk an X.509 chain, check the
/// pinned cert's EKU/validity, or do revocation — those are the P4 auditor verifier's job. Here the
/// pinned cert IS the trust decision (an operator pins the exact TSA signer out-of-band).
pub fn verify_tst_pinned(
    resp_der: &[u8],
    expected_root: Hash,
    pinned_signer_cert_der: &[u8],
) -> Result<crate::anchor::TstFacts, TstVerifyError> {
    // Same shared parse + imprint + signed-attributes core as P4 (imprint checked first).
    let checked = parse_and_verify_signed_attrs(resp_der, expected_root)?;

    let pinned = Certificate::from_der(pinned_signer_cert_der)
        .map_err(|e| TstVerifyError::ParseError(format!("pinned signer certificate: {e}")))?;

    // The load-bearing AUTHENTICITY check: the CMS SignerInfo signature MUST verify under the PINNED
    // cert's public key — NOT the token's embedded cert. Same verify_signature primitive P4 uses on
    // the embedded key, so there is exactly ONE signature path.
    verify_signature(
        &pinned.tbs_certificate.subject_public_key_info,
        &checked.cms_sig_alg,
        &checked.signed_attrs_der,
        &checked.cms_signature,
    )?;

    Ok(crate::anchor::TstFacts {
        gen_time_unix: checked.gen_time_unix,
        serial: checked.serial,
    })
}

/// Parse a single PEM-encoded X.509 certificate into its DER bytes. A small convenience for callers
/// (e.g. the P1b producer builder) that hold a PINNED TSA cert as PEM config but call
/// [`verify_tst_pinned`], which takes DER. Feature-gated with the rest of the verifier crypto.
///
/// TOLERANT of surrounding whitespace: each line is trimmed and blank lines dropped BEFORE decoding.
/// The RFC 7468 decoder is strict (leading whitespace on a base64 line — e.g. from a Terraform `<<-`
/// heredoc that did not fully dedent, or a pasted indented cert — is otherwise rejected as invalid
/// PEM). Trimming per line is safe: PEM base64 lines never carry internal whitespace.
pub fn cert_pem_to_der(pem: &str) -> Result<Vec<u8>, TstVerifyError> {
    use der::DecodePem;
    let normalized: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let cert = Certificate::from_pem(normalized.as_bytes())
        .map_err(|e| TstVerifyError::ParseError(format!("pinned cert PEM decode: {e}")))?;
    cert.to_der()
        .map_err(|e| TstVerifyError::ParseError(format!("re-encode pinned cert to DER: {e}")))
}

/// True iff the cert's ExtendedKeyUsage extension CONTAINS id-kp-timeStamping (presence-only). Weaker
/// than [`check_timestamping_eku`] (which also requires critical + sole for RFC 3161 conformance); a
/// misconfiguration guard only wants to know "does this look like a TSA signer at all?".
fn cert_eku_contains_timestamping(cert: &Certificate) -> bool {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts.iter() {
            if ext.extn_id == ExtendedKeyUsage::OID {
                if let Ok(eku) = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) {
                    return eku.0.contains(&ID_KP_TIME_STAMPING);
                }
            }
        }
    }
    false
}

/// Non-cryptographic FACTS about a pinned TSA signer certificate, for a producer's INIT-TIME
/// misconfiguration guard + expiry lead-time monitoring (ADR-043 P2). Deliberately does NOT verify
/// anything — mac-lead scoped hard cert-validity/chain checks to the P4 offline verifier; this is a
/// classification an operator can act on before the `AnchorVerifyFailures` outcome-alarm ever fires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedCertInfo {
    /// The certificate's Subject DN (RFC 4514), for the warning message.
    pub subject: String,
    /// Whether the EKU extension contains id-kp-timeStamping. A TSA SIGNER must; a CA root (a common
    /// mis-pin) does not — `false` here almost always means "you pinned the wrong cert".
    pub has_timestamping_eku: bool,
    /// basicConstraints CA:TRUE. A TSA SIGNER is an end-entity leaf; `true` here (e.g. the issuing CA
    /// root) means the pinned key never signs the CMS SignerInfo, so live tokens will fail P2 auth.
    pub is_ca: bool,
    /// The certificate's `notAfter`, seconds since the Unix epoch — for days-until-expiry monitoring.
    pub not_after_unix: u64,
}

/// Parse a DER X.509 certificate and extract the non-cryptographic [`PinnedCertInfo`] facts (EKU
/// presence, CA flag, `notAfter`) a producer uses at INIT to warn on a mis-pinned cert and to monitor
/// expiry lead-time. Reuses the module's existing cert helpers; no verification is performed.
pub fn inspect_pinned_cert(cert_der: &[u8]) -> Result<PinnedCertInfo, TstVerifyError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| TstVerifyError::ParseError(format!("inspect pinned cert: {e}")))?;
    Ok(PinnedCertInfo {
        subject: dn(&cert.tbs_certificate.subject),
        has_timestamping_eku: cert_eku_contains_timestamping(&cert),
        is_ca: cert_is_ca(&cert),
        not_after_unix: cert_not_after_unix(&cert),
    })
}

/// Pull every X.509 `Certificate` embedded in the SignedData `certificates` field.
fn collect_certificates(sd: &SignedData) -> Vec<Certificate> {
    use cms::cert::CertificateChoices;
    let mut out = Vec::new();
    if let Some(set) = &sd.certificates {
        for choice in set.0.iter() {
            if let CertificateChoices::Certificate(c) = choice {
                out.push(c.clone());
            }
        }
    }
    out
}

/// Find the embedded cert matching the `SignerIdentifier` (IssuerAndSerialNumber or SKI).
fn find_signer_cert(certs: &[Certificate], sid: &SignerIdentifier) -> Option<Certificate> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => certs
            .iter()
            .find(|c| {
                c.tbs_certificate.serial_number == ias.serial_number
                    && c.tbs_certificate.issuer == ias.issuer
            })
            .cloned(),
        SignerIdentifier::SubjectKeyIdentifier(ski) => certs
            .iter()
            .find(|c| cert_ski(c).as_deref() == Some(ski.0.as_bytes()))
            .cloned(),
    }
}

/// The SubjectKeyIdentifier extension bytes of a cert, if present.
fn cert_ski(cert: &Certificate) -> Option<Vec<u8>> {
    use x509_cert::ext::pkix::SubjectKeyIdentifier;
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id == SubjectKeyIdentifier::OID {
            if let Ok(ski) = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()) {
                return Some(ski.0.as_bytes().to_vec());
            }
        }
    }
    None
}

/// Get the FIRST value of the signed attribute with `oid`, as a borrowed `Any`.
fn get_attr_value<'a>(
    attrs: &'a cms::signed_data::SignedAttributes,
    oid: &ObjectIdentifier,
) -> Option<&'a Any> {
    attrs
        .iter()
        .find(|a| a.oid == *oid)
        .and_then(|a| a.values.iter().next())
}

#[cfg(test)]
mod chain_tests {
    //! Chain-validation NEGATIVE tests (AI-review #2002 HIGH-1/2/3), driven by a synthetic OpenSSL
    //! PKI committed under `tests/fixtures/synthetic/` (see that dir's README). These drive the exact
    //! trust-anchor / chain-walk / signer-leaf paths the real freeTSA vector cannot produce (it can't
    //! forge freeTSA-signed adversarial certs). The RSA-SHA256 and ECDSA-P256-SHA256 chains here also
    //! exercise those `verify_signature` dispatch branches (AI-review #2002 LOW-2 coverage gap).
    use super::*;
    use x509_cert::der::Decode;

    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/synthetic/");
    /// A time safely inside every synthetic cert's validity window (notBefore ~2026-07, notAfter ~2046).
    const T: u64 = 1_800_000_000; // 2027-01-15 UTC

    fn cert(name: &str) -> Certificate {
        let der =
            std::fs::read(format!("{FIX}{name}")).unwrap_or_else(|e| panic!("read {name}: {e}"));
        Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
    }

    // ---- positive chains (also cover verify_signature: RSA-SHA256 self-sig + ECDSA-P256) ---------

    #[test]
    fn direct_chain_to_selfsigned_root_ok() {
        // inter (RSA) signed by the self-signed RSA root; root is a valid self-signed CA anchor.
        let dn = build_chain_to_root(&cert("syn_inter.der"), &[], &[cert("syn_root.der")], T)
            .expect("direct chain must verify");
        assert!(dn.contains("MLC-Test-Root"), "anchored at root: {dn}");
    }

    #[test]
    fn multilevel_chain_with_intermediate_ok() {
        // leaf -> inter -> root, exercising the backtracking intermediate walk (MEDIUM-2).
        let dn = build_chain_to_root(
            &cert("syn_leaf.der"),
            &[cert("syn_inter.der")],
            &[cert("syn_root.der")],
            T,
        )
        .expect("3-level chain must verify");
        assert!(dn.contains("MLC-Test-Root"));
    }

    #[test]
    fn ec_p256_direct_chain_ok() {
        // EROOT/ELEAF are P-256 → exercises the ECDSA-P256-SHA256 branch of verify_signature.
        let dn = build_chain_to_root(&cert("syn_eleaf.der"), &[], &[cert("syn_eroot.der")], T)
            .expect("EC chain must verify");
        assert!(dn.contains("MLC-Test-ECRoot"));
    }

    // ---- HIGH-1: a substituted trusted root (same issuer identity) must NOT silently pass --------

    #[test]
    fn high1_same_dn_matching_ski_wrong_key_is_explicit_chaininvalid() {
        // rootfake_ski: subject == inter.issuer AND SKI == the real root's SKI (defeats the AKI/SKI
        // filter), but a DIFFERENT key. The TERMINAL signature check must fail LOUD — not fall
        // through to the intermediate walk (that silent fall-through was the HIGH-1 finding).
        match build_chain_to_root(
            &cert("syn_inter.der"),
            &[],
            &[cert("syn_rootfake_ski.der")],
            T,
        ) {
            Err(TstVerifyError::ChainInvalid(m)) => {
                assert!(
                    m.contains("did not sign"),
                    "explicit terminal sig failure, got: {m}"
                );
            }
            other => panic!("expected explicit ChainInvalid, got {other:?}"),
        }
    }

    #[test]
    fn high1_same_dn_different_ski_is_filtered_and_rejected() {
        // rootfake: same subject DN but a DIFFERENT SKI than inter's AKI → filtered by the AKI/SKI
        // disambiguation, so it never anchors → ChainInvalid (does not chain). No false VERIFIED.
        assert!(matches!(
            build_chain_to_root(&cert("syn_inter.der"), &[], &[cert("syn_rootfake.der")], T),
            Err(TstVerifyError::ChainInvalid(_))
        ));
    }

    // ---- HIGH-2: a non-self-signed cert supplied as the trusted anchor must be rejected ----------

    #[test]
    fn high2_non_selfsigned_anchor_rejected() {
        // `inter` DID sign `leaf`, but `inter` is NOT self-signed (it was issued by root). Supplying
        // it as the sole trusted root must be rejected by the self-signature guard (HIGH-2).
        match build_chain_to_root(&cert("syn_leaf.der"), &[], &[cert("syn_inter.der")], T) {
            Err(TstVerifyError::ChainInvalid(m)) => {
                assert!(
                    m.contains("self-signed"),
                    "self-sign guard message, got: {m}"
                );
            }
            other => panic!("expected ChainInvalid(not self-signed), got {other:?}"),
        }
    }

    // ---- HIGH-3: a CA cert (even with the timeStamping EKU) must not be the signer leaf ----------

    #[test]
    fn high3_ca_signer_is_signernotleaf() {
        let cats = cert("syn_cats.der"); // CA:TRUE + critical/sole EKU timeStamping
        assert!(cert_is_ca(&cats), "fixture must be a CA");
        assert_eq!(
            check_timestamping_eku(&cats),
            Ok(()),
            "fixture must carry a critical, sole timeStamping EKU"
        );
        assert_eq!(
            require_end_entity(&cats),
            Err(TstVerifyError::SignerNotLeaf)
        );
        // a genuine end-entity leaf passes.
        assert_eq!(require_end_entity(&cert("syn_leaf.der")), Ok(()));
    }

    #[test]
    fn empty_trusted_roots_is_chaininvalid() {
        assert!(matches!(
            build_chain_to_root(&cert("syn_inter.der"), &[], &[], T),
            Err(TstVerifyError::ChainInvalid(_))
        ));
    }

    // ---- F1: DoS work-budget — the backtracking walk terminates in BOUNDED work ------------------

    #[test]
    fn f1_too_many_embedded_certs_is_chainsearchexhausted() {
        // A hostile token stuffing more than MAX_EMBEDDED_CERTS candidate CAs (here: the same CA
        // cloned, i.e. a same-key cluster) is rejected OUTRIGHT before the walk — bounded work, a
        // distinct fail-closed error, never a hang and never a false VERIFIED.
        let inter = cert("syn_inter.der");
        let many: Vec<Certificate> = std::iter::repeat_n(inter, MAX_EMBEDDED_CERTS + 1).collect();
        match build_chain_to_root(&cert("syn_leaf.der"), &many, &[cert("syn_root.der")], T) {
            Err(TstVerifyError::ChainSearchExhausted(m)) => {
                assert!(
                    m.contains("candidate certificates"),
                    "cap message, got: {m}"
                );
            }
            other => panic!("expected ChainSearchExhausted (embedded-cert cap), got {other:?}"),
        }
    }

    #[test]
    fn f1_same_key_cluster_under_cap_dedups_and_terminates() {
        // A cluster of identical CA clones UNDER the cap, with a WRONG (non-anchoring) root: the
        // (subject, SKI) visited-set collapses the cluster so the walk does NOT explore K paths — it
        // terminates quickly as "does not chain" (ChainInvalid), not a K^depth hang. Proves the
        // visited-set path, complementing the count-cap test above.
        let inter = cert("syn_inter.der");
        let cluster: Vec<Certificate> = std::iter::repeat_n(inter, MAX_EMBEDDED_CERTS).collect();
        // syn_eroot is a real self-signed CA but unrelated to this chain → never anchors syn_leaf.
        match build_chain_to_root(&cert("syn_leaf.der"), &cluster, &[cert("syn_eroot.der")], T) {
            Err(TstVerifyError::ChainInvalid(_)) => {}
            other => panic!("expected ChainInvalid (bounded, does-not-chain), got {other:?}"),
        }
    }

    // ---- F2: digest/sig-alg cross-check (RFC 5652 §5.3, the open AI MEDIUM) -----------------------

    #[test]
    fn f2_digest_alg_mismatching_sig_alg_is_siginvalid() {
        use super::{
            require_consistent_digest_alg, OID_ECDSA_SHA256, OID_RSA_SHA256, OID_SHA256,
            OID_SHA384, OID_SHA512,
        };
        // digestAlgorithm (SHA-512) disagrees with the hash the signatureAlgorithm (RSA-SHA256)
        // implies → SigInvalid. This is the F2 finding: a token whose messageDigest hash differs from
        // the signature's bound hash must NOT verify.
        assert_eq!(
            require_consistent_digest_alg(&OID_SHA512, &OID_RSA_SHA256),
            Err(TstVerifyError::SigInvalid)
        );
        assert_eq!(
            require_consistent_digest_alg(&OID_SHA384, &OID_ECDSA_SHA256),
            Err(TstVerifyError::SigInvalid)
        );
        // Consistent pair verifies (returns the resolved HashKind, so Ok).
        assert!(require_consistent_digest_alg(&OID_SHA256, &OID_RSA_SHA256).is_ok());
        assert!(require_consistent_digest_alg(&OID_SHA256, &OID_ECDSA_SHA256).is_ok());
    }

    // ---- F3: EKU criticality/sole-purpose (RFC 3161 §2.3) ----------------------------------------

    #[test]
    fn f3_noncritical_eku_is_rejected() {
        // EKU carries timeStamping but the extension is NOT marked critical → rejected.
        assert_eq!(
            check_timestamping_eku(&cert("syn_leaf_eku_noncrit.der")),
            Err(TstVerifyError::EkuNotCriticalOrNotSole)
        );
    }

    #[test]
    fn f3_extra_eku_purpose_is_rejected() {
        // EKU is critical and contains timeStamping BUT also clientAuth → not the sole purpose → rejected.
        assert_eq!(
            check_timestamping_eku(&cert("syn_leaf_eku_extra.der")),
            Err(TstVerifyError::EkuNotCriticalOrNotSole)
        );
    }

    #[test]
    fn f3_critical_sole_timestamping_eku_ok() {
        // The genuine leaf (critical, sole timeStamping) still passes — no regression of the good path.
        assert_eq!(check_timestamping_eku(&cert("syn_leaf.der")), Ok(()));
        assert_eq!(check_timestamping_eku(&cert("syn_eleaf.der")), Ok(()));
    }

    // ---- Test-debt negatives (mac-lead: each fails-closed; add explicit coverage) -----------------

    #[test]
    fn negative_missing_eku_extension_is_ekumissing() {
        // (iii) an end-entity leaf with NO EKU extension at all → EkuMissing (distinct from the
        // non-critical / not-sole EkuNotCriticalOrNotSole case).
        assert_eq!(
            check_timestamping_eku(&cert("syn_leaf_noeku.der")),
            Err(TstVerifyError::EkuMissing)
        );
    }

    #[test]
    fn negative_cert_expired_at_gentime_is_expired() {
        // (iv) a genTime AFTER the anchor's notAfter → Expired (not a silent pass). The synthetic
        // root's window ends ~2046; a genTime in 2065 is outside it.
        const YEAR_2065: u64 = 3_000_000_000;
        assert_eq!(
            build_chain_to_root(
                &cert("syn_inter.der"),
                &[],
                &[cert("syn_root.der")],
                YEAR_2065
            ),
            Err(TstVerifyError::Expired)
        );
    }

    #[test]
    fn negative_unsupported_sig_alg_never_ok() {
        use super::verify_signature;
        // (v) an unsupported signature algorithm (Ed25519, 1.3.101.112) → Unsupported, NEVER Ok. Uses
        // a real synthetic SPKI so the dispatch reaches the unsupported-algorithm arm, not a parse error.
        let leaf = cert("syn_leaf.der");
        let ed25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
        match verify_signature(
            &leaf.tbs_certificate.subject_public_key_info,
            &ed25519,
            b"message",
            b"signature",
        ) {
            Err(TstVerifyError::Unsupported(_)) => {}
            other => panic!("unsupported alg must fail closed as Unsupported, got {other:?}"),
        }
    }
}
