# P4 offline-verifier test fixtures — REAL RFC 3161 vector

These are a **genuine** freeTSA (https://freetsa.org) RFC 3161 Time-Stamp vector, not synthetic. They
are the ground truth for `tests/offline_verify.rs` (the `anchor::verify_tst_full` crypto-correctness
gate) and the `commitment_proof_verify` end-to-end test.

## Provenance / how to regenerate

The token timestamps the **frozen KAT p2 Merkle root** used across the crate's proof tests
(`proof_gen.rs` `P2_ROOT`), so one token serves both the crypto tests and the bundle test:

```
ROOT=5fb58d89ca9e40abece0d6b1447d5783094112244c17e9b5b7aa5c89c84f8012   # proof_gen P2_ROOT

# request (imprint = ROOT, sha256, embed signer cert), POST to freeTSA:
openssl ts -query -digest "$ROOT" -sha256 -cert -out req.tsq
curl -H "Content-Type: application/timestamp-query" --data-binary @req.tsq \
     https://freetsa.org/tsr -o freetsa_kat_response.tsr

# the trusted CA root (the auditor's out-of-band anchor):
curl https://freetsa.org/files/cacert.pem -o freetsa_cacert.pem
openssl x509 -in freetsa_cacert.pem -outform DER -out freetsa_cacert.der

# the signer LEAF cert (used only for the "wrong trusted root" negative test):
curl https://freetsa.org/files/tsa.crt -o freetsa_tsa_leaf.crt
openssl x509 -in freetsa_tsa_leaf.crt -outform DER -out freetsa_tsa_leaf.der
```

Independently confirmed with OpenSSL before committing:

```
$ openssl ts -verify -digest $ROOT -in freetsa_kat_response.tsr -CAfile freetsa_cacert.pem
Verification: OK
```

## Files

| File                            | What                                                                                          | Used for                                |
| ------------------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------- |
| `freetsa_kat_response.tsr`      | `TimeStampResp` DER over `P2_ROOT`. Embeds the signer cert (ECDSA P-384) **and** the CA root. | the token under test                    |
| `freetsa_cacert.pem` / `.der`   | freeTSA CA root (self-signed, CA:TRUE, RSA).                                                  | the auditor-supplied trusted anchor     |
| `freetsa_tsa_leaf.crt` / `.der` | freeTSA TSA signing cert (CA:FALSE, EKU timeStamping).                                        | negative "wrong trusted root" test only |

## Crypto exercised by this vector

- **CMS SignerInfo signature:** `ecdsa-with-SHA512` (OID 1.2.840.10045.4.3.4) over an **ECDSA P-384**
  signer key; digest SHA-512; signed attributes `contentType`(id-ct-TSTInfo) + `messageDigest`.
- **Certificate chain signature (signer → CA root):** `sha512WithRSAEncryption` (RSA-PKCS1 SHA-512).
- Facts: `genTime` = 1783338948 (2026-07-06 11:55:48 UTC), serial = `0x05FD9908`.

Note: freeTSA's live signer is P-384/SHA-512, so the committed real-vector test concretely exercises
the ECDSA-P384 + RSA-SHA512 paths. The P-256 / RSA-SHA256 / SHA-384 branches share the same dispatch
but are not covered by a committed real vector here (freeTSA rotated off P-256).
