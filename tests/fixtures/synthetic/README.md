# Synthetic PKI fixtures — P4 chain-validation NEGATIVE tests (AI-review #2002 HIGH-1/2/3 + P4 fast-follows F1/F3)

These are **synthetic, public** OpenSSL-generated X.509 certificates (throwaway keys — NOT secrets)
used by the chain-validation unit tests in `src/tst_verify.rs` (`mod chain_tests`). The real freeTSA
vector (`../freetsa_*`) cannot produce the adversarial certs these tests need (you cannot sign certs
with freeTSA's CA key), so a small self-contained PKI is committed instead.

## Topology

```
syn_root         self-signed RSA CA  (CN=MLC-Test-Root)   ── valid trust anchor
 └─ syn_inter    RSA CA, signed by root (CN=MLC-Test-Inter, non-self-signed)
     └─ syn_leaf RSA end-entity, EKU timeStamping, CA:FALSE (CN=MLC-Test-TSA)

syn_eroot        self-signed P-256 CA (CN=MLC-Test-ECRoot)
 └─ syn_eleaf    P-256 end-entity, EKU timeStamping (CN=MLC-Test-ECTSA)

syn_rootfake     self-signed RSA CA, SAME subject DN as syn_root, DIFFERENT key, DIFFERENT SKI
syn_rootfake_ski self-signed RSA CA, SAME subject DN AND SAME SKI as syn_root, DIFFERENT key
syn_cats         self-signed RSA CA:TRUE that ALSO carries a critical/sole timeStamping EKU

# P4 fast-follow EKU fixtures (F3 / test-debt): self-signed RSA end-entities (CA:FALSE); only the EKU
# extension is inspected by check_timestamping_eku, so no chaining/keys are needed.
syn_leaf_noeku        end-entity, NO Extended Key Usage extension at all
syn_leaf_eku_noncrit  end-entity, EKU=timeStamping but the extension is NOT critical
syn_leaf_eku_extra    end-entity, EKU critical = timeStamping + clientAuth (not the sole purpose)
```

## What each proves

| Fixture(s)                            | Test                                                                                    | Finding             |
| ------------------------------------- | --------------------------------------------------------------------------------------- | ------------------- |
| `syn_inter` + `syn_root`              | direct chain verifies (RSA-SHA256 self-sig)                                             | positive / LOW-2    |
| `syn_leaf` + `syn_inter` + `syn_root` | 3-level chain via backtracking walk                                                     | positive / MEDIUM-2 |
| `syn_eleaf` + `syn_eroot`             | EC chain verifies (ECDSA-P256-SHA256)                                                   | positive / LOW-2    |
| `syn_rootfake_ski`                    | same DN + same SKI, wrong key → terminal sig check fails LOUD (not silent fall-through) | **HIGH-1**          |
| `syn_rootfake`                        | same DN, different SKI → filtered by AKI/SKI disambiguation → rejected                  | **HIGH-1**          |
| `syn_inter` as `--trusted-root`       | non-self-signed cert rejected as anchor                                                 | **HIGH-2**          |
| `syn_cats`                            | CA cert (with TS EKU) rejected as signer → SignerNotLeaf                                | **HIGH-3**          |
| `syn_inter` ×(N>64) as candidates     | embedded-cert count cap → `ChainSearchExhausted` (bounded work, no hang)                | **F1** (DoS)        |
| `syn_inter` ×64 + unrelated root      | same-key cluster collapsed by (subject,SKI) visited-set → bounded `ChainInvalid`        | **F1** (DoS)        |
| `syn_leaf_noeku`                      | no EKU extension → `EkuMissing`                                                         | test-debt (iii)     |
| `syn_leaf_eku_noncrit`                | EKU present but not critical → `EkuNotCriticalOrNotSole`                                | **F3**              |
| `syn_leaf_eku_extra`                  | EKU critical but timeStamping not sole → `EkuNotCriticalOrNotSole`                      | **F3**              |

## Regenerate

Certs are valid 2026-07 .. ~2046 (20-year window) so tests do not rot. To regenerate, see the
`openssl` commands in the PR #2002 discussion; keys are ephemeral and intentionally not committed.
