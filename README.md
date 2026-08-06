# meshlogic-merkle

The **MAC-1 Merkle commitment core** and the **M6-c signed decision-chain** — MeshLogic's tamper-evidence primitive.

This crate is **extracted standalone** (from the platform monorepo) for one reason: it must be **byte-identical everywhere the evidence chain is produced OR verified** — the Windows agent, the macOS agent, the driver, and MESHLOGIC03's independent Python re-deriver. A crypto/canonicalization primitive behind a monorepo git-dep (rev-pin drift) or a vendored copy (format fork) is exactly where drift is unacceptable. One source of truth, one light dep.

## What's here
- **`signed_leaf`** — the ADR-062 per-agent Ed25519 signed `CommitmentLeaf` (domain-separated preimage `MeshLogic/CommitmentLeaf/v1 || 0x00 || JCS(leaf)`), fail-closed against a pinned fleet trust store. *(feature `leaf-verify`)*
- **`decision_chain`** — the **M6-c increment-1a** per-decision signed **hash-linked chain** + the independent re-deriver (`verify_decision_chain`), plus the on-disk `cooperation-decisions.jsonl` append/load helpers the deployed reader consumes. Un-enrolled boxes emit honest **unsigned** rows (never fixture-sign a prod proof). *(feature `leaf-verify`)*
- **`commitment_leaf` / `jcs` / `roots_chain` / `chain_verify` / `anchor` / `coanchor`** — RFC 6962 Merkle over ADR-042 `content_hash` leaves, the JCS (RFC 8785) canon, the period roots-chain (increment-2 accumulator), and the RFC 3161 / Rekor anchoring + offline verifier.

## Consuming it (git dependency, rev-pinned)
```toml
meshlogic-merkle = { git = "https://github.com/MeshLogic-Pty-Ltd/meshlogic-merkle.git", rev = "<sha>", features = ["leaf-verify"] }
```

## Chain format (the frozen cross-platform contract)
- `content_hash = sha256_hex(canonical_preimage)`  ·  `canon_spec_version = "MLCH-1"`
- `chain_hash_n = sha256_hex( prev_tip_hex + content_hash_hex )`, genesis `prev_tip = ""`
- on-disk row serializes the chain-link as **`"hash"`** (the deployed `read_decision_chain` tip field)
- signature: Ed25519 over `MeshLogic/CommitmentLeaf/v1 || 0x00 || JCS(leaf_envelope)`
- `identity = {endpoint_id, org_id, event_sequence, event_class, captured_at}` — **integers stay integers** (RFC-8785 ↔ `json.dumps` parity)

The independent verifier is MESHLOGIC03's `evchain-verify.py`; two implementations of one spec is the auditor-proof posture.

## Honesty tier
1a earns *"tamper-evident chain exists + re-derives within a trusted-boot session."* Robustness across host compromise gates on the per-agent signing key (1a-key), an external rewind counter, and the periodic external anchor (increment 2).
