# TOS PQ-Native — Q1–Q6 Implementation Plan

Baseline: `doc/pq-native/DESIGN-DIRECTION.md` (PQ-native from Genesis, minimal
crypto agility, resource-budget-first). Branch `feat/pq-native`, off `main`
`2004ce5e6`. The abandoned `feat/validator-auth-p0` is research reference only.

## What already exists on `main` (build on this, don't rebuild)

| Asset | Where | Use |
|---|---|---|
| ML-DSA-44 verify + keygen/sign | `crypto/pq/mldsa44.{h,cpp}`, `crypto/pq/tools/key-tool.cpp` | Q1 primitive (verify + CLI keygen/public/sign) |
| ML-DSA-44 sizes | pub **1312 B**, sig **2420 B**, ctx ≤255, msg ≤8192 | resource-budget constants |
| VM PQ opcodes | `crypto/vm/pqops.{h,cpp}`, `tosctl/src/vm/src/executor/pq.rs`, `tosctl/src/vm/pq-config.h` | Q6 (TVM/wallet verify) |
| Variable-length consensus sigs | `validator/consensus/simplex/candidate-resolver.cpp` (`signature.signature.size()`), `voteSignatureSet` | Q3 already tolerates non-64-byte sigs |

## The core gaps

- `tos/tos-types.h:487` `ValidatorDescr.key` is `Ed25519_PublicKey` (fixed 256-bit) → **Q2**.
- `crypto/block/block.tlb:600` `ed25519_signature#5 = CryptoSignature`; `block_signatures_ordinary#11` / `#12` carry `HashmapE 16 CryptoSignaturePair` with fixed 64-byte sigs → **Q4**.
- `crypto/block/check-proof.cpp` verifies the 64-byte path → **Q5**.
- `ConfigParam16` (`block.tlb:713`) has no PQ resource-budget enforcement → **budget gate**.

## Identity/address layering (applies across all Q)

~~~text
Address / Validator ID / Key ID  = fixed 32 bytes
PQ public key                    = variable (1312 B for ML-DSA-44), chain-state only
key_id  = Hash(domain || algorithm_id || public_key)
~~~
Validator ID / Key ID never expand to the full key in wallet/RPC/explorer by default.

## PQ suite + resource budget (the real hard limit)

Minimal suite (not a policy system):
~~~text
PQSuite { algorithm_id; max_public_key_bytes; max_signature_bytes }
ML-DSA-44: algorithm_id=<fixed>, max_public_key_bytes=1312, max_signature_bytes=2420
~~~
Frozen budget a mainnet config MUST satisfy (genesis has exactly one active suite;
unknown algorithm_id fails closed; no local algorithm choice; no Ed25519 fallback):
~~~text
committee_size <= max_main_validators
committee_size * max_signature_bytes + certificate_framing <= max_certificate_bytes
worst_case_certificate_verification <= consensus_verification_budget
~~~
A `ConfigParam16` change that breaks the budget → the node **rejects the config**
(never truncate signers, shrink signatures, or silently downgrade).

## Q1–Q6, in dependency order

### Q1 — PQ sign/verify primitive  *(mostly present)*
- Present: `verify_mldsa44`, sizes, keygen/sign CLI. 
- Do: expose a clean library sign/keygen API (not only the CLI); a `PQSuite`
  descriptor with `algorithm_id` + the two byte caps; `key_id` helper
  `Hash(domain‖algorithm_id‖public_key)`; unknown-`algorithm_id` fail-closed.
- Gate: C++/Rust KAT vectors for ML-DSA-44 (sign/verify/malformed), byte-exact.

### Q2 — ValidatorSet carries PQ public keys
- Do: `ValidatorDescr` gains `{ algorithm_id, pq_public_key (var), validator_id:32 }`
  while keeping `weight` + `addr` (ADNL). Validator ID stays 32 bytes; the full key
  is state-only. `ValidatorSet` hash/compare uses the 32-byte IDs + key_id, not the
  raw key. Election / config param 34/35 carry the PQ key.
- Gate: a ValidatorSet round-trips PQ descriptors; `get_validator` by 32-byte id.

### Q3 — Simplex proposal/vote/certificate use PQ signatures
- Do: vote/certificate signature fields carry `{algorithm_id, signature(var)}`;
  verification calls `verify_mldsa44` over the exact signed statement. Reuse the
  existing variable-length handling; remove any 64-byte assumptions in the vote path.
- Gate: single-node then multi-node Simplex round with ML-DSA-44; conflict rules
  (notarize/finalize/skip) preserved.

### Q4 — BlockSignatures / BlockProof become PQ-native
- Do: a PQ-native `BlockSignatures` TL-B constructor (variable-length signature per
  signer, `algorithm_id`), and a PQ `CryptoSignature`/pair form; `accept-block`,
  `top-shard-descr`, `validate-broadcast` produce/consume it. Weighted-quorum rules
  unchanged. (Genesis is PQ-only, so this can be the sole finality form — no era
  split, no legacy `#11/#12` coexistence required by protocol.)
- Gate: block proof round-trips; quorum verification; golden vectors.

### Q5 — Lite client verifies PQ finality proofs
- Do: `crypto/block/check-proof.cpp` / `BlockProofLink::validate` verify the PQ
  BlockSignatures against the PQ ValidatorSet from the key block; `lite_api.tl`
  signature set carries PQ sigs; Rust lite verifier implemented (no
  `UNSUPPORTED` placeholder — genesis is PQ, so the lite path must verify PQ).
- Gate: C++ and Rust lite verify parity on shared vectors.

### Q6 — Wallet / TVM PQ signature verification  *(mostly present)*
- Present: `pqops` + `pq.rs` VM opcodes.
- Do: confirm the wallet/account verification path uses the PQ opcode; key import
  and address derivation (address independent of key). 
- Gate: C++/Rust VM opcode parity; a PQ wallet signs+verifies a transfer.

## Cross-cutting deliverables (per baseline §7–8)
- genesis tooling (21 active validators, PQ registry), key generation/import.
- RPC / block-explorer display of 32-byte ID / Key ID (expand key on demand).
- cross-language C++/Rust vectors for every Q.
- multi-node consensus rehearsal (4 → 21).
- **measurements at 21 / 32 / 64 / 100 validators** BEFORE fixing genesis params:
  pubkey state size, single-sig size, full certificate size, cert verification
  latency, proposal/vote propagation, block-size impact, CPU/memory, lite-proof
  size + verify cost. These pick: genesis active count, `max_main_validators`,
  `max_certificate_bytes`, verification budget, propagation budget.

## Suggested genesis config direction (from baseline, to be confirmed by measurement)
~~~text
genesis active masterchain validators = 21
max_main_validators = 100   max_validators = 400   min_validators = 4
PQ suite = ML-DSA-44 (pub 1312, sig 2420)
~~~

## Explicit non-goals (do not reintroduce from the abandoned branch)
Config46 validator-auth registry; C0/C2/C3 phases; five-role key hierarchy; VAC1
universal certificate; signer-permit hierarchy; legacy/PQ era split; migration
checkpoints; historical fallback; multi-algorithm coexistence. DA/ZK/cross-chain
redesign and unrelated node-actor refactors are out of scope for this phase.

## Sequencing
Q1 (finish primitive/suite) → Q2 (ValidatorSet) → Q3 (Simplex) → Q4 (BlockProof)
→ Q5 (lite) → Q6 (wallet/TVM), with the resource-budget gate landing with Q2/Q4
and the measurement harness landing alongside Q3/Q4 (it needs a real committee +
certificate to measure).
