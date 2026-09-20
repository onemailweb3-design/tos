# Shielded pool: implementation branch

This branch (`feat/shielded-pool`) is where the protocol-native shielded transfer
pool gets built. It does not hold the design. The design, its evidence, the
open decisions and the review record live in the `memo` repository under
`privacy/`, and this branch follows them:

| Document | Role |
|---|---|
| `privacy/TOS_SHIELDED_POOL_V1_IMPLEMENTATION_PROFILE.md` | **The coding input.** Normative for V1 wire, state and circuit behaviour; where any other privacy document disagrees with it, it wins. |
| `privacy/TOS_SHIELDED_POOL_SPEC.md` | The specification. Section 0 states what is hidden from whom; section 12 lists the safety gates that must close before production code; section 13 says what counts as proof. |
| `privacy/TOS_VS_EIP8182_PRIVACY.md` | What this design hides compared with the reference design, per party. |
| `privacy/TOS_SHIELDED_POOL_EIP8182_PORT.md` | Measurements and hard limits on this chain. |
| `privacy/TOS_POSEIDON2_OPCODE_WORK_ORDER.md` | The one instruction the pool needs to be worth shipping. |
| `privacy/TOS_SHIELDED_POOL_V1_OPEN_RULINGS.md` | **The rulings.** Questions the profile did not answer, and the answers given on 2026-09-20. A1 and A2 are carried out on this branch; the next review checks conformance, not the choice. |
| `privacy/TOS_SHIELDED_POOL_V1_OPEN_RULINGS_2.md` | The second register: what measuring the contract turned up afterwards, and the two confirmations the first register left open. |
| `privacy/REVIEW_PROMPT.md` | The standing invitation to find what is wrong. |

When this branch and those documents disagree, the documents win and the branch
is fixed.

## What is on this branch

Both probes below were run on this branch on a Linux host, against `func` and
`fift` built from this tree with clang-21. The sandbox looks for the compiler
at `build/crypto/func` and honours `TOS_ROOT`, so the build directory has to be
named `build` — the `build-clang21` that `BUILD.md` suggests is not found.

**The indexed Merkle tree**

- `tosctl/src/node-control/contracts/tests/imt_sandbox.rs` — an indexed Merkle
  tree run inside the VM through the sandbox, with a placeholder hash. It
  establishes that a dictionary costs exactly `2n - 1` cells for both 32-bit
  and 256-bit keys, which is what makes the 65,536-cell account limit a hard
  ceiling of 32,768 nullifiers, and that batching the path recomputation is not
  free: for two scattered leaves it saves one hash and costs about 10,000 more
  gas. Five mutations were run against it; four kill the test they target and
  the fifth survives correctly. Its measurement record is
  `memo/privacy/measurements/imt-in-tvm-20260920/`.

  It was first verified on `feat/validator-auth-p0`. **It has now been run on
  this branch**, on the Linux host, against a FunC compiler built from this
  tree: three tests, all green, reproducing the same `2n - 1` table for 32-bit
  and 256-bit keys and the same batching figures.

**Deposit binding and backing**

- `tosctl/src/node-control/contracts/tests/shielded_pool_deposit_sandbox.rs` — the
  two gates at the top of the safety list, P0-0 (the contract computes the note
  from the principal it actually admitted; a depositor-supplied commitment is
  read and ignored) and P0-1 (no `ACCEPT` anywhere; a deposit is refused with
  exit 40 rather than paid for from the pool; balance >= liability + reserve
  asserted after every transaction, once by the contract and once from account
  state). Four tests, all green, and the four mutations listed at the bottom of
  the file were each run and each turns its named test red.

  The first mutation run found a hole. `M2`, which inserts `accept_message()`
  into the deposit path, **left every test green**. The reason is worth keeping:
  each test's message carried enough value to buy the whole path either way, so
  with or without `ACCEPT` the deposit ended at the same exit 40 with the pool's
  balance untouched. A refusal the message can afford says nothing about who
  would have paid. The gate was asserted but not tested.

  Closing it needed a message in the window where the difference is visible.
  Measured on this executor at 400 nanotos per gas unit: below roughly 20,000
  nanotos the compute phase is skipped outright (`NoGas`) and the VM never runs,
  and at 520,000 the message buys the whole 1,259-gas path. A deposit carrying
  400,000 buys 1,000 gas and therefore dies halfway:

  | | exit code | gas used | pool balance |
  |---|---|---|---|
  | as written | `-14`, out of gas | 1,000 — exactly what it bought | unchanged |
  | with `accept_message()` | 40, reached a check it could not afford | 1,285 | **-114,000 nanotos** |

  `a_message_that_cannot_pay_for_its_own_gas_never_reaches_the_pools_balance`
  pins that row, and asserts first that the compute phase actually ran, so a
  future change that pushes the value below the skip threshold fails loudly
  instead of passing vacuously. `M2` now turns it red on the exit code, naming
  the 1,285 gas spent against 1,000 bought.

  The hash here is a placeholder (`cell_hash`). Nothing in this file depends on
  which hash is used, and nothing in it says anything about gas per transfer.

**The Poseidon2 instruction pair**

- `POSEIDON2_PERM8` (`0xF93200`) and `POSEIDON2_HASH7` (`0xF93201`), implemented
  in both VMs at global version 17, with the earlier signature instruction left
  on its own minimum of 16. The frozen t=8 parameters are generated from a
  pinned upstream commit by `crypto/poseidon2/manifest-gen`, which also emits
  the known-answer vectors — that reference publishes vectors only for narrower
  widths, so the t=8 ones had to be produced by running it. Each VM rebuilds the
  same manifest byte stream from its own tables and compares the digest.

  Seventeen mutations (`test/poseidon2/mutations.py`) are run against both VMs
  and each is killed by the assertion it was aimed at, with the other VM left
  green. Two are worth remembering: perturbing the internal matrix changes no
  output, because the permutation reads only the diagonal, so the manifest
  digest is the only thing standing behind that table; and running one fewer
  partial round leaves the manifest intact, so only the vectors catch it.

  The gas price is a **development tariff** of 3,000. It is not a measurement
  and not a production claim: benchmarking the pinned implementation on target
  CPUs and choosing a price with a stated margin still has to happen before
  activation, in both VMs at once.

**Note commitments and the commitment tree**

- `crypto/smartcont/shielded/` — sections 4 and 5 of the profile in FunC: the
  five commitment and nullifier constructions, and the 7-ary depth-12 tree with
  the canonical frontier store from 13.1. The domain constants and the
  empty-subtree ladder are generated, not written by hand: the profile forbids a
  hand-written domain table, and a contract recomputing the ladder would pay
  twelve permutations per append for a value that never changes.

  Two checks carry the weight. The frontier is incremental, so the suite also
  rebuilds the whole tree from every leaf and requires the two to agree at each
  of fifty appends across two group boundaries — a different computation, not
  the same one written twice. And the ladder is recomputed from the permutation
  and required to match the generated table.

  Canonical state must not store an explicit zero. A commitment is never zero,
  so that rule had no path to reach it until the suite appends a zero leaf: the
  slot must be absent rather than stored, the root must stay the empty root, and
  a later non-zero append must bring the slot back.

  Eight mutations (`test/shielded-pool/mutations.py`), each killed by the test
  it was aimed at.

  **The cross-check this section used to be waiting for now exists**, and it
  agrees. See the circuit entry below. What is still not established here is
  gas: these are get-methods, not a pool transaction.

**The nullifier indexed Merkle tree**

- `crypto/smartcont/shielded/imt.fc` — section 7 in FunC: the shape and leaf
  tuple, `IMT-LEAF` and `IMT-NODE`, the 7.0 empty-subtree ladder and the
  genesis sentinel root, the eight numbered steps of the 7.1 non-membership and
  insertion contract, and the canonical witness cell encoding of 7.2.

  The 7.0 ladder is built from `IMT-NODE` and is a *different* ladder from the
  `COMMIT-NODE` one generated in `empty-roots.fc`. No generated IMT table
  exists, so `imt.fc` recomputes it rather than carrying a hand-written
  constant; `imt_insert` never calls it, so the hot path pays nothing. The
  suite asserts the two ladders differ at every level, so reusing the wrong one
  later is caught. Generating an `IMT_EMPTY` table from `manifest-gen` would
  remove the recomputation and has not been done.

  `tosctl/src/node-control/contracts/tests/shielded_imt_sandbox.rs` runs all of
  it in a VM at global version 17: thirteen tests, closing section 19 gate 10.
  Two sequential nullifiers both insert, with the second witness taken against
  the root after the first; a bad successor tuple, a non-empty append slot, and
  duplicate or reordered witnesses each fail with a named exit code. A zero
  nullifier is refused because the head sentinel holds value zero and step 2 is
  strict — the sentinel is what reserves zero, not a rule of its own.

  The check that carries the weight is the one that is not a restatement. The
  contract folds a caller-supplied 72-element path into a root; the reference
  beside it never folds a path at all, but keeps a map from leaf index to tuple
  and rebuilds every level. A path that happens to fold to a plausible root
  cannot pass unnoticed.

  Thirty-four mutations (`test/shielded-pool/mutations-imt.py`), each killed by
  the test it was aimed at.

  Two guards here could not be killed and were ruled on rather than left
  annotated (register C1 and C2). The redundant half of step 4's capacity bound
  is **deleted**: the first half implies it, and a guard no test can reach is a
  guard nobody maintains. The non-zero allocated leaf hash is **kept and
  extracted** into `imt_require_allocated_leaf_hash`, which a mutation now hits
  directly — it is a property of the permutation rather than of any input, so
  it is an invariant worth stating once where it can be tested, not a check
  scattered through a parser.

  Section 7.2's "reject special cells" is delegated to `begin_parse`, which
  throws before the contract's own checks run. Rather than write a second
  exotic-cell detector in FunC, the suite now constructs **real** exotic cells:
  a pruned branch and a merkle proof, each placed at the witness root and at
  the head, middle and end of both paths, fourteen cases in all, each required
  to fail **before** this module's own field parsing — the criterion being an
  exit code that does not fall in this module's range.

**The intent digest and ML-DSA-44 authorization**

- `crypto/smartcont/shielded/auth.fc` — section 9 and the 4.1
  `pq_auth_key_hash` rule. The key hash is computed from the actual canonical
  1312-byte public-key byte chain, not from a pre-hashed input, enforcing the
  layout rules `crypto/vm/pqops.cpp` enforces for ML-DSA operands. The rule
  that a chunk carrying a reference must fill its cell is what makes a
  fixed-length operand's chain layout unique: 1312 is 10x127 + 42. Both halves
  of the digest and the final digest follow 9.3 exactly, and two full
  signatures are verified over the digest's 32 raw big-endian bytes under the
  fixed 28-byte context of 9.4 — always, including for a phantom slot, so
  nothing takes a shortcut for a slot that happens to be phantom.

  This chain ships an ML-DSA-44 **verifier only**: no signing, no key
  generation. Testing section 9 needs signatures over digests the contract
  computes, which cannot come from `test/pq-mldsa44/fixtures.json`. The suite
  therefore pins a test-only signer as a dev-dependency and proves
  interoperability before trusting it for anything else, in both directions:
  this repository's own fixture signatures verify under that signer, and the
  signer's signatures verify under `PQCHECKSIG_MLDSA44` inside the VM, with a
  wrong key and a wrong context both rejected so the verifier is not merely
  answering true. That test runs first and is a hard gate; if it fails nothing
  else in the file means anything.

  Eight tests close section 19 gate 6, using an attacker's own genuinely valid
  keypair whose signature is first shown to verify on chain — so the
  substitution is not defeated by a bad signature — and gate 8, comparing the
  full per-cell encoding of both bundles and requiring them equal in the
  one-real and two-real cases. Each of the fourteen fields the digest is
  specified to bind is changed alone and required to move the digest.

  Twenty-three mutations (`test/shielded-pool/mutations-auth.py`), each killed
  by the test it was aimed at.

  **What it does not establish**: nothing about how much a signature costs in a
  transaction, which the pool contract's measurement below supplies.

  One toolchain gap surfaced here and has since been closed: the mnemonic
  `PQCHECKSIG_MLDSA44` lived in `crypto/fift/lib/PQ.fif`, which the sandbox
  assembler does not include, so `auth.fc` had to emit `0xF93100` directly. It
  now lives in `Asm.fif` beside the two Poseidon2 mnemonics and `auth.fc` names
  it.

**Anchors, the execution domain, and the persistent state**

- `crypto/smartcont/shielded/anchors.fc` — section 6: the two anchor rings and
  the rule that an anchor is accepted only on an exact match of kind, id and
  root, never on a root that merely looks plausible. `domain.fc` — section 8:
  the execution domain bound to this chain's `GLOBALID` and this account, and
  the recipient hash, which is defined only for a workchain-zero standard
  address and refuses anything else rather than hashing it anyway.
  `state.fc` — section 13: the state root, the configuration and the verifying
  key chain, each with its frozen shape and each refusing anything that is not
  that shape.

  Twenty-three anchor mutations and twenty state mutations, each killed by the
  test it was aimed at.

  One defect here was found by the branch's own mutation discipline rather than
  by reading. Section 13.2 initialises `last_anchor_epoch` to `0xffffffff`, and
  the first implementation wrote the epoch checkpoint under `epoch >
  last_anchor_epoch` — which is never true against that sentinel, so no
  checkpoint would have been written until the year 6053. The sentinel is "not
  yet recorded", not a very late epoch. It is tested explicitly and a mutation
  restores the old comparison and requires the test to go red. The reading is
  registered as A4 and still wants a one-line confirmation.

  Another came from a rule that was written but not marked. `config_parse` and
  `authorize_intent` were called for their checks with their results unused,
  and FunC, seeing no `impure`, removed the calls entirely — signature
  verification included. Both are `impure` now, and the mutation
  `config-parse-purity` exists so the next function that only validates does
  not repeat it.

**The transact message and on-chain Groth16**

- `crypto/smartcont/shielded/transact.fc` — section 12.2's wire shapes, section
  13.3's frozen cell layouts and section 10's eighteen public inputs in the
  order the verifying key's IC points are allocated in. A field element that
  arrives on the wire must already be canonical: it is refused, not reduced.

- `crypto/smartcont/shielded/groth16.fc` — the verifying key read as a byte
  chain and the pairing check itself, `e(-A,B) · e(alpha,beta) · e(vk_x,gamma)
  · e(C,delta) = 1`, over the 18-input multiexponentiation. The contract slices
  the canonical bytes out of state and hands them straight to `BLS_G1_ADD`,
  `BLS_G1_MULTIEXP` and `BLS_PAIRING`; ruling A1 requires that there be no
  second endian or flag conversion on chain, and there is none.

  The development proof from the circuit verifies inside the VM at **204,493
  gas**, and its four mutations do not. Twenty-two transact mutations and
  twelve Groth16 mutations, each killed by the test it was aimed at.

**The circuit**

- `tools/shielded-pool-circuit/` — work package C: the Poseidon2 t=8 gadgets,
  the section 4 and 5 relations, section 11 over the frozen section 10 public
  input vector, and the section 10.1 development proof and verifying key. It is
  standalone, not a member of the `tosctl` workspace, with its own `Cargo.lock`
  and exact pins, the way `crypto/poseidon2/manifest-gen` is. The Groth16
  backend is an implementation choice; the relations, the input ordering and
  the output format are not.

  The parameters are parsed from `crypto/poseidon2/manifest.bin` at build time
  and refused unless the file hashes to the pinned digest, so no constant table
  is written by hand. The gadget reproduces all 21 permutation and all 28 hash
  vectors, out of circuit and again with the constraints generated and the R1CS
  satisfied. The manifest alone is not evidence, and this was measured rather
  than assumed: running one fewer partial round leaves the three manifest tests
  green and turns five vector tests red.

  **This is the cross-check the note and tree layer was waiting for.** Sections
  4 and 5 existed in two places written by the same author from the same
  document, so a misreading of the profile would have appeared in both and
  neither would have caught it. These gadgets are an independent third reading,
  written from the profile before the FunC was read. `crosscheck/` compiles the
  shielded FunC library with `build/crypto/func`, deploys it at global version
  17 and compares get-method results against values pinned in circuit: sixty
  section 4 values across ten cases, thirteen empty roots, four interior nodes
  and fifteen sequential frontier appends. **All of them agree. No disagreement
  was found.** The comparison can fail — a deliberately wrong expected value is
  run through the same path and is required to panic.

  Section 11 is implemented over the 18-element vector, with the allocation
  order read back out of the constraint system because that order *is* the
  verifying key's IC order. Twenty-one relations carry twenty-three removal
  tests: each requires the full circuit to reject the witness and the weakened
  circuit to accept it, and names the exploit removal lets through — minting
  through conservation, spending a note the pool never issued, double-spending
  through a free nullifier, rewriting the fee slot after signing. Three state a
  baseline, because the witness cannot be built while an earlier relation
  holds. One relation is recorded as redundant rather than exploitable: the
  profile makes the same boolean remove a phantom amount from conservation, so
  a phantom amount reaches no other relation.

  The pairing equation was measured, not recalled, as the profile demands: six
  candidate sign and order patterns against one valid proof and four mutations,
  and the two that survive are the same statement written both ways.

  **What it does not establish**: nothing here is a production artifact. The
  development keys come from a fixed seed, so the toxic waste is known and
  these keys must never verify a real transaction; the fixture says so in its
  own `warning` field. Two places where the profile is not self-sufficient were
  reported rather than decided:

  Two places where the profile was not self-sufficient were reported rather
  than decided, and **both have since been ruled** (register A1 and A2):

  - section 10.1 fixed the compressed point lengths (48 and 96) but named no
    byte order, and the two candidate conventions differ in bytes at the same
    length. **Ruled**: V1 wire bytes are the blst/IETF compressed encoding,
    defined as what this chain's own BLS primitives accept and produce. The
    encoder now builds the IETF layout and hands it to blst, and every point is
    required to survive `deserialize` then `compress` unchanged before it can
    reach a fixture or a digest. Worth stating because it looks like a
    migration and is not: this changed no byte. The fixture regenerates
    identical, verifying key and all, so the 1248-byte stream and its SHA-256
    `5b760517...` stand.
  - the profile gave no width for `withdrawal_fee`. An unbounded fee wraps the
    field and can balance a theft. **Ruled**: the circuit enforces
    `0 <= fee < 2^120`, a withdrawal requires a non-zero fee and a transfer
    requires a zero one, all three in `circuit.rs` behind their own relation
    switches with removal tests.

**The pool contract**

- `crypto/smartcont/tos-shielded-pool-v1.fc` — sections 16.1, 16.2 and 16.4:
  deposit, transact and reserve top-up, with exit codes 200-229 and disjoint
  ranges below it so a code from the library can be told apart from a code from
  the handler.

  Two rules shape the whole contract. It never calls `ACCEPT`, so an inbound
  message pays for its own execution or does not execute; and the depositor
  never supplies the final note commitment, so it cannot deposit one and buy a
  note worth a hundred. Both are tested by removing them and watching a named
  test go red.

  `shielded_pool_sandbox.rs` covers deposit and top-up in eight tests;
  `shielded_pool_transact_sandbox.rs` covers transact in five. Between them,
  twenty-six mutations (`test/shielded-pool/mutations-pool.py`), each killed by
  the test it was aimed at.

  A transact is written in the profile's order and the suite requires each step
  to fail with its own code **in its own place**: funding before anything else
  even when everything else is also wrong, then the unbuilt withdrawal path,
  then the validity window, the anchor, the two nullifier insertions against
  the running tree rather than the tree the message started with, the two
  authorizations, and the proof. A failure at any of them leaves every
  get-method reading exactly what it read before.

  Both suites build the contract from one source list
  (`tests/shielded_pool_library/`). They used to keep their own and drifted:
  the deposit suite went on compiling a pool without the transact libraries and
  was testing a contract that no longer existed.

**What a transact costs**

- Measured on this executor, not estimated. A message that fails at step N has
  paid for steps 1 through N, so the cost of each step is the difference
  between two failures:

  | cumulative gas | step |
  |---:|---|
  | 10,437 | parse and the validity window |
  | 63,818 | + the anchor |
  | 497,031 | + one whole nullifier insertion, the second rejected |
  | 846,470 | + both insertions and the first authorization |
  | **1,117,121** | + the second authorization and the proof |

  **The proof is not what costs.** The two nullifier insertions account for
  about 716,000 of that, roughly 239 Poseidon2 hashes, against 204,493 for the
  whole Groth16 verification measured on its own.

  The network's default per-transaction limit is **1,000,000**, so this path
  does not run to completion on an ordinary account, and the profile's
  `TRANSACT_GAS_CEILING` of 2,000,000 can never take effect: `SETGASLIMIT`
  cannot raise a transaction above the network's own limit. The measurement was
  taken with the sandbox's limit raised to 10,000,000, which is a measuring
  instrument and not a claim. Both facts are asserted by tests rather than left
  in a comment. The decision this forces is registered as D1 in
  `privacy/TOS_SHIELDED_POOL_V1_OPEN_RULINGS_2.md`; the short version is that
  the Poseidon2 gas price those insertions are billed at is still a placeholder,
  so pricing it against measured cost decides whether V1 fits.

**The whole mutation set**, run end to end on 2026-09-20 at this branch's tip:
185 mutations across nine batteries — 8 notes and tree, 34 IMT, 23
authorization, 23 anchors, 20 state, 22 transact wire, 12 Groth16, 26 pool
contract, 17 Poseidon2 across both VMs — and every one of them was killed by
the test or assertion it was aimed at. The log is in
`privacy/measurements/transact-in-tvm-20260920/all-mutations.out`.

**Still not built**: section 15's withdrawal payout and its bounce recovery
(step 16 of 16.2 refuses with code 206 today), section 16.3, the wallet, and
the zerostate generator. There is no production prover, so **no proof that
verifies has ever been produced** — every transact in the suite stops at the
pairing, and the cost of a *successful* transact is therefore still unmeasured.

## What gates this branch

The safety gates in the specification's section 12 are ordered by whether
failing them loses money. The first seven (P0-0 through P0-6) cover how funds
enter, where they actually reside in the account balance, who pays for
computation, who is authorised to spend, and that a spend cannot half-commit.
There is now a pool contract, so the distinction that used to matter here — a
probe showing a rule is enforceable versus a contract obeying it — has moved.
What the contract does obey, with a named test and a mutation behind each: the
principal it admits is the principal the note is built for, no path calls
`ACCEPT`, the funding inequality is checked before any work, backing is
asserted against the end state, and a failure at any step of a transact leaves
the state untouched.

What is still open is not enforcement but completeness and freezing. A
withdrawal cannot be paid out yet, no proof that verifies has ever been
produced, and the numbers that would let a state be frozen — the production
Poseidon2 gas price, the production verifying key, the canonical anchor-ring
shape — are all still open questions in the register. A gate is closed by a
contract obeying a rule *and* by the constants that rule depends on being the
ones that will ship.

Two things do not wait, because their windows close earlier than their
urgency suggests:

- the Poseidon2 instruction is a genesis-time decision (adding it afterwards is
  a hard fork) — **done**: both VMs implement it at version 17. What has not
  been done is pricing it against measured cost;
- the hash parameters are frozen by the implementation profile — t=8, `RF=8`,
  `RP=57`, against a pinned upstream commit — and are now **implemented**, with
  vectors generated from that pin. The earlier claim on this branch that `RP`
  matched no published reference, and the `RP=22` figure behind it, were wrong
  and have been withdrawn upstream. Every gas figure still rests on these
  parameters, and the throughput numbers in the older documents were measured
  against a different shape, so they stay historical until a whole transaction
  is measured.

## Working rules here

The chain's `CLAUDE.md` applies in full. Three of its rules have already been
paid for on this work and are repeated so they are not paid for twice:

- a test that cannot fail is not evidence — remove what it tests and watch it
  go red before believing it;
- compiling a contract is not running it, and a model is not a measurement;
- the same quantity written in two places will drift. Point at one source.
