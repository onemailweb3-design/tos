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
  The window is derived from this chain's ConfigParam 21 rather than written
  down -- a flat 667 for the first hundred gas, then 436,907 per 65,536 gas --
  because a price change would otherwise turn the starved message into one
  that can afford the path, and the test would pass for the wrong reason. That
  is not a hypothetical: the constant was written down as 400,000 when gas
  cost 400 nanotos, and stopped starving anything twice, once when the price
  was aligned to TON's live value and again when it was cut tenfold. Below the
  skip threshold the compute phase is skipped outright (`NoGas`) and the VM
  never runs, which is the other end of the same window. A deposit carrying
  what a thousand gas costs buys a thousand gas, and therefore dies halfway:

  | | exit code | gas used | pool balance |
  |---|---|---|---|
  | as written | `-14`, out of gas | 1,000 — exactly what it bought | unchanged |
  | with `accept_message()` | 40, reached a check it could not afford | 1,285 | **285 gas the message never bought** |

  The last column is stated in gas on purpose. What those 285 gas cost the
  pool is ConfigParam 21's business: 1,900 nanotos at the current 6.666 a gas,
  and 114,000 when this row was first measured at 400.

  `a_message_that_cannot_pay_for_its_own_gas_never_reaches_the_pools_balance`
  pins that row, and asserts first that the compute phase actually ran, so a
  future change that pushes the value below the skip threshold fails loudly
  instead of passing vacuously. `M2` now turns it red on the exit code, naming
  the 1,285 gas spent against 1,000 bought.

  The hash here is a placeholder (`cell_hash`). Nothing in this file depends on
  which hash is used, and nothing in it says anything about gas per transfer.

**The Poseidon2 instructions**

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

  The gas price is a **development tariff** of 2,800. It is not a measurement
  and not a production claim: benchmarking the pinned implementation on target
  CPUs and choosing a price with a stated margin still has to happen before
  activation, in both VMs at once. It came down from 3,500 when the Rust
  permutation was made proportionate to the C++ one, which moved the bracket
  the tariff is the top of.

- `POSEIDON2_PATH7` (`0xF93202`), at global version **18**, folds a whole
  Merkle path in one instruction: a leaf, a domain and up to 64 levels of six
  siblings each, returning the root. It exists because the nullifier tree's
  two insertions were walking their paths in FunC, and the bookkeeping around
  the hashing cost more than the hashing -- 52% of an insertion, down to 10%
  once the VM did the walk. Its tariff is 500 plus 3,000 a level, to which the
  VM adds the two cell loads a level costs, so a level is 3,200 in total. Like
  the tariff above, those are assembled numbers rather than benchmarked ones.

  Both VMs implement it and both are held to the same vector, each pinning the
  other's output by hash. That is not ceremony: the C++ implementation shipped
  with two defects a single-VM test could not have found. It wrote the domain
  into the state once before the loop, where the permutation's own output
  overwrites it, so every level past the first hashed against the wrong
  domain; and it charged each path cell twice, 50 gas a level more than the
  Rust VM. The first was caught by a withdrawal refused on a real node, the
  second by comparing the two VMs' marginal cost per level. Neither had a C++
  test until then.

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

  The frontier store is a chain of twelve level nodes, not a dictionary. It
  was a `HashmapE 7` keyed by `level * 7 + position` until 2026-09-21; the key
  space is 0..83, dense and known at compile time, and the access is a
  sequential walk, so nothing about it wanted a sparse container. What decided
  the change was the cost *shape* rather than the constant: a dictionary
  append ran from 108,544 gas at genesis up to 172,192 at the worst reachable
  leaf index, while the chain runs from 127,412 down to 123,544. A sender
  pre-pays the ceiling and a ceiling has to cover the worst age the pool can
  reach, so under the dictionary every sender paid for a maturity most pools
  will never have. The transact ceiling fell from 1,620,000 to 1,460,000 on
  that change alone, and went back to its present 1,470,000 when the maximum
  behind it was re-measured on the four denominations a pool is really
  deployed with rather than the one a fixture found convenient.

  `frontier_store_shape.rs` keeps both containers and fails if they stop
  differing that way; `frontier_cost_is_flat.rs` holds the property the
  ceiling rests on.

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
  it in a VM at global version 18: thirteen tests, closing section 19 gate 10.
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
  18 and compares get-method results against values pinned in circuit: sixty
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
  own `warning` field.

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
  `shielded_pool_transact_sandbox.rs` covers transact in six. Between them,
  forty mutations (`test/shielded-pool/mutations-pool.py`), each killed by the
  test it was aimed at.

  Neither suite writes a gas ceiling down any more. They read each one out of
  the contract, because a ceiling copied into a test makes the rule an
  agreement between two numbers in the same file: lowering the contract's
  deposit ceiling to 180,000 -- above the path at every age, so nothing breaks
  and no cost test notices -- left the test whose only job is that ceiling
  green.

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
  | 10,439 | parse and the validity window |
  | 64,031 | + the anchor |
  | 65,670 | + the first insertion, rejected at its witness |
  | 270,038 | + one whole insertion, the second rejected |
  | 483,502 | + both insertions and the first authorization |
  | **753,513** | + the second authorization and the proof |

  **The proof is not what costs.** The two nullifier insertions account for
  about 418,000 of that, against 204,493 for the whole Groth16 verification
  measured on its own.

  A whole successful withdrawal — which this table does not reach, because
  every row is a *refusal* — measures 1,175,034 at the dearest state a pool
  can be in, and the frozen `TRANSACT_GAS_CEILING` is 1,470,000 by the
  production rule C = max(10,000, round_up_10,000(ceil(M × 5 / 4))).

  That state is neither end of a pool's life. Full anchor rings make a
  transact dearer and a higher leaf index makes it slightly cheaper, so the
  maximum sits at full rings on the **youngest** tree that can have them —
  4,096 mutations in, since the recent ring is keyed by the leaf counter
  modulo its 4,096 slots. A fresh pool measures 1,171,462 and the worst leaf
  index 1,169,973, so a ceiling taken from either end alone is short. The
  measurement is also on the deployed configuration's four denominations: the
  contract walks the list to validate an amount, and the figure was 4,305 low
  while it was taken against one. The basechain grants a
  transaction 30,000,000, so the contract's own ceiling is the binding one,
  which is the point of having it. Both halves of
  `MEASURED_MAX < ceiling <= chain limit` are asserted by tests rather than
  left in a comment.

  These figures are three reductions below where they started: 342,976 when
  the nullifier inserts stopped walking their paths in FunC and started
  calling `POSEIDON2_PATH7`, 99,950 when the Poseidon2 tariff came down from
  3,500 to 2,800, and 120,859 when the frontier changed container.

  **And what the sender actually pays is a price, not a gas count.** A
  transact cost its sender 0.098 TOS against 0.000356 for an ordinary payment
  — 275 times — and the target was 0.01. No amount of contract work reaches that
  while gas is priced as it was: the Groth16 verification alone is 204,493
  gas, which at 66.66 nanotos is 0.0136 TOS, over the whole budget before the
  pool does anything. The three engineering levers were measured and offered —
  a transfer ceiling of its own (−2.5%), a nullifier dictionary instead of an
  IMT (−400,000 gas, at a pool lifetime capped around 20–65k nullifiers), and
  1-in/2-out instead of 2-in/3-out (−333,000 gas, and it must be decided
  before the ceremony fixes the circuit) — and all three together still land
  at 0.0347. So the basechain gas price was cut tenfold instead, `gas_price`
  4,369,067 to 436,907 and `flat_gas_price` 6,667 to 667, leaving forwarding,
  storage and masterchain gas alone.

  | | before | after |
  |---|---:|---:|
  | a transact, what the sender attaches — the ceiling, whatever it spends | 0.098000 | **0.009800** |
  | a withdrawal, the whole fee the chain charged | 0.078382 | **0.008104** |
  | deposit, ceiling | 0.014667 | 0.001467 |
  | ordinary payment | 0.000356 | 0.000202 |

  Both middle figures are a withdrawal, which is the transact the harness
  runs; its charge includes the payout message's forward fee, so it is 295,368
  nanotos above what its 1,171,374 gas costs on its own. A transact that pays
  nobody out is cheaper — 1,144,235 gas, 0.007628 in compute — but it attaches
  the same 0.009800, because the ceiling is one number for both branches. A
  ceiling of its own would save a transfer about 2.5%; it was offered and not
  taken.

  The cut lands almost entirely on computation, which is the point: an
  ordinary payment is about half forwarding, so it falls 43% where a private
  transfer falls 90%. Nothing about the pool moved — prices live in the
  chain's zerostate, so `profile_hash`, the genesis state hash `fd9303eb…` and
  the deployment address are where they were, and every gas figure above is a
  count of work and unchanged.

**On a real chain, not only in the executor**

- `scripts/shielded-pool-onchain-e2e.py` owns a localnet, deploys the exact
  state the frozen manifest names, and plays the fixture's messages through
  it. The executor is the code a validator runs, but running it is not running
  a chain: it has no block production, no message queue, no forward fees and
  no account storage.

  Four paths have been through it: a deposit, a withdrawal whose payout is
  taken, a payout the recipient refuses, and the recovery note that refusal
  mints. **The chain charged the same gas as the sandbox on every message.**
  The harness attaches section 14.1's minimum to the nanoton rather than a
  padded value, because a run that carries more than the funding rule demands
  is not testing the funding rule.

  `--validators N` builds a set rather than a single node, and both scenarios
  have been run on three. It is worth keeping separate from the rest: with one
  validator there is no catchain round and no block anyone has to accept from
  somebody else, so "the executor runs a transact" and "a validator set agrees
  on a block containing one" are different claims, and a transact is by a
  wide margin the heaviest transaction this chain has. On three validators the
  figures are the same to the gas — a deposit at 155,694 and 157,584, a taken
  withdrawal at 1,171,374, a refused one at 1,171,462 and its recovery at
  167,058, each equal to the sandbox and each inside its ceiling — and the
  withdrawal cost 0.008104 TOS.

  Two things were found here that no sandbox could have found. `POSEIDON2_PATH7`
  in the C++ VM lost its domain after the first level, so a withdrawal was
  refused at exit 115 on a node while every sandbox test was green — the Rust
  VM had a test and the C++ one did not. And an anchor epoch is thirty
  seconds, so two messages seconds apart can straddle a checkpoint boundary on
  a chain while the sandbox, whose clock is frozen when the fixture is built,
  never does; that is 1,896 gas of difference the harness now recognises from
  the transactions' own timestamps, bounded at 10,000 so the tolerance cannot
  swallow a real divergence.

**The whole mutation set**, re-run end to end on 2026-09-21 at this branch's tip:
223 mutations across ten batteries — 9 notes and tree, 34 IMT, 23
authorization, 23 anchors, 21 state, 22 transact wire, 12 Groth16, 40 pool
contract, 17 payout, 22 recovery — and every one of them was killed by the
test it was aimed at. The 17 Poseidon2 mutations across both VMs were not
re-run in that pass, because nothing under `crypto/vm` changed in it.

The batteries themselves had a portability bug worth naming, because it is the
failure mode this whole document is about. Seven of the ten pointed `TOS_ROOT`
at a hardcoded path under one person's home directory and the other three at
the checkout they were run from — so run from a git worktree, which has every
source and no build of its own, all ten failed at baseline with
`POSEIDON2_HASH7:-?`. That looks like a broken contract and is a missing
assembler. They now share one resolver that finds the build.

**Still not run**: the production Groth16 ceremony. Everything this paragraph
used to list is built — section 15's withdrawal payout and its bounce
recovery, section 16.3, the wallet and the zerostate generator — and a
withdrawal now runs end to end in the sandbox, is refused, bounces, and comes
back as a recovery note, with every figure above measured on that path. What
does not exist is a verifying key anyone should trust with money: the
development key comes from a single-party setup whose seed is in the source,
so **no proof under a production key has ever been produced**, and nothing
here is evidence about one.

The *machinery* is now built and exercised end to end. Phase 1 is a 2^15 slice
fetched from the Zcash Sapling powers of tau, committed, verified as a
well-formed powers-of-tau string and turned into the Lagrange basis a setup
consumes. Phase 2 is a multi-party computation written against arkworks, with
four binaries a ceremony is actually run from, and the whole pipeline —
committed slice, starting key, contributions, beacon, 1,248 bytes — has been
driven into a deployed pool that accepted a real private transfer, while the
same pool refused a proof made under the pre-ceremony key.

So what remains is not engineering. It is **participants**, a **beacon named
before the ceremony opens**, a second independent verifier, and the two circuit
questions that have to be answered before a verifying key is frozen.
`doc/shielded-pool-ceremony.md` holds all of it; the choice between the Zcash
and Filecoin ceremonies, and the audit of the round counts behind it, are in
`memo/privacy/measurements/zcash-transcript-audit-20260921/`.

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

What is still open is not enforcement but freezing. The paths themselves all
run: a deposit, a withdrawal with its payout, a payout the recipient refuses
and the recovery note that refusal mints have each been put through a real
node — on a three-validator set as well as a single one — and the chain
charged the same gas as the sandbox on every message. A transfer that pays
nobody out is the one path proved only in the sandbox; it is the same handler
taking a cheaper branch, but that is an argument rather than a run, and it is
recorded as one. What is not settled are the numbers a frozen state depends on —
the production Poseidon2 tariff, measured on target CPUs rather than
assembled; the production verifying key, which needs a ceremony; and the
mainnet parameters, which the profile makes an activation decision. A gate is
closed by a contract obeying a rule *and* by the constants that rule depends
on being the ones that will ship.

An earlier version of this paragraph said a withdrawal could not be paid out
and no proof that verifies had ever been produced. Both had been false for
some time, and the paragraph twenty-five lines above already said so. It is
recorded here rather than quietly deleted, because a document contradicting
itself in two places is exactly what nothing fails on.

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
