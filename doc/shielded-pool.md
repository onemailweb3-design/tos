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

**Nothing else.** No pool contract, no circuit, no instruction, no wallet.

## What gates this branch

The safety gates in the specification's section 12 are ordered by whether
failing them loses money. The first seven (P0-0 through P0-6) cover how funds
enter, where they actually reside in the account balance, who pays for
computation, who is authorised to spend, and that a spend cannot half-commit.
None of them is closed. What the two probes establish is that the rules P0-0
and P0-1 state are enforceable in this VM and that the assertions for them
discriminate — not that a pool contract obeys them, because there is no pool
contract yet. Production code on this branch waits for the gates.

Two things do not wait, because their windows close earlier than their
urgency suggests:

- the Poseidon2 instruction is a genesis-time decision (adding it afterwards is
  a hard fork), even though the pool can run without it at roughly 45 times the
  hashing cost;
- the hash parameters are now frozen by the implementation profile — t=8,
  `RF=8`, `RP=57`, against a pinned upstream commit — so what remains is
  implementing them with vectors generated from that pin, not choosing them.
  The earlier claim on this branch that `RP` matched no published reference,
  and the `RP=22` figure behind it, were wrong and have been withdrawn
  upstream. Every gas figure still rests on these parameters, and the
  throughput numbers in the older documents were measured against a different
  shape.

## Working rules here

The chain's `CLAUDE.md` applies in full. Three of its rules have already been
paid for on this work and are repeated so they are not paid for twice:

- a test that cannot fail is not evidence — remove what it tests and watch it
  go red before believing it;
- compiling a contract is not running it, and a model is not a measurement;
- the same quantity written in two places will drift. Point at one source.
