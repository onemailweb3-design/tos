# Shielded pool: implementation branch

This branch (`feat/shielded-pool`) is where the protocol-native shielded transfer
pool gets built. It does not hold the design. The design, its evidence, the
open decisions and the review record live in the `memo` repository under
`privacy/`, and this branch follows them:

| Document | Role |
|---|---|
| `privacy/TOS_SHIELDED_POOL_SPEC.md` | The specification. Section 0 states what is hidden from whom; section 12 lists the safety gates that must close before production code; section 13 says what counts as proof. |
| `privacy/TOS_VS_EIP8182_PRIVACY.md` | What this design hides compared with the reference design, per party. |
| `privacy/TOS_SHIELDED_POOL_EIP8182_PORT.md` | Measurements and hard limits on this chain. |
| `privacy/TOS_POSEIDON2_OPCODE_WORK_ORDER.md` | The one instruction the pool needs to be worth shipping. |
| `privacy/REVIEW_PROMPT.md` | The standing invitation to find what is wrong. |

When this branch and those documents disagree, the documents win and the branch
is fixed.

## What is on this branch

**Verified in the VM**

- `tosctl/src/node-control/contracts/tests/imt_sandbox.rs` — an indexed Merkle
  tree run inside the VM through the sandbox, with a placeholder hash. It
  establishes that a dictionary costs exactly `2n - 1` cells for both 32-bit
  and 256-bit keys, which is what makes the 65,536-cell account limit a hard
  ceiling of 32,768 nullifiers, and that batching the path recomputation is not
  free: for two scattered leaves it saves one hash and costs about 10,000 more
  gas. Five mutations were run against it; four kill the test they target and
  the fifth survives correctly. Its measurement record is
  `memo/privacy/measurements/imt-in-tvm-20260920/`.

  It was verified on `feat/validator-auth-p0`. **It has not yet been run on
  this branch.** Until it is, treat it as source that compiled elsewhere, not
  as evidence here.

**Nothing else.** No pool contract, no circuit, no instruction, no wallet.

## What gates this branch

The safety gates in the specification's section 12 are ordered by whether
failing them loses money. The first seven (P0-0 through P0-6) cover how funds
enter, where they actually reside in the account balance, who pays for
computation, who is authorised to spend, and that a spend cannot half-commit.
None of them is closed. Production code on this branch waits for them.

Two things do not wait, because their windows close earlier than their
urgency suggests:

- the Poseidon2 instruction is a genesis-time decision (adding it afterwards is
  a hard fork), even though the pool can run without it at roughly 45 times the
  hashing cost;
- the hash parameters (`RF`/`RP`) currently on record match no published
  reference, and every gas figure rests on them.

## Working rules here

The chain's `CLAUDE.md` applies in full. Three of its rules have already been
paid for on this work and are repeated so they are not paid for twice:

- a test that cannot fail is not evidence — remove what it tests and watch it
  go red before believing it;
- compiling a contract is not running it, and a model is not a measurement;
- the same quantity written in two places will drift. Point at one source.
