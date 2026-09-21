# Small-field VM instructions, and what they are for

**Status:** proposal. Nothing here is implemented, and nothing here is part of
the shielded pool V1.

**Measured against:** `feat/shielded-pool` @ `3564cfec`.

---

## 1. Why

A FRI-based proof system needs no trusted setup and rests only on the
collision resistance of a hash, which is an assumption the commitment tree
already carries. Adopting one would remove a ceremony, the quantum exposure
of a pairing, and the per-circuit setup that makes any future circuit change
expensive. What has kept it out of reach is the cost of verifying such a
proof in this VM.

That cost was measured rather than argued.
`tools/shielded-pool-circuit/crosscheck/tests/stark_verifier_sketch.rs`
writes the two loops a FRI verifier is almost entirely made of -- a Merkle
authentication path and one folding step over a cubic extension of Goldilocks
-- and prices them at the parameters that reach 128 bits of **proven**
security for the pool's circuit (trace 8 x 2^12, blowup 16, 60 queries,
folding factor 8, three FRI layers):

| | gas |
| --- | ---: |
| one Merkle level | 1,422 |
| one folding step, eight extension elements | 67,293 |
| 60 queries x 62 levels | 5,289,840 |
| 60 queries x 3 layers | 12,112,740 |
| **the two loops** | **17,402,580** |

Against 204,493 gas for the whole Groth16 verification, and 1,730,942 for an
entire withdrawal. Carried through, a private transfer would pre-pay about
9.5 TOS instead of 0.87, and a 60M block would hold three of them instead of
thirty-four.

## 2. What the measurement actually says

The interesting part is not the total. It is where the total goes.

| | share of the total | share that is the computation |
| --- | ---: | ---: |
| Merkle paths | 30% | **0.14%** |
| FRI folding | 70% | 87% is extension multiplication, of which **10%** is the multiply |

A Merkle level costs 1,422 gas of which the SHA256 over sixty-four bytes is
**two**. The rest is `begin_cell()` at 500, cell loads at 100 each, and slice
handling. One cubic-extension multiplication costs 2,431 gas of which nine
`muldivmod` instructions are about 234.

So the cost is not the cryptography. It is the interpreter. These
instructions do not make the arithmetic faster; they remove the interpreter
from around it.

This is also why Groth16 is cheap here and expensive on the EVM: the hard
part is one native instruction, `BLS_PAIRING`. The question was never
"Groth16 or STARK". It is "which one does the VM have an instruction for".

## 3. The instructions

Encoding follows the existing convention: `0xf93` then one hex digit of
family, then the member. `0` is BLS, `2` is Poseidon2. `3` is proposed here
for the small-field family. `0xf933xx` is unused today.

All three require global version 18.

### 3.1 `GLEXT3_MUL` -- 0xf93300

```
(a0 a1 a2 b0 b1 b2 - c0 c1 c2)
```

Multiplies two elements of the cubic extension of Goldilocks,
`p = 2^64 - 2^32 + 1`, with `u^3 = u + 1`. Each limb is an integer in
`[0, p)`; a limb outside that range throws a range check error.

`GLEXT3_ADD` (0xf93301) and `GLEXT3_SUB` (0xf93302) follow, with the same
stack shape.

**This is the one that cannot be avoided.** A verifier evaluates the AIR's
transition constraints at the out-of-domain point, and those constraints are
*circuit-specific* -- no instruction can absorb them, they have to be written
in FunC. The pool's AIR is eight constraints of degree five, which is on the
order of a hundred extension multiplications: 243,000 gas at today's prices,
more than the entire Groth16 verification, before a single query is checked.

It is also the only one of the three that commits to nothing. Any small-field
proof system needs it, and it fixes no FRI parameter.

### 3.2 `MERKLE_PATH_ROOT` -- 0xf93310

```
(leaf path index depth - root)
```

`leaf` and `root` are 256-bit integers. `path` is a cell chain, each cell one
256-bit sibling and a reference to the next. At level `i` the sibling is
combined on the left when bit `i` of `index` is set and on the right
otherwise, and the pair is hashed as sixty-four bytes.

The hash is **SHA256**, fixed by the opcode.

> Poseidon2 must not be used for this. At 3,500 gas a permutation, 3,720
> levels is 13M gas -- worse than the FunC loop it would replace. The
> circuit's own commitment tree stays Poseidon2; the proof system's internal
> Merkle trees are a different tree and want a different hash.

Three consumers, not one: FRI queries, inclusion proofs against the pool's
own trees read by other contracts, and any light-client style check.

### 3.3 `FRI_FOLD8` -- 0xf93320

```
(values alpha0 alpha1 alpha2 - r0 r1 r2)
```

`values` is a cell chain of eight cubic-extension elements, three 64-bit
limbs each. Interpolates the degree-seven polynomial through them and
evaluates it at `alpha`.

This is the most effective of the three and the least flexible: it writes the
folding factor and the field into consensus code. It should be added last, if
at all, and only once a verifier exists to prove the shape is right.

## 4. Gas

Prices are **not proposed here**. They must be measured the way the Poseidon2
tariff was: against instructions that already have a price, on the target
CPU, with the result stated as a bracket rather than a point.
`tools/poseidon2-bench` is that tool and takes a new subject without
modification.

The shape each price should take, following the existing table:

```
GLEXT3_MUL         flat
MERKLE_PATH_ROOT   base + depth * per_level
FRI_FOLD8          flat
```

### 4.1 A pricing problem this work uncovered, independent of any of the above

Hashing appears to be underpriced relative to the Poseidon2 tariff that was
frozen at 3,500.

| | ns per gas |
| --- | ---: |
| POSEIDON2_PERM8, C++ VM | 5.5 |
| POSEIDON2_PERM8, Rust VM | 9.2 |
| SHA256 at `1 + bytes/33` | about 66 |

Seven to twelve times cheaper per unit of work than the instruction whose
price was just set by measurement. That is a denial-of-service surface and it
has nothing to do with STARKs.

It also makes the estimate in section 5 ambiguous: priced by the existing
table a native Merkle path is a few thousand gas, priced consistently with
Poseidon2 it is about 170,000. The estimate below takes the second, because
consistency is worth more than optimism.

**This should be measured on its own, before and regardless of this
proposal.**

## 5. What the three would buy

Priced consistently with the Poseidon2 tariff:

| | gas |
| --- | ---: |
| Merkle paths, native | ~170,000 |
| folding, native | ~36,000 |
| parsing an 88 KB proof, ~700 cells at 100 | ~70,000 |
| transcript, out-of-domain evaluation, DEEP composition | ~150,000 |
| **a whole STARK verification** | **~420,000** |

Against 204,493 for Groth16: about twice, which is the same order. A private
transfer's ceiling would move from 2,170,000 to roughly 2,700,000, the sender
would pre-pay about 1.1 TOS instead of 0.87, and throughput would be
essentially unchanged.

At that point the setup ceremony, the quantum exposure and the per-circuit
freeze all go away for a cost that rounds to nothing.

**These are estimates built from measured pieces, not measurements.** They
are good enough to decide whether to start, and not good enough to decide
anything else.

## 6. What not to do

**Do not add an instruction that verifies a whole STARK.** It would write the
proof system, its parameters and the AIR encoding into consensus code, which
is harder to change than any contract. The three above are primitives; a
verifier built from them stays in FunC where it can be replaced.

**Do not add these for the shielded pool.** V1 is Groth16 and is not waiting
on them. If they are worth adding they are worth adding on their own merits,
and 3.1 has merits that have nothing to do with proofs: a small field with
native arithmetic is useful to anything that has outgrown 257-bit integers.

## 7. Sequence

Nothing here is ready to implement. In order:

1. **Measure SHA256 against the anchors** (section 4.1). Independent of the
   rest, and possibly a live issue.
2. **`GLEXT3_*` alone**, priced by measurement, with the V15/V16/V17-style
   executed matrix the Poseidon2 work order requires. It commits to nothing.
3. **A FunC verifier for one real proof**, on top of 2, with `MERKLE_PATH_ROOT`
   emulated. This is what turns section 5 from an estimate into a
   measurement, and it is the first point at which the question can actually
   be answered.
4. `MERKLE_PATH_ROOT`, then `FRI_FOLD8`, only if 3 says they are where the
   gas still is.

Step 3 is the gate. Everything before it is cheap; everything after it should
wait for it.
