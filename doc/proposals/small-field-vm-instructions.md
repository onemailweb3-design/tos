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

The interesting part is not the total. It is that the two halves are
expensive **for different reasons**, and only one of them is what everybody
assumes.

| | share of the total | what that share is |
| --- | ---: | --- |
| Merkle paths | 30% | 12% hashing, **88% cell and slice bookkeeping** |
| FRI folding | 70% | **72% is `muldivmod` instructions**, 15% other arithmetic, 13% bookkeeping |

**The Merkle half is the interpreter.** A level costs 1,422 gas of which the
SHA256 over sixty-four bytes is 170, measured. The rest is `begin_cell()` at
500, cell loads at 100 each, and slice handling. An instruction that walks
the whole path removes that and keeps the hashing.

**The folding half is not.** One cubic-extension multiplication costs 2,431
gas, and nine `muldivmod` instructions are 2,016 of it -- eighty-three
percent. There is no interpreter overhead to remove. The problem is that the
instruction is the wrong size: `muldivmod` multiplies and divides 257-bit
integers, and a Goldilocks multiplication needs 64 bits. Every field
operation pays 257-bit prices for 64-bit work.

The scale of that mismatch is the argument for section 3.1. A cubic-extension
multiplication is about forty nanoseconds of real work; at the price
POSEIDON2_PERM8 was set to by measurement, that is worth four to seven gas.
It costs 2,431.

**TVM has no small-field arithmetic at all.** That, and not the proof system,
is what makes a FRI verifier expensive here -- and it is why Groth16 is cheap:
its hard part is one native instruction sized for the job.

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

**This is the one that cannot be avoided, and the one with the largest
margin.** Measured, a cubic-extension multiplication written over
`muldivmod` costs 2,431 gas to do about forty nanoseconds of work -- roughly
five hundred times what the same work is worth at the price
POSEIDON2_PERM8 was measured into.

It is also load-bearing in a way no other instruction can relieve. A verifier
evaluates the AIR's transition constraints at the out-of-domain point, and
those constraints are *circuit-specific*: no instruction can absorb them,
they have to be written in FunC. Together with the DEEP composition, which is
per query, that is on the order of eight hundred extension operations --
about two million gas at today's prices, ten times the entire Groth16
verification, before a single Merkle path is walked.

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

The hash is **SHA256**, fixed by the opcode. The instruction already exists
as `SHA256U` (0xf902) and is not what is being added: what is being added is
the loop around it. At 170 gas a hash and 1,422 gas a level, an instruction
that walks the whole path removes about 1,250 gas of bookkeeping per level
and keeps the 170.

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

### 4.1 Where SHA256 actually sits, and a correction

An earlier draft of this document claimed SHA256 was seven to twelve times
underpriced against the Poseidon2 tariff and called it a denial-of-service
surface. **That was wrong, and wrong in the direction that matters.** The
figure came from the `HASHEXT` formula, `1 + bytes/33`; `SHA256U` is a
different opcode with different accounting. Measured rather than derived, one
SHA256 of sixty-four bytes costs **170 gas**.

| | ns per gas |
| --- | ---: |
| POSEIDON2_PERM8, C++ VM | 5.5 |
| POSEIDON2_PERM8, Rust VM | 9.2 |
| SHA256U, measured at 170 gas | about 1.2 to 2.9 |

Fewer nanoseconds per gas means more gas per unit of work, so SHA256U is
priced **two to seven times more conservatively** than the instruction whose
price was set by measurement. There is no denial-of-service surface here and
nothing to fix.

What this does change is section 5. Hashing is the largest single item in a
Merkle level, and a native instruction cannot remove it -- only the
bookkeeping around it. Priced consistently with Poseidon2 a sixty-four byte
SHA256 is worth thirty to fifty gas, so the 3,720 levels of a verification
are 120,000 to 200,000 gas of irreducible hashing whatever instruction wraps
them.

## 5. What the three would buy

Estimated, with every assumption stated. The hashing and the extension
arithmetic are priced at the rate POSEIDON2_PERM8 was measured into -- forty
five gas a sixty-four byte SHA256, six gas an extension multiplication --
because pricing them at today's basic-instruction rates would flatter the
result.

| | gas | how it is arrived at |
| --- | ---: | --- |
| Merkle paths | ~167,000 | 3,720 levels x 45, the hashing an instruction cannot remove |
| FRI folding | ~35,000 | 180 folds x 24 multiplications x 6, plus 50 a fold of handling |
| parsing an 88 KB proof | ~69,000 | 689 cells at 100 |
| transcript, out-of-domain, DEEP | ~43,000 | ~800 extension operations at 50 all-in, plus 20 hashes |
| **a whole STARK verification** | **~315,000** | |

Against 204,493 for Groth16: **about one and a half times**. Carried through:

| | today | with the three instructions |
| --- | ---: | ---: |
| a withdrawal | 1,730,942 | ~1,841,000 |
| its ceiling | 2,170,000 | ~2,310,000 |
| the sender pre-pays | 0.87 TOS | ~0.92 TOS |
| private transfers in a 60M block | 34 | 32 |

Six percent. At that price the setup ceremony, the quantum exposure of a
pairing and the per-circuit freeze all go away for something that rounds to
nothing.

For contrast, the same verification without the instructions is 17.4M gas,
9.5 TOS and three transfers a block. **The instructions are the whole
difference between the two, which is the point of this document.**

**These are estimates built from measured pieces, not measurements.** The
measured pieces are in section 7.2. They are good enough to decide whether to
start and not good enough to decide anything else.

## 6. What not to do

**Do not add an instruction that verifies a whole STARK.** It would write the
proof system, its parameters and the AIR encoding into consensus code, which
is harder to change than any contract. The three above are primitives; a
verifier built from them stays in FunC where it can be replaced.

**Do not add these for the shielded pool.** V1 is Groth16 and is not waiting
on them. If they are worth adding they are worth adding on their own merits,
and 3.1 has merits that have nothing to do with proofs: a small field with
native arithmetic is useful to anything that has outgrown 257-bit integers.

## 7. Where every number here comes from

This document had a figure wrong once -- section 4.1 -- because it was
derived from a formula belonging to a different opcode instead of measured.
Every number is therefore listed with its provenance, so the next reader can
tell which ones would survive a change of mind and which would not.

### 7.1 Measured

Run `cargo test --release --test stark_verifier_sketch -- --nocapture` in
`tools/shielded-pool-circuit/crosscheck`, and `cargo run --release` in
`tools/stark-size-probe`.

| | value | where |
| --- | ---: | --- |
| one SHA256 of 64 bytes | 170 gas | sketch, slope over 1,000 |
| one `muldivmod`, 257-bit | 224 gas | sketch, slope over 1,000 |
| one cubic-extension multiplication | 2,431 gas | sketch, slope over 100 |
| one Merkle level | 1,422 gas | sketch, slope from depth 4 to 16 |
| one FRI folding step | 67,293 gas | sketch |
| the two inner loops | 17,402,580 gas | sketch |
| Groth16 verification, whole | 204,493 gas | `shielded_groth16_sandbox` |
| a withdrawal, whole | 1,730,942 gas | `transact_in_a_mature_pool` |
| one transact message | 15,548 bytes | `withdrawal_round_trip` |
| STARK proof, 128-bit proven | 88,095 bytes | size probe |
| LDE domain, layers, depths | 2^16, 3, [16,16,13,10,7] | size probe, read off the proof |
| levels a query | 62 | the same, summed |
| POSEIDON2_PERM8 | 3,500 gas | `crypto/vm/poseidon2ops.h` |
| cell create / cell load | 500 / 100 gas | `crypto/vm/vm.h` |
| `SHA256U` | 0xf902 | `crypto/vm/tosops.cpp` |
| 0xf933xx unused, version 17 current | -- | grep, `common/global-version.h` |
| `groth16.fc` | 120 lines | `wc -l` |

### 7.2 Estimated, with the assumption named

| | value | assumption |
| --- | ---: | --- |
| a 64-byte SHA256 priced at the crypto anchor | 30-55 gas | ~300 ns at 5.5-9.2 ns/gas |
| a cubic-extension multiplication, native | 4-7 gas | ~40 ns at the same |
| POSEIDON2_PERM8 in nanoseconds | 19,350 / 32,060 | B1, C++ and Rust VM, on a shared host |
| extension operations in transcript+OOD+DEEP | ~800 | 8 constraints of degree 5 at one point, plus 12 a query |
| cells in an 88 KB proof | 689 | 1023 bits a cell |
| a whole STARK verification | ~315,000 gas | section 5's table |
| everything in section 5's second table | -- | follows from the above and D6 |

### 7.3 Known to be soft

- The nanosecond figures behind the crypto anchor were measured on a shared
  192-thread Xeon, not on target hardware. Everything priced against them
  moves together if that changes.
- The ~800 extension operations is the least grounded number in this
  document. It is an AIR that does not exist yet, evaluated by a verifier
  that does not exist yet.
- `muldivmod` at 224 gas and SHA256 at 170 are both far more conservative per
  unit of work than POSEIDON2_PERM8 at 3,500. That is consistent across both,
  so it may be that the basic instruction prices carry dispatch overhead by
  design -- or that the Poseidon2 tariff is the outlier. This document does
  not resolve it and does not need to, because section 5 prices the new
  instructions at the *crypto* rate, which is the conservative direction for
  a proposal that wants them.

## 8. Sequence

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
