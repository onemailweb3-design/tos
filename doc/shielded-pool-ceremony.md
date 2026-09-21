# The shielded pool's Groth16 ceremony

Every proof this branch has ever produced verifies under a key drawn from the
seed `tos-shielded-pool-v1-devkeys-001`. The seed is in the source, so the
toxic waste is public, so **anyone can forge a proof under that key** and mint
themselves a note. Section 17 and section 20 say so, the fixture says so in its
own `warning` field, and it is the single reason this pool cannot hold money
today.

Replacing it needs a two-phase trusted setup. This document is what exists of
that ceremony so far, what it establishes, and what is deliberately not built
yet.

## What has to be produced

One thing, in the end: **1,248 bytes**. Section 10.1's verifying key, which
goes into the genesis configuration store, which fixes the state hash, which
fixes the deployment address. Everything else a ceremony generates — the
proving key, the transcripts, the attestations — exists to make those bytes
trustworthy.

## Phase 1: reused, sliced, and checked

Phase 1 is circuit-independent, so it is not ours to run. The BLS12-381
powers-of-tau this chain uses is the published Filecoin transcript,
`challenge_19`, run to 2^27 and derived from the Zcash Sapling ceremony.

**This circuit needs 2^15.** Not chosen — measured:

```
constraints 18,107   instance 19   witness 18,215
QAP degree 18,234 -> domain 2^15 = 32,768        (14,534 to spare)
```

`tools/shielded-pool-ceremony/tests/degree.rs` holds that against the circuit
on every run, and it is a gate rather than a note: every byte offset below is a
function of the exponent, so a circuit that grew past 32,768 would make an
already-fetched slice *the wrong bytes* rather than too few of them.

### Eighteen megabytes out of seventy-two gibibytes

The accumulator stores five sections, each in ascending power order, so a
degree-2^15 SRS is a prefix of every section rather than a prefix of the file:

| section | points | bytes | offset |
|---|---:|---:|---:|
| `tau_g1` | 65,535 | 6,291,360 | 64 |
| `tau_g2` | 32,768 | 6,291,456 | 25,769,803,744 |
| `alpha_tau_g1` | 32,768 | 3,145,728 | 51,539,607,520 |
| `beta_tau_g1` | 32,768 | 3,145,728 | 64,424,509,408 |
| `beta_g2` | 1 | 192 | 77,309,411,296 |

18,874,464 bytes, fetched with five HTTP range requests.

Getting those offsets wrong is the worst error available here: the bytes would
parse, the points would be on the curve and in the right subgroup, and
verification would fail with nothing to say about why. Two independent facts
guard it.

**The total.** The layout implies a file size and the server publishes one, and
they agree to the byte: 77,309,411,488. That pins the element counts, the
uncompressed widths and the 64-byte transcript-digest prefix.

**The order.** A total is the same whatever order the sections are in, so it
pins nothing about which comes first. The order is the one
`Accumulator::serialize` writes; what actually catches an order mistake is the
verification, because sections read in the wrong order are not powers of the
same tau and no pairing check holds. There is a test for exactly that.

### What the verification establishes

`verify-phase1-slice` parses the slice — blst deciding what a point is,
including the **subgroup** check a hostile transcript would be trying to get
past — and then runs the checks `Accumulator::verify` runs, restricted to a
prefix, which is sound because each is a statement about consecutive elements:

* the zeroth power is the generator, in both groups;
* the tau in G1 is the tau in G2;
* alpha and beta advance by that same tau;
* the beta in G1 is the beta in G2;
* and every remaining power, batched into one pairing check per section with
  randomness drawn from the operating system — not from the slice, because
  scalars a malicious transcript could predict are scalars it could cancel
  against.

Nine tests build strings broken one way at a time and require the check aimed
at each to catch it, including the two that every other check passes: a string
of consistent powers of the *wrong generator*, and alpha and beta sections
swapped.

### What it does not establish

**Nothing about who knows tau.** That property comes from the contribution
chain — many participants from 2017 on, each multiplying in a secret and
proving they did — and re-verifying it means replaying every response in the
transcript, not reading the final accumulator. A slice cannot carry it and no
amount of pairing arithmetic on the slice will produce it.

So a deployment relies on two different things and should say so: **structure
checked here, custody inherited from the published ceremony.** The 64-byte
digest at the head of the challenge file is recorded in the slice's provenance
so a deployment can be held against that ceremony's attestations.

```
transcript digest 6e3f4b98e6c205d0efa5abc917dd03e28864016df380936fa4e9865595c5d698
                  63eff93e8badf8e6b8c8cbfd5ab3a415ef7ba50b86e124bd9bfcd3f9aab67124
```

## Phase 2: not built, and why not sketched

Phase 2 is circuit-specific, so it has to be ours. It is **the one remaining
engineering task**, and it is deliberately absent rather than half-present.

`ark-groth16` 0.5 has no MPC module. That was checked in its source, not
assumed — a web search confidently said otherwise. The two mature
implementations are Filecoin's `phase2` (bellman) and gnark's `mpcsetup` (Go),
and both want the circuit expressed in their own constraint system. So the
options are:

| | cost | risk |
|---|---|---|
| implement BGM17 over arkworks | a real piece of protocol code | ours to get right, and a subtle error is invisible |
| Filecoin's `phase2` | re-express 18,107 constraints in bellman | **two circuits that must be identical**, with nothing checking that they are |
| gnark's `mpcsetup` | re-express them in gnark | the same, plus a Go/Rust boundary |

The second and third look cheaper than they are. A second implementation of
this circuit is not a translation exercise; it is a second chance to get the
relations wrong, and the ceremony would fix whichever one it was fed. The
circuit already exists once in arkworks and is cross-checked against the FunC,
so the first option keeps the number of circuits at one.

That is a recommendation, not a decision, and it is the reason nothing was
written here in a hurry.

## The acceptance gate

Whatever produces the key, this is what says it is usable.
`shielded_pool_circuit_crosscheck::acceptance` **deploys a pool carrying
exactly the candidate bytes, proves a real transfer under the matching proving
key, sends it, and requires the contract to accept.** Everything short of that
is a claim about a serializer.

It reports the key's digest, its IC count, its length, the deployment address
the key implies, and the transact's exit code.

Five tests establish that the gate judges rather than nods:

* it accepts the key this repository ships (digest `5b760517…`);
* it accepts **a key it has never seen**, from a different setup — which is the
  case a ceremony actually presents, and the one a fixture-shaped check would
  fail;
* it **refuses a proof made under a different key** from the one deployed
  (exit 262). Without this the two above would pass for a gate that never
  compares the proof to the key at all;
* it refuses a key of the wrong length;
* and two different keys give two different deployment addresses — which is
  why no address can be published before the ceremony ends.

## What is needed from people

1. **Participants.** Any number; the property needed is that at least one
   destroys their randomness. Each contributes to the phase-2 transcript and
   publishes an attestation.
2. **A random beacon** to finalise, fixed in advance: what it is, at what
   height or time, and who witnesses it.
3. **A second verifier.** Someone outside this repository running the
   acceptance gate against the produced key and getting the same digest.

## What must be decided before it starts

A ceremony fixes the circuit. Two open questions change the circuit, so both
have to be answered first:

* **Charging the recovery's compute to the recovered amount.** It removes
  `withdrawal_fee`'s entire section 14.2 justification — the money is already
  back in the pool when the note is minted — and would let the fee be sized for
  whatever else it is for, or be near zero. It changes section 15.4 and the
  circuit.
* **1-in/2-out instead of 2-in/3-out.** Worth about 333,000 gas, and it is a
  different circuit.

Neither is urgent on its own. Both become unfixable the moment the verifying
key is frozen.

## Running it

```
# the slice: five range requests, ~18 MB, resumable
uv run python scripts/shielded-pool-phase1-slice.py --out artifacts/phase1

# and what the bytes actually are
cargo run --release --manifest-path tools/shielded-pool-ceremony/Cargo.toml \
    --bin verify-phase1-slice -- \
    artifacts/phase1/phase1-2m15.bin artifacts/phase1/phase1-2m15.json

# the gate, against the key this repository ships
cargo test --release --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml \
    --test ceremony_acceptance
```

Fetching and judging are separate on purpose: one half needs the network and no
cryptography, the other needs cryptography and no network.
