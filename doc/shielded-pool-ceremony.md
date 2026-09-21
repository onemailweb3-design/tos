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

Phase 1 is circuit-independent, so it is not ours to run — it is ours to
*choose*, and the choice is a **custody** decision rather than a technical one.
Whichever ceremony is picked, the deployment inherits that ceremony's
participants and nothing else. So the transcript is a described thing in
`layout.rs` with its provenance attached, not a constant somebody once typed,
and the provenance record beside every fetched slice names it in its first
field.

### Which ceremony, and why

Two published BLS12-381 powers-of-tau are large enough:

| | Zcash Sapling | Filecoin |
|---|---|---|
| degree | 2^21 — 64× this circuit | 2^27 |
| when | 2017–2018 | end of 2019 |
| provenance | **the canonical BLS12-381 ceremony**; later ones reference it | its own ceremony, *not* a continuation of Zcash's — Zcash's 2^21 was too small for Filecoin's hundred-million-gate circuits |
| attested | 87 named humans + a public random beacon, of an 89-round chain | not examined here |
| an 18 MB slice takes | **seconds** (Internet Archive) | ~25 minutes (IPFS gateway) |

**The default is Zcash.** Better provenance, far better availability, and its
contribution chain turned out to be *auditable from published material* — two
links of it were recomputed against PGP signatures from 2017 before it was made
the default. Filecoin's only advantage is headroom this circuit does not need;
it is kept as an alternative, because two independent sources hedge
availability and one of them has already lost its original host.

Neither is preferred by the code. `--transcript filecoin` switches, and the
tests pin both ceremonies' artifacts so that changing the default means moving
a pin rather than discovering later that nothing was checking.

The full audit, including the 89-vs-88-vs-87 round count and the two hash
computations that resolve it, is in
`memo/privacy/measurements/zcash-transcript-audit-20260921/`.

**This circuit needs 2^15.** Not chosen — measured:

```
constraints 18,107   instance 19   witness 18,215
QAP degree 18,234 -> domain 2^15 = 32,768        (14,534 to spare)
```

`tools/shielded-pool-ceremony/tests/degree.rs` holds that against the circuit
on every run, and it is a gate rather than a note: every byte offset below is a
function of the exponent, so a circuit that grew past 32,768 would make an
already-fetched slice *the wrong bytes* rather than too few of them.

### Eighteen megabytes, and where they sit in each file

The accumulator stores five sections, each in ascending power order, so a
degree-2^15 SRS is a prefix of every section rather than a prefix of the file.
Both ceremonies were fetched on 2026-09-21; the sections are the same shape and
the same size either way, and only the offsets differ.

**Zcash** — the default. The accumulator is the last of 89 records, so every
offset is deep in the file. Slice
`1bfd7acdb3ecbfaaa695ab159a7a643a2eb58203a4d93361040c6bd4c2aa3d6e`:

| section | points | bytes | offset | sha256 |
|---|---:|---:|---:|---|
| `tau_g1` | 65,535 | 6,291,360 | 106,300,550,400 | `b228baf1…47d9d9` |
| `tau_g2` | 32,768 | 6,291,456 | 106,703,203,488 | `01aafa19…322585` |
| `alpha_tau_g1` | 32,768 | 3,145,728 | 107,105,856,672 | `0377104a…91b832` |
| `beta_tau_g1` | 32,768 | 3,145,728 | 107,307,183,264 | `4e36cc73…696ece` |
| `beta_g2` | 1 | 192 | 107,508,509,856 | `7137a823…75ec73` |

**Filecoin** — a challenge file, so the accumulator starts 64 bytes in. Slice
`d161614630b0504bd02075a9f57e7ca18d24f0c7c911c5cda5a686e91b8ced75`:

| section | points | bytes | offset | sha256 |
|---|---:|---:|---:|---|
| `tau_g1` | 65,535 | 6,291,360 | 64 | `5fe833e9…22e602` |
| `tau_g2` | 32,768 | 6,291,456 | 25,769,803,744 | `97f86b31…bdb502` |
| `alpha_tau_g1` | 32,768 | 3,145,728 | 51,539,607,520 | `bb92e0d5…b71491` |
| `beta_tau_g1` | 32,768 | 3,145,728 | 64,424,509,408 | `fc3dae17…92c617` |
| `beta_g2` | 1 | 192 | 77,309,411,296 | `605833eb…f1d3ba` |

Anyone holding a transcript can reproduce its slice with five reads, because
the slice file is those ranges end to end with nothing added. The full hashes
are in each fetch's provenance record and pinned in
`tools/shielded-pool-ceremony/tests/the_real_slice.rs`.

### Where the artifacts live

```
artifacts/phase1/phase1-zcash-2m15.bin      18,874,464   1bfd7acd…   ← stored
artifacts/phase1/phase1-zcash-2m15.json          1.6 KB              ← stored
artifacts/phase1/phase1-filecoin-2m15.json       1.6 KB              ← stored
artifacts/phase1/phase1-filecoin-2m15.bin   18,874,464   d1616146…   fetch on demand
```

**The default ceremony's bytes are in the repository.** Eighteen megabytes is a
real cost and a smaller one than it first sounds: this repository already
carries a 27 MB source file and two of 19.5 MB, against a history of 593 MB.

What it buys is not convenience. **A deployment's entire custody argument rests
on those bytes**, and until they were committed they existed in exactly one
place in the world that we do not control. Zcash's original S3 host is already
gone — both the torrents and the per-response files return 404 — so the Internet
Archive copy is the only one left. Storing them is the difference between
"reproducible, as long as one archive survives" and "reproducible".

**Filecoin's bytes are not stored, and that is the point of storing Zcash's.**
The reason to carry a second ceremony was to hedge availability, and committing
the default's slice is a better hedge than a second remote host. What is kept
is its *descriptor and its record* — forty lines and 1.6 KB — so that
`--transcript filecoin` still fetches and verifies, the code still has two
ceremonies to be held to rather than one it might quietly assume, and the
check that refuses one ceremony's slice under the other's name still has
something to refuse. Eighteen megabytes for a contingency that a fetch answers
in twenty-five minutes is not a trade worth making.

The records are 1.6 KB each and carry the ceremony's name, the ranges by offset
and length, each section's SHA-256, the slice's own, and the custody sentence.
They are what lets bytes obtained by *any* route — a mirror, a torrent, a
colleague's disk, this repository — be checked rather than trusted.

A slice can still be re-fetched and the result must be identical; that is what
the hashes are for. Zcash's takes seconds, Filecoin's about twenty-five minutes
through its IPFS gateway.

The reference string stays out, and the reasoning is not the same. It is seven
seconds of arithmetic from a slice that is now in the repository, so storing it
would add a derived copy that can go stale while removing no dependency on
anybody.

**The tests against the real slices now run by default**, which is what storing
the bytes actually bought. While they had to be fetched the choice was between
failing for everyone who had not fetched them and skipping quietly — and a test
that passes while doing nothing is the failure this repository's `CLAUDE.md`
opens with — so they were `#[ignore]`d and hardly ever ran. The strongest
evidence here now runs on every invocation, for about twenty seconds.

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

**And it has been run against the real slice, both ways.** The 18 MB fetched
from the transcript verifies: 131,839 points, all in the prime-order subgroup,
every ratio holding. Then two genuine powers from that same transcript,
`tau_g1[40000]` and `tau_g1[40001]`, were swapped — every point still valid,
every point still in the subgroup, the file still hashing to its record — and
it was refused:

```
REFUSED: structure: the G1 powers of tau are not consecutive powers of one tau
```

A single flipped bit is caught earlier and more cheaply, by `blst` with
`BLST_POINT_NOT_ON_CURVE`, which is why the swap is the interesting case: it is
the one a corrupted or hostile transcript could survive everything but the
pairing checks with.

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

## Phase 1.5: the basis change nobody mentions

A verified slice is not yet something a setup can use, and the step between is
easy to miss because it has no ceremony around it.

The transcript stores the **monomial** basis: `τ^0, τ^1, τ^2, …` in the
exponent. Groth16's setup needs the **Lagrange** basis over the evaluation
domain — `L_0(τ), L_1(τ), …` where `L_j` is the polynomial that is 1 at `ω^j`
and 0 at every other root of unity. It needs that because the QAP polynomials
`A_i, B_i, C_i` are defined by their values on the domain, so `A_i(τ)` is a
combination of `L_j(τ)` and not of `τ^j`.

The two are related by an inverse DFT, in the exponent:

```
L_j(X) = (1/n) · Σ_i ω^(-ji) · X^i        so        L_j(τ)·G = (1/n) · Σ_i ω^(-ji) · (τ^i·G)
```

which is exactly `ifft` applied to the group elements. Filecoin runs this as a
separate stage they call phase 1.5, with a `create_lagrange` binary, and
publish the results as `phase1radix2m{k}`.

**Those files do not help us.** Only `phase1radix2m19` and `phase1radix2m27`
are published, and a Lagrange basis is tied to one evaluation domain: the
2^19 basis is not a prefix of the 2^15 one, it is a different set of
polynomials over a different set of roots. So this circuit's 2^15 basis has to
be computed here.

That is done, in `tools/shielded-pool-ceremony/src/lagrange.rs`. It is a good
deal safer than what follows it, and worth saying why: **the transform has no
secrets.** It is a fixed linear map, so its output can be checked against its
input rather than trusted, and four independent checks do exactly that.

The same stage also builds the **`h` query**, the other thing the monomial
basis is needed for. Groth16's prover divides by the vanishing polynomial
`t(X) = X^n − 1`, so the setup needs `τ^i·t(τ)` for `i` up to `n−2` — which is

```
τ^i·t(τ) = τ^(i+n) − τ^i
```

and that is the only reason the transcript's G1 section runs to `2n−2` rather
than `n−1`. It is also the reason the slice's longest range is the one it is.

### Checking a transform that has no secrets

Four checks, each able to fail, none of them a restatement of the arithmetic:

* **Against the definition, with τ known.** A slice built from a chosen τ makes
  `L_j(τ)` computable in closed form — `ω^j(τ^n − 1) / (n(τ − ω^j))` — with no
  FFT anywhere. Every output element is required to equal it. This is the test
  that would catch a wrong domain, a forward transform where an inverse was
  meant, or a missing `1/n`.
* **The basis sums to one.** `Σ_j L_j(X) = 1` identically, so `Σ_j L_j(τ)·G`
  must be exactly the generator. Cheap, and independent of everything else.
* **A random polynomial, evaluated two ways.** Pick values `e_j` on the domain.
  Then `Σ_j e_j·L_j(τ)` over the Lagrange output must equal `Σ_i c_i·τ^i` over
  the monomial input, where `c = ifft(e)` in the field. Two different routes
  from the same polynomial to the same point.
* **The `h` query advances by τ**, batched into one pairing check, the same way
  the phase-1 powers are.

And the pieces are tied to each other: `e(L_j(τ)·G1, G2) = e(G1, L_j(τ)·G2)`
batched over the whole vector, so the two groups carry the same basis.

Eight tests break a constructed transform one way at a time. The sharpest is
two basis elements swapped **in both groups at once**: the sum is unchanged, so
the identity check passes; the groups still agree with each other, so the
pairing check passes; every point is genuine. Only going back to the powers it
was built from sees it. A swap in G1 alone is the easier case — the pairing
check catches that one first.

### Done, on the real slice

```
n = 32,768 basis points a group, 32,767 in the h query
transform  5.5 s        verify  1.4 s
reference string b30791cf1925a9184e90d9088acbc8299ae172fd3ef9958d892065368325baba
```

Seven seconds, so this is a step in the ceremony rather than an artifact to
store: the SRS is derived from the slice whenever it is needed, and the slice
is what carries the hashes. The digest above exists so a phase-2 transcript can
record which reference string it built on without carrying twenty megabytes of
it.

The permutation test runs against the real basis too — elements 11,111 and
22,222 of the genuine 2^15 basis, swapped in both groups, refused.

## Phase 2: not built, and why not sketched

Phase 2 is circuit-specific, so it has to be ours. With phase 1 fetched and
phase 1.5 done, it is **the only remaining engineering task**, and it is
deliberately absent rather than half-present.

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

The slices are in the repository, so nothing has to be fetched first.

```
# everything, including the real slices, their hashes and the basis change
cargo test --release --manifest-path tools/shielded-pool-ceremony/Cargo.toml

# what a slice actually is, the basis change, and the reference string phase 2
# would start from -- one run, because a verified slice on its own is not yet
# usable and the step between is easy to forget
cargo run --release --manifest-path tools/shielded-pool-ceremony/Cargo.toml \
    --bin verify-phase1-slice -- \
    artifacts/phase1/phase1-zcash-2m15.bin artifacts/phase1/phase1-zcash-2m15.json

# the gate a ceremony's verifying key has to pass
cargo test --release --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml \
    --test ceremony_acceptance

# and, to confirm a stored slice is still what the transcript serves:
# re-fetch and require the hashes to be identical
uv run python scripts/shielded-pool-phase1-slice.py --out artifacts/phase1
# --transcript filecoin for the other ceremony
```

Fetching and judging are separate on purpose: one half needs the network and no
cryptography, the other needs cryptography and no network. That separation is
why a re-fetch is a check rather than a refresh — the hashes it has to
reproduce are already in git.
