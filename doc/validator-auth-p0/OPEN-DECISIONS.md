# Two boundaries this profile does not yet fix

**Status: open. Neither boundary is decided here, and the next revision should
propose one normative answer to each rather than more prior art.**

Everything else in this directory proposes a concrete answer. These two do not,
and a freeze that leaves them open would ship a contract two implementations can
satisfy differently. Each section states the gap in terms of the files that have
it, then records how an established proof-of-stake protocol solved the same
problem, then sketches what adopting that shape would mean here and what it
still leaves to decide.

Prior art is not authority. The referenced design answers a question this profile
also has; it was reached under different constraints and its details are cited so
a reviewer can check them rather than take them on trust.

## 1. Where a scheduled lifecycle transition lives

### The gap

`VAU1` signs an `effective_from` coordinate and retirement is one of its
operations. [LIFECYCLE.md](LIFECYCLE.md) permits a coordinate no earlier than
inclusion, and immutable key versions must not be edited.

But canonical `VAI1` state holds only `active` and `pending` lists of `RoleRef`,
and a `RoleRef` is `role:u8 key:KeyRef`. It can encode neither a retirement nor
its deadline.

Take a retirement included at height 100 with `effective_from = 200`, for a key
whose immutable descriptor says `valid_until = 1000`:

- removing the active reference immediately stops new-session selection, which
  is 100 blocks earlier than the signed coordinate;
- keeping it leaves the deadline recorded nowhere in specified state.

Neither is correct, and no third option exists in the current grammar. A reader
cannot implement this from the specification, and two implementers who guess
will not agree.

### How the beacon chain represents this

Ethereum's consensus specification puts every scheduled transition on the record
it belongs to, as an explicit coordinate:

```python
class Validator(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    effective_balance: Gwei
    slashed: Boolean
    activation_eligibility_epoch: Epoch
    activation_epoch: Epoch
    exit_epoch: Epoch
    withdrawable_epoch: Epoch
```

A record is created with every epoch field set to `FAR_FUTURE_EPOCH`, defined as
`Epoch(2**64 - 1)`. That sentinel means *not scheduled*, and the comparison runs
in that direction:

```text
exit_epoch == FAR_FUTURE_EPOCH   ->  no exit is scheduled
exit_epoch != FAR_FUTURE_EPOCH   ->  an exit is already scheduled
```

`initiate_validator_exit` returns immediately on `validator.exit_epoch !=
FAR_FUTURE_EPOCH`, and `process_voluntary_exit` requires `validator.exit_epoch
== FAR_FUTURE_EPOCH` before accepting a new one. Scheduling an exit computes a
queue epoch and assigns it to `exit_epoch`.

What is borrowed here is only that the coordinate lives in authenticated state
behind a sentinel. The economic machinery around it -- exit queues, a withdrawal
delay, the balance rules -- answers a different question and is not proposed.

Three properties follow, and all three are what is missing here:

- the state is self-contained, so nothing has to scan historical operations to
  reconstruct what is pending;
- promotion and removal are comparisons against an authenticated coordinate,
  which is deterministic and replayable;
- a record can be simultaneously in use and scheduled to stop being used,
  because those are different fields rather than presence in a list.

### What this would mean here

Put the coordinate on the reference rather than in list membership:

```text
RoleRef = role:u8 key:KeyRef scheduled_from:u32 scheduled_until:u32
```

with a `NOT_SCHEDULED` sentinel — `0xFFFFFFFF` for a u32 coordinate, mirroring
the exclusive upper bound that [WIRE.md](WIRE.md) already says cannot wrap.
Selection at a session's authenticated anchor then reads the coordinates instead
of inferring intent from which list a reference appears in.

Still to decide, and not answered by the prior art:

- must a register or rotate operation's coordinate equal the new descriptor's
  `valid_from`, or is the operation coordinate stored separately? The current
  text does not say, and the two are not the same thing.
- what cancels or replaces a pending operation, and what happens to a second
  operation naming the same key?
- does a session already under way keep using a key past its scheduled removal?
  The beacon chain answers yes by fixing committees at epoch boundaries;
  [LIFECYCLE.md](LIFECYCLE.md) says existing sessions retain selected immutable
  versions, which points the same way but does not state it as a rule about
  scheduled removal.

### Constraints either encoding must satisfy

These came out of review and are not optional once a shape is chosen.

**A sentinel is not one rule.** `0xFFFFFFFF` means different things in a start
field and an end field, and both have to be stated. It must never be usable as a
real scheduling coordinate, arithmetic on it must not wrap, and "no scheduled
retirement" must not silently override the key's own `valid_until`. Eligibility
is the conjunction: the key's immutable validity interval **and** the schedule,
never either alone.

**Do not make a caller guess its own inclusion height.** Requests are signed
before they are included, so a coordinate the caller picks cannot reliably equal
the block that carries it. If immediate retirement is chosen, encode it as
*effective at the coordinate of the including block*, not as a height the caller
signs and hopes to match. This is a usability consequence of sign-then-include
ordering, not a detail.

**Evaluate the schedule where the snapshot is built.** Scheduling rules belong in
the construction of an authenticated committee snapshot, not in the verification
path, so the work lands on a state-update or session-creation boundary rather
than on every signature check. The cost after real integration still has to be
measured; nothing here promises it is free.

### The cheaper alternative, and why review argues against it

Make retirement immediate-only: require the coordinate to equal the inclusion
height and reject anything else. This needs no new state and no promotion rules.

Review recommends against it. Pre-announcing a transition is the useful case for
key rotation, algorithm migration and coordinated activation, which are the
things this profile exists to enable; saving a small amount of state is a poor
trade against them. It remains a legitimate answer, but it has to be chosen
deliberately rather than arrived at by leaving the gap open.

### Which shape review prefers

Not two coordinate fields bolted onto `RoleRef`, but an explicit **pending
operation record** in identity state that determines the operation kind, the old
key, the new key, the effective coordinate, and the authorizing request. The
number of pending operations per role and per algorithm profile must be bounded.

An interval-shaped `RoleRef` can also work. Whichever encoding is chosen, four
behaviours have to be pinned down rather than described: how old and new keys
switch atomically at a rotation boundary, how a pending operation is cancelled or
replaced, how a restart reaches the same result from the same authenticated
state, and how a session already under way keeps its snapshot.

### Tests either option requires

Before, exactly at, and after the coordinate. Restart from the same
authenticated state and reach the same selection. Old-session retention.
Cancellation of a pending key. Conflicting or replaced requests. A deterministic
reference state transition is enough to settle the specification; native
execution is a later gate.

## 2. How the signer's responses are encoded

### The gap

[SIGNER.md](SIGNER.md) fixes a strict JSON envelope: responses carry exactly
`api_version`, `request_id`, `result`, `error`, with exactly one of
`result`/`error` non-null, and result or receipt bytes are hex.

The envelope is specified. What travels inside it is not. `SignResult`,
`RequestState`, `Capabilities`, the preparation, staging and retirement
responses, and the durable receipt have no grammar anywhere:
[WIRE.md](WIRE.md) does not define them, `wire.tl` does not declare them, and
`reference.SCHEMAS` does not contain them. Method descriptions list conceptual
fields; knowing that a receipt binds a sequence number and a result hash does not
tell an independent implementer how to encode or decode one.

Two implementations can each follow the prose, choose different field layouts,
both report `api_version 1`, and fail to interoperate. Nothing in the profile
would catch that.

### How the beacon-chain remote signer specifies this

The remote signing interface between validator clients and remote signers is
published as an OpenAPI document, `remote-signing-oapi.yaml`, and linted in CI.
Its signing request is a discriminated union: `oneOf` over one named schema per
duty, selected by an explicit field.

```yaml
oneOf:
  - $ref: '#/components/schemas/AttestationSigning'
  - $ref: '#/components/schemas/BeaconBlockSigning'
  - ...
discriminator:
  propertyName: type
  mapping:
    ATTESTATION:            '#/components/schemas/AttestationSigning'
    BLOCK_V2:               '#/components/schemas/BeaconBlockSigning'
    VOLUNTARY_EXIT:         '#/components/schemas/VoluntaryExitSigning'
    RANDAO_REVEAL:          '#/components/schemas/RandaoRevealSigning'
    SYNC_COMMITTEE_MESSAGE: '#/components/schemas/SyncCommitteeMessageSigning'
    AGGREGATION_SLOT:       '#/components/schemas/AggregationSlotSigning'
```

Two things are worth separating. The first is the discipline: every request and
response shape is named, machine-readable and checkable, so a second
implementation is verified rather than argued with. The second is that the
signer, not the client, owns slashing protection — which matches the `duties`
table here, and is why that table's anti-equivocation slot is the constraint it
is.

### What this would mean here

One machine-readable schema per endpoint, request bodies discriminated by an
explicit field, and golden request, response and error fixtures beside the
existing signing vectors.

Still to decide:

- **Which format.** This profile is byte-oriented everywhere else, and
  [WIRE.md](WIRE.md) already has an ordered binary grammar. A byte grammar for
  the result and receipt types, carried in the existing thin JSON envelope, may
  fit better than adopting a full OpenAPI document for a seven-path API. CDDL or
  JSON Schema are the other candidates. The requirement is that it be normative
  and machine-readable, not that it be any particular one of these.
- **Receipts and context permits.** Standardized bytes, or explicitly versioned
  adapter-private attachments with a named trust and validation contract? Both
  are defensible; silence is not.
- **The administration authorization snapshot.** Stake-owner proof of
  possession, an identity's administration keys, and governance quorum must not
  become interchangeable by accident, and the snapshot each is read from has to
  be identified.

### Which shape review prefers

One machine-readable **ordered binary schema** as the single authority for
internal encoding, carried inside the existing thin JSON envelope, with JSON
Schema constraining only the transport layer:

```text
canonical binary schema
    -> exact request, result, receipt and error types, with fixed vectors
    -> thin JSON envelope carrying those bytes
```

This continues the byte-oriented design already in [WIRE.md](WIRE.md) and avoids
maintaining two internal representations that can drift apart. A route-level
description may still be useful, but it should not become a second inner
encoding specification. That the referenced project chose OpenAPI shows one way
to reach interoperability; it does not make that format the requirement.

**A schema validates fields, not protocol semantics.** Correlating a response to
its request, establishing where a receipt's authority comes from, and binding a
cursor to a snapshot are separate checks that no schema performs. Duplicate JSON
keys in particular must be rejected during parsing, before the document becomes a
map and the duplicate disappears.

**Four authorizations must stay distinct** and must not substitute for one
another: stake-owner authorization, proof of possession of the new key, the
identity's current administration keys, and governance quorum. The next revision
should make that separation visible in the types and validation rules rather than
only in prose.

### Tests this requires

Strict-parser cases for unknown and duplicate fields, canonical integer and hex
forms, result/error exclusivity, response correlation to request identity,
declared limits, and snapshot-bound pagination where a cursor exists.

## What this document is not

It is not a decision, and it does not freeze anything. Both boundaries are open
until a reviewed revision fixes them, and
[README.md](README.md) already requires that a freeze record bind the approved
artifact set. Adopting either shape above would change `VAI1` or add schema
files, which is an interface change and therefore review work, not editorial.

## References

- Beacon chain specification, `Validator` container and `FAR_FUTURE_EPOCH`:
  https://ethereum.github.io/consensus-specs/specs/phase0/beacon-chain/
- Remote signing API, OpenAPI source:
  https://github.com/ethereum/remote-signing-api
- The earlier HTTP signer interface it replaced, for the history of the problem:
  https://eips.ethereum.org/EIPS/eip-3030
