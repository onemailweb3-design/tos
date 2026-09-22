# Phase-2 ceremony — open participation

**Status: contribution 1 by tosman is signed and verified; registration remains
open. Parameters are not finalised and must not be deployed.**

[Contribution 1 and verification evidence](CONTRIBUTION-1.md).
[Download the public contribution bundle](https://github.com/tosnetwork/tos/releases/tag/shielded-pool-phase2-contribution-1);
[server publication receipt](contribution-1-publication-receipt.json).
The privacy-cleaned bundle matched SHA-256 `1af43216e0231c36c94eb8bc037a68ec1218a7ab7568b49ea54dd491f51d981b`.

See [ANNOUNCEMENT.md](ANNOUNCEMENT.md) for the fixed parameters and open
registration rules. The publication receipt was recorded before opening.

See [privacy cleanup and signed commit mapping](PRIVACY-CLEANUP.md) for the
metadata-only history rewrite and unchanged signed artifact payloads.

## If you are going to contribute

**[`PARTICIPANT-GUIDE.md`](PARTICIPANT-GUIDE.md)** — every command, from an
empty VPS to a published attestation. It assumes you have never seen this
repository. Roughly 25 minutes, most of it waiting.

## This is the second attempt, and the reasons matter

A first ceremony was run and **withdrawn on 2026-09-22**. Its directory has
been removed rather than kept alongside this one — two ceremony directories
invite exactly one mistake, which is contributing to the wrong one, and it
produced nothing worth keeping. It remains in git history: the artifacts were
added in `7ec052e00` and `7ed85e8dc`, and removing them here does not remove
them from the repository's past.

The three reasons it was withdrawn are written down here because **every one
of them is invisible in the artifacts afterwards** — a ceremony that made all
three mistakes produces a file indistinguishable from one that made none.

### 1. The beacon was a block that had already been mined

It named a Bitcoin block that was already six deep. The announcement said so,
and said a redo should use a future height, but being honest about a weakness
does not remove it: every contributor could read the beacon before drawing
their scalar.

**What this ceremony does instead:** the beacon is a block that does not
exist, and contributions close 144 blocks before it. Independent publication
evidence must establish that contributions closed before the beacon became
known. The height gap supplies a schedule, not a proof of unpredictability;
the ceremony tools do not enforce the deadline.

### 2. Nothing verified signatures

The contribution script could sign from the day it was written, and **no tool
in this repository ever checked a signature.** A ceremony with nine forged
attestations and one with nine genuine ones passed every check that existed,
identically. An instrument that answers by staying silent.

**What this ceremony does instead:**
`test/shielded-pool/verify-attestations.py` exists *before* the ceremony
opens, and it refuses a document naming a contribution the chain does not
contain, a valid document moved to another position, a signature from a key
nobody published, a genuine signature over different bytes, a roster listing
one key under two names, and a ceremony in which no verified contribution
comes from anyone declared independent of the operator. Twenty-three cases
exercise acceptance and refusals for specific reasons.

### 3. The announcement and the first contribution were published together

Both arrived in the same push, minutes apart. No outside observer saw the
announcement while it was still a commitment rather than a description, so
"announced first" could only be asserted by the party who wrote both.

**What this ceremony does instead:** the announcement is published and
archived, with the publication recorded, before `phase2-begin` is run at all.

### What was *not* wrong with it

Worth stating, because withdrawing a ceremony invites the assumption that the
machinery failed, and it did not. The mathematics audited, the chain linked,
the starting key rebuilt from the committed phase-1 slice, and the result
cross-checked against a second pairing library. **The same code runs this
ceremony.** It was withdrawn for what surrounded the computation.

No contribution carries over. The starting key is the same digest, but that
is a property of the construction — it is a function of the circuit and the
phase-1 slice, not of any ceremony.

## Open participation

The operator has removed the requirements to fix the entire participant list,
use old signing keys, or name outside verifiers before opening. Participants
may join throughout the contribution window, and newly generated signing keys
are accepted. Register each public key and identity before accepting its
contribution, then publish the register revision and digest with that contribution.

An operator contribution can be first. It is valid but does not count as an
independent participant. Outside participation and verification remain final
acceptance conditions; neither needs to be arranged before the first contribution.

| Step | State |
|---|---|
| Publish fixed circuit, code revision, deadline and beacon | see published announcement |
| Publish and retain announcement snapshot and publication receipt | completed before opening |
| Register tosman and its new public signing key | public key and initial register published |
| Open and accept the first signed contribution | completed: tosman, not independent |
| Register and accept additional participants | throughout the contribution window |
| Close, apply the announced beacon, verify and accept | only after all final gates pass |

The confirmed heights remain **970141** (close) and **970285** (beacon).
The initial register is not a closed list. Never rewrite accepted identities,
keys or contributions; publish additions with their history.

## Files

- [ANNOUNCEMENT.md](ANNOUNCEMENT.md): formal announcement.
- [PARTICIPANT-GUIDE.md](PARTICIPANT-GUIDE.md): contribution instructions.
- [roster.template.json](roster.template.json): registration format.
- [keys/tosman.md](keys/tosman.md): first contributor's public signing identity.

The published announcement and publication receipt identify the opening.
The beacon and final verification results appear only after closing.
Operator procedure: [runbook](../../doc/shielded-pool-phase2-runbook.md).
