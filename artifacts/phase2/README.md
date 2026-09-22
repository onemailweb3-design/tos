# Phase-2 ceremony — not open

**Status: being prepared. Nothing has been contributed. No parameters from
this directory exist yet, and none may be deployed.**

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
exist, and contributions close 144 blocks before it. "Every contribution was
in before the beacon could be computed" is then structural rather than
probabilistic, and an outsider can check it.

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
comes from anyone independent of the operator. Twenty-two cases, each one
watched to fail.

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

## What has to happen before this opens

In this order. The order is the point: each step is only worth something if
the ones before it are already public.

| # | step | who | state |
|---|---|---|---|
| 1 | attestation verification exists and can fail | done | `test/shielded-pool/verify-attestations.py`, 22 cases |
| 2 | recruit participants, at least one independent of the operator | **operator** | **blocked — needs people** |
| 3 | collect each participant's already-public signing key into `roster.json` | operator | blocked on 2 |
| 4 | fix the beacon height and the closing height | operator | **confirmed 2026-09-22**: close 970,141, beacon 970,285 |
| 5 | publish the announcement, archive it, record where and when | operator | blocked on 2–3 |
| 6 | run `phase2-begin`, publish the starting digests | operator | blocked on 5 |
| 7 | contributions, in any order, each signed | participants | blocked on 6 |
| 8 | close at the announced beacon, verify from outside | verifiers | blocked on 7 |

## What is in here

```
ANNOUNCEMENT.draft.md    the announcement, with every undecided field marked TO FIX
PARTICIPANT-GUIDE.md     how to contribute, from a bare VPS, one command at a time
roster.template.json     the participant roster to fill in and pin
```

`roster.json`, `ceremony/`, `beacon.bin` and `attestation-N.txt` appear as the
steps above are taken. There is nowhere in any of them for a secret to go,
which is why they live in a public repository while the ceremony runs.

Procedure for the operator: [`../../doc/shielded-pool-phase2-runbook.md`](../../doc/shielded-pool-phase2-runbook.md).
