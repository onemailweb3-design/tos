# Authenticated activation and historical eras

## Proposed allocation and state

Propose ConfigParam 46 for ValidatorAuthConfig and Config8 capability bit 10 (1024)
for capValidatorAuthV1. These are not installed in production schemas/constants or
live state by this PR; freeze requires collision review. TVM v16 wallet verification
is not an implicit validator-authority switch.

wire.tlb fixes the root and four references. Version is 1; chain_domain and interface
digest are immutable for this profile. registry_revision advances once per block with applied
identity/key changes, including due transitions, with checked overflow. current_policy names an immutable VAP1 in the policy map.

| Dictionary | Key | AuthBytes value |
| --- | --- | --- |
| identities | validator identity, zero for global admin nonce | VAI1 |
| keys | H(key,VAK1) | VAK1 |
| policies | H(policy,VAP1) | VAP1 |
| control.activations | effective_from masterchain height | VAT1 |
| control.observations | H(observation,VAO1) | VAO1 |

Validate typed values, key/value hash bindings and every referenced identity/key/
policy. Generic cell validation is insufficient. Preserve authenticated historical
objects/roots and public archives. Negative config indices cannot supply authority.
Fresh P0 genesis requires capability 1024 AND Config46, Config9 mandatory index 46,
and Config10 critical index 46. Initial policy is C0 revision 1, previous zero,
effective_from 0, no enabled observations. From this genesis there is one current
authoritative format, not concurrent legacy fallback. Earlier development chains
need an explicit testnet transition or separately named fresh genesis; no mainnet
reset is authorized.

Authority-sensitive indices include 0,1,8,9,10,11,15,16,17,28,29,30,32..37,39,40,46.
Review them under current admin authority. Critical voting labels alone do not
make contract signatures PQ-safe. C2/C3 is blocked until election, config, recovery
and replacement paths cannot remove their own gate with weaker authority.

## Deterministic policy selection

Policies form a strictly increasing effective_from schedule with linked previous
hashes and consecutive revisions. VAT1 binds the next policy and a pre-activation
finalized masterchain checkpoint (seqno/root/file/resulting-state). Checkpoint
seqno is less than effective_from; do not hash the future state containing itself.
Two policies at one height are invalid. Replacing pending activation requires a
new currently authorized admin operation before the boundary, never a local flag.

At committee-session creation, use authenticated masterchain anchor B and select
the policy with greatest effective_from <= B. Materialize accepted pending
transitions using LIFECYCLE.md before selecting keys, including exact-boundary
effects before cancellation requests. Admit all required keys for every
selected member/role, freeze the full snapshot, then derive session ID. Key validity
must cover expected session lifetime. Missing/offline members cannot be dropped
to change the denominator. An unsupported active profile must fail before signing
or counting a certificate, not merely log an upgrade warning.

A session born before activation keeps its policy until protocol-defined termination.
Later receipt height, local time or current config does not change old duties.
New sessions cannot borrow old authority. Native integration must establish and
test the existing agreed finite session termination rule, not add a signer-local
timeout. Split/merged shards select from their referenced masterchain anchors;
each parent certificate is checked under its own era and cannot authorize the new
child duty. Admin operations instead use current inclusion-time authority and
freshness; old sessions do not create an administration bypass.

## C1/C2/C3 and release evidence

C1 activates approved VAO1 diagnostics separately. VAP1 stays classical and its
required components do not change merely because observations succeed/fail.
Malformed authenticated registry updates still fail; diagnostic status is not
permission to ignore malformed consensus state.
C2 requires both profiles for each counted signer over the same VAS1; C3 permits
only approved PQ authority, with no classical extra component as an alternative.
This profile selects neither future PQ algorithm nor production activation date.
Calendar plans such as 2029 are not consensus coordinates.

Operator flags, missing backends and timeouts cannot downgrade policy. Emergency
rollback requires a separate explicit network/release decision. Readiness evidence
binds source commit, compiler/build profile, binary SHA-256, interface/vector
digests, network/genesis, full committee inventory and activation coordinates.
A source commit alone does not identify differently configured binaries. Readiness
percentages are not quorum and cannot relax complete required-key admission.

Required real rehearsal: native nodes and an independent Rust verifier agree before,
at and after the boundary; stale duties remain era-correct; old proofs fail for new
duties; missing keys/unknown profiles fail closed; shard handover, archives, restart
and signer recovery work. Measure hostile full certificates, blocks and propagation,
not only verifier microbenchmarks. Embedded bridge verifiers need their own upgrade.
Long-offline clients require independently trusted checkpoints; one supplied by the
same untrusted historical peer is not a new trust anchor. PQ signatures do not
repair forged classical history or make transport PQ-safe. No activation broadcaster
or claimed completed operational approval/rehearsal is included here.

The candidate fingerprint binds the canonical binary schema, thin transport
schema and lifecycle/API semantics through profile.json artifact hashes. A green
reference CI run is a candidate-design gate only: native state updates, independently
verified proof ranges, receipt frontier/fencing, and old-session integration remain
required before activation. Full Ubuntu build stays manually triggered.
