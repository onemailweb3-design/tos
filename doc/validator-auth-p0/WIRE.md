# P0 canonical wire and signing profile

BCP 14 MUST/SHOULD terms describe the proposed contract, not an enabled rule.

## 1. Ordered binary grammar

All integers are big-endian; i32 uses two's complement. h is exactly 32 bytes.
`blob(N)` is u32 length then that many bytes, at most N; no padding. `list(w,N,T)`
is a count in unsigned width w, at most N, followed by inline T objects.
Every tagged object starts with its four ASCII tag bytes, u16 version=1, and
u16 flags=0. Untagged records have only their listed fields. Nested tagged objects
are inline, without an additional implicit length. Field order is normative:

```text
Suite       = suite:u16 parameters:u16
KeyRef      = suite:u16 parameters:u16 epoch:u64 key_id:h
Component   = KeyRef signature:blob(65536)
Record      = identity:h components:list(u8,2,Component)
RoleRef     = role:u8 key:KeyRef
Key VAK1    = identity:h role:u8 suite:u16 parameters:u16 epoch:u64
              valid_from:u32 valid_until:u32 public_key:blob(16384)
              capacity_domain:h capacity_limit:u64
Policy VAP1 = revision:u64 previous:h interface_digest:h effective_from:u32
              phase:u8 suites:list(u8,2,Suite) max_envelope:u32 max_certificate:u32
Member      = identity:h stake_id:h weight:u64 adnl_id:h keys:list(u8,10,Key)
Committee VAM1 = policy:h election:h workchain:i32 shard:u64 catchain:u32
                anchor_mc:u32 members:list(u16,1024,Member)
Duty VAD1   = network:i32 genesis_root:h genesis_file:h policy:h committee:h
              session:h workchain:i32 shard:u64 anchor_mc:u32 catchain:u32
              position:u64 role:u8 payload_hash:h
Statement VAS1 = duty:Duty identity:h keys:list(u8,2,KeyRef)
Envelope VAE1  = duty:Duty payload:blob(4096) record:Record
Certificate VAC1 = duty:Duty payload:blob(4096) records:list(u16,1024,Record)
Update VAU1 = operation:u8 identity:h nonce:u64 previous:h effective_from:u32
              old_key:h new_key:blob(32768) new_policy:blob(4096)
              operation_data:blob(4096)
Identity VAI1 = identity:h stake_id:h owner_workchain:i32 owner_address:h
                next_nonce:u64 previous:h active:list(u8,10,RoleRef)
                pending:list(u8,10,RoleRef)
Activation VAT1 = revision:u64 previous:h next_policy:h effective_from:u32
                  checkpoint_seqno:u32 checkpoint_root:h checkpoint_file:h
                  checkpoint_state:h
Observation VAO1 = suite:u16 parameters:u16 registry_root:h valid_from:u32
                   valid_until:u32 enabled:u8
```

Unknown versions, nonzero flags, overflow, unknown tags, wrong counts/lengths,
trailing bytes and duplicate/unknown authoritative components MUST be rejected.
There are no ignored extension TLVs, varints or optional fields. Empty signature
and public-key payloads are invalid. Empty lists require explicit semantic permission.
Parsing is not authentication; a structurally representable future suite is not
an admitted C0 suite.

Suite/profile `(1,1)` is the only C0 allocation. Zero is invalid; IDs 2..32767 need
reviewed production allocation; 32768..65535 are private/test IDs forbidden in
production authority. More than two components requires a versioned upgrade.
`H(label,bytes)` is SHA-256(ASCII(`TOS/P0/`+label+`/v1`) || 00 || bytes).
Object IDs use lowercase grammar names: key, policy, committee, statement,
identity, update, activation, observation. No truncation is permitted.
The interface artifact digest is instead the unprefixed SHA-256 in README.md.
Future PQ review MUST assess these 256-bit hashes and inherited candidate/chain
hashes together; this is not a blanket 128-bit PQ collision-security claim.

## 2. Keys, policies and the complete roster

Key ID = H(key,VAK1), covering the entire immutable descriptor. Epoch starts at 1.
Validity is `[valid_from,valid_until)` at the session's authenticated masterchain
anchor, not local time or message arrival height. The exclusive u32 upper bound
cannot wrap. C0 keys have 32 public-key bytes and all-zero capacity metadata.

Policy ID = H(policy,VAP1). Revision starts at 1 and advances by one; previous is
zero only at genesis. C0 phase=0 requires exactly `(1,1)`, max_envelope=4096 and
max_certificate=524288. C2 phase=2 requires one classical and one approved PQ
profile in ascending `(suite,parameters)` order; C3 phase=3 requires one approved
PQ profile. Phase=1 is not an authoritative encoding: shadow uses separate VAO1
state. Observation enabled is exactly 0 or 1, and its interval is nonempty.

Committee ID = H(committee,VAM1). Include all members, including absent voters,
in strictly increasing identity order. Identities and stake IDs must be unique
and nonzero. Weights come from authenticated election state, are positive, and
sum to at most floor((2^64-1)/3). A wire claim never creates weight. Member keys
are sorted by `(role,suite,parameters)` and contain all required profiles for
roles 1..5: exactly five keys in C0, ten in C2. Key identities match their owner.
Admit actual key bytes before compiling the immutable snapshot.

The committee does not contain its session ID, avoiding a commitment cycle.
For consensus roles the new session ID is H(session, network:i32 || genesis_root:h
|| genesis_file:h || committee_id:h || native_options_hash:h || vertical_seqno:u32
|| key_block_seqno:u32). Inputs come from trusted session creation; dimensions not
used by a legacy creation path are explicitly zero. Roster, workchain/shard,
catchain and anchor are already bound by committee_id. ADNL remains transport
metadata, not a signing credential. Diagnostics never mutate a running snapshot.

## 3. Duty, payload and the bytes actually signed

Roles are proposal=1, notarize=2, finalize=3, skip=4, administration=5. Position is
u64; consensus roles must fit u32 and equal the Simplex slot. Admin uses its u64
operation nonce and target-scoped session as defined in LIFECYCLE.md.
Payload hash = H(payload, role:u8 || canonical_payload_bytes).
Native payloads retain little-endian TL inside this big-endian outer format:

| Role | Exact payload |
| --- | --- |
| 1 | Serialized consensus.candidateId, 40 bytes |
| 2 | Serialized consensus.simplex.notarizeVote including candidate ID, 44 bytes |
| 3 | Serialized consensus.simplex.finalizeVote including candidate ID, 44 bytes |
| 4 | Serialized consensus.simplex.skipVote, 8 bytes |
| 5 | Canonical VAU1 administrative intent |

Constructor, exact consumption and slot/nonce must agree with Duty. The proposal
caller still validates the actual candidate and recomputes its ID. Signing a
claimed candidate hash is not block validation. Expected genesis, policy,
committee, session and duty MUST be derived independently from authenticated state,
not copied from a received object and compared to themselves.

For each signer construct VAS1 from the complete Duty, identity and the exact
sorted required key references. Every required component signs these **identical
complete VAS1 bytes**. Signature bytes are not in VAS1. Ed25519 signs neither JSON,
a supplied prehash, a BOC file hash nor the old dataToSign wrapper. A future suite's
internal preprocessing must be explicit and authenticate the same VAS1.

VAE1 has one record. VAC1 has 1..1024 strictly identity-sorted records. Reject
unknown/duplicate signers and nonmatching component profiles, key IDs or epochs.
Complete structural/resource admission before expensive verification. Verify every
included required signature, even surplus signatures after quorum. Return authorized
weight only after all succeed. Require `3*S >= 2*W` with checked/widened arithmetic;
W is the full trusted committee, not a filtered subset or supplied total.

## 4. Exact C0 Ed25519 acceptance

Suite `(1,1)` is Pure Ed25519 with internal SHA-512, not Ed25519ctx/ph. The outer
VAS1 provides domain separation. A and R must be canonical compressed Edwards
encodings: y < 2^255-19, successful curve decoding, and no x=0/sign-bit-1 alias.
Admit A only if A != identity and [L]A=identity, with L the prime subgroup order.
S is little-endian and must satisfy 0 <= S < L. Verify the noncofactored equation
`[S]B = R + [SHA-512(R || A || VAS1) mod L]A`.
R need not have a separate subgroup multiplication because the equation and
admitted A imply it. Cache admitted keys per immutable snapshot; do not put an
extra public-key subgroup multiplication on every vote.
C++ and Rust must prove the same edge-case acceptance set. These rules are for
the new suite only; historical signatures retain their historical rules.

## 5. Bounds and canonical cells

Hard caps: public key 16384 bytes; component 65536; components 2; keys/member 10;
members/signers 1024; payload 4096; canonical object 8388608; envelope 262144.
C0 has the tighter policy caps above. A future activation must prove that the
entire selected committee fits its active budgets; do not trim weight/signers to
fit. The outer contract fits ML-DSA-44-sized material, not every future algorithm
at maximum committee size. Larger requirements need a reviewed profile version.

AuthBytes has version=1, byte_length, SHA-256(raw canonical payload) and one root
reference. Only ordinary level-0 cells occur inside it. A leaf is tag 0, seven-bit
length 1..120, exactly length*8 data bits, no refs. A branch is tag 1, three-bit
child count 2..4, u32 byte_length and that many ordered refs, no extra bits/refs.
For a nonleaf size n choose the smallest capacity `120*4^k` with `n <= 4*capacity`;
split into full capacity chunks and one possibly shorter last chunk, recursively.
No empty leaves, single-child branches, alternate balancing or trailing content.

Limit depth to nine edges below the byte-node root (ten including AuthBytes),
100000 logical node occurrences and 12582912 serialized BOC bytes. Shared equal
cells are allowed but every occurrence counts; deduplication cannot evade budgets.
Reject cycles/exotic cells. Authenticated Merkle-proof wrappers may exist outside
AuthBytes. Hash reconstructed bytes for object IDs, not BOC index/CRC packaging.
The logical-tree oracle does not substitute for native BOC acceptance tests.

## 6. Native TL and legacy formats

The six explicit IDs in wire.tl wrap VAE1/VAC1/VAK1/VAP1/VAM1/VAU1 in `data:bytes`.
TL encodes constructor IDs little-endian. Its bytes length must be minimal: one
byte for <254, otherwise 254 plus three little-endian length bytes; zero padding;
no trailing bytes. The 8 MiB bound fits this representation.
Import constructors alongside, never instead of, historical ones. A native TL
parser must accept the combined schema before implementation. The generic bytes
field is not itself a validator: typed decoding and trusted policy verification
remain mandatory. Native TL-B/BOC and C++/Rust differential execution remain
explicit production implementation gates.
