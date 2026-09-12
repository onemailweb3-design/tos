# Persistent validator identity and key lifecycle

## Identity and genesis

Identity = H(identity, chain_domain:h || stake_id:h || creation_nonce:u64).
The authenticated elector/registry allocates a unique stake ID and creation nonce;
one stake ID cannot receive committee weight twice. A legacy public-key short ID
may remain an index, never an independent recovery authority. ADNL is not authority.
chain_domain is fixed public genesis input, not the zerostate hash. Genesis records
do not contain their own enclosing state's hash. Actual zerostate root/file hashes
enter signed duties after genesis construction, avoiding a circular commitment.

VAI1 holds the owner account, next allowed admin nonce, predecessor view hash and
active/pending RoleRefs sorted by `(role,suite,parameters)`. Each list has at most
ten entries, one active and one pending version per role/profile. Immutable VAK1
versions remain retrievable by key ID in an authenticated public archive.
Registration creates no stake, membership or weight; election logic still does that.

## VAU1 operation semantics

Nonce must be >= the target's next_nonce. Apply sets next_nonce=nonce+1 with checked
arithmetic; UINT64_MAX is rejected. Skipped nonces allow an explicit new owner
intent after a known unusable request without reusing its signed duty. Unknown
broadcast/signing results require reconciliation, not automatic replacement.
Previous is the exact predecessor VAI1 hash, or current policy ID for global
operations. Conflict never means transparently re-sign under a new predecessor.
Unused fixed fields are zero and unused byte fields empty:

| operation | Required nonempty fields |
| --- | --- |
| 1 register | assigned identity and new_key=VAK1; old_key zero |
| 2 rotate | existing identity, old_key, new_key=VAK1 |
| 3 retire | existing identity and old_key; byte fields empty |
| 4 policy | zero target identity, new_policy=VAP1; old_key zero |
| 5 election | existing identity; operation_data = stake_id:h || beneficiary_workchain:i32 || beneficiary_address:h || election_id:h |
| 6 configuration | zero target identity; operation_data = parameter_index:i32 || previous_cell_hash:h || proposed_cell_hash:h |

Fields not listed in a row must be empty/zero. A newly allocated identity has
previous=zero and proven elector allocation plus stake-owner approval. Later
operations use the actual current identity view. The zero-ID identity record
holds the global admin nonce but is never a committee member. Configuration values
and state proofs are separate bounded attachments whose hashes must match before
apply. Election intents associate identity with an independently authorized stake
operation; existing value/ownership/timelock/selection checks remain mandatory.

Effective_from cannot precede inclusion. Register/rotate stage a new version for
sessions anchored at/after this coordinate. Existing sessions retain selected
immutable versions. Retire prevents new selection, not historical verification.
Cancelling a pending key is retirement, never editing the immutable descriptor.

## Authorization and proof of possession

New registration requires authenticated stake-owner approval AND new-key PoP.
Existing identity changes additionally require its currently authoritative
administration-role keys: both components in C2, approved PQ in C3. A classical
owner wallet, old keyring handle or operator connection cannot bypass that rule.
Lost-key recovery needs a separately reviewed network-authorized procedure.
This proposal does not make all validator funds or wallets PQ-safe.

Policy/config changes require the trusted governance committee's current-policy
quorum plus normal configuration-voting rules. Election, complaint/config votes
and privileged config paths must be covered before PQ enforcement; key onboarding
alone does not migrate them.

Admin Duty uses workchain=-1, full masterchain shard, governing committee catchain
and anchor, position=VAU1.nonce, and session=H(admin-session, network:i32 ||
genesis_root:h || genesis_file:h || VAU1.identity:h). This namespaces nonces by
target without resetting them when a key, epoch or suite changes. Inclusion must
use current policy/predecessor and occur within 128 masterchain blocks of anchor.
Unlike old consensus sessions, old-era admin duties do not remain new authority.

PoP signs `ASCII("TOS/P0/pop/v1") || 00 || network:i32 || chain_domain:h ||
blob(VAU1) || key_id:h`; blob is u32 length-prefixed. Validate the proposed key and
exact suite before verifying. PoP never supplies ownership or quorum. Genesis
uses the pre-genesis chain_domain and an approved offline allocation manifest,
not a not-yet-known zerostate hash. Stateful PoP consumes the same globally fenced
capacity as ordinary signing.

## Epochs, states and retention

Epoch starts at 1 and strictly increases per `(identity,role,suite,parameters)`;
no wrap. Stateful capacity_domain = H(capacity, suite:u16 || parameters:u16 ||
blob(public_key)); its capacity limit comes from the reviewed suite. The same
material under a new role, identity or epoch cannot obtain fresh capacity. Every
HSM/provider reference to that material shares a single allocation authority.
C0 stateless descriptors have zero capacity metadata.

Local key states: PENDING -> ACTIVE -> RETIRED -> DESTROYED; pending cancellation
uses PENDING -> RETIRED. Destruction means destroying secrets, not public history
or signer tombstones. Reorgs, session pruning and compaction must not rewind safety
state. Public historical descriptors/policies remain authenticated by their era's
state roots; a current registry lookup is insufficient for old proofs.

signer-store.sql is a reference persistence contract, not a mandated storage engine.
u64 values are eight big-endian bytes, not signed SQLite INTEGERs. Public key
versions and consumed capacity are immutable. Terminal results cannot revert to
pending. Cross-role rules and checked arithmetic still need one serialized service
transaction. A local database cannot prove that itself and its backups were not
rolled back; external fencing is specified in SIGNER.md.
