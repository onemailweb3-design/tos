# Signer service API and failure contract v1

## Typed API

The exact types and method allocations are [canonical-schema.json](canonical-schema.json);
[API-CONTRACT.md](API-CONTRACT.md) supplies mandatory semantic checks. These are
review-candidate semantics; actor/future scheduling adapters
may differ. All buffers are bounded/owned. No method accepts peer-supplied code or
raw secret bytes.

```text
get_capabilities() -> Capabilities | SignerError
get_public_key(KeyId) -> KeyDescriptor | SignerError
prepare_key(KeyPreparationRequest) -> KeyDescriptorAndHandle | SignerError
stage_key(StageKeyRequest) -> KeyDescriptorAndPossessionProof | SignerError
sign(SignRequest) -> SignResult | SignerError
get_result(SignRequestId) -> RequestState | SignerError
retire_key(RetireRequest) -> RetirementReceipt | SignerError
```

Capabilities includes api_version=1, interface digest, installed/admitted profiles,
request/result limits, persistent_journal, fencing and stateful flags. These are
discovery claims, not substitutes for binary/fault-test evidence. Existing generic
Keyring export/raw-sign APIs MUST refuse consensus-designated handles; network keys
remain a separate namespace.

KeyPreparationRequest includes identity, role, suite/parameters, epoch, validity,
provider handle or a generate request, preparation_id and fence. It durably binds
preparation_id to those parameters and returns an immutable public descriptor and
opaque 32-byte handle. Reusing the ID for different parameters is a conflict.
Preparation has no chain authority. It precedes constructing VAU1, so generating
a new key never requires a request to already know that key's public bytes.

StageKeyRequest = proposed VAK1, handle, canonical VAU1, separately typed owner/current-administration
authorizations, context permit and fence. Input PoP is absent; the result supplies it. It verifies and journals PoP for that already
prepared key. RetireRequest = key_id, canonical VAU1, typed current-administration proof, context
permit and fence. Cancel refers to the exact pending transition. Neither bypasses admin nonce/CAS or exposes private material.

SignRequest has its tagged version/flags header, request_id:h,
key_handles:list(u8,2,h), envelope_template:blob(262144), permit:VAPt and fence:u64. The template is VAE1
with empty signature fields in canonical required-component order; it is not
admissible network authentication until filled. Handles resolve to those exact
key references. The trusted local consensus adapter authenticates a bounded
context permit tying the template to network, registry, policy, session
and allowed duty. A peer's asserted context is not such a permit. Receipt validation
against trusted state is a mandatory native integration gate.

The service derives request_id=H(sign-request,complete VAS1) and rejects a mismatch.
SignResult includes request_id, statement_id, record, fence and a durable
receipt binding journal sequence/result hash. A receipt carries no extra quorum
weight. RequestState is ABSENT, RESERVED, COMPLETE or BURNED. ABSENT is not proof
that an external primitive never exposed a signature during an uncertain failure.

## Transport

Remote deployment uses HTTP/2 over TLS 1.3 with mutual authentication and per-chain/
method ACLs. Local deployment may use a mode-0600 Unix socket and OS peer credentials.
This is not a claim of PQ transport authentication. Application media type:
`application/vnd.tos.validator-auth.v1+json`. JSON is transport only, never signed.
Reject duplicate/unknown fields, invalid UTF-8, floats/NaN and noncanonical hex.
Only api_version="1" is a transport integer string; all other integers
are inside the canonical binary payload, never nested JSON fields. Binary fields are lowercase even-length hex of exact-width or
bounded canonical bytes. No compression or redirects. Whole request/response cap
is 4 MiB; binary payload cap 2000000 bytes; template cap 262144 bytes;
proof attachment cap 1 MiB. Permits and receipts have exact bounded schema types.

Paths: /v1/capabilities (GET), /v1/keys/public, /v1/keys/prepare, /v1/keys/stage,
/v1/sign, /v1/requests/result, /v1/keys/retire (POST). Responses have exactly
api_version, request_id, result, error; exactly one of result/error is non-null.
Capabilities request_id is zero. Errors have code, retryable, request_state and
message; message is diagnostic, not control flow. Canonical result/error objects (including typed receipts) are
hex and do not replace canonical binary objects with nested JSON equivalents.

| code | Meaning | Action |
| --- | --- | --- |
| 1 | BAD_REQUEST | Correct malformed request; no automatic signing retry |
| 2 | UNAUTHORIZED | Stop |
| 3 | UNKNOWN_KEY | Reconcile provisioning |
| 4 | DISABLED_SUITE | Stop; no fallback |
| 5 | CONTEXT_MISMATCH | Re-read authenticated context |
| 6 | KEY_NOT_VALID | Reconcile lifecycle |
| 7 | CONFLICT | Stop and investigate |
| 8 | FENCED | Stop stale signer instance |
| 9 | CAPACITY_EXHAUSTED | Rotate under current authority |
| 10 | STORAGE_UNAVAILABLE | Query exact request; do not re-sign |
| 11 | RESULT_UNCERTAIN | Preserve/burn capacity under reviewed recovery |
| 12 | BACKEND_ERROR | No cryptographic fallback |
| 13 | HISTORY_UNAVAILABLE | Acquire authenticated history |
| 14 | UNSUPPORTED_PROFILE | Upgrade; no legacy retry |

Only reads/result polling may be retried automatically. An identical sign request
may recover the exact durable result, never allocate new stateful capacity.
A timeout is not an invalid signature and cannot trigger Ed25519-only fallback.

## Durable duty and conflict rules

One fenced writer validates all context/key references, checks conflicts, reserves
the exact statement and all component capacity, and commits/fsyncs journal plus
external monotonic witness BEFORE invoking the primitive. It commits the complete
result and witness BEFORE release. A partial hybrid result is never an authoritative
envelope; internally completed components may be retained for recovery only.

Conflict namespace is `(chain,identity,session,workchain,shard,position)`, with
per-role records. It excludes candidate, algorithm and key epoch: changing those
cannot manufacture a new duty. Admin uses its target-scoped session. Preserve both
arrival orders of these current Simplex rules:

| Pair | Result |
| --- | --- |
| same role, identical payload | Exact cached result if complete |
| same role, different payload | Reject |
| notarize A / finalize A | Allowed subject to consensus permit |
| notarize A / finalize B | Reject |
| finalize / skip | Reject |
| notarize / skip | Allowed subject to consensus permit |

These are conflict rules, not a replacement for the permission to vote. One proposal
per leader slot is separately reserved. Stateful allocation is globally unique per
actual key material across roles, shards, sessions, PoP and failover. Slot*2+type
is not an acceptable capacity schedule.

| Failure point | Required recovery |
| --- | --- |
| Before reservation commit | No primitive call; retry only under current fence |
| After reservation/before call | Keep capacity consumed |
| During call/before result commit | RESULT_UNCERTAIN; stateful capacity burned |
| After complete commit/before reply | Return exact stored result |
| After reply | Exact retransmission only; conflicting statement refused |
| Two writers/stale lease | Primitive rejects stale fence, including delayed in-flight calls/results |
| Reorg/session pruning | Never rewind safety ledger |
| Restored disk/VM | Compare with external non-rollbackable frontier; mismatch stops signing |
| Lost witness/ambiguous backup | Fail closed, no automatic failover |
| Exhaustion/wrap | Stop and rotate, never modulo reset |

A local transaction, lock, clock lease, WAL or same-disk backup is not an independent
fence. Stateful/automatic-failover deployment must specify a non-rollbackable witness
or HSM generation that fences the primitive, not only its RPC handler. P0 reserves
these API/capability obligations; C0 enables no stateful suite. Reference SQL/tests
do not establish this distributed/hardware safety property.

Exact request/result/error/receipt, request-state variant, issuer trust, size and
correlation rules are in [API-CONTRACT.md](API-CONTRACT.md). A retirement receipt
is neither proof of chain inclusion nor permission to destroy a key used by an
old session; lifecycle selection and signer safety retention remain distinct.
