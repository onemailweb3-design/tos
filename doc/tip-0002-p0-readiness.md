# Validator authentication: inventory, executable regressions and isolated agility

## Scope and status

The production validator remains Ed25519-only. No online signer, consensus
handler, keyring operation, TL/TL-B constructor, configuration parameter or
historical proof encoding is changed here. The experimental verifier is **not
included by production sources** and its test signer is **not linked into node
targets**. `TOS_BUILD_VALIDATOR_AUTH_TESTS` defaults to `OFF`.

This is preparation for [TIP-0002](https://github.com/tosnetwork/TIP/pull/1),
reviewed at `231570f4ae4511b5e42c6b8ce0fdb5576b2663d9`. It is not a completed P0
launch profile. That draft has not allocated the outer wire constructors,
production suite/profile IDs, canonical extension semantics or signer-service
errors. The in-process experiment deliberately cannot be mistaken for those
unallocated formats: its transcript domains contain `EXPERIMENT`, its identifiers
are local test choices, and it has no network decoder or activation hook.

The inventory was followed through the actual C++ source on the mainline
`758aa29ff21fbdd8d6f15fb9f4e47da60e2c449d` boundary. Source hashes are emitted with
each run so later reviews need not rely on line numbers. The pre-existing 25-case
Boolean policy corpus remains a **model**, separately labeled from the new real
signature tests. Neither a model verdict nor successful parsing is authentication.

## Production authentication and trust boundaries

| Boundary | Actual implementation | What it establishes and what must be preserved |
| --- | --- | --- |
| Committee/key admission | `crypto/block/mc-config.cpp`, `crypto/block/validator-set.cpp`, `validator/consensus/bridge.cpp` | Configured Ed25519 keys and positive bounded weights become the trusted set. `ValidatorSet` checks weight accumulation and duplicate key identities. The bridge explicitly constructs `pubkeys::Ed25519`; a future adapter must not accept arbitrary generic `PublicKey` variants. |
| Session identity | `ValidatorManagerImpl::get_validator_set_id` in `validator/manager.cpp` | Hashes `validator.group`, `groupEx` or `groupNew`, including workchain/shard, catchain sequence, options hash and the full ordered member list of public-key hashes, ADNL IDs and weights; newer forms also include vertical/key-block sequence. **There already is indirect full-committee binding.** There is no explicit genesis/network/PQ-policy/key-epoch field in that session statement. |
| Proposal signing | `validator/consensus/block-producer.cpp` | Keyring signs `consensus.dataToSign(session_id, serialized candidateId)`. Candidate ID binds slot and candidate hash data. |
| Proposal verification | `Candidate::deserialize` and `PeerValidator::check_signature` in `validator/consensus/types.cpp` | Checks leader/source/slot and candidate structure, reconstructs the candidate ID, then verifies the same session wrapper. The new runtime tests exercise the empty-candidate path; full candidate payload validation is not claimed covered by that fixture. |
| Notarize, Finalize, Skip | `validator/consensus/simplex/pool.cpp`, `votes.cpp`, `types.cpp` | Three different unsigned-vote constructors under the shared session wrapper. The inner TL constructor provides role separation today; sharing a wrapper is **not absence of domain separation**. Stateful signing capacity would still require independent operational allocation/fencing. |
| Vote certificates | `Certificate<T>::from_tl` in `validator/consensus/simplex/certificate.cpp` | Rejects out-of-range and duplicate signer indexes, accumulates checked weight, requires `quorum_threshold(total_weight)`, and verifies every included signature. A surplus invalid signer is not ignored after reaching quorum. |
| Ordinary stored proofs | `BlockSignatureSetOrdinary::to_sign` and the base verifier in `crypto/block/signature-set.cpp` | Signs **bare `tos.blockId(root_cell_hash, file_hash)`**, not `dataToSign`. Vset hash/catchain metadata, block/header verification and trust in the selected committee are separate caller checks. Do not rewrite these historical preimages. |
| Simplex stored proofs | `BlockSignatureSetSimplex::to_sign` and certificate conversion | Reconstructs candidate ID from the requested block and candidate hash data, then wraps a notarize or finalize vote with the stored session ID. Approval and finality are distinct; an approval cannot be serialized as a finalized proof. |
| TL-B proof decoder | `unpack_signatures_dict`, `BlockSignatureSet::fetch` | `ed25519_signature#5`, exactly 64 signature bytes, contiguous 16-bit dictionary indexes, no trailing leaf bits/refs, at most 1024 decoded signatures. `fetch(cell, vset)` also checks claimed weight, but **does not verify the signatures**. |
| Proof consumers | `validator/impl/check-proof.cpp`, `accept-block.cpp`, `top-shard-descr.cpp`, `validator/validate-broadcast.cpp`, `validator/manager.cpp` | Select the trusted committee and dispatch final/approval verification; `CheckProof` also compares authenticated weight to claimed weight. The entrypoint tests below do not replace actor/network integration tests of these callers. |
| Light-client chain proofs | `crypto/block/check-proof.cpp`, `validator/impl/liteserver.cpp` | A forward proof-chain consumer derives the committee from a trusted key block/state then verifies signatures. The liteserver's proof construction/serialization is not itself a second authentication check. |
| Wire and other languages | `crypto/block/block.tlb`, `tl/generate/scheme/{tos_api,lite_api}.tl`, `tosctl/src/block/src/signature.rs` | Current public keys and stored signature components still have Ed25519-specific widths. C++ TL/lite/TL-B round trips are tested here; a future extensible Rust codec and cross-language PQ certificate format are not implemented. |
| Signer/key lifecycle | `keyring/keyring.h`, `keyring/keyring.cpp`, `keys/keys.cpp`, `keys/encryptor.cpp`, `validator-engine/validator-engine.cpp` | Generic keyring sign calls currently select a legacy key hash. They do not implement durable stateful leaf allocation, key-epoch policy selection, crash fencing or anti-rollback recovery. |
| Election and administrative authority | `crypto/smartcont/elector-code.fc`, `config-code.fc`, validator-engine election/proposal vote creators | Election registration, complaint votes and configuration votes verify classical signatures; config also has an administrative signing path. They must be migrated or explicitly constrained before PQ-required consensus can be claimed. These contracts are inventoried here, not dynamically migrated/tested by this suite. |
| Explicit trust shortcuts | `skip_check_signatures_` in proof loading, `is_fake_` in block acceptance, `signatures_checked_` in broadcast validation | Existing replay/bootstrap/trusted-caller modes are not newly exposed network authorization. A future enforcing policy must audit provenance and policy/epoch-sensitive cache reuse rather than assuming every caller always performs fresh verification. |

`PeerValidator` uses a generic key container, whose other users include non-signing
modes. Its production safety argument depends on Ed25519 admission in the bridge,
not on treating every `PublicKey` variant as a valid validator algorithm. This is
a future-adapter constraint, **not a demonstrated live bypass**.

The shared quorum rule remains `3 * signed_weight >= 2 * total_weight`, with
widened arithmetic and the existing total-weight cap. This work does not change
the consensus threshold or attempt to select a different BFT protocol.

## What is executable now

### Unchanged production entrypoints

`test/validator-auth/test-production.cpp` compiles the actual consensus source
files and links the actual block-signature library. It does not reproduce those
verifiers in the test. Deterministic, publicly disclosed fixture seeds produce
real Ed25519 signatures for:

- Proposals and all three signed vote decoders, cross-role/session/key/payload
  negatives, signature truncation/oversize and malformed proposal conditions.
- All three certificate types at the exact two-of-three boundary, weighted
  subsets, the full committee denominator, duplicates/unknown indexes, invalid
  signatures and an invalid surplus signer after quorum.
- Ordinary and Simplex finality proofs, approval/finality separation, real
  TL/lite/TL-B round trips, context substitution and fixed-width rejection.
- Decoder tag/leaf shape/index/count/weight boundaries, 1024/1025 dictionary
  entries, and a parsed-but-cryptographically-invalid proof.

`legacy-golden.json` locks the exact old public preimages, signatures and proof
BOCs. `check_transcripts.py` independently reconstructs the legacy TL signing
wrappers from their schemas and checks Ed25519 with libsodium, rather than the
OpenSSL implementation used by the native verifier. Optional `--openssl-mldsa`
also cross-checks the experiment with an independently implemented ML-DSA
provider; it requires an OpenSSL version that actually supports ML-DSA and fails
rather than silently skipping when requested.

### Algorithm-neutral, isolated candidate verification

`validator/auth/experimental.h` supplies a concrete **in-process** registry,
policy, statement, component and verification interface. It is intentionally
unreachable from the running validator:

- Owned immutable registry snapshots with sorted unique identities, checked
  weights, bounded key records, role/profile/epoch/validity and a full-roster
  cryptographic commitment, including validators who did not sign.
- Deterministic candidate statements binding network, genesis, full registry,
  governance-policy commitment, authority phase, session, shard, slot, role,
  payload, signer identity and both required key references.
- Exact, bounded, canonically ordered authoritative components, cheap complete
  admission before crypto, no unknown-provider fallback, no weight on failure,
  no early success after quorum, and explicit backend failure.
- Classical, observation-only shadow, same-signer hybrid **AND**, and PQ-required
  policies. Shadow diagnostics have a separate result type, are never invoked
  by authoritative verification, and do not alter the classical transcript.

`test-experimental.cpp` uses real Ed25519 and real FIPS 204 Pure ML-DSA-44 signing
and verification, with a private test-only signer library and the existing pinned
portable verifier. It tests five roles across four policies, missing/invalid
components, separate component quorums, every statement binding, key validity and
epoch relabeling, registry/resource bounds and backend faults. ML-DSA-44 is an
available stateless test candidate here, **not the selected validator PQ suite**.

A clearly named noncryptographic shape probe reaches the aggregate byte budget
with hypothetical large components; it never returns a valid signature. That
probe tests admission limits only and is not counted as cryptographic evidence.
The candidate limits and identifiers are not production consensus allocations.

## Performance and activation boundary

No live verification call, serialization, key lookup, quorum arithmetic or
registry construction has been changed. No additional hash, memory allocation,
virtual call, PQ verification or diagnostic sidecar is inserted into that path.
`check_isolation.py` rejects accidental production inclusion/linkage and records
28 audited source hashes. Compare these to the reviewed base to establish the
unchanged-source boundary; this is not a claim to have benchmarked a whole node.

`test-validator-auth-production --benchmark` measures the existing real peer
verification and ordinary-proof quorum operations with checked positive controls.
Timing is recorded separately from deterministic transcripts. It is a local
baseline for later work, not a production TPS/latency certificate and not evidence
that an eventual activated PQ scheme has zero overhead. The experimental generic
verifier itself is not being promised to be cost-free.

## Build and verification

The focused targets require the repository's ordinary native dependencies. An
example Linux configuration using system OpenSSL is:

```sh
cmake -S . -B build-validator-auth -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DTOS_ARCH= \
  -DTOS_BUILD_VALIDATOR_AUTH_TESTS=ON \
  -DUSE_QUIC=OFF -DTOS_USE_ROCKSDB=OFF -DTOS_USE_ABSEIL=OFF \
  -DCMAKE_SKIP_INSTALL_RULES=ON \
  -DOPENSSL_CRYPTO_LIBRARY="$(pkg-config --variable=libdir openssl)/libcrypto.so" \
  -DOPENSSL_SSL_LIBRARY="$(pkg-config --variable=libdir openssl)/libssl.so" \
  -DOPENSSL_INCLUDE_DIR="$(pkg-config --variable=includedir openssl)"
cmake --build build-validator-auth --target test-validator-auth-production \
  test-validator-auth-experimental test-validator-auth-policy test-quorum -j2
ctest --test-dir build-validator-auth --output-on-failure \
  -R '^(validator-auth-(production|experimental)|test-validator-auth-policy|test-quorum(-static-grep)?)$'
mkdir -p validator-auth-results
build-validator-auth/test/validator-auth/test-validator-auth-production > validator-auth-results/production.tsv
build-validator-auth/test/validator-auth/test-validator-auth-experimental > validator-auth-results/experimental.tsv
python test/validator-auth/check_transcripts.py validator-auth-results/production.tsv \
  validator-auth-results/experimental.tsv --out validator-auth-results/independent.json
python test/validator-auth/check_isolation.py --out validator-auth-results/isolation.json
python test/validator-auth/mutations.py --build build-validator-auth --out validator-auth-results/mutations.json
```

System libsodium is required by the independent Ed25519 checker. The disabled
QUIC/storage options and skipped install rules are **focused test configuration**,
not a supported production-node packaging profile. The sanitizer job instruments
the same source boundary and the portable test signer. The general Ubuntu full
build remains manual-only and is not dispatched by this suite.

The conformance workflow executes the tests on x86-64 and AArch64, runs a separate
ASan/UBSan build, checks deterministic transcripts/legacy BOCs across them, and
runs compiling mutations only on release x86-64. A mutant must compile and fail
an explicit assertion; a crash, timeout or build error is not a kill. Every
restored baseline must reproduce its original transcript. CI status is evidence
only for the exact final head whose tests actually completed.

## Remaining launch decisions and implementation

Before calling a validator P0-ready, freeze the reviewed production API/wire
profile and implement it end to end: key registry and rotation, signer service,
bounded TL/TL-B/Rust/RPC/bridge/light-client codecs, authentic policy selection,
canonical extension rules and launch vectors. Then wire approved providers into
the real callers and measure that changed hot path and the slowest supported
validator under hostile block/network loads. Stateful PQ schemes additionally
need durable capacity allocation, fencing, crash/recovery/backup tests and
anti-rollback state outside prunable session storage. None is supplied by an
in-process key-epoch field.

No future algorithm is enabled by its identifier appearing in these fixtures.
The network/transport key exchange, proof aggregation, operator approval and
coordinated phase activation are separate work. Passing this suite is not
permission to change a historical preimage, accept a peer-selected policy or
claim whole-stack post-quantum security.
