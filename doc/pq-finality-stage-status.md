# Post-quantum finality stage status

This document records the implementation evidence for sections 3 through 10 of
`N5-EXECUTION-ORDER.md`.  It is an implementation status, not an activation
decision, an independent audit, or a claim beyond the boundaries stated for each
gate.  Test names below are the names registered in CTest unless explicitly
identified as Rust or workflow-only tests.

The design document uses stage-prefixed gate names.  Source and test names use
subject names instead; the mappings below are normative for finding the evidence
in this tree.

## Section 3: measured and frozen carrier

Commits:

- `c4fabb76445ccf3a008b9f026857553e47eb8d0a` — route-limit inventory and gate.
- `c4acd8914926172383fd5e837aaf1e7622fa0981` — prescribed verdict rows and explicit projections.
- `5d02341d37f8fe661c682591a002bad6840ce984` — measurement switched from a hand-built `#13` value to the production serializer.
- `b11a4d9c8c65a1f4b98e8e11e5ebc9a69c1b8781` — generated node/lite sizes replaced the incorrect projections.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-0-block-signature-measure` | `block-signature-carrier-measure` | Deterministic production serialization at 1/21/32/64/100/400 signers; the 400-signer BOC is 1,020,996 bytes with SHA-256 `0C05E72DD2095B0B3497CEF3422DFBC65B42891BB011C75E769AC245FA0B9B63`. | Network admission, proof verification, or block acceptance. |
| `n5-0-block-signature-limits` | `block-signature-carrier-bound` | The frozen one-MiB persisted envelope admits the canonical 400-signer object and the production serializer refuses 401 signers. | A 400-member live committee, transport throughput, or cryptographic quorum. |
| Static route inventory required by §3.3 | `block-signature-carrier-routes` | Every named production limit still equals the recorded value and every route minimum and measured headroom recomputes. | A live overlay peer graph or encrypted external connection; those are separate later gates. |

Mutations observed:

- Lowering the production ADNL external packet constant by 4096 produced exactly
  `ROUTE_CONSTANT_MISMATCH: adnl::adnl_ext_max_packet_bytes recorded=16777216 actual=16773120`.
- Changing the recorded one-signer node projection by one byte produced exactly
  `ROUTE_PROJECTION_SIZE_MISMATCH: object=projected-tosNode.signatureSet.simplexPq signers=1 recorded=2645 measurement=2644`.

The generated TL codec later established that the projection had invented
`4 * signer_count + 4` bytes of vector/element framing.  The authoritative node
and lite sizes are 2,636 / 51,836 / 78,896 / 157,616 / 246,176 / 984,176 bytes
at 1 / 21 / 32 / 64 / 100 / 400 signers.  The persisted BOC and its frozen
envelope did not move.

## Section 4: canonical C++ and Rust `#13` codec

Commits:

- `5d02341d37f8fe661c682591a002bad6840ce984` — C++ `#13` schema, checked codec, shared fixture, and C++ mutations.
- `af3c1334d20b52a4a426e9a8739d5a35b47f6459` — Rust codec and byte-identical shared-fixture round trip.
- `65b8a65dfd567cd07e937908460c409f698b1c76` — cross-language unknown-signer and algorithm-mismatch parity.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-block-signature-codec-cpp` | `pq-block-signature-vectors` | C++ accepts and rejects the shared canonical BOCs for the recorded structural rule and reserializes accepted rows byte-for-byte. | ML-DSA validity, trusted session derivation, or quorum. |
| `n5-pq-block-signature-codec-rust` | Rust `shared_pq_block_signature_codec_parity_does_not_verify_finality` | Rust consumes the same fixture, applies the same structural reason code, and reserializes accepted rows byte-for-byte. | Rust finality verification; Rust is a codec/tooling consumer here. |
| `n5-pq-block-signature-parity` | The preceding C++ and Rust tests over `test/pq-native/pq-block-signature-vectors.txt` | The two languages accept the same structural language and emit the same BOC bytes. | Semantic proof acceptance by a node or lite client. |

Mutations observed:

- Removing C++ tag discrimination produced `VECTOR_REASON_MISMATCH`; the input
  remained rejected by a later rule, so this guard is reason-sensitive rather
  than the only refusal.
- Removing the C++ signer-count bound produced
  `VECTOR_UNEXPECTED_ACCEPT case=401-signers expected=signer_count`.
- Removing the C++ exact-signature-length check produced
  `VECTOR_UNEXPECTED_ACCEPT case=wrong-signature-length-short expected=signature_length`.
- Removing C++ PQBytes canonicality produced
  `VECTOR_UNEXPECTED_ACCEPT case=noncanonical-pqbytes expected=noncanonical_pqbytes`.
- Removing the C++ duplicate-validator check produced
  `VECTOR_UNEXPECTED_ACCEPT case=duplicate-validator-id expected=duplicate_validator_id`.
- Removing the C++ dictionary index/count check produced
  `VECTOR_UNEXPECTED_ACCEPT case=dictionary-gap expected=dictionary_index`.
- Removing the C++ candidate bound produced `VECTOR_REASON_MISMATCH`; a later
  candidate check still refused the row for a different reason.
- The corresponding Rust removals produced, exactly:
  `RUST_VECTOR_UNEXPECTED_ACCEPT case=401-signers expected=signer_count`,
  `RUST_VECTOR_UNEXPECTED_ACCEPT case=wrong-signature-length-short expected=signature_length`,
  `RUST_VECTOR_UNEXPECTED_ACCEPT case=duplicate-validator-id expected=duplicate_validator_id`, and
  `RUST_VECTOR_UNEXPECTED_ACCEPT case=dictionary-gap expected=dictionary_index`.
- Restoring Rust's former “skip unknown signer” behavior produced
  `RUST_VECTOR_UNEXPECTED_ACCEPT case=unknown-validator-id expected=unknown_validator_id`.

For the two reason-shadowed C++ mutations, the retained review transcript records
the exact emitted marker but not the dynamic `actual=` suffix.  That is a
mutation-evidence retention limitation; it is not relabeled here as a complete
raw transcript.

## Section 5: trusted-set, signature, quorum, and session binding

Commits:

- `da478ed3edb44a7982e92f1799945112e5eafe40` — authoritative weight and ML-DSA verification.
- `65b8a65dfd567cd07e937908460c409f698b1c76` — unknown signer and descriptor-algorithm refusal.
- `b199f068243c56f81d5c9391365dc0a73805aff6` — one shared session derivation, exact Param30-cell commitment, and governing-snapshot vectors.
- `ab4e32f743db8e8e300cc03010f2f775c4c03753` — trusted expected-session verification boundary and production caller source guard.
- `1347c91435908902296e61b3a76470723baba2c9` — bidirectional classical-carrier inventory and removal of the dead, misleading disk-manager session helper.
- `1897d48329ca80d21d11f0005c7b4684a1aca50b` — admission-path carrier markers classified by their actual classical-only or PQ-reachable branches.
- `fe0896df8c8604ca6f4572e3f284bb0b0a7105e6` — session-options hashing moved below consensus to preserve link boundaries.

The bidirectional classical-carrier inventory contains 51 rows covering 44
Git-tracked paths, 86 distinct marker entries and 280 source sites.  Its earlier
408-site figure included 130 occurrences in eight untracked
`tl/generate/auto/tl/*` build outputs.  Those derived copies are now excluded;
their two authoritative tracked schema inputs remain inventoried.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-block-signature-conformance` | `pq-block-signature-conformance` | Stable validator ID, descriptor type/algorithm/key, signed preimage, role, every included signature, checked weight, and quorum are enforced. | That every production proof consumer supplies the right trusted context. |
| `n5-pq-block-signature-no-legacy` | `pq-block-signature-no-legacy` | Cell, node-TL, and lite-TL `#11/#12` carriers are refused before classical verification under a PQ set. | Removal of historical classical codecs. |
| `n5-pq-session-binding` | `validator-session-derivation`, `validator-session-param30`, `validator-session-global-id`, `validator-session-local-override`, `validator-session-governing-snapshot`, `validator-session-session-path`, `validator-session-constructor-selection`, `pq-block-signature-conformance`, `pq-finality-boundary-source` | The shared formula commits governing-state `global_id`, Param29 hash, exact selected Param30 cell hash and group coordinates; a proof must match a separately trusted expected session. | Execution of the sole production derivation caller in `validator/manager.cpp`; see Registered gaps. |

Mutations observed:

- Omitting Param30 from the derivation produced `PARAM30_CHANGE_DID_NOT_CHANGE_SESSION`.
- Omitting `global_id` produced `GLOBAL_ID_CHANGE_DID_NOT_CHANGE_SESSION`.
- Letting a node-local noncritical override enter the commitment produced
  `LOCAL_NONCRITICAL_OVERRIDE_CHANGED_SESSION`.
- Reusing a session path across Param30 changes produced
  `PARAM30_CHANGE_REUSED_SESSION_PATH`.
- Removing expected-session comparison produced
  `PQ_BLOCK_SIGNATURE_UNEXPECTED_ACCEPT case=wrong-workchain-shard-session expected=carried session_id does not match trusted expected session_id`.
- Returning after quorum instead of checking surplus signatures produced
  `PQ_BLOCK_SIGNATURE_UNEXPECTED_ACCEPT case=invalid-surplus-signature expected=pq signatures: invalid signature`.
- Allowing a legacy cell carrier under a PQ set produced
  `PQ_BLOCK_SIGNATURE_UNEXPECTED_ACCEPT case=cell-ordinary-under-pq-set expected=unsupported carrier for post-quantum validator set`.

The Simplex end-to-end and vote-journal tests coexist with the new formula but do
not exercise it: their bus session ID is a fixture constant.

## Section 6: generated network carriers, checked parsing, and capacity

Commits:

- `b11a4d9c8c65a1f4b98e8e11e5ebc9a69c1b8781` — generated node/lite PQ TL variants and shared TL fixture.
- `cadd24c26be58950d10fa3dcc25274c93505d72c` — checked untrusted parsers, pre-decompression ordering, crypto counters, and true signature-volume accounting.
- `51f865505b83745c871b8b28fc3e785481ec7fb6` — production-predicate node/lite carrier capacity gates.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-node-tl-checked` | `pq-signature-tl-vectors`, `test-pq-network-parser-resource` | Generated node/lite TL round trips preserve authority fields and structural rejects happen before crypto; compressed-V2 rejects signatures before decompression. | Cryptographic finality or transport delivery. |
| `n5-pq-node-carrier-capacity` | `pq-node-finality-carrier-capacity` | Complete 21/100/400 signer finality broadcasts match recorded sizes, pass the exact production Plumtree admission predicate, and reach the checked receiver parser. | A live overlay peer graph, FEC propagation, block acceptance, or throughput. |
| `n5-pq-lite-carrier-capacity` | `pq-lite-forward-proof-carrier-capacity` | Complete 21/100/400 signer lite answer fixtures match recorded sizes, pass the exact ADNL external framed-TCP send/receive predicates, and reach the checked lite parser. | A live encrypted TCP actor pair or trusted-chain advancement. |

The design's RLDP wording does not match this tree: production lite queries use
`AdnlExtClient`/`AdnlExtServer` over framed TCP.  The gate follows that actual
route.  All complete-object rows in
`test/pq-native/block-signature-carrier-routes.tsv`, including compressed V2,
now have measured `STATIC FIT` verdicts; no `UNKNOWN` row remains.

Mutations observed:

- Changing one C++ TL authority field produced
  `TL_VECTOR_CONTENT_MISMATCH case=node-final`; the equivalent Rust-side field
  change produced `RUST_TL_VECTOR_ALGORITHM_MISMATCH case=node-final`.
- Removing the node/lite exact-signature check produced
  `RESOURCE_GATE_UNEXPECTED_ACCEPT case=node-signature-2419` and the analogous
  `lite-signature-2419` failure.
- Inserting an ML-DSA call into structural parsing produced
  `RESOURCE_GATE_CRYPTO_CALLS case=node-401-signers expected=0 actual=1`.
- Moving compressed-V2 signature parsing after decompression produced
  `COMPRESSED_ORDER_DECOMPRESSION expected=0 actual=1`.
- Lowering Plumtree admission to one byte below the otherwise-valid node payload
  produced `CARRIER_LIMIT_NEGATIVE route=node` when the production refusal was
  disabled; the intact gate reports `reason=payload_limit crypto_calls=0`.
- Lowering the ADNL framed-packet allowance to one byte below the otherwise-valid
  lite answer produced `CARRIER_LIMIT_NEGATIVE route=lite` when the production
  refusal was disabled; the intact gate reports `reason=packet_limit crypto_calls=0`.
- Changing the recorded node size produced
  `CARRIER_RECORDED_SIZE_GATE_FAILED route=node`; changing the recorded lite size
  produced `CARRIER_RECORDED_SIZE_GATE_FAILED route=lite`.
- Removing the 401-signer checked-parse refusal produced
  `CARRIER_401_UNEXPECTED_ACCEPT route=node` and
  `CARRIER_401_UNEXPECTED_ACCEPT route=lite`.

## Section 7: exact FinalCert-to-`#13` conversion

Commits:

- `488f885a5c868fff0c8f010922ee59daff692132` — fail-soft certificate conversion and removal of the normal carrier-missing seam.
- `1f1192fceaaa94bf0030806a947a74ba15c7a9cd` — local accepted finality bound to the trusted session.
- `4137595e2d610dd18f647635e02db22d3350bdb8` — three-consecutive-block progress and independent trusted-context verification of every accepted proof.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-exact-certificate-carry` | `test-consensus-simplex2-pq-finality-e2e-single`, `test-consensus-simplex2-pq-finality-e2e-multi`, `test-consensus-simplex2-pq-finality-e2e-21`, `test-consensus-simplex2-pq-finality-e2e-100` | For every signer in one selected proof, journal, FinalCert, `#13`, DB-loaded set, and BlockProof-loaded set carry identical randomized ML-DSA bytes; every accepted proof in the run is independently checked at the trusted-context verifier; at least three unique consecutive blocks are accepted; normal PQ finality emits no carrier-missing event. | The five restart cuts or five-way byte comparison of every proof (the independent verifier, rather than the five-way comparison, covers every accepted proof). |

Mutation observed:

- Re-signing during conversion produced
  `EXACT_SIGNATURE_BYTES_MISMATCH signer=0 journal/final-cert/carrier/db/block-proof are not byte-identical`.
- Restoring the old conversion refusal made the accepted-chain scenarios fail
  with `finalized only 0 blocks, expected at least 40`.

## Section 8: persistence, proof consumers, and broadcasts

Commits:

- `d20860dfa6fdf2844f8e54d3c5e183710d81932a` — 21/100 archive and database round trip plus nine-field corruption matrix.
- `6c0df3a85a4386bc0a5413f619d5f3d966df6d38` — CheckProof and serialized TopBlockDescr consumers.
- `d270017f83da57eab61dbfde1cee5e3fee029b2e` — AcceptBlock trusted-session boundary.
- `40141c9a94b1c8fe4e555701d90f3cbebcb04285` — persistence gate inventory.
- `890875a5dc236a23e646fe7ddf2260ad13bfec52` — persisted BlockProof fixture.
- `62d5c48a3f1d5c5cbb314bf942964dabfef00422` — semantic compressed-V2 and finality broadcast round trips.
- `659a717df7c0209f10fe55fd50834679051ce9b7` — restored PQ catch-up and empty-chain restart scenarios.
- `a8d3baa063ac3de3250867602c168aecd8e81c88` — JSON-RPC refuses the unsupported PQ signature carrier instead of emitting an empty classical list.
- `cce69caf023cf087c67134a028a31da1fff028b7` — bounded arrival-order cache for finality evidence that cannot yet be verified.
- `3de7316c83b14678d6b2620f706daf335bb92706` — TopBlockDescr authority comes from the masterchain snapshot named by its shard proof, not the node's current state.
- `4b801892ef542f3148a358590a1e9ce450bcb0eb` — focused TopBlockDescr coverage now drives the production `prevalidate` consumer and its governing-state guard.
- `b64af02c37f01a5f9543385c6adba130298bd156` — evidence-aware Plumtree identity and authenticated-sender, byte-bounded pending finality admission.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-db-roundtrip` | `test-pq-signature-persistence` | Real RootDb/archive store/get/fetch returns 21/100 signer `#13` bytes unchanged and the result verifies. | Process-crash atomicity at every persistence cut. |
| `n5-pq-block-proof` | `test-pq-signature-persistence` plus the PQ Simplex end-to-end tests | AcceptBlock's extracted PQ boundary, serialized/persisted BlockProof signature-envelope extraction, and a low-level proof-verifier reject/accept matrix preserve and verify `#13`. | A production `CheckProof` actor invocation. Deleting `CheckProof::check_signatures`' rejection of verifier errors leaves this focused test green. |
| `n5-pq-top-shard-descr` | `test-pq-signature-persistence` | A production `ShardTopBlockDescrQ::fetch` parses a real shard proof link, then production `prevalidate` accepts session A using the named governing state after the current state advances to B, rejects using B as the governing state, and rejects a valid session-B signature at the pre-change position. | The actor that asynchronously obtains the current and governing states from `ValidatorManager`; the focused test supplies purpose-built state objects directly to the production consumer. |
| `n5-pq-broadcast-roundtrip` | `pq-broadcast-semantic-roundtrip` | The same 21/100 fixtures traverse compressed-V2 and simple-Plumtree TL, are checked against trusted PQ context, and call ML-DSA exactly once per included signer; 400 is structurally measured. | A live overlay peer graph, block-acceptance actor scheduling, or FEC behavior. |
| Accepted-chain regressions restored by §10.5.3 | `test-consensus-simplex2-pq-state-resolver-catch-up`, `test-consensus-simplex2-pq-empty-chain-restart` | A lagging node recovers an evicted finalized ID through live DB lookup; a chain longer than 4096 empty candidates resumes after a cold resolver restart and reuses its completed-ancestor cache. | The five crash cuts required by §10.5.4. |
| JSON-RPC unsupported-carrier behavior | `test-json-rpc-parse` | A PQ lite signature set produces error `-32603` with an explicit unsupported-carrier message, while genuine absence remains the only path to an empty classical list. | Rendering PQ signatures in the public JSON model. |
| Unverified finality admission | `test-pending-finality-cache`, `finality-evidence-admission-source` | Public and fast-sync Plumtree IDs commit to the block and canonical signature set; authenticated sender identity reaches the manager; one sender gets one unverified candidate per block and at most 1 MiB, while the store has a 16 MiB byte budget with a 4096-byte minimum charge; invalid/valid arrivals from distinct senders preserve arrival order and the valid final is accepted. | A live Plumtree peer graph or the actor-scheduled `ValidatorManagerImpl` ingress; the behavioural gate exercises the exact production transport-ID helper and pending-store implementation, while the source gate pins their production wiring. |

The nine persisted corruption rows and their asserted reasons are: constructor →
`unsupported carrier for post-quantum validator set`; validator ID →
`pq signatures: unknown validator_id`; algorithm →
`pq signatures: unsupported algorithm`; PQBytes length →
`pq signatures: signature length 2419, expected 2420`; signature chunk →
`pq signatures: invalid signature`; session ID →
`carried session_id does not match trusted expected session_id`; slot →
`pq signatures: invalid signature`; candidate data →
`pq signatures: invalid signature`; claimed weight → `signature weight mismatch`.

Mutations observed:

- Corrupting the stored/reloaded 21-signer bytes produced
  `PQ_SIGNATURE_PERSISTENCE_BYTES_MISMATCH signers=21`.
- Bypassing the AcceptBlock expected-session check produced
  `PQ_BLOCK_SIGNATURE_UNEXPECTED_ACCEPT case=accept_block_wrong_session expected=carried session_id does not match trusted expected session_id`.
- Bypassing the extracted low-level proof-verifier matrix produced
  `PQ_BLOCK_SIGNATURE_UNEXPECTED_ACCEPT case=invalid_signature expected=pq signatures: invalid signature`.
- Deleting the governing-state check from production `ShardTopBlockDescrQ::validate_internal`
  produced
  `PQ_BLOCK_SIGNATURE_REASON_MISMATCH case=top_descr_current_state_is_not_governing expected=top block description governing state mismatch actual=ShardTopBlockDescr for (0,8000000000000000,42):3CA07AC18F14A3D906CC28AA6FD6AB0F5438703611BD8B998E0D4B1AB7320AC7:0E768FA97910A760F489744EC9AEAF5637282B2270BBC17E034670D73FA76BFB does not have valid signatures: [Error : 0 : pq finality: carried session_id does not match trusted expected session_id]`.
- Deleting production `CheckProof::check_signatures`' `result.is_error()` rejection left
  `test-pq-signature-persistence` green (`1/1 ... Passed`).  This is retained as
  evidence that the focused BlockProof gate does not exercise the production actor.
- Dropping the serialized BlockProof signature reference produced
  `PQ_BLOCK_PROOF_ENVELOPE_ID_OR_SIGNATURES_MISMATCH`.
- Dropping TopBlockDescr PQ metadata preservation produced
  `PQ_TOP_BLOCK_DESCR_ENVELOPE_METADATA_MISMATCH`.
- Skipping broadcast verification produced
  `PQ_BROADCAST_CRYPTO_CALLS route=compressed-v2 expected=21 actual=0`.
- Accepting a tampered broadcast pair produced
  `PQ_BROADCAST_TAMPER_UNEXPECTED_ACCEPT case=invalid-signature`.
- Disabling the catch-up lookup produced
  `catch-up test never recovered an evicted finalized ID through live DB lookup`.
- Dropping the persisted finalized anchor across the empty-chain restart produced
  `missing-manager-anchor fallback was not exercised`.
- Stopping after the first invalid unverified final, without changing the
  candidate bound, produced
  `PENDING_FINALITY_ORDER_FAILURE: bad final displaced the later valid final`.
- Reversing unverified candidate processing, without changing the candidate
  bound, produced
  `PENDING_FINALITY_ORDER_FAILURE: later bad final ran before the earlier valid final`.
- Allowing the current post-key-block masterchain state to stand in for the
  snapshot named by the shard proof produced
  `PQ_TOP_BLOCK_DESCR_CURRENT_STATE_ACCEPTED_AS_GOVERNING`.
- Restoring the block-only transport identity produced
  `PENDING_FINALITY_TRANSPORT_DEDUP_FAILURE: invalid finality occupied the honest finality transport id`.
- Removing the one-unverified-candidate-per-sender guard produced
  `PENDING_FINALITY_SENDER_ISOLATION_FAILURE: one sender occupied more than one block candidate`.
- Removing the per-sender byte guard produced
  `PENDING_FINALITY_SENDER_BUDGET_FAILURE: one sender exceeded its 1048576-byte share`.
- Removing the total byte guard produced
  `PENDING_FINALITY_TOTAL_BUDGET_FAILURE: store exceeded its 16777216-byte budget`.
- Replacing the public Plumtree route's evidence-aware helper with the old
  block-only ID produced
  `FINALITY_ADMISSION_SOURCE_FAILURE: public Plumtree finality route lost its evidence-aware transport id (validator/full-node-shard.cpp)`.

## Section 9: transport authority

Commit:

- `81ef38f8644653483900ff55cb9123072c3190a2` — ADNL transport-root authority, local reference-counted signer registry, engine lifecycle wiring, and inventory closure.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-transport-authority` | `test-validator-transport-authority` | A PQ descriptor authorizes its explicit Ed25519 ADNL ID; a held matching key issues a certificate; `validator_id` and unrelated permanent-key roots cannot authorize or issue it on the fast-sync path; consensus rotation preserves and ADNL rotation changes authority; startup/add/delete/expiry/overlap/no-key registry behavior holds. | A live fast-sync overlay graph. |
| `n5-no-classical-finality-fallback` | `consensus-no-fallback` plus workflow `.github/workflows/classical-key-inventory.yml` | Consensus source has no keyring-signing fallback, and every `classical_key()` use is inventoried with no `aborts-on-pq` row. | Arbitrary wrong-source substitutions that do not spell `classical_key()`. |

Mutations observed:

- Reverting signer selection to the legacy permanent-key registry produced
  `TRANSPORT_AUTHORITY_FAILURE: matching validator ADNL key did not issue a certificate`.
- Reintroducing `classical_key()` in `validator/full-node.cpp` produced
  `classical-key check failed: validator/full-node.cpp reads a classical key (1 sites) and is not in the inventory`.
- Reintroducing it in `validator/full-node-fast-sync-overlays.cpp` produced
  `classical-key check failed: validator/full-node-fast-sync-overlays.cpp reads a classical key (1 sites) and is not in the inventory`.

The focused behavior test covers the full-node authority helper.  Fast-sync uses
the production `fast_sync_validator_transport_authority` extraction used by the
overlay update path.  Its positive proves the matching ADNL key can issue an
authorized certificate; separate negatives prove that sourcing roots from
`validator_id` or an unrelated permanent Ed25519 key cannot authorize that
certificate or select the held ADNL signer.

## Section 10: lite proof chain and accepted-chain checklist

Commits:

- `468ceccb0c3d333f5a2eb6c6a709129b19e46b20` — liteserver `#13` generation and two-step production lite proof-chain verification over framed TCP.
- `a601b54398da07bcf1037e793475cac054ae75db` — Rust codec-only boundary made explicit in the test name and CI filter.
- `659a717df7c0209f10fe55fd50834679051ce9b7` — the two formerly blocked accepted-chain scenarios restored.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-lite-forward-proof` | `test-pq-lite-forward-proof` | Two consecutive 21-signer proof steps traverse the production ADNL external client/server framed-TCP harness, derive step two's trusted set from step one's destination key block, call ML-DSA exactly 42 times, and advance; a 100-signer step calls it exactly 100 times. | Rust finality verification, a public-network deployment, arbitrary latency/loss, or performance. |
| `n5-pq-block-signature-parity` tooling part | Rust `shared_pq_block_signature_codec_parity_does_not_verify_finality` in `.github/workflows/pq-mldsa44.yml` | C++ and Rust parse and reserialize the same persisted `#13` BOC. | Rust proof validation or trusted-chain advancement. |
| §10.5.3 restored scenarios | `test-consensus-simplex2-pq-state-resolver-catch-up`, `test-consensus-simplex2-pq-empty-chain-restart` | The two accepted-chain scenarios disabled at the old carrier seam run with PQ finality without weakening their original assertions. | The complete §10.5.2/§10.5.4 matrix below. |

The lite negative matrix asserts: classical carrier, wrong validator ID, wrong
algorithm, wrong signature, wrong session, wrong slot, wrong candidate, sub-quorum,
wrong validator-set hash, wrong catchain seqno, invalid surplus signature, and a
previous-set signature on the next step.  The `previous-set-on-next-step` row fails
with `unknown validator_id`, which is the observable proof that step two did not use
a test-global copy of step one's set.

Mutations observed:

- Skipping lite signature verification produced
  `PQ_LITE_FORWARD_PROOF_FAILURE: two-step verifier calls expected=42 actual=0`.
- Reusing the previous set for the next step produced
  `PQ_LITE_FORWARD_PROOF_FAILURE: negative previous-set-on-next-step expected=unknown validator_id actual=accepted`.
- Removing the framed-TCP answer-size refusal produced
  `PQ_LITE_FORWARD_PROOF_FAILURE: lite answer limit below required bytes did not refuse`.

The eight migrated adversarial scenarios were audited against their disabled
classical registrations.  Each PQ registration retains the same attack flag(s),
and the shared final assertions still check malicious-observer injection,
adaptive membership rotation, relay exercise and deduplication, query-rate
limits, and resolver-state non-growth.  Packet loss, node restart, and network
partition additionally have to increment their injection counters before the PQ
gate can complete.  The classical registrations required five accepted heights;
their PQ counterparts now require three *consecutive unique* accepted heights,
the explicit section 10.5 criterion.  This is a deliberate change: it is stronger
evidence of continuity, because three adjacent unique heights must advance, and
weaker evidence of volume, because three is fewer than five.  No attack-specific
assertion was dropped.

The finalization-backpressure scenario is deliberately exempt from that general
three-block progress bar.  Its premise is that an over-limit finalization backlog
stops production.  It instead requires the over-limit transition, zero candidates
while throttled, the cleared transition, and at least one accepted block after
recovery.  Loss and partition still require their injected adversity followed by
three consecutive unique accepted heights.  Transient finalization failure must
exhaust its finite injected failures and then meet the same three-height bar.
Permanent finalization failure does not use the progress gate: its contract is to
retain the certificate, stop retrying it, and stop production.

## Registered gaps and explicit non-claims

The following are gaps, not green claims.

1. **Manager integration is not exercised.**
   `derive_validator_session_identity` has one production caller,
   `validator/manager.cpp`.  Direct vector/consequence tests exercise the shared
   helper, but no test drives that actor caller.  The consensus end-to-end harness
   assigns a constant `bus->session_id` and is insensitive to the formula.  The
   current tree lacks an actor-scheduler validator-engine harness, so this is not
   covered by the available integration harness; it is not evidence that the caller
   works merely because adjacent end-to-end tests are green.

2. **Three API/tooling consumers remain incomplete.**

   - `toslib/toslib/ToslibClient.cpp` explicitly returns
     `post-quantum block signatures are not supported by toslib yet`; this is a
     loud refusal, not support.
   - JSON-RPC now returns error `-32603` with
     `post-quantum block signatures are not supported by JSON-RPC yet`; it is a
     loud refusal, not support.  The former empty-classical-list response was a
     defect and was fixed in `a8d3baa063ac3de3250867602c168aecd8e81c88`.
   - `sdk/js/packages/client/src/types.ts` models only ordinary and classical
     Simplex block signatures; it has no PQ response type.  The generic
     `rawCall<T>` performs no runtime decoding, coercion, or field stripping, so
     it cannot itself turn a PQ value into an empty classical list.  This is
     unfinished static type support, not a second silent downgrade.

3. **Carrier route rows are resolved.**
   No `UNKNOWN` row remains in `block-signature-carrier-routes.tsv`; compressed-V2
   complete objects are measured at 1/21/100/400 and marked `STATIC FIT`.

4. **A live overlay peer graph is not exercised by the carrier gates.**
   The capacity gate calls the production admission functions, and the semantic
   gate serializes, parses, and verifies complete objects, but neither stands up
   a live overlay peer graph.  This is a harness boundary, not an unresolved row
   in the route table.

5. **Section 10.5 is only partially met.**
   The old carrier-missing normal path is gone, accepted blocks and finalized
   markers continue, the two disabled accepted-chain scenarios are restored, and
   the PQ loss/restart/partition/byzantine/adversarial variants remain registered.
   The general gate now requires three consecutive accepted blocks and independently
   verifies every accepted proof observed during its run under the trusted context.
   The document's prescribed registered names
   `test-consensus-simplex2-pq-persisted-finality-single`,
   `test-consensus-simplex2-pq-persisted-finality-multi`, and
   `test-consensus-simplex2-pq-persisted-finality-21` are deliberately not added.
   The same coverage runs under the subject names mapped in section 7; aliases
   would duplicate CI runtime without adding evidence, and renaming would likewise
   add no evidence.  This is a documented naming deviation, not an unmet gate.

   The five restart cuts listed in §10.5.4 remain a gap.  They need deterministic
   cut points spanning the Simplex journal, `#13` storage,
   BlockProof storage, the finalized marker, and a reconstruction from DB/archive
   state without actor memory.  The first four require production failpoints and
   restart orchestration; the fifth requires the engine/manager persistence harness
   that this tree currently lacks.  A mock-only version would not establish the
   required crash property.  These are missing scenarios, not a claim that the
   properties are intrinsically untestable.

6. **Mutation transcripts are not repository artifacts.**
   This file records the exact failure lines retained in the implementation/review
   record.  Two early C++ reason-shadowing mutations retained only their exact
   `VECTOR_REASON_MISMATCH` marker, not the full dynamic suffix.  Reproducing raw
   transcripts is possible by rerunning those mutations, but the original complete
   output cannot be reconstructed from committed files alone.

7. **The focused BlockProof fixture does not run the `CheckProof` actor.**
   `test-pq-signature-persistence` parses a serialized BlockProof envelope and
   calls the shared verifier directly.  Deleting the real actor's verifier-error
   rejection leaves it green.  Exercising `CheckProof` requires an actor scheduler,
   a `ValidatorManager` actor serving block handles and governing state, a proof
   whose verified header and state update match that state, and persistence sinks
   for the accepted proof/handle transitions.  The manager interface is broad and
   this tree has no focused fake implementing that orchestration.  This is missing
   integration coverage; the direct matrix is not production-consumer coverage.

   TopBlockDescr no longer shares this gap at its decisive boundary: the focused
   fixture supplies two masterchain-state objects with configuration and shard
   topology to the real `ShardTopBlockDescrQ::prevalidate` method.  Removing the
   production governing-state guard makes that gate red.  The surrounding actor's
   asynchronous state-history lookup remains outside the focused test.
