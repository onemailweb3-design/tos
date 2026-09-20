add_executable(test-consensus test-consensus.cpp)
target_link_libraries(test-consensus PRIVATE
    adnl
    adnltest
    dht
    overlay
    tdactor
    tdutils
    tl_api
    tos_validator
    validator
)

# N4.2/N4.3 — the live sign->verify round through PeerValidator::check_signature.
add_executable(test-n4-consensus-verify test-n4-consensus-verify.cpp)
set_target_properties(test-n4-consensus-verify PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-n4-consensus-verify PRIVATE
    validator
    tos_validator
    adnl
    overlay
    dht
    tl_api
    tl-utils
    tos_crypto
    tos_pq_consensus_signer
    tos_pq_consensus
    tos_mldsa44
    tdactor
    tdutils
)
add_test(NAME n4-consensus-verify COMMAND test-n4-consensus-verify)

# N4 — the structural and cryptographic guards on the live Simplex entrypoints, under
# post-quantum keys. It links the production sources through `validator`; nothing here
# re-implements quorum arithmetic or signature checking.
add_executable(test-n4-certificate-conformance test-n4-certificate-conformance.cpp)
set_target_properties(test-n4-certificate-conformance PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-n4-certificate-conformance PRIVATE
    validator
    tos_validator
    tos_block
    adnl
    overlay
    dht
    tl_api
    tl-utils
    tos_crypto
    tos_pq_consensus_signer
    tos_pq_consensus
    tos_mldsa44
    tdactor
    tdutils
)
add_test(NAME n4-certificate-conformance COMMAND test-n4-certificate-conformance)

# The same binary emits one transcript per signing domain. This rebuilds each preimage from
# the TL constructor schemas in Python and requires an exact match, so the C++ serializer
# cannot agree with itself about a change to what a validator signs.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME n4-simplex-preimages
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/check-simplex-preimages.py
                     $<TARGET_FILE:test-n4-certificate-conformance>)
endif()

add_executable(test-validator-manager-resource-policy test-validator-manager-resource-policy.cpp)
target_link_libraries(test-validator-manager-resource-policy PRIVATE
    adnl
    adnltest
    dht
    overlay
    tdactor
    tdutils
    tl_api
    tos_validator
    validator
)

add_executable(test-liteserver-admission test-liteserver-admission.cpp)
target_link_libraries(test-liteserver-admission PRIVATE
    td-test-main
    tdutils
    tl_api
)
tos_test(test-liteserver-admission)

add_test(
    NAME test-consensus-simplex2-loss
    COMMAND test-consensus --duration 4 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --net-loss 0.15 --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-restart
    COMMAND test-consensus --duration 5 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --gremlin-period 0.5:0.8
            --gremlin-downtime 0.1:0.2 --gremlin-times 4 --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-partition
    COMMAND test-consensus --duration 5 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --net-gremlin-period 0.5:0.8
            --net-gremlin-downtime 0.1:0.2 --net-gremlin-times 4 --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-malicious-observer
    COMMAND test-consensus --duration 5 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --malicious-observer-attack
            --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-relay-loop
    COMMAND test-consensus --duration 5 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --relay-loop-test
            --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-adaptive-byzantine
    COMMAND test-consensus --duration 7 --n-nodes 7 --target-rate-ms 100
            --net-ping 0.005:0.02 --adaptive-byzantine-n 2
            --adaptive-byzantine-period 0.35 --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-manager-ingress-adversarial
    COMMAND test-consensus --duration 7 --n-nodes 7 --target-rate-ms 100
            --net-ping 0.005:0.02 --malicious-observer-attack
            --relay-loop-test --adaptive-byzantine-n 2
            --adaptive-byzantine-period 0.35 --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-candidate-relay-eviction
    COMMAND test-consensus --candidate-relay-eviction-test
)
add_test(
    NAME test-consensus-simplex2-state-resolver-cache-unit
    COMMAND test-consensus --state-resolver-cache-unit-test
)
add_test(
    NAME test-consensus-simplex2-state-resolver-inflight-admission-unit
    COMMAND test-consensus --state-resolver-inflight-admission-unit-test
)
add_test(
    NAME test-consensus-simplex2-skipped-slot-resolution-unit
    COMMAND test-consensus --skipped-slot-resolution-unit-test
)
add_test(
    NAME test-consensus-simplex2-candidate-resolver-retention-unit
    COMMAND test-consensus --candidate-resolver-retention-unit-test
)
add_test(
    NAME test-consensus-simplex2-candidate-resolver-interleaving-unit
    COMMAND test-consensus --candidate-resolver-interleaving-unit-test
)
add_test(
    NAME test-consensus-simplex2-db-finalized-slot-dedup-unit
    COMMAND test-consensus --simplex-db-finalized-slot-dedup-unit-test
)
add_test(
    NAME test-consensus-validator-manager-resource-policy-unit
    COMMAND test-consensus --validator-manager-resource-policy-unit-test
)
add_test(
    NAME test-validator-manager-resource-policy-actor
    COMMAND test-validator-manager-resource-policy
)
add_test(
    NAME test-consensus-simplex2-state-resolver-catch-up
    COMMAND test-consensus --duration 8 --n-nodes 5 --target-rate-ms 50
            --net-ping 0.002:0.01 --catch-up-downtime 2.5
            --min-finalized-blocks 40
)
set_tests_properties(
    test-consensus-simplex2-state-resolver-catch-up
    PROPERTIES ENVIRONMENT
        "TOS_SIMPLEX_STATE_CACHE_MAX_ENTRIES=8;TOS_SIMPLEX_FINALIZED_CACHE_MAX_ENTRIES=8;TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS=8"
)
# N4.5 — the post-quantum round end to end, and the boundary it stops at. A slot finalized
# by every node, every signature in its certificate verified independently, a restart that
# rebuilds that certificate from persisted records with signatures matching their signers'
# journals, that slot latched at the carrier boundary, and then nothing: no accepted block
# and no finalized-block marker on any node.
#
# How far the round gets is now part of the claim, because the group stops at the boundary
# rather than only latching the slot that reached it. Measured after that change: one slot
# reaches an agreed certificate, at four nodes and at a hundred, and it is slot 0 both times.
# What the gate requires is that the slot every node agreed on is latched on every node, that
# the group then produces no further candidate, vote or certificate across a settle window,
# and that asking about a latched slot again is answered from the latch rather than waited
# on.
add_test(
    NAME test-consensus-simplex2-pq-finality-e2e-single
    COMMAND test-consensus --duration 40 --n-nodes 1 --target-rate-ms 100
            --net-ping 0:0 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-finality-e2e-multi
    COMMAND test-consensus --duration 40 --n-nodes 4 --target-rate-ms 100
            --net-ping 0.005:0.02 --pq-finality-e2e-test
)
# The structural scales N4.5 asks for, at the two this harness can carry. Measured on one
# developer machine: 21 nodes in 0.4s, 100 in 2.5s. The measurements and the boundary above
# them are recorded in the plan document; N6 runs the launch measurement set on real hosts.
add_test(
    NAME test-consensus-simplex2-pq-finality-e2e-21
    COMMAND test-consensus --duration 120 --n-nodes 21 --target-rate-ms 100
            --net-ping 0.005:0.02 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-finality-e2e-100
    COMMAND test-consensus --duration 300 --n-nodes 100 --target-rate-ms 100
            --net-ping 0.005:0.02 --pq-finality-e2e-test
)
# The same gate with the finalization concurrency limit set to one, which is what lets the
# retry probe build the pressure it needs: a finalization refused before its attempt begins,
# and one that fails inside it. Both have to come back rather than disappear -- a certificate
# dropped with nothing left to ask for it again costs nothing in an N4-only build, where the
# chain does not advance either way, and is a stuck chain in N5.
add_test(
    NAME test-consensus-simplex2-pq-finality-retry
    COMMAND test-consensus --duration 40 --n-nodes 4 --target-rate-ms 100
            --net-ping 0.005:0.02 --pq-finality-e2e-test --finalization-retry-probe
)
set_tests_properties(
    test-consensus-simplex2-pq-finality-retry
    PROPERTIES ENVIRONMENT "TOS_SIMPLEX_FINALIZED_INFLIGHT_MAX=1"
)
# The same gate, with the adversarial scenarios turned on. Their attack machinery was never
# the part that needed N5 -- only their `--min-finalized-blocks` assertion was -- so running
# them against the post-quantum gate restores the end-to-end half of N4.5's checklist: that
# traffic from outside the validator set does not become authority, that certificate gossip
# deduplicates, that an adaptive Byzantine membership does not stop the round, and that an
# agreed certificate is still reached under packet loss, node churn and partition. Each
# scenario has to inject its adversity before the round it is credited with.
#
# What these do NOT establish, despite the temptation to claim it: that a *valid* signature
# attributed to the wrong signer index is refused. The malicious observer sends a
# classical-length signature from outside the set, so a rejection here could be for the
# length rather than for the attribution. That property is proven where the inputs can be
# built exactly -- n4-certificate-conformance, with real post-quantum signatures, covers a
# vote signed by one validator presented as another, an out-of-range index and a repeated
# signer; and n4-consensus-verify covers a genuine transport-key signature carrying no
# consensus authority.
add_test(
    NAME test-consensus-simplex2-pq-malicious-observer
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --malicious-observer-attack --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-relay-loop
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --relay-loop-test --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-adaptive-byzantine
    COMMAND test-consensus --duration 40 --n-nodes 7 --target-rate-ms 100
            --net-ping 0.005:0.02 --adaptive-byzantine-n 2
            --adaptive-byzantine-period 0.35 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-manager-ingress-adversarial
    COMMAND test-consensus --duration 40 --n-nodes 7 --target-rate-ms 100
            --net-ping 0.005:0.02 --malicious-observer-attack --relay-loop-test
            --adaptive-byzantine-n 2 --adaptive-byzantine-period 0.35 --pq-finality-e2e-test
)
# One validator passes the others' signed votes on as its own, byte for byte, over its own
# correctly authenticated transport. Nothing is forged and a vote carries no signer field, so
# the only thing that could make a relayed vote count as the relayer's is the transport it
# arrived over. This is the end-to-end form of the property the certificate conformance test
# proves at unit level: attribution follows the signature, never the transport.
add_test(
    NAME test-consensus-simplex2-pq-byzantine-relay
    COMMAND test-consensus --duration 40 --n-nodes 7 --target-rate-ms 100
            --net-ping 0.005:0.02 --byzantine-relay-node 3 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-query-abuse
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --query-abuse-test --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-loss
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --net-loss 0.15 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-restart
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --gremlin-period 0.5:0.8
            --gremlin-downtime 0.1:0.2 --gremlin-times 4 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-partition
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --net-gremlin-period 0.5:0.8
            --net-gremlin-downtime 0.1:0.2 --net-gremlin-times 4 --pq-finality-e2e-test
)

# Two of the no-fallback invariants are properties of the source that no run can observe:
# a legacy carrier built and thrown away, and a keyring signature produced and discarded.
# They are checked where they exist, in the code.
if(Python3_Interpreter_FOUND)
    add_test(NAME n4-no-fallback
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/check-no-fallback.py)
endif()

# N4.4 — the two-phase own-vote journal: signed records replay byte for byte, an
# intent-only record is signed once, and a record this node cannot verify as its own
# stops the group instead of producing a second signature.
add_test(
    NAME test-consensus-simplex2-vote-journal
    COMMAND test-consensus --duration 30 --n-nodes 1 --target-rate-ms 50
            --net-ping 0:0 --vote-journal-test
)
add_test(
    NAME test-consensus-simplex2-empty-chain-restart
    COMMAND test-consensus --duration 110 --n-nodes 1 --target-rate-ms 1
            --net-ping 0:0 --empty-chain-restart-test --min-finalized-blocks 1
)
add_test(
    NAME test-consensus-simplex2-query-abuse
    COMMAND test-consensus --duration 5 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --query-abuse-test
            --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-codec-boundary
    COMMAND test-consensus --configured-maximum-candidate-test
)
add_test(
    NAME test-consensus-simplex2-genesis-config
    COMMAND $<TARGET_FILE:create-state>
            -I ${CMAKE_SOURCE_DIR}/crypto/fift/lib
            -I ${CMAKE_BINARY_DIR}/crypto/smartcont
            -I ${CMAKE_SOURCE_DIR}/crypto/smartcont
            -s ${CMAKE_CURRENT_SOURCE_DIR}/simplex2-genesis-config.fif
)

# These scenarios assert that blocks are finalized and accepted, which an N4-only build
# cannot do: the N4/N5 seam refuses to turn a post-quantum finality certificate into a
# block signature set, so no block is ever accepted. They are legacy regression tests for
# behaviour that only exists once N5 provides the post-quantum carrier.
#
# Eight of the ten originally disabled here have come back as pq- variants above: their
# attack machinery never needed N5, only their `--min-finalized-blocks` assertion did, and
# the post-quantum gate gives them a liveness floor in its place. What is left are the two
# whose subject really is the accepted chain -- catching up to a finalized height, and
# rebuilding after thousands of empty blocks.
#
# They are disabled rather than deleted, and disabled rather than left failing: ctest
# reports a disabled test as disabled, so the gap stays visible instead of turning the
# suite red for a reason nobody reads, or green for a reason nobody checked. N5 removes
# this block and they must pass again.
set_tests_properties(
    test-consensus-simplex2-loss
    test-consensus-simplex2-restart
    test-consensus-simplex2-partition
    test-consensus-simplex2-malicious-observer
    test-consensus-simplex2-relay-loop
    test-consensus-simplex2-adaptive-byzantine
    test-consensus-simplex2-manager-ingress-adversarial
    test-consensus-simplex2-state-resolver-catch-up
    test-consensus-simplex2-empty-chain-restart
    test-consensus-simplex2-query-abuse
    PROPERTIES DISABLED TRUE
)
