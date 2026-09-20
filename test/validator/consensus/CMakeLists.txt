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
# N4.5 — the post-quantum round end to end, and the boundary it stops at. One slot
# finalized by every node, every signature in its certificate verified independently, a
# restart that rebuilds that certificate from persisted records with signatures matching
# their signers' journals, and then nothing: no accepted block and no finalized-block
# marker. One certificate is the whole of it: candidates keep being produced, but no
# later slot is finalized, because resolving the state a later step needs goes through the
# finalization that the seam has latched.
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
# The end-to-end gate can see that no block was accepted and no marker was written, but
# not an object that was built and thrown away. "No legacy carrier is constructed" is a
# structural property, so it is checked structurally.
if(Python3_Interpreter_FOUND)
    add_test(NAME n4-no-legacy-carrier
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/check-no-legacy-carrier.py)
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

# These scenarios all assert that blocks are finalized and accepted, which an N4-only
# build cannot do: the N4/N5 seam refuses to turn a post-quantum finality certificate
# into a block signature set, so the chain agrees on its first slot and stops there.
# They are legacy regression tests for behaviour that only exists once N5 provides the
# post-quantum carrier, and they are not evidence about N4 -- that is what the two
# pq-finality-e2e tests above are for.
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
