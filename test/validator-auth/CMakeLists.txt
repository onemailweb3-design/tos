# Compile the real production entrypoints, not a reimplementation of quorum or parsing.
add_executable(test-validator-auth-production
  test-production.cpp
  ../../validator/consensus/types.cpp
  ../../validator/consensus/simplex/votes.cpp
  ../../validator/consensus/simplex/certificate.cpp
  ../../validator/consensus/payload.cpp
  ../../validator/consensus/candidate-codec.cpp
  ../../validator/consensus/session-compat.cpp)
target_include_directories(test-validator-auth-production PRIVATE ${PROJECT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/validator ${PROJECT_SOURCE_DIR}/common)
target_link_libraries(test-validator-auth-production PRIVATE tos_block keys tos_crypto tdactor tdutils tl_lite_api)
add_test(NAME validator-auth-production COMMAND test-validator-auth-production)

# The signer is a separate test library. Production verification remains verify-only.
set(MLDSA_TEST_SOURCE "${PROJECT_SOURCE_DIR}/third-party/mldsa-native/mldsa")
add_library(validator-auth-test-signer STATIC "${MLDSA_TEST_SOURCE}/mldsa_native.c")
target_include_directories(validator-auth-test-signer PRIVATE "${MLDSA_TEST_SOURCE}" "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(validator-auth-test-signer PRIVATE MLD_CONFIG_FILE="signer-config.h")
set_target_properties(validator-auth-test-signer PROPERTIES C_STANDARD 90 C_STANDARD_REQUIRED ON)
add_executable(test-validator-auth-experimental test-experimental.cpp)
target_include_directories(test-validator-auth-experimental PRIVATE "${PROJECT_SOURCE_DIR}" "${MLDSA_TEST_SOURCE}" "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(test-validator-auth-experimental PRIVATE MLD_CONFIG_FILE="signer-config.h")
target_link_libraries(test-validator-auth-experimental PRIVATE validator-auth-test-signer tos_mldsa44 tos_crypto tdutils)
add_test(NAME validator-auth-experimental COMMAND test-validator-auth-experimental)
