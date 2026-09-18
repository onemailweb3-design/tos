/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
// PQ-native consensus identity primitives (N1). Pure declarations: the fixed
// ML-DSA-44 lengths, the consensus algorithm id, the consensus key/signature
// value types, and the stable key-id derivation. Encoding to cells (PQBytes) and
// the signer live in separate units; this header carries no backend dependency.
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "mldsa44.h"

namespace tos::pq {

// The one consensus signature suite admitted at genesis. Unknown ids fail closed;
// there is no local algorithm choice and no Ed25519 fallback.
enum class PQAlgorithmId : std::uint16_t { unknown = 0, mldsa44 = 1 };

inline constexpr bool is_admitted(PQAlgorithmId a) noexcept { return a == PQAlgorithmId::mldsa44; }

// Fixed suite lengths (from the vendored backend), promoted into the consensus layer.
struct PQSuite {
  PQAlgorithmId algorithm_id;
  std::size_t public_key_bytes;
  std::size_t signature_bytes;
};
inline constexpr PQSuite mldsa44_suite{PQAlgorithmId::mldsa44, mldsa44_public_key_bytes,
                                       mldsa44_signature_bytes};

// Structural hard bounds enforced before allocation/verification. max_certificate_bytes
// is the worst-case a mainnet config must stay within; a config exceeding it is
// rejected deterministically before install (never truncated).
struct PQConsensusLimits {
  PQAlgorithmId algorithm_id = PQAlgorithmId::mldsa44;
  std::size_t public_key_bytes = mldsa44_public_key_bytes;   // 1312
  std::size_t signature_bytes = mldsa44_signature_bytes;     // 2420
  std::size_t max_certificate_signers = 400;                 // protocol max (ConfigParam16 max_validators)
  std::size_t max_main_validators = 100;                     // recommended masterchain committee ceiling
  // framing allowance per signer (validator_id + algorithm_id + cell overhead), generous.
  std::size_t framing_bytes_per_signer = 64;
  std::size_t certificate_bytes(std::size_t signers) const noexcept {
    return signers * (signature_bytes + framing_bytes_per_signer);
  }
  std::size_t max_certificate_bytes() const noexcept { return certificate_bytes(max_certificate_signers); }
};

// A validator's consensus public key. key_id is stable-per-key (rotating the PQ key
// changes key_id); the validator_id that stays constant across rotation lives in the
// validator descriptor, not here.
struct ConsensusPQKey {
  PQAlgorithmId algorithm_id{PQAlgorithmId::unknown};
  std::array<std::uint8_t, 32> key_id{};
  std::string public_key;  // exactly public_key_bytes for the suite
  bool operator==(const ConsensusPQKey&) const = default;
};

struct ConsensusPQSignature {
  PQAlgorithmId algorithm_id{PQAlgorithmId::unknown};
  std::string signature;  // exactly signature_bytes for the suite
  bool operator==(const ConsensusPQSignature&) const = default;
};

// Domain-separation constants. The key-id domain binds the algorithm and public key;
// the consensus signature context separates consensus finality from every other
// ML-DSA use (wallet/agent), so a signature from one domain never verifies in another.
inline constexpr std::string_view key_id_domain = "tos.pq.consensus.key-id.v1";
inline constexpr std::string_view consensus_sign_context = "tos.pq.consensus.finality.v1";

// key_id = SHA-256(key_id_domain || u16_le(algorithm_id) || public_key). Stable for a
// given (algorithm, key); independent of validator_id.
std::array<std::uint8_t, 32> derive_key_id(PQAlgorithmId algorithm_id,
                                           std::string_view public_key);

// Structural validation (size + admitted algorithm). Returns false, never throws, on
// any malformed input; callers fail closed.
bool valid_public_key(PQAlgorithmId algorithm_id, std::string_view public_key) noexcept;
bool valid_signature(PQAlgorithmId algorithm_id, std::string_view signature) noexcept;

}  // namespace tos::pq
