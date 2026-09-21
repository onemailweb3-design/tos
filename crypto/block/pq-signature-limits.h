/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <cstddef>

#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-consensus.h"

namespace block::pq {

inline constexpr std::size_t pq_block_signatures_max_signers = tos::pq::PQConsensusLimits{}.max_certificate_signers;
inline constexpr std::size_t pq_block_signature_bytes = tos::pq::mldsa44_signature_bytes;

// The canonical 400-signer block_signatures_simplex_pq#13 BOC measures 1,020,996
// bytes. One MiB leaves 27,580 bytes for future framing without changing this
// persisted envelope, and remains below both external carriers: FullNode's 4 MiB
// proof limit and the overlay's 16 MiB FEC-broadcast limit.
inline constexpr std::size_t pq_block_signatures_hard_max_bytes = 1U << 20;

static_assert(pq_block_signatures_max_signers == 400);
static_assert(pq_block_signature_bytes == 2420);

inline constexpr bool pq_block_signatures_accepts_signer_count(std::size_t count) {
  return count <= pq_block_signatures_max_signers;
}

// This predicate is the byte gate for future external proof/broadcast decoders.
// It is deliberately independent of parsing and verification so hostile input is
// refused before either can consume resources.
inline constexpr bool pq_block_signatures_accepts_serialized_size(std::size_t bytes) {
  return bytes <= pq_block_signatures_hard_max_bytes;
}

}  // namespace block::pq
