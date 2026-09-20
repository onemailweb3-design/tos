/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

// The hard structural size a post-quantum Simplex protocol message may reach, and the
// per-peer transport allowance that must carry it.
//
// A single ML-DSA-44 signature is 2420 bytes, so one signed vote (~2472 B) already
// exceeds the current direct-message carrier (Adnl::get_mtu() 1440 - overlay header 36 =
// 1404 B). N4 raises the consensus peer stream allowance to carry these; this header is
// the one place the ceiling is written, so the transport guard, the inbound size check
// and the tests cannot silently disagree.
//
// This is a HARD STRUCTURAL bound, not the launch policy. N6 may choose a smaller
// `max_certificate_bytes` / validator count inside it, but nothing may exceed this
// envelope without a protocol change. Measured exactly by
// `test/pq-native/n4-0-carrier-measure.cpp` (cert400 = 972856 B) and derived below from
// the N1 structural signer ceiling so it cannot drift from the encoding.

#include <cstddef>

#include "crypto/pq/mldsa44.h"

namespace tos::validator::consensus::simplex {

// The exact serialized worst case, derived from the TL encoding so a change to either
// side is caught by the static_assert rather than by a validator in production:
//   - a boxed `consensus.simplex.voteSignature` = constructor id (4) + who:int (4) +
//     signature:bytes (4-byte length prefix + 2420) = 2432 bytes;
//   - the enclosing `consensus.simplex.certificate` frame = certificate ctor id (4) +
//     one boxed UnsignedVote (notarize/finalize is the largest at 44) + voteSignatureSet
//     ctor id (4) + vector length (4) = 56 bytes.
inline constexpr std::size_t kVoteSignatureMaxBytes = 4 + 4 + 4 + tos::pq::mldsa44_signature_bytes;  // 2432
inline constexpr std::size_t kCertificateFrameBytes = 4 + 44 + 4 + 4;                                // 56

// The N1 structural signer ceiling (PQConsensusLimits::max_certificate_signers). Raising
// it is a deliberate change that must re-derive the carrier, which the static_assert
// below forces.
inline constexpr std::size_t kMaxCertificateSigners = 400;

// The frozen hard maximum for one inner Simplex protocol message. A clean ceiling above
// the exact 400-signer worst case, with headroom for the small per-vote header. An
// inbound message larger than this is refused before it is parsed.
inline constexpr std::size_t simplex_protocol_hard_max_bytes = 1'000'000;

static_assert(kCertificateFrameBytes + kMaxCertificateSigners * kVoteSignatureMaxBytes <=
                  simplex_protocol_hard_max_bytes,
              "the frozen Simplex carrier hard max no longer covers a certificate at the N1 signer ceiling; "
              "re-measure and raise it deliberately, and re-size the peer-MTU allowance");

// The overlay/adnl framing added on the direct-message path: the `overlay.message`
// header is a 4-byte constructor id plus a 32-byte overlay id (this is the 36 the current
// `Overlays::max_message_size() == Adnl::get_mtu() - 36` already subtracts).
inline constexpr std::size_t simplex_carrier_framing_bytes = 36;

// The bounded per-peer transport allowance the QUIC/ADNL guard installs for consensus
// peers: the inner hard max plus the framing that wraps it on the wire.
inline constexpr std::size_t simplex_carrier_peer_mtu_bytes =
    simplex_protocol_hard_max_bytes + simplex_carrier_framing_bytes;

// The inbound gate: an inner Simplex protocol message above the hard max is rejected
// before parsing, independently of the transport stream cap.
inline constexpr bool simplex_carrier_accepts(std::size_t inner_message_bytes) {
  return inner_message_bytes <= simplex_protocol_hard_max_bytes;
}

}  // namespace tos::validator::consensus::simplex
