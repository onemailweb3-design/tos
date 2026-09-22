/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <cstddef>
#include <optional>
#include <vector>

#include "keys/keys.hpp"
#include "validator/validator-transport-authority.h"

namespace tos::validator {

struct PendingBlockFinalitySender {
  bool local{true};
  PublicKeyHash peer;

  static PendingBlockFinalitySender local_source() {
    return {};
  }
  static PendingBlockFinalitySender remote(PublicKeyHash peer) {
    return {false, peer};
  }
  bool operator==(const PendingBlockFinalitySender &other) const {
    return local == other.local && (local || peer == other.peer);
  }
  bool operator<(const PendingBlockFinalitySender &other) const {
    if (local != other.local) {
      return local < other.local;
    }
    return !local && peer < other.peer;
  }
};

enum class PendingFinalityIngressRejection { None, MissingRemoteByteCount, MissingLocalMeasurement };

struct PendingFinalityIngressDecision {
  PendingBlockFinalitySender sender;
  std::size_t accounted_bytes{0};
  PendingFinalityIngressRejection rejection{PendingFinalityIngressRejection::None};

  bool admitted() const {
    return rejection == PendingFinalityIngressRejection::None;
  }
};

// This is the manager's admission boundary between authenticated transport
// metadata and the byte-bounded pending store. Remote evidence must carry the
// exact received payload size; treating a missing size as zero would give it a
// free resource charge. Local evidence has no wire payload and instead must
// supply its measured intrinsic signature size.
inline PendingFinalityIngressDecision prepare_pending_finality_ingress(
    const PublicKeyHash *source_peer, std::size_t received_bytes,
    std::optional<std::size_t> local_signature_bytes = std::nullopt) {
  if (source_peer != nullptr) {
    if (received_bytes == 0) {
      return {PendingBlockFinalitySender::remote(*source_peer), 0,
              PendingFinalityIngressRejection::MissingRemoteByteCount};
    }
    return {PendingBlockFinalitySender::remote(*source_peer), received_bytes,
            PendingFinalityIngressRejection::None};
  }
  if (!local_signature_bytes) {
    return {PendingBlockFinalitySender::local_source(), 0,
            PendingFinalityIngressRejection::MissingLocalMeasurement};
  }
  return {PendingBlockFinalitySender::local_source(), *local_signature_bytes,
          PendingFinalityIngressRejection::None};
}

// Only the transport identity carried by a descriptor in the exact validator
// set governing this evidence is entitled to the committee-reserved capacity.
// Public-overlay peers remain authenticated transport senders, but they are not
// consensus authorities and therefore draw from the shared public pool.
inline bool pending_finality_sender_is_validator(const PendingBlockFinalitySender &sender,
                                                 const std::vector<ValidatorDescr> &validators) {
  if (sender.local) {
    return true;
  }
  for (const auto &validator : validators) {
    if (validator_transport_root(validator) == sender.peer) {
      return true;
    }
  }
  return false;
}

}  // namespace tos::validator
