/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <cstddef>
#include <deque>
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

struct PendingFinalityAuthorityKey {
  ShardIdFull shard;
  CatchainSeqno catchain_seqno;
  td::uint32 validator_set_hash;

  bool operator==(const PendingFinalityAuthorityKey &other) const {
    return shard == other.shard && catchain_seqno == other.catchain_seqno &&
           validator_set_hash == other.validator_set_hash;
  }
};

// Repeated unverified broadcasts normally name the same validator coordinates.
// Cache the locally derived transport roots so a flood pays the validator-set
// computation once per coordinate triple instead of once per arrival. The
// manager clears this memo when its trusted masterchain state changes, so a
// cached negative result cannot survive the state update that makes a set known.
class PendingFinalityAuthorityMemo {
 public:
  template <class Loader>
  bool contains(const PendingFinalityAuthorityKey &key, const PublicKeyHash &peer, Loader &&loader) {
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
      if (it->key == key) {
        auto roots = std::move(it->roots);
        entries_.erase(it);
        entries_.push_back({key, std::move(roots)});
        return contains_peer(entries_.back().roots, peer);
      }
    }
    auto roots = loader();
    if (entries_.size() == max_entries) {
      entries_.pop_front();
    }
    entries_.push_back({key, std::move(roots)});
    return contains_peer(entries_.back().roots, peer);
  }

  void clear() {
    entries_.clear();
  }

  std::size_t size() const {
    return entries_.size();
  }

 private:
  struct Entry {
    PendingFinalityAuthorityKey key;
    std::vector<PublicKeyHash> roots;
  };

  static bool contains_peer(const std::vector<PublicKeyHash> &roots, const PublicKeyHash &peer) {
    for (const auto &root : roots) {
      if (root == peer) {
        return true;
      }
    }
    return false;
  }

  static constexpr std::size_t max_entries = 2;
  std::deque<Entry> entries_;
};

}  // namespace tos::validator
