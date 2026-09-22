/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <algorithm>
#include <cstddef>
#include <deque>
#include <map>
#include <utility>

namespace tos::validator {

enum class PendingFinalityAdmission { Keep, Append, Replace };
enum class PendingFinalityRejection { None, Policy, SenderAlreadyPending, SenderBudget, TotalBudget };

struct PendingFinalityAdmissionResult {
  PendingFinalityAdmission action{PendingFinalityAdmission::Keep};
  PendingFinalityRejection rejection{PendingFinalityRejection::None};

  bool admitted() const {
    return rejection == PendingFinalityRejection::None && action != PendingFinalityAdmission::Keep;
  }
};

// Remote entries are charged by their received boxed-TL payload bytes; local
// entries use their measured intrinsic signature bytes. A minimum charge for
// either source bounds both memory and object count: at most 4096
// minimum-sized candidates can be pending globally.
inline constexpr std::size_t pending_finality_total_budget_bytes = 16 * 1024 * 1024;
inline constexpr std::size_t pending_finality_sender_budget_bytes = 1024 * 1024;
inline constexpr std::size_t pending_finality_minimum_charge_bytes = 4096;

// A verified cached value keeps the old strength policy: final replaces
// approve, while equal strength and downgrades keep the verified value.
// Unverified evidence has no block-level ownership: distinct authenticated
// senders append candidates which are verified in arrival order once the block
// supplies the trusted context.
constexpr PendingFinalityAdmission pending_finality_admission(bool has_cached, bool cached_is_verified,
                                                              bool cached_is_final, bool incoming_is_verified,
                                                              bool incoming_is_final) {
  if (!has_cached) {
    return PendingFinalityAdmission::Replace;
  }
  if (incoming_is_verified) {
    if (!cached_is_verified || (!cached_is_final && incoming_is_final)) {
      return PendingFinalityAdmission::Replace;
    }
    return PendingFinalityAdmission::Keep;
  }
  if (cached_is_verified) {
    return !cached_is_final && incoming_is_final ? PendingFinalityAdmission::Append : PendingFinalityAdmission::Keep;
  }
  return PendingFinalityAdmission::Append;
}

template <class Evidence, class Sender>
class PendingFinalityCandidates {
 public:
  struct Entry {
    Evidence evidence;
    Sender sender;
    std::size_t accounted_bytes;
    bool verified;
    bool is_final;
  };

  PendingFinalityAdmission admission(bool verified, bool is_final) const {
    bool cached_is_verified = false;
    bool cached_is_final = false;
    for (const auto &entry : entries_) {
      if (entry.verified) {
        cached_is_verified = true;
        cached_is_final = cached_is_final || entry.is_final;
      }
    }
    auto action = pending_finality_admission(!entries_.empty(), cached_is_verified, cached_is_final, verified,
                                             is_final);
    if (processing_ && action == PendingFinalityAdmission::Replace) {
      action = PendingFinalityAdmission::Append;
    }
    return action;
  }

  PendingFinalityAdmission admit(Evidence evidence, Sender sender, std::size_t accounted_bytes, bool verified,
                                  bool is_final) {
    auto action = admission(verified, is_final);
    if (action == PendingFinalityAdmission::Keep) {
      return action;
    }
    if (action == PendingFinalityAdmission::Replace) {
      entries_.clear();
    }
    entries_.push_back(Entry{std::move(evidence), std::move(sender), accounted_bytes, verified, is_final});
    return action;
  }

  bool has_unverified_from(const Sender &sender) const {
    for (const auto &entry : entries_) {
      if (!entry.verified && entry.sender == sender) {
        return true;
      }
    }
    return false;
  }

  std::size_t accounted_bytes() const {
    std::size_t result = 0;
    for (const auto &entry : entries_) {
      result += entry.accounted_bytes;
    }
    return result;
  }

  std::size_t accounted_bytes(const Sender &sender) const {
    std::size_t result = 0;
    for (const auto &entry : entries_) {
      if (entry.sender == sender) {
        result += entry.accounted_bytes;
      }
    }
    return result;
  }

  const Entry *begin_processing() {
    if (processing_ || entries_.empty()) {
      return nullptr;
    }
    processing_ = true;
    return &entries_.front();
  }

  void complete_front(bool accepted) {
    if (!processing_ || entries_.empty()) {
      return;
    }
    bool accepted_final = accepted && entries_.front().is_final;
    entries_.pop_front();
    if (accepted_final) {
      entries_.clear();
    }
    processing_ = false;
  }

  void mark_front_verified() {
    if (processing_ && !entries_.empty()) {
      entries_.front().verified = true;
    }
  }

  void cancel_processing() {
    processing_ = false;
  }

  bool empty() const {
    return entries_.empty();
  }

  std::size_t size() const {
    return entries_.size();
  }

  bool processing() const {
    return processing_;
  }

 private:
  std::deque<Entry> entries_;
  bool processing_ = false;
};

template <class BlockKey, class Sender, class Evidence>
class PendingFinalityStore {
 public:
  using Candidates = PendingFinalityCandidates<Evidence, Sender>;

  PendingFinalityAdmissionResult admit(const BlockKey &block, Sender sender, Evidence evidence,
                                       std::size_t serialized_bytes, bool verified, bool is_final) {
    auto it = entries_.find(block);
    auto action = it == entries_.end() ? PendingFinalityAdmission::Replace
                                       : it->second.admission(verified, is_final);
    if (action == PendingFinalityAdmission::Keep) {
      return {action, PendingFinalityRejection::Policy};
    }
    if (!verified && it != entries_.end() && it->second.has_unverified_from(sender)) {
      return {PendingFinalityAdmission::Keep, PendingFinalityRejection::SenderAlreadyPending};
    }

    const auto charge = std::max(serialized_bytes, pending_finality_minimum_charge_bytes);
    const auto removed_total = action == PendingFinalityAdmission::Replace && it != entries_.end()
                                   ? it->second.accounted_bytes()
                                   : 0;
    const auto removed_sender = action == PendingFinalityAdmission::Replace && it != entries_.end()
                                    ? it->second.accounted_bytes(sender)
                                    : 0;
    if (exceeds_budget(sender_bytes(sender), removed_sender, charge, pending_finality_sender_budget_bytes)) {
      return {PendingFinalityAdmission::Keep, PendingFinalityRejection::SenderBudget};
    }
    if (exceeds_budget(total_bytes(), removed_total, charge, pending_finality_total_budget_bytes)) {
      return {PendingFinalityAdmission::Keep, PendingFinalityRejection::TotalBudget};
    }
    if (it == entries_.end()) {
      it = entries_.emplace(block, Candidates{}).first;
    }
    return {it->second.admit(std::move(evidence), std::move(sender), charge, verified, is_final),
            PendingFinalityRejection::None};
  }

  Candidates *get_if_exists(const BlockKey &block) {
    auto it = entries_.find(block);
    return it == entries_.end() ? nullptr : &it->second;
  }

  const Candidates *get_if_exists(const BlockKey &block) const {
    auto it = entries_.find(block);
    return it == entries_.end() ? nullptr : &it->second;
  }

  void erase(const BlockKey &block) {
    entries_.erase(block);
  }

  std::size_t total_bytes() const {
    std::size_t result = 0;
    for (const auto &[unused, candidates] : entries_) {
      (void)unused;
      result += candidates.accounted_bytes();
    }
    return result;
  }

  std::size_t sender_bytes(const Sender &sender) const {
    std::size_t result = 0;
    for (const auto &[unused, candidates] : entries_) {
      (void)unused;
      result += candidates.accounted_bytes(sender);
    }
    return result;
  }

 private:
  static bool exceeds_budget(std::size_t current, std::size_t removed, std::size_t added, std::size_t budget) {
    current -= removed;
    return current > budget || added > budget - current;
  }

  std::map<BlockKey, Candidates> entries_;
};

}  // namespace tos::validator
