/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <cstddef>
#include <deque>
#include <utility>

namespace tos::validator {

enum class PendingFinalityAdmission { Keep, Append, Replace };

// A verified cached value keeps the old strength policy: final replaces
// approve, while equal strength and downgrades keep the verified value.
// Unverified evidence is never allowed to evict other unverified evidence.
// It is retained as another bounded candidate until the block supplies the
// trusted context needed to verify candidates in arrival order.
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

template <class Evidence, std::size_t MaxCandidates>
class PendingFinalityCandidates {
 public:
  struct Entry {
    Evidence evidence;
    bool verified;
    bool is_final;
  };

  static_assert(MaxCandidates > 0);

  PendingFinalityAdmission admit(Evidence evidence, bool verified, bool is_final) {
    bool cached_is_verified = false;
    bool cached_is_final = false;
    for (const auto &entry : entries_) {
      if (entry.verified) {
        cached_is_verified = true;
        cached_is_final = cached_is_final || entry.is_final;
      }
    }
    auto action =
        pending_finality_admission(!entries_.empty(), cached_is_verified, cached_is_final, verified, is_final);
    // The front entry is owned by an asynchronous verifier. Do not invalidate
    // it while that verifier is running; a verified arrival waits behind it.
    if (processing_ && action == PendingFinalityAdmission::Replace) {
      action = PendingFinalityAdmission::Append;
    }
    if (action == PendingFinalityAdmission::Keep ||
        (action == PendingFinalityAdmission::Append && entries_.size() >= MaxCandidates)) {
      return PendingFinalityAdmission::Keep;
    }
    if (action == PendingFinalityAdmission::Replace) {
      entries_.clear();
    }
    entries_.push_back(Entry{std::move(evidence), verified, is_final});
    return action;
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

}  // namespace tos::validator
