/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "crypto/block/signature-set.h"

#include "votes.h"

namespace tos::validator::consensus::simplex {

// The N4/N5 boundary, expressed as one distinguishable status code.
//
// A verified post-quantum Simplex certificate stops at the conversion into a
// block::BlockSignatureSet: that carrier is N5's, and the legacy one is a fixed 64-byte
// Ed25519 encoding whose serializer refuses anything else and whose verification refuses a
// post-quantum validator outright. So the conversion fails, permanently and by design.
//
// It must not be mistaken for `timeout`/`notready`. Those mean "try again"; this means
// "this build cannot do it at all", and the finalization sequencer has to tell them apart
// so it latches the slot instead of retrying the same refusal forever. The value is
// deliberately outside the ErrorCode 6xx band. N5 removes the refusal by installing the
// post-quantum carrier.
inline constexpr int n5_carrier_required_error_code = 4501;

inline bool is_n5_carrier_required(const td::Status& status) {
  return status.code() == n5_carrier_required_error_code;
}

namespace tl {

using voteSignature = tos_api::consensus_simplex_voteSignature;
using VoteSignatureRef = tl_object_ptr<voteSignature>;

using voteSignatureSet = tos_api::consensus_simplex_voteSignatureSet;
using VoteSignatureSetRef = tl_object_ptr<voteSignatureSet>;

using certificate = tos_api::consensus_simplex_certificate;
using CertificateRef = tl_object_ptr<certificate>;

}  // namespace tl

template <ValidVote T>
struct Certificate : td::CntObject {
  struct VoteSignature {
    PeerValidatorId validator;
    td::BufferSlice signature;
  };

  static td::Result<td::Ref<Certificate<T>>> from_tl(tl::voteSignatureSet&& set, T vote, const Bus& bus);
  static td::Result<td::Ref<Certificate<Vote>>> from_tl(tl::certificate&& cert, const Bus& bus)
    requires std::same_as<T, Vote>;

  Certificate(T vote, std::vector<VoteSignature> signatures) : vote(vote), signatures(std::move(signatures)) {
  }

  CntObject* make_copy() const override;

  // Convert this certificate into the block-finality carrier. Fallible on purpose: in N4
  // this always refuses with `n5_carrier_required_error_code`, because the carrier is N5's
  // and the legacy one cannot hold a post-quantum signature. The caller must handle the
  // refusal; it must not be able to get a legacy set by ignoring a status.
  td::Result<td::Ref<block::BlockSignatureSet>> to_signature_set(const CandidateRef& candidate, const Bus& bus) const
    requires td::OneOf<T, NotarizeVote, FinalizeVote>;

  tl::VoteSignatureSetRef to_tl_vote_signature_set() const;
  tl::CertificateRef to_tl() const;
  td::BufferSlice serialize() const;

  auto consume_and_downcast(auto&& func) &&
    requires std::same_as<T, Vote>
  {
    auto visitor = [&]<typename U>(const U& vote) {
      std::vector<typename Certificate<U>::VoteSignature> casted_signatures;
      for (auto& sig : signatures) {
        casted_signatures.emplace_back(sig.validator, std::move(sig.signature));
      }
      auto cert = td::make_ref<Certificate<U>>(vote, std::move(casted_signatures));
      return func(std::move(cert));
    };
    return std::visit(visitor, vote.vote);
  }

  td::Ref<Certificate<Vote>> consume_and_upcast() &&
    requires(!std::same_as<T, Vote>);

  T vote;
  std::vector<VoteSignature> signatures;
};

template <typename T>
using CertificateRef = td::Ref<Certificate<T>>;

using NotarCert = Certificate<NotarizeVote>;
using SkipCert = Certificate<SkipVote>;
using FinalCert = Certificate<FinalizeVote>;
using NotarCertRef = CertificateRef<NotarizeVote>;
using SkipCertRef = CertificateRef<SkipVote>;
using FinalCertRef = CertificateRef<FinalizeVote>;

}  // namespace tos::validator::consensus::simplex
