/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "td/utils/overloaded.h"
#include "tos/quorum.h"
#include "validator/consensus/bus.h"

#include "certificate.h"

namespace tos::validator::consensus::simplex {

template <ValidVote T>
td::Result<td::Ref<Certificate<T>>> Certificate<T>::from_tl(tl::voteSignatureSet&& set, T vote, const Bus& bus) {
  auto vote_to_sign = serialize_tl_object(vote.to_tl(), true);

  std::vector<bool> voted(bus.validator_set.size(), false);
  std::vector<VoteSignature> signatures;
  ValidatorWeight voted_weight = 0;

  for (auto& signature : set.votes_) {
    auto who = static_cast<td::uint32>(signature->who_);
    if (who >= bus.validator_set.size()) {
      return td::Status::Error(PSTRING() << "Invalid validator index " << who << " in certificate");
    }
    if (voted[who]) {
      return td::Status::Error(PSTRING() << "Duplicate validator index " << who << " in certificate");
    }
    voted[who] = true;

    auto validator = PeerValidatorId{who}.get_using(bus);
    signatures.emplace_back(VoteSignature{validator.idx, std::move(signature->signature_)});
    if (!tos::checked_add_validator_weight(voted_weight, validator.weight)) {
      return td::Status::Error("Validator vote weight sum exceeds protocol cap");
    }
  }

  if (voted_weight < tos::quorum_threshold(bus.total_weight)) {
    return td::Status::Error("Not enough signatures in certificate");
  }

  for (const auto& [who, signature] : signatures) {
    auto validator = PeerValidatorId{who}.get_using(bus);
    if (!validator.check_signature(bus.session_id, vote_to_sign, signature)) {
      return td::Status::Error(PSTRING() << "Invalid vote signature for " << validator);
    }
  }

  return td::make_ref<Certificate<T>>(std::move(vote), std::move(signatures));
}

template <ValidVote T>
td::Result<td::Ref<Certificate<Vote>>> Certificate<T>::from_tl(tl::certificate&& cert, const Bus& bus)
  requires std::same_as<T, Vote>
{
  auto vote_to_sign = serialize_tl_object(cert.vote_, true);
  auto vote = Vote::from_tl(std::move(*cert.vote_));
  return from_tl(std::move(*cert.signatures_), std::move(vote), bus);
}

template <ValidVote T>
td::CntObject* Certificate<T>::make_copy() const {
  std::vector<VoteSignature> copied_signatures;
  for (const auto& sig : signatures) {
    copied_signatures.emplace_back(VoteSignature{sig.validator, sig.signature.clone()});
  }
  return new Certificate<T>(vote, std::move(copied_signatures));
}

template <ValidVote T>
tl::VoteSignatureSetRef Certificate<T>::to_tl_vote_signature_set() const {
  std::vector<tl::VoteSignatureRef> tl_sigs;
  for (const auto& [validator, signature] : signatures) {
    auto idx = static_cast<td::uint32>(validator.value());
    tl_sigs.push_back(create_tl_object<tl::voteSignature>(idx, signature.clone()));
  }
  return create_tl_object<tl::voteSignatureSet>(std::move(tl_sigs));
}

template <ValidVote T>
tl::CertificateRef Certificate<T>::to_tl() const {
  return create_tl_object<tl::certificate>(vote.to_tl(), to_tl_vote_signature_set());
}

template <ValidVote T>
td::BufferSlice Certificate<T>::serialize() const {
  return serialize_tl_object(to_tl(), true);
}

template <ValidVote T>
td::Result<td::Ref<block::BlockSignatureSet>> Certificate<T>::to_signature_set(const CandidateRef& candidate,
                                                                               const Bus& bus) const
  requires td::OneOf<T, NotarizeVote, FinalizeVote>
{
  CHECK(candidate->id == vote.id);

  // The carrier seam.
  //
  // Everything up to here is this build's: the votes are post-quantum, the quorum is weighted, and
  // every signature in this certificate has been verified against the key the validator set
  // records. Turning that certificate into a block::BlockSignatureSet is where the carrier work begins,
  // and the only carrier that exists today is the legacy one: its serializer writes
  // `ed25519_signature#5` and takes exactly 64 bytes per signature, and its verification
  // refuses a post-quantum validator outright. A 2420-byte signature cannot enter it.
  //
  // So this refuses, and it refuses *here* -- before any legacy object is constructed. The
  // construction is not skipped behind a condition, it is absent: there is no branch, flag
  // or build option in this function that can produce a legacy set from a post-quantum
  // certificate. The post-quantum carrier replaces this refusal; until then a node
  // can agree on finality and cannot persist it, which is exactly what a build with no carrier is.
  return td::Status::Error(
      carrier_missing_error_code,
      PSTRING()
          << "block-signature carrier not implemented: a post-quantum Simplex certificate (session "
          << bus.session_id.to_hex() << ", slot " << vote.id.slot
          << ") cannot be converted into a block signature set until a post-quantum block-signature carrier exists");
}

template <ValidVote T>
td::Ref<Certificate<Vote>> Certificate<T>::consume_and_upcast() &&
  requires(!std::same_as<T, Vote>)
{
  std::vector<Certificate<Vote>::VoteSignature> casted_signatures;
  for (auto& sig : signatures) {
    casted_signatures.emplace_back(sig.validator, std::move(sig.signature));
  }
  return td::make_ref<Certificate<Vote>>(vote, std::move(casted_signatures));
}

template struct Certificate<NotarizeVote>;
template struct Certificate<SkipVote>;
template struct Certificate<FinalizeVote>;
template struct Certificate<Vote>;

}  // namespace tos::validator::consensus::simplex
