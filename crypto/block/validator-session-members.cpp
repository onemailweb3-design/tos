/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <cstring>
#include <keys/keys.hpp>

#include "block/validator-session-members.h"
#include "block/validator-set.h"
#include "pq/pq-consensus.h"

namespace block {

std::vector<tos::tl_object_ptr<tos::tos_api::engine_validator_GroupMember>> validator_session_members(
    const std::vector<tos::ValidatorDescr>& nodes) {
  std::vector<tos::tl_object_ptr<tos::tos_api::engine_validator_GroupMember>> members;
  members.reserve(nodes.size());
  for (const auto& n : nodes) {
    if (n.is_pq()) {
      members.push_back(tos::create_tl_object<tos::tos_api::validator_groupMemberPQ>(n.validator_id.value,
                                                                                     n.key_id.value, n.addr, n.weight));
    } else {
      auto pub_key = tos::PublicKey{tos::pubkeys::Ed25519{n.classical_key()}};
      members.push_back(tos::create_tl_object<tos::tos_api::validator_groupMember>(
          pub_key.compute_short_id().bits256_value(), n.addr, n.weight));
    }
  }
  return members;
}

td::Status validate_pq_consensus_descriptor(const tos::ValidatorDescr& descr) {
  if (!descr.is_pq()) {
    return td::Status::Error("validator descriptor is classical; the post-quantum consensus path does not accept it");
  }
  const auto algorithm_id = static_cast<tos::pq::PQAlgorithmId>(descr.algorithm_id);
  if (!tos::pq::is_admitted(algorithm_id)) {
    return td::Status::Error(PSTRING() << "validator descriptor names an unadmitted consensus algorithm "
                                       << descr.algorithm_id);
  }
  if (descr.pq_public_key.size() != tos::pq::mldsa44_public_key_bytes) {
    return td::Status::Error(PSTRING() << "validator descriptor's consensus public key is "
                                       << descr.pq_public_key.size() << " bytes, expected "
                                       << tos::pq::mldsa44_public_key_bytes);
  }
  auto derived = tos::pq::derive_key_id(algorithm_id, descr.pq_public_key);
  if (!derived || std::memcmp(derived->data(), descr.key_id.value.data(), 32) != 0) {
    return td::Status::Error("validator descriptor's consensus key id does not derive from its public key");
  }
  return td::Status::OK();
}

td::Bits256 validator_adnl_identity(const tos::ValidatorDescr& descr) {
  if (!descr.addr.is_zero()) {
    return descr.addr;
  }
  // Only a classical descriptor can leave it implicit; a post-quantum one is refused at
  // decode without an explicit address.
  return tos::PublicKey{tos::pubkeys::Ed25519{descr.classical_key()}}.compute_short_id().bits256_value();
}

td::Status authorise_collate_request(const ValidatorSet& validator_set, const tos::ValidatorId& creator,
                                     const td::Bits256& src) {
  const auto* descr = validator_set.get_validator(creator);
  if (descr == nullptr) {
    return td::Status::Error("collate query: creator is not in the validator set");
  }
  if (src != validator_adnl_identity(*descr)) {
    return td::Status::Error("collate query: authenticated ADNL identity does not belong to the named creator");
  }
  return td::Status::OK();
}

}  // namespace block
