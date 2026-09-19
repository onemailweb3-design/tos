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
#include "block/validator-session-members.h"

#include <keys/keys.hpp>

namespace block {

std::vector<tos::tl_object_ptr<tos::tos_api::engine_validator_GroupMember>> validator_session_members(
    const std::vector<tos::ValidatorDescr>& nodes) {
  std::vector<tos::tl_object_ptr<tos::tos_api::engine_validator_GroupMember>> members;
  members.reserve(nodes.size());
  for (const auto& n : nodes) {
    if (n.is_pq()) {
      members.push_back(tos::create_tl_object<tos::tos_api::validator_groupMemberPQ>(n.validator_id.value, n.key_id.value,
                                                                                n.addr, n.weight));
    } else {
      auto pub_key = tos::PublicKey{tos::pubkeys::Ed25519{n.classical_key()}};
      members.push_back(tos::create_tl_object<tos::tos_api::validator_groupMember>(
          pub_key.compute_short_id().bits256_value(), n.addr, n.weight));
    }
  }
  return members;
}

td::Bits256 validator_adnl_identity(const tos::ValidatorDescr& descr) {
  if (!descr.addr.is_zero()) {
    return descr.addr;
  }
  // Only a classical descriptor can leave it implicit; a post-quantum one is refused at
  // decode without an explicit address.
  return tos::PublicKey{tos::pubkeys::Ed25519{descr.classical_key()}}.compute_short_id().bits256_value();
}

}  // namespace block
