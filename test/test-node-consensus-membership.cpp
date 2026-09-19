/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
// Unit test for node_validator_membership, the pure core behind
// NodeConsensusStatus.is_validator. It proves the tri-state is REAL against a live-built
// validator set, so a regression to a hardwired value is caught:
//   - a local key that IS in the set   -> {has_keys=true,  in_set=true}
//   - a local key NOT in the set       -> {has_keys=true,  in_set=false}  (must not be true)
//   - no local keys at all             -> {has_keys=false, in_set=false}  (caller => null)
//   - membership via the permanent set -> same as temp
// The set carries ONLY the member key; the decision follows the key sets PASSED IN, which is
// why membership from live manager keys can never go stale against an online key change.
#include "validator/node-consensus-status.h"

#include "tos/tos-types.h"

#include <cstdio>
#include <set>
#include <utility>
#include <vector>

using namespace tos;

namespace {
Bits256 bits_with_first_byte(td::uint8 b) {
  Bits256 x;
  x.set_zero();
  x.as_slice()[0] = static_cast<char>(b);
  return x;
}

PublicKeyHash short_id_of(const Ed25519_PublicKey& key) {
  return PublicKey{pubkeys::Ed25519{key}}.compute_short_id();
}
}  // namespace

int main() {
  Ed25519_PublicKey pub_member{bits_with_first_byte(0x11)};
  Ed25519_PublicKey pub_outsider{bits_with_first_byte(0x22)};

  // A validator set containing ONLY the member key.
  std::vector<ValidatorDescr> nodes;
  nodes.emplace_back(pub_member, /*weight=*/1);
  block::ValidatorSet set(/*cc_seqno=*/0, ShardIdFull{masterchainId}, std::move(nodes));

  PublicKeyHash member_key = short_id_of(pub_member);
  PublicKeyHash outsider_key = short_id_of(pub_outsider);

  int failures = 0;
  // Real checks, not assert(): assert() is stripped under NDEBUG, which would make this
  // test pass without evaluating anything.
  auto expect = [&](const char *name, std::pair<bool, bool> got, bool want_has, bool want_in) {
    if (got.first != want_has || got.second != want_in) {
      std::printf("FAIL %s: got {has_keys=%d,in_set=%d} want {%d,%d}\n", name, got.first, got.second, want_has,
                  want_in);
      failures++;
    }
  };

  {
    std::set<PublicKeyHash> temp{member_key};
    expect("member_temp_key_in_set", validator::node_validator_membership(set, temp, {}, {}), true, true);
  }
  {
    std::set<PublicKeyHash> temp{outsider_key};
    expect("configured_non_member_not_in_set", validator::node_validator_membership(set, temp, {}, {}), true, false);
  }
  {
    expect("no_local_keys_unknown", validator::node_validator_membership(set, {}, {}, {}), false, false);
  }
  {
    std::set<PublicKeyHash> perm{member_key};
    expect("member_permanent_key_in_set", validator::node_validator_membership(set, {}, perm, {}), true, true);
  }

  // A post-quantum validator: its identity has nothing to do with any Ed25519 key, and
  // membership follows what this node custodies for it.
  {
    const auto pq_id = tos::ValidatorId{bits_with_first_byte(0xa0)};
    const auto held_key = tos::ConsensusKeyId{bits_with_first_byte(0xb0)};
    const auto rotated_key = tos::ConsensusKeyId{bits_with_first_byte(0xb1)};
    std::vector<ValidatorDescr> pq_nodes;
    pq_nodes.emplace_back(pq_id, /*algorithm_id=*/1, held_key, std::string(1312, '\x01'), /*weight=*/1,
                          bits_with_first_byte(0xc0));
    block::ValidatorSet pq_set(/*cc_seqno=*/0, ShardIdFull{masterchainId}, std::move(pq_nodes));

    // Holding the key the set records for that validator is what makes this node it.
    validator::PqConsensusCustody holding{{pq_id, held_key}};
    expect("pq_custodied_key_is_member", validator::node_validator_membership(pq_set, {}, {}, holding), true, true);

    // Holding a key that is no longer the one recorded does not: a validator that has
    // rotated away from this key is not us any more.
    validator::PqConsensusCustody stale{{pq_id, rotated_key}};
    expect("pq_stale_key_is_not_member", validator::node_validator_membership(pq_set, {}, {}, stale), true, false);

    // The back door this phase exists to close: every Ed25519 key in the world, and no
    // custody, must not make this node a post-quantum consensus validator. The keys
    // offered here include one whose identity is the validator's own identity, which is
    // exactly what the old membership rule would have accepted.
    std::set<PublicKeyHash> every_ed25519{member_key, outsider_key, PublicKeyHash{pq_id.value},
                                          PublicKeyHash{held_key.value}};
    expect("ed25519_keys_alone_are_not_pq_membership",
           validator::node_validator_membership(pq_set, every_ed25519, every_ed25519, {}), true, false);

    // And custody for some other validator is not custody for this one.
    validator::PqConsensusCustody elsewhere{{tos::ValidatorId{bits_with_first_byte(0xa9)}, held_key}};
    expect("custody_of_another_validator_is_not_membership",
           validator::node_validator_membership(pq_set, {}, {}, elsewhere), true, false);
  }

  if (failures == 0) {
    std::printf("test-node-consensus-membership: 9/9 scenarios OK\n");
    return 0;
  }
  std::printf("test-node-consensus-membership: %d scenario(s) FAILED\n", failures);
  return 1;
}
