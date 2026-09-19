/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#ifdef NDEBUG
#undef NDEBUG  // test assertions must stay live even in Release (-DNDEBUG)
#endif
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "block/mc-config.h"
#include "block/validator-set.h"
#include "crypto/pq/pq-bytes.h"
#include "crypto/pq/pq-consensus.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

namespace {

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

td::Bits256 key_id_of(const std::string& public_key) {
  auto derived = tos::pq::derive_key_id(tos::pq::PQAlgorithmId::mldsa44, public_key);
  assert(derived.has_value());
  td::Bits256 out;
  std::memcpy(out.data(), derived->data(), derived->size());
  return out;
}

// One post-quantum descriptor, with every field under the caller's control so a single
// rule can be broken at a time and nothing else.
td::Ref<vm::Cell> pq_descriptor(const td::Bits256& validator_id, int algorithm_id,
                                const td::Bits256& key_id, const std::string& public_key,
                                td::uint64 weight, const td::Bits256& adnl_addr) {
  vm::CellBuilder cb;
  cb.store_long(0xb3, 8);
  cb.store_bits_bool(validator_id.cbits(), 256);
  cb.store_long(algorithm_id, 16);
  cb.store_bits_bool(key_id.cbits(), 256);
  cb.store_ref(tos::pq::pack_pq_bytes(td::Slice(public_key), tos::pq::pq_bytes_hard_max).move_as_ok());
  cb.store_long(static_cast<long long>(weight), 64);
  cb.store_bits_bool(adnl_addr.cbits(), 256);
  return cb.finalize();
}

// A validators_ext#12 set around the given descriptors.
td::Ref<vm::Cell> validator_set_cell(const std::vector<td::Ref<vm::Cell>>& descriptors, td::uint64 total_weight) {
  vm::Dictionary dict{16};
  for (std::size_t i = 0; i < descriptors.size(); i++) {
    td::BitArray<16> key;
    key.store_ulong(i);
    auto cs = vm::load_cell_slice_ref(descriptors[i]);
    bool ok = dict.set(key.cbits(), 16, cs);
    assert(ok);
  }
  vm::CellBuilder cb;
  cb.store_long(0x12, 8);                                            // validators_ext#12
  cb.store_long(100, 32);                                            // utime_since
  cb.store_long(200, 32);                                            // utime_until
  cb.store_long(static_cast<long long>(descriptors.size()), 16);     // total
  cb.store_long(static_cast<long long>(descriptors.size()), 16);     // main
  cb.store_long(static_cast<long long>(total_weight), 64);           // total_weight
  cb.store_maybe_ref(dict.get_root_cell());                          // list
  return cb.finalize();
}

}  // namespace

int main() {
  const std::string key_a(tos::pq::mldsa44_public_key_bytes, '\x11');
  const std::string key_b(tos::pq::mldsa44_public_key_bytes, '\x22');
  const auto vid = fill(0xa0);
  const auto adnl = fill(0xc0);
  const auto kid_a = key_id_of(key_a), kid_b = key_id_of(key_b);
  assert(kid_a != kid_b);  // different keys really do have different identities

  // The same validator, before and after rotating its consensus key.
  auto before = block::Config::unpack_validator_set(
                    validator_set_cell({pq_descriptor(vid, 1, kid_a, key_a, 5, adnl)}, 5), false)
                    .move_as_ok();
  auto after = block::Config::unpack_validator_set(
                   validator_set_cell({pq_descriptor(vid, 1, kid_b, key_b, 5, adnl)}, 5), false)
                   .move_as_ok();

  block::ValidatorSet set_before{1, tos::ShardIdFull{tos::masterchainId}, before->export_validator_set()};
  block::ValidatorSet set_after{1, tos::ShardIdFull{tos::masterchainId}, after->export_validator_set()};

  // Membership is by the stable identity, so rotation does not move the validator in or
  // out of the set. This is the whole point of keeping the two identities apart.
  assert(set_before.is_validator(tos::ValidatorId{vid}));
  assert(set_after.is_validator(tos::ValidatorId{vid}));

  // The consensus key identity did change, and it is tracked separately.
  assert(set_before.get_validator_by_key_id(tos::ConsensusKeyId{kid_a}) != nullptr);
  assert(set_before.get_validator_by_key_id(tos::ConsensusKeyId{kid_b}) == nullptr);
  assert(set_after.get_validator_by_key_id(tos::ConsensusKeyId{kid_b}) != nullptr);
  assert(set_after.get_validator_by_key_id(tos::ConsensusKeyId{kid_a}) == nullptr);

  // The descriptor really carries the rotated key, not a stale one.
  assert(set_before.get_validator(tos::ValidatorId{vid})->pq_public_key == key_a);
  assert(set_after.get_validator(tos::ValidatorId{vid})->pq_public_key == key_b);
  assert(set_after.get_validator(tos::ValidatorId{vid})->is_pq());

  // An ADNL address is not a membership identity. It is a distinct type at compile time,
  // so the only way to ask with it is to say so explicitly -- and it finds nothing.
  assert(!set_after.is_validator(tos::ValidatorId{adnl}));

  // A descriptor may not claim a key identity its key does not derive.
  assert(block::Config::unpack_validator_set(
             validator_set_cell({pq_descriptor(vid, 1, kid_a, key_b, 5, adnl)}, 5), false)
             .is_error());
  // Nor an unknown algorithm, nor a key of the wrong length, nor a missing ADNL identity,
  // nor a zero validator identity.
  assert(block::Config::unpack_validator_set(
             validator_set_cell({pq_descriptor(vid, 7, kid_a, key_a, 5, adnl)}, 5), false)
             .is_error());
  const std::string short_key(tos::pq::mldsa44_public_key_bytes - 1, '\x11');
  assert(block::Config::unpack_validator_set(
             validator_set_cell({pq_descriptor(vid, 1, key_id_of(key_a), short_key, 5, adnl)}, 5), false)
             .is_error());
  assert(block::Config::unpack_validator_set(
             validator_set_cell({pq_descriptor(vid, 1, kid_a, key_a, 5, fill(0))}, 5), false)
             .is_error());
  assert(block::Config::unpack_validator_set(
             validator_set_cell({pq_descriptor(fill(0), 1, kid_a, key_a, 5, adnl)}, 5), false)
             .is_error());

  printf("VALIDATOR_IDENTITY_OK rotation keeps validator_id, changes key_id; bindings enforced\n");
  return 0;
}
