/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include "block/validator-session-id.h"
#include "block/validator-session-members.h"
#include "td/utils/misc.h"
#include "tl-utils/common-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "validator/consensus/db-path.h"
#include "validator/consensus/session-compat.h"
#include "vm/boc.h"
#include "vm/cells.h"

namespace {

td::Bits256 fill(unsigned char value) {
  td::Bits256 result;
  std::memset(result.data(), value, 32);
  return result;
}

td::Ref<vm::Cell> simplex_cell(td::uint32 slots) {
  vm::CellBuilder builder;
  if (!builder.store_long_bool(0x22, 8) || !builder.store_long_bool(0, 5) || !builder.store_long_bool(2, 2) ||
      !builder.store_long_bool(0, 1) || !builder.store_long_bool(slots, 32) || !builder.store_long_bool(0, 1)) {
    std::abort();
  }
  return builder.finalize();
}

struct Vector {
  td::int32 global_id{-239};
  td::Bits256 options_hash;
  td::Ref<vm::Cell> config_cell;
  td::BufferSlice config_boc;
  tos::ShardIdFull shard{tos::masterchainId, tos::shardIdAll};
  td::uint32 vertical_seqno{7};
  tos::BlockSeqno key_seqno{91};
  tos::CatchainSeqno catchain_seqno{17};
  tos::ValidatorDescr validator;
  td::Bits256 session_config_hash;
  tos::ValidatorSessionId session_id;
};

Vector make_vector() {
  tos::ValidatorSessionConfig config;
  tos::validator::consensus::ValidatorSessionOptions options{config};
  auto cell = simplex_cell(4);
  auto boc = vm::std_boc_serialize(cell, 0);
  if (boc.is_error()) {
    std::abort();
  }
  Vector vector{
      .options_hash = options.get_hash(),
      .config_cell = cell,
      .config_boc = boc.move_as_ok(),
      .validator = tos::ValidatorDescr{tos::ValidatorId{fill(0xa1)}, 1, tos::ConsensusKeyId{fill(0xb2)},
                                       std::string(1312, '\x5c'), 23, fill(0xc3)},
      .session_config_hash = {},
      .session_id = {},
  };
  auto identity = block::derive_validator_session_identity(
      vector.global_id, vector.options_hash, td::Bits256{cell->get_hash().bits()}, vector.shard, vector.catchain_seqno,
      {vector.validator}, vector.vertical_seqno, vector.key_seqno, true);
  vector.session_config_hash = identity.session_config_hash;
  vector.session_id = identity.session_id;
  return vector;
}

std::string render(const Vector& vector) {
  std::ostringstream out;
  out << "global_id\tparam29_hash\tselected_param30_cell_boc\tselected_param30_cell_hash\tworkchain\tshard\t"
         "vertical_seqno\tlast_key_block_seqno\tcatchain_seqno\tvalidator_id\tkey_id\tadnl\tweight\t"
         "session_config_hash\tvalidator_session_id\n";
  out << vector.global_id << '\t' << vector.options_hash.to_hex() << '\t'
      << td::hex_encode(vector.config_boc.as_slice()) << '\t' << vector.config_cell->get_hash().to_hex() << '\t'
      << vector.shard.workchain << '\t' << vector.shard.shard << '\t' << vector.vertical_seqno << '\t'
      << vector.key_seqno << '\t' << vector.catchain_seqno << '\t' << vector.validator.validator_id.value.to_hex()
      << '\t' << vector.validator.key_id.value.to_hex() << '\t' << vector.validator.addr.to_hex() << '\t'
      << vector.validator.weight << '\t' << vector.session_config_hash.to_hex() << '\t' << vector.session_id.to_hex()
      << '\n';
  return out.str();
}

int check(const char* path, td::Slice only) {
  if (!only.empty() && only != "param30" && only != "global-id" && only != "local-override" &&
      only != "governing-snapshot" && only != "session-path" && only != "constructor-selection") {
    std::fprintf(stderr, "UNKNOWN_SESSION_DERIVATION_CHECK name=%s\n", only.str().c_str());
    return 2;
  }
  auto vector = make_vector();
  std::ifstream input(path, std::ios::binary);
  std::ostringstream contents;
  contents << input.rdbuf();
  if (!input || contents.str() != render(vector)) {
    std::fprintf(stderr, "SESSION_DERIVATION_VECTOR_MISMATCH file=%s\n", path);
    return 1;
  }

  auto other_cell = simplex_cell(5);
  auto identity_b = block::derive_validator_session_identity(
      vector.global_id, vector.options_hash, td::Bits256{other_cell->get_hash().bits()}, vector.shard,
      vector.catchain_seqno, {vector.validator}, vector.vertical_seqno, vector.key_seqno, true);
  auto hash_b = identity_b.session_config_hash;
  auto session_b = identity_b.session_id;
  if ((only.empty() || only == "param30") && (hash_b == vector.session_config_hash || session_b == vector.session_id)) {
    std::fprintf(stderr, "PARAM30_CHANGE_DID_NOT_CHANGE_SESSION\n");
    return 1;
  }

  auto other_global_identity = block::derive_validator_session_identity(
      vector.global_id + 1, vector.options_hash, td::Bits256{vector.config_cell->get_hash().bits()}, vector.shard,
      vector.catchain_seqno, {vector.validator}, vector.vertical_seqno, vector.key_seqno, true);
  auto other_global = other_global_identity.session_config_hash;
  auto other_global_session = other_global_identity.session_id;
  if ((only.empty() || only == "global-id") &&
      (other_global == vector.session_config_hash || other_global_session == vector.session_id)) {
    std::fprintf(stderr, "GLOBAL_ID_CHANGE_DID_NOT_CHANGE_SESSION\n");
    return 1;
  }

  tos::SelectedNewConsensusConfig selected{.config = {},
                                           .cell_hash = td::Bits256{vector.config_cell->get_hash().bits()}};
  auto before_override =
      block::validator_session_config_hash(vector.global_id, vector.options_hash, selected.cell_hash);
  selected.config.noncritical_params.target_rate = std::chrono::milliseconds(9999);
  auto after_override = block::validator_session_config_hash(vector.global_id, vector.options_hash, selected.cell_hash);
  if ((only.empty() || only == "local-override") && before_override != after_override) {
    std::fprintf(stderr, "LOCAL_NONCRITICAL_OVERRIDE_CHANGED_SESSION\n");
    return 1;
  }

  // K is governed by the snapshot before it, while K+1 is governed by K's state.
  // Verification binds this expected id in the following unit; this test pins
  // the governing-snapshot boundary without pulling that verifier work forward.
  const auto k_under_a =
      block::derive_validator_session_identity(
          vector.global_id, vector.options_hash, td::Bits256{vector.config_cell->get_hash().bits()}, vector.shard,
          vector.catchain_seqno, {vector.validator}, vector.vertical_seqno, vector.key_seqno, true)
          .session_id;
  const auto after_k_under_b =
      block::derive_validator_session_identity(
          vector.global_id, vector.options_hash, td::Bits256{other_cell->get_hash().bits()}, vector.shard,
          vector.catchain_seqno, {vector.validator}, vector.vertical_seqno, vector.key_seqno, true)
          .session_id;
  if ((only.empty() || only == "governing-snapshot") &&
      (k_under_a != vector.session_id || k_under_a == session_b || after_k_under_b != session_b)) {
    std::fprintf(stderr, "GOVERNING_SNAPSHOT_BOUNDARY_FAILED\n");
    return 1;
  }

  auto path_a = tos::validator::consensus::consensus_db_dir_name(vector.shard, vector.catchain_seqno, vector.session_id,
                                                                 td::Slice{});
  auto path_b =
      tos::validator::consensus::consensus_db_dir_name(vector.shard, vector.catchain_seqno, session_b, td::Slice{});
  if ((only.empty() || only == "session-path") && path_a == path_b) {
    std::fprintf(stderr, "PARAM30_CHANGE_REUSED_SESSION_PATH\n");
    return 1;
  }

  if (only.empty() || only == "constructor-selection") {
    auto legacy = block::derive_validator_session_identity(vector.global_id, vector.options_hash, selected.cell_hash,
                                                           vector.shard, vector.catchain_seqno, {vector.validator}, 0,
                                                           vector.key_seqno, false);
    auto expected_legacy = tos::create_hash_tl_object<tos::tos_api::validator_group>(
        vector.shard.workchain, vector.shard.shard, vector.catchain_seqno, legacy.session_config_hash,
        block::validator_session_members({vector.validator}));
    auto extended = block::derive_validator_session_identity(vector.global_id, vector.options_hash, selected.cell_hash,
                                                             vector.shard, vector.catchain_seqno, {vector.validator},
                                                             vector.vertical_seqno, vector.key_seqno, false);
    auto expected_extended = tos::create_hash_tl_object<tos::tos_api::validator_groupEx>(
        vector.shard.workchain, vector.shard.shard, vector.vertical_seqno, vector.catchain_seqno,
        extended.session_config_hash, block::validator_session_members({vector.validator}));
    if (legacy.session_id != expected_legacy || extended.session_id != expected_extended ||
        vector.session_id == legacy.session_id || vector.session_id == extended.session_id) {
      std::fprintf(stderr, "SESSION_CONSTRUCTOR_SELECTION_CHANGED\n");
      return 1;
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 1) {
    std::fputs(render(make_vector()).c_str(), stdout);
    return 0;
  }
  if (argc == 2) {
    return check(argv[1], {});
  }
  if (argc == 3) {
    return check(argv[1], td::Slice{argv[2], std::strlen(argv[2])});
  }
  std::fprintf(stderr, "usage: %s [vector-file [check-name]]\n", argv[0]);
  return 2;
}
