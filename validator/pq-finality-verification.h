/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include "block/signature-set.h"
#include "block/validator-session-id.h"
#include "validator/interfaces/config.h"
#include "validator/interfaces/shard.h"

namespace tos::validator {

namespace detail {

inline td::Result<block::PQFinalityVerificationContext> derive_pq_finality_context(
    td::int32 global_id, const ValidatorSessionConfig& session_config,
    const td::optional<SelectedNewConsensusConfig>& selected_config, td::Ref<block::ValidatorSet> validator_set,
    BlockIdExt block_id, td::uint32 vertical_seqno, BlockSeqno previous_key_block_seqno) {
  if (validator_set.is_null()) {
    return td::Status::Error("pq finality context: trusted validator set is missing");
  }
  if (!selected_config) {
    return td::Status::Error("pq finality context: selected ConfigParam 30 is missing or malformed");
  }
  if (!selected_config.value().config.protocol_version_supported()) {
    return td::Status::Error("pq finality context: selected ConfigParam 30 protocol version is unsupported");
  }
  auto identity = block::derive_validator_session_identity(
      global_id, block::validator_session_options_hash(session_config), selected_config.value().cell_hash,
      block_id.shard_full(),
      validator_set->get_catchain_seqno(), validator_set->export_vector(), vertical_seqno, previous_key_block_seqno,
      session_config.new_catchain_ids);
  return block::PQFinalityVerificationContext{std::move(validator_set), block_id, identity.session_id};
}

}  // namespace detail

inline td::Result<block::PQFinalityVerificationContext> derive_pq_finality_context(
    const MasterchainState& governing_state, td::Ref<block::ValidatorSet> validator_set, BlockIdExt block_id,
    td::uint32 vertical_seqno, BlockSeqno previous_key_block_seqno) {
  return detail::derive_pq_finality_context(governing_state.get_global_id(), governing_state.get_consensus_config(),
                                            governing_state.get_selected_new_consensus_config(block_id.id.workchain),
                                            std::move(validator_set), block_id, vertical_seqno,
                                            previous_key_block_seqno);
}

inline td::Result<block::PQFinalityVerificationContext> derive_pq_finality_context(
    const ConfigHolder& governing_config, td::Ref<block::ValidatorSet> validator_set, BlockIdExt block_id,
    td::uint32 vertical_seqno, BlockSeqno previous_key_block_seqno) {
  return detail::derive_pq_finality_context(governing_config.get_global_id(), governing_config.get_consensus_config(),
                                            governing_config.get_selected_new_consensus_config(block_id.id.workchain),
                                            std::move(validator_set), block_id, vertical_seqno,
                                            previous_key_block_seqno);
}

}  // namespace tos::validator
