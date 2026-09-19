/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "pq-vote.h"

#include <functional>

#include "pq/mldsa44.h"

#include "vm/cellslice.h"

namespace block::pq {
namespace {

// Both bodies have the same shape: the operation, a query id, what is being voted on,
// and the signature behind a reference. Written once so the two cannot drift.
td::Result<td::Ref<vm::Cell>> vote_body(td::uint32 op, td::uint64 query_id,
                                        const std::function<bool(vm::CellBuilder&)>& subject,
                                        td::Slice signature) {
  TRY_RESULT(packed, tos::pq::pack_pq_bytes(signature, tos::pq::mldsa44_signature_bytes));
  vm::CellBuilder cb;
  if (!(cb.store_long_bool(op, 32) && cb.store_long_bool(query_id, 64) && subject(cb) &&
        cb.store_ref_bool(std::move(packed)))) {
    return td::Status::Error("a validator vote does not fit in one cell");
  }
  return cb.finalize();
}

}  // namespace

td::Result<td::Ref<vm::Cell>> config_vote_body(td::uint64 query_id, td::uint16 idx,
                                               const td::Bits256& proposal_hash,
                                               td::Slice signature) {
  return vote_body(tos::pq::config_pq_vote_op, query_id,
                   [&](vm::CellBuilder& cb) {
                     return cb.store_long_bool(idx, 16) && cb.store_bits_bool(proposal_hash.cbits(), 256);
                   },
                   signature);
}

td::Result<td::Ref<vm::Cell>> complaint_vote_body(td::uint64 query_id, td::uint16 idx,
                                                  td::uint32 election_id,
                                                  const td::Bits256& complaint_hash,
                                                  td::Slice signature) {
  return vote_body(tos::pq::elector_pq_complaint_op, query_id,
                   [&](vm::CellBuilder& cb) {
                     return cb.store_long_bool(idx, 16) && cb.store_long_bool(election_id, 32) &&
                            cb.store_bits_bool(complaint_hash.cbits(), 256);
                   },
                   signature);
}

}  // namespace block::pq
