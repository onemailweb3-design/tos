/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// The message bodies a validator sends to vote, built where the node can build them.
//
// The signed bytes live in crypto/pq/pq-elector.h and are held to the shared vectors by
// every producer. These are the cells that carry them: the operation, what is being voted
// on, and the signature as the byte chain the verifying instruction takes. Nothing here
// states who is voting -- the contract reads that from the validator set at the index the
// message names, which is what stops a vote naming one validator and counting for
// another.
//
// They are here rather than in a Fift script because a script is a second place the wire
// can be written, and the two would drift the first time one of them changed.

#include "pq/pq-bytes.h"
#include "pq/pq-elector.h"
#include "vm/cells.h"

namespace block::pq {

// `PQvo`: a validator of the current set votes for a configuration proposal.
td::Result<td::Ref<vm::Cell>> config_vote_body(td::uint64 query_id, td::uint16 idx,
                                               const td::Bits256& proposal_hash,
                                               td::Slice signature);

// `PQco`: a validator of the current set votes on a complaint against a validator of a
// past election.
td::Result<td::Ref<vm::Cell>> complaint_vote_body(td::uint64 query_id, td::uint16 idx,
                                                  td::uint32 election_id,
                                                  const td::Bits256& complaint_hash,
                                                  td::Slice signature);

}  // namespace block::pq
