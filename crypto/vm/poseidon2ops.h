/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include <string>

namespace vm {
class OpcodeTable;

inline constexpr unsigned poseidon2_perm8_opcode = 0xf93200;
inline constexpr unsigned poseidon2_hash7_opcode = 0xf93201;
inline constexpr unsigned poseidon2_path7_opcode = 0xf93202;
inline constexpr int poseidon2_min_version = 17;
// PATH7 is newer than the two above. A node built for 17 implements them and
// not it, so it carries its own floor rather than sharing theirs.
inline constexpr int poseidon2_path7_min_version = 18;

// The deepest path the instruction will walk. A level is two 768-bit cells,
// so 64 levels is 128 cells -- far past any plausible tree and far inside the
// 512 that SHA256C allows itself. The bound is belt and braces next to the
// per-level gas below, not instead of it.
inline constexpr int poseidon2_path7_max_depth = 64;
// Measured, on 2026-09-20, against instructions whose price is already fixed:
// BLS12-381 G1 addition, G1 subgroup check and G2 addition, on the same curve
// over the same field. The permutation came to between 2,137 and 3,462 gas in
// the slower of the two VMs, and this is that upper bound rounded up.
//
// Rounded up rather than to the middle because the two directions are not
// symmetric: overpricing costs users money, underpricing is a
// denial-of-service surface. The anchors agree with one another only to
// within 1.61x, so a tighter figure would be false precision.
//
// Both VMs carry the same number and it is changed in both at once.
// `test/poseidon2/mutations.py` fails if they drift apart.
inline constexpr long long poseidon2_perm8_gas_price = 3500;
inline constexpr long long poseidon2_hash7_gas_price = 3500;

// PATH7 is one HASH7 a level plus the two cells that level's siblings live
// in, so it is priced as exactly that and nothing is being bought cheaply by
// moving the loop into the VM. The base covers popping five operands.
//
// These two are NOT measured. The permutation's 3,500 is, and the 200 is the
// VM's own price for two cell loads; the sum is an assembly of prices rather
// than an instruction that was benchmarked. Before this leaves a testnet it
// wants the same treatment POSEIDON2_PERM8 got: measured against instructions
// that already have a price, on target hardware, quoted as a bracket.
inline constexpr long long poseidon2_path7_base_gas_price = 500;
inline constexpr long long poseidon2_path7_level_gas_price = 3700;

void register_poseidon2_ops(OpcodeTable& table);

namespace poseidon2 {
// Runs the pinned permutation over eight canonical field elements, each given
// as a 32-byte big-endian value, in place.
void permute(unsigned char state[8][32]);
// Rebuilds the frozen manifest byte stream from the vendored tables, so a table
// that drifts is caught by a digest rather than by reading it.
std::string manifest_bytes();
}  // namespace poseidon2
}  // namespace vm
