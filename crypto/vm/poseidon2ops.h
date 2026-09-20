/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include <string>

namespace vm {
class OpcodeTable;

inline constexpr unsigned poseidon2_perm8_opcode = 0xf93200;
inline constexpr unsigned poseidon2_hash7_opcode = 0xf93201;
inline constexpr int poseidon2_min_version = 17;
// Development tariff, not a production claim: overpricing only makes tests
// expensive, while underpricing is a denial-of-service surface. Both VMs carry
// the same number, and a production price replaces it in both at once.
inline constexpr long long poseidon2_perm8_gas_price = 3000;
inline constexpr long long poseidon2_hash7_gas_price = 3000;

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
