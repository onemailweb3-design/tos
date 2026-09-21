/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <array>
#include <cassert>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include "block-signature-carrier-common.h"

int main() {
  constexpr std::array<std::size_t, 6> counts{1, 21, 32, 64, 100, 400};
  std::ostringstream measured_output;
  measured_output << "signers\tcells\tdepth\tblock_signatures_boc\tblock_proof_boc\tnode_tl\tlite_tl\t"
                     "simplex_certificate_tl\tboc_minus_certificate\tinput\n";
  for (const auto count : counts) {
    const bool valid = count <= 100;
    const auto measured = block_signature_carrier_test::measure(count, valid);
    measured_output << measured.signers << '\t' << measured.cells << '\t' << measured.depth << '\t'
                    << measured.signatures_boc_bytes << '\t' << measured.block_proof_boc_bytes << '\t'
                    << measured.node_tl_bytes << '\t' << measured.lite_tl_bytes << '\t' << measured.certificate_tl_bytes
                    << '\t' << measured.boc_minus_certificate << '\t' << (valid ? "valid" : "deterministic-size")
                    << '\n';
  }
  measured_output << "401\tREFUSED\tREFUSED\tREFUSED\tREFUSED\tREFUSED\tREFUSED\tREFUSED\tREFUSED\tstructural\n";

  std::ifstream input(MEASUREMENTS_FILE);
  assert(input && "the committed carrier measurement file must be readable");
  std::string expected;
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line[0] != '#') {
      expected += line + '\n';
    }
  }
  const auto measured_text = measured_output.str();
  if (measured_text != expected) {
    std::fprintf(stderr, "MEASUREMENT_DRIFT: measured carrier bytes differ from the committed TSV\n%s",
                 measured_text.c_str());
    return 1;
  }
  std::fwrite(measured_text.data(), 1, measured_text.size(), stdout);
  return 0;
}
