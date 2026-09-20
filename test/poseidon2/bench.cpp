/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
// B1, the C++ half: what POSEIDON2_PERM8 and POSEIDON2_HASH7 cost here.
//
// A tariff has to cover the slower of the two implementations, so measuring
// one of them settles nothing. This runs the *same compiled probe* the Rust
// benchmark runs -- `tools/poseidon2-bench` writes it out -- because two
// implementations timed on two different programs would be a comparison of
// the programs.
//
// The method is the same as well: each subject is timed against a loop that
// does everything except the instruction, the two are measured back to back
// so that drift lands on both, and the per-repeat difference is minimised
// rather than averaged.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "common/bitstring.h"
#include "td/utils/base64.h"
#include "td/utils/buffer.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/cells.h"
#include "vm/cp0.h"
#include "vm/stack.hpp"
#include "vm/vm.h"

namespace {

struct Subject {
  const char* name;
  // The gas price already in crypto/vm/vm.h, or 0 for the two being priced.
  long long price;
  unsigned method_id;
  unsigned baseline_id;
};

// The method ids the Rust benchmark prints when it writes the probe. They are
// crc16-derived and stable; a mismatch would show up as an unknown-method exit
// rather than a wrong number.
//
// CHKSIGNU is absent on purpose. It was the one anchor whose cost is not point
// decompression, but given the same invalid signature the two VMs charge the
// same gas and take 67 ns and 32,441 ns: this one rejects before verifying and
// the other does not. An anchor the two implementations disagree about by four
// hundred times cannot calibrate either of them.
const std::vector<Subject> kSubjects = {
    {"POSEIDON2_PERM8", 0, 118365, 113038},  {"POSEIDON2_HASH7", 0, 80881, 65739},
    {"BLS_G1_ADD", 3900, 71435, 95410},      {"BLS_G1_NEG", 750, 79976, 121841},
    {"BLS_G1_INGROUP", 2950, 118906, 70687}, {"BLS_G2_ADD", 6100, 129497, 116093},
};

struct Sample {
  double nanos;
  long long gas;
  int exit;
};

// One execution of one get-method over the probe's code.
Sample run_once(td::Ref<vm::Cell> code, unsigned method_id, int rounds) {
  td::Ref<vm::Stack> stack{true};
  stack.write().push_smallint(rounds);
  stack.write().push_smallint(static_cast<long long>(method_id));
  const long long budget = 1ll << 50;
  vm::VmState state{vm::load_cell_slice_ref(code), 17, std::move(stack), vm::GasLimits{budget, budget}};
  const auto started = std::chrono::steady_clock::now();
  const int exit = ~state.run();
  const auto elapsed = std::chrono::steady_clock::now() - started;
  return Sample{std::chrono::duration<double, std::nano>(elapsed).count(), state.gas_consumed(), exit};
}

// One subject against its own baseline: back to back inside each repeat, and
// the smallest difference wins. A shared machine drifts, and a drift that
// lands on one pass and not the other is subtracted straight into the answer.
struct Measured {
  double nanos_per_op;
  long long gas_per_op;
};

Measured measure(td::Ref<vm::Cell> code, const Subject& subject, int rounds, int repeats) {
  run_once(code, subject.method_id, rounds);
  run_once(code, subject.baseline_id, rounds);
  double best = 1e300;
  long long gas_per_op = 0;
  for (int repeat = 0; repeat < repeats; ++repeat) {
    const Sample with = run_once(code, subject.method_id, rounds);
    const Sample without = run_once(code, subject.baseline_id, rounds);
    if (with.exit != 0 || without.exit != 0) {
      std::fprintf(stderr, "%s exited %d/%d\n", subject.name, with.exit, without.exit);
      std::exit(1);
    }
    const double per_op = (with.nanos - without.nanos) / rounds;
    best = per_op < best ? per_op : best;
    gas_per_op = (with.gas - without.gas) / rounds;
  }
  return Measured{best, gas_per_op};
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr,
                 "usage: bench-poseidon2 <probe.boc> [rounds] [repeats]\n"
                 "the probe is written by tools/poseidon2-bench with\n"
                 "POSEIDON2_BENCH_DUMP_CODE set.\n");
    return 2;
  }
  const int rounds = argc > 2 ? std::atoi(argv[2]) : 2000;
  const int repeats = argc > 3 ? std::atoi(argv[3]) : 15;

  auto bytes = td::read_file(td::CSlice(argv[1]));
  if (bytes.is_error()) {
    std::fprintf(stderr, "cannot read %s\n", argv[1]);
    return 1;
  }
  auto code = vm::std_boc_deserialize(bytes.move_as_ok());
  if (code.is_error()) {
    std::fprintf(stderr, "%s is not a BOC\n", argv[1]);
    return 1;
  }
  vm::init_op_cp0();
  SET_VERBOSITY_LEVEL(verbosity_ERROR);

  std::printf("C++ VM, %d rounds, best of %d\n\n", rounds, repeats);
  std::printf("%-18s%10s%10s%12s%14s\n", "instruction", "ns/op", "gas/op", "known gas", "ns per gas");

  std::vector<std::pair<const Subject*, double>> anchors;
  std::vector<std::pair<const Subject*, double>> unpriced;
  for (const auto& subject : kSubjects) {
    const Measured measured = measure(code.ok(), subject, rounds, repeats);
    if (subject.price > 0) {
      std::printf("%-18s%10.1f%10lld%12lld%14.4f\n", subject.name, measured.nanos_per_op, measured.gas_per_op,
                  subject.price, measured.nanos_per_op / static_cast<double>(subject.price));
      anchors.emplace_back(&subject, measured.nanos_per_op);
    } else {
      std::printf("%-18s%10.1f%10lld%12s%14s\n", subject.name, measured.nanos_per_op, measured.gas_per_op, "?", "?");
      unpriced.emplace_back(&subject, measured.nanos_per_op);
    }
  }

  // An anchor whose own price is far from its own cost cannot price anything
  // else, and BLS_G1_NEG is the case in point: it flips a sign bit on
  // compressed bytes and never decompresses.
  double loosest = 0;
  for (const auto& [subject, nanos] : anchors) {
    loosest = std::max(loosest, nanos / static_cast<double>(subject->price));
  }
  std::printf("\n%-18s%-18s%12s%10s\n", "instruction", "against", "implied gas", "used");
  for (const auto& [subject, nanos] : unpriced) {
    for (const auto& [anchor, anchor_nanos] : anchors) {
      const double ratio = anchor_nanos / static_cast<double>(anchor->price);
      const bool used = ratio > loosest / 10.0;
      std::printf("%-18s%-18s%12.0f%10s\n", subject->name, anchor->name,
                  nanos / anchor_nanos * static_cast<double>(anchor->price), used ? "yes" : "no");
    }
  }

  std::printf("\n%-18s%14s%14s\n", "instruction", "low", "high");
  for (const auto& [subject, nanos] : unpriced) {
    double low = 1e300;
    double high = 0;
    for (const auto& [anchor, anchor_nanos] : anchors) {
      const double ratio = anchor_nanos / static_cast<double>(anchor->price);
      if (ratio <= loosest / 10.0) {
        continue;
      }
      const double implied = nanos / anchor_nanos * static_cast<double>(anchor->price);
      low = std::min(low, implied);
      high = std::max(high, implied);
    }
    std::printf("%-18s%14.0f%14.0f\n", subject->name, low, high);
  }
  return 0;
}
