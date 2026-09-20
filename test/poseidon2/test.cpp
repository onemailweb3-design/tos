/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The Poseidon2 t=8 instruction pair, against vectors produced by executing the
// pinned upstream reference, and against the rules that make a permutation safe
// to put in a consensus ISA: it starts at exactly one version, it refuses
// anything that is not already a field element rather than reducing it, and it
// costs what it says it costs.
//
// The vectors are generated, never hand-written: crypto/poseidon2/manifest-gen
// produces both this table and the one the Rust VM uses, and both VMs rebuild
// the same manifest byte stream and compare its digest, so a constant that
// differs between them cannot pass unnoticed.

#include <array>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "openssl/digest.hpp"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cp0.h"
#include "vm/opctable.h"
#include "vm/poseidon2-kat.h"
#include "vm/poseidon2-params.h"
#include "vm/poseidon2ops.h"
#include "vm/pqops.h"
#include "vm/stack.hpp"
#include "vm/vm.h"

namespace {

int failures = 0;

void require(bool ok, const std::string& why) {
  if (!ok) {
    std::cerr << "FAIL  " << why << '\n';
    ++failures;
  }
}

std::string hex(const unsigned char* bytes, std::size_t len) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < len; ++i) {
    out << std::setw(2) << static_cast<unsigned>(bytes[i]);
  }
  return out.str();
}

using State = unsigned char[8][32];

td::RefInt256 int_of(const unsigned char bytes[32]) {
  td::RefInt256 value{true};
  if (!value.write().import_bytes(bytes, 32, false)) {
    throw std::runtime_error("cannot import a 256-bit test value");
  }
  return value;
}

td::Ref<vm::Cell> opcode_cell(unsigned opcode) {
  return vm::CellBuilder().store_long(opcode, 24).finalize();
}

struct Run {
  int exit;
  long long gas;
  std::vector<std::string> stack;  // top last
};

// Runs one instruction over a prepared stack. Anything already on the stack is
// free, so the gas reported is the instruction's own price plus the fixed
// overhead of running a one-instruction continuation.
Run run(unsigned opcode, const std::vector<td::RefInt256>& inputs, int version = 17, long long budget = 1000000,
        td::Ref<vm::Cell> extra = {}) {
  td::Ref<vm::Stack> stack{true};
  for (const auto& value : inputs) {
    stack.write().push_int(value);
  }
  if (extra.not_null()) {
    stack.write().push_cell(extra);
  }
  vm::VmState state{vm::load_cell_slice_ref(opcode_cell(opcode)), version, std::move(stack),
                    vm::GasLimits{budget, budget}};
  const int exit = ~state.run();
  Run result{exit, state.gas_consumed(), {}};
  if (exit == 0) {
    auto& final_stack = state.get_stack();
    std::vector<std::string> reversed;
    while (final_stack.depth() > 0) {
      unsigned char bytes[32];
      auto value = final_stack.pop_int_finite();
      if (!value->export_bytes(bytes, 32, false)) {
        throw std::runtime_error("a result does not fit in 256 unsigned bits");
      }
      reversed.push_back(hex(bytes, 32));
    }
    result.stack.assign(reversed.rbegin(), reversed.rend());
  }
  return result;
}

std::vector<td::RefInt256> state_inputs(const unsigned char state[8][32]) {
  std::vector<td::RefInt256> inputs;
  for (int i = 0; i < 8; ++i) {
    inputs.push_back(int_of(state[i]));
  }
  return inputs;
}

// ---------------------------------------------------------------------------

void check_manifest() {
  namespace p2 = vm::poseidon2;
  const auto bytes = p2::manifest_bytes();
  const std::size_t expected =
      sizeof(p2::manifest_tag) + 32 + 4 +
      32 * (p2::state_width + p2::state_width * p2::state_width + p2::rounds_total * p2::state_width);
  require(bytes.size() == expected,
          "manifest is " + std::to_string(bytes.size()) + " bytes, expected " + std::to_string(expected));
  unsigned char digest[32];
  digest::hash_str<digest::SHA256>(digest, bytes.data(), bytes.size());
  require(std::memcmp(digest, p2::manifest_sha256, 32) == 0,
          "manifest digest " + hex(digest, 32) + " does not match the pinned " + hex(p2::manifest_sha256, 32));
  // Shape, independently of content: a table of the wrong size would still hash.
  require(p2::rounds_total == p2::rounds_f + p2::rounds_p, "round counts do not add up");
  require(p2::rounds_f == 8 && p2::rounds_p == 57, "round counts are not the frozen 8/57");
  require(p2::state_width == 8 && p2::sbox_alpha == 5, "width or S-box degree is not the frozen one");
}

// Nothing below is believed until these pass: they catch a permutation that is
// the identity, one that ignores its input, and a vector table that is degenerate.
void check_instrument() {
  namespace kat = vm::poseidon2::kat;
  State state;
  std::memcpy(state, kat::perm8[0].input, sizeof(state));
  State once;
  std::memcpy(once, state, sizeof(state));
  vm::poseidon2::permute(once);
  require(std::memcmp(once, state, sizeof(state)) != 0, "the permutation returned its input");

  State twice;
  std::memcpy(twice, state, sizeof(state));
  vm::poseidon2::permute(twice);
  require(std::memcmp(once, twice, sizeof(state)) == 0, "the permutation is not deterministic");

  State nudged;
  std::memcpy(nudged, state, sizeof(state));
  nudged[7][31] ^= 1;
  vm::poseidon2::permute(nudged);
  require(std::memcmp(once, nudged, sizeof(state)) != 0, "the last input lane does not reach the output");

  std::memcpy(nudged, state, sizeof(state));
  nudged[0][31] ^= 1;
  vm::poseidon2::permute(nudged);
  require(std::memcmp(once, nudged, sizeof(state)) != 0, "the first input lane does not reach the output");

  for (const auto& vector : kat::perm8) {
    for (int lane = 0; lane < 8; ++lane) {
      require(std::memcmp(vector.output[lane], vm::poseidon2::modulus_be, 32) < 0,
              std::string(vector.name) + ": a frozen output is not below the modulus");
    }
  }
  require(std::memcmp(kat::perm8[0].output, kat::perm8[1].output, sizeof(State)) != 0,
          "two different vectors carry the same frozen output");
}

void check_vectors() {
  namespace kat = vm::poseidon2::kat;
  for (const auto& vector : kat::perm8) {
    State state;
    std::memcpy(state, vector.input, sizeof(state));
    vm::poseidon2::permute(state);
    require(std::memcmp(state, vector.output, sizeof(state)) == 0,
            std::string(vector.name) + ": permutation does not match the pinned reference");

    const auto executed = run(vm::poseidon2_perm8_opcode, state_inputs(vector.input));
    require(executed.exit == 0, std::string(vector.name) + ": PERM8 exited " + std::to_string(executed.exit));
    if (executed.exit == 0) {
      require(executed.stack.size() == 8, std::string(vector.name) + ": PERM8 left a wrong stack depth");
      for (int lane = 0; lane < 8 && lane < static_cast<int>(executed.stack.size()); ++lane) {
        require(executed.stack[lane] == hex(vector.output[lane], 32),
                std::string(vector.name) + ": PERM8 lane " + std::to_string(lane) + " differs in the VM");
      }
    }
  }

  for (const auto& vector : kat::hash7) {
    State state;
    std::memcpy(state, vector.state, sizeof(state));
    vm::poseidon2::permute(state);
    require(std::memcmp(state[0], vector.output, 32) == 0,
            std::string(vector.name) + ": HASH7 reference value differs");

    const auto executed = run(vm::poseidon2_hash7_opcode, state_inputs(vector.state));
    require(executed.exit == 0, std::string(vector.name) + ": HASH7 exited " + std::to_string(executed.exit));
    if (executed.exit == 0) {
      require(executed.stack.size() == 1, std::string(vector.name) + ": HASH7 must leave exactly one value");
      if (!executed.stack.empty()) {
        require(executed.stack[0] == hex(vector.output, 32),
                std::string(vector.name) + ": HASH7 result differs in the VM");
      }
    }
  }

  // HASH7 is lane 0 of the same permutation, and must not be any other lane.
  State state;
  std::memcpy(state, kat::perm8[0].input, sizeof(state));
  const auto permuted = run(vm::poseidon2_perm8_opcode, state_inputs(state));
  const auto hashed = run(vm::poseidon2_hash7_opcode, state_inputs(state));
  require(permuted.exit == 0 && hashed.exit == 0, "the two instructions disagree on a valid state");
  if (permuted.exit == 0 && hashed.exit == 0) {
    require(hashed.stack.at(0) == permuted.stack.at(0), "HASH7 is not lane 0 of PERM8");
    for (int lane = 1; lane < 8; ++lane) {
      require(hashed.stack.at(0) != permuted.stack.at(lane),
              "HASH7 result coincides with lane " + std::to_string(lane));
    }
  }

  // The domain table has its own manifest, rebuilt here the way the generator
  // wrote it. Nothing on chain commits to this digest; it exists so the table
  // cannot drift between the three places it is written.
  {
    std::string stream;
    const char tag[] = "TOS-SHIELDED-DOMAINS-v1";
    stream.append(tag, sizeof(tag));  // the trailing NUL is part of the stream
    stream.push_back(static_cast<char>(std::size(kat::domains)));
    for (const auto& domain : kat::domains) {
      const std::size_t length = std::char_traits<char>::length(domain.label);
      stream.push_back(static_cast<char>(length));
      stream.append(domain.label, length);
      stream.append(reinterpret_cast<const char*>(domain.value), 32);
    }
    unsigned char digest[32];
    digest::hash_str<digest::SHA256>(digest, stream.data(), stream.size());
    require(std::memcmp(digest, kat::domain_manifest_sha256, 32) == 0, "domain manifest digest " + hex(digest, 32) +
                                                                           " does not match the generated " +
                                                                           hex(kat::domain_manifest_sha256, 32));
  }

  for (const auto& domain : kat::domains) {
    bool nonzero = false;
    for (unsigned char byte : domain.value) {
      nonzero = nonzero || byte != 0;
    }
    require(nonzero, std::string(domain.label) + ": domain constant is zero");
    require(std::memcmp(domain.value, vm::poseidon2::modulus_be, 32) < 0,
            std::string(domain.label) + ": domain constant is not below the modulus");
  }
}

void check_version_gate() {
  namespace kat = vm::poseidon2::kat;
  const auto inputs = state_inputs(kat::perm8[0].input);
  for (int version = 0; version <= 16; ++version) {
    for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
      const auto result = run(opcode, inputs, version);
      require(result.exit == 6, "opcode " + hex(reinterpret_cast<const unsigned char*>(&opcode), 3) +
                                    " was accepted at version " + std::to_string(version));
    }
  }
  for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
    require(run(opcode, inputs, 17).exit == 0, "an opcode was refused at version 17");
  }
  // The earlier instruction must not have been dragged forward with it. At 16 it
  // is reachable, so it fails on its own arguments rather than on the version.
  const auto mldsa = run(vm::pq_mldsa44_opcode, {}, 16);
  require(mldsa.exit == 2, "ML-DSA no longer runs at version 16 (exit " + std::to_string(mldsa.exit) + ")");
}

void check_fail_closed() {
  namespace kat = vm::poseidon2::kat;
  namespace p2 = vm::poseidon2;

  auto with_lane = [&](int lane, td::RefInt256 value) {
    auto inputs = state_inputs(kat::perm8[0].input);
    inputs[lane] = std::move(value);
    return inputs;
  };

  unsigned char modulus_minus_one[32];
  std::memcpy(modulus_minus_one, p2::modulus_be, 32);
  modulus_minus_one[31] -= 1;  // the modulus ends in 0x01, so this cannot borrow
  unsigned char all_ones[32];
  std::memset(all_ones, 0xff, 32);

  for (int lane = 0; lane < 8; ++lane) {
    for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
      require(run(opcode, with_lane(lane, int_of(p2::modulus_be))).exit == 5,
              "the modulus itself was accepted in lane " + std::to_string(lane));
      require(run(opcode, with_lane(lane, int_of(all_ones))).exit == 5,
              "2^256-1 was accepted in lane " + std::to_string(lane));
      require(run(opcode, with_lane(lane, -int_of(all_ones))).exit == 5,
              "a negative input was accepted in lane " + std::to_string(lane));
      require(run(opcode, with_lane(lane, td::make_refint(-1))).exit == 5,
              "minus one was accepted in lane " + std::to_string(lane));
      // The boundary below it must still be a legal field element.
      require(run(opcode, with_lane(lane, int_of(modulus_minus_one))).exit == 0,
              "the largest field element was refused in lane " + std::to_string(lane));
    }
  }

  // Nothing is reduced: r and 0 are different inputs and must not agree.
  const auto zero_lane = run(vm::poseidon2_perm8_opcode, with_lane(3, td::make_refint(0)));
  require(zero_lane.exit == 0, "a zero lane was refused");

  for (int depth = 0; depth < 8; ++depth) {
    auto inputs = state_inputs(kat::perm8[0].input);
    inputs.resize(depth);
    for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
      require(run(opcode, inputs).exit == 2, "a stack of " + std::to_string(depth) + " was not an underflow");
    }
  }

  // A non-integer operand is a type error, not a silent conversion.
  auto short_inputs = state_inputs(kat::perm8[0].input);
  short_inputs.pop_back();
  for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
    require(run(opcode, short_inputs, 17, 1000000, vm::CellBuilder().finalize()).exit == 7,
            "a cell operand was not a type error");
  }
}

void check_gas() {
  namespace kat = vm::poseidon2::kat;
  // Specification literals, not implementation constants: the development
  // tariff, the cost of a 24-bit instruction, and the implicit return.
  const long long expected = 3500 + 34 + 5;
  const auto inputs = state_inputs(kat::perm8[0].input);
  for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
    const auto baseline = run(opcode, inputs);
    require(baseline.exit == 0, "gas baseline did not run");
    require(baseline.gas == expected,
            "gas is " + std::to_string(baseline.gas) + ", expected " + std::to_string(expected));
    const auto exact = run(opcode, inputs, 17, baseline.gas);
    require(exact.exit == 0, "the exact budget was not enough");
    const auto starved = run(opcode, inputs, 17, baseline.gas - 1);
    require(starved.exit == -14, "one gas short did not run out of gas");
    // A refused input is still charged: probing must not be free.
    auto bad = inputs;
    bad[0] = int_of(vm::poseidon2::modulus_be);
    const auto refused = run(opcode, bad);
    require(refused.exit == 5, "the refusal changed");
    require(refused.gas >= 3500, "a refused input was charged less than the tariff");
  }
}

void check_opcode_registration() {
  const auto* table = vm::init_op_cp0();
  require(table != nullptr, "the opcode table did not build");
  for (auto [opcode, name] : {std::pair<unsigned, const char*>{vm::poseidon2_perm8_opcode, "POSEIDON2_PERM8"},
                              {vm::poseidon2_hash7_opcode, "POSEIDON2_HASH7"}}) {
    auto slice = vm::load_cell_slice(opcode_cell(opcode));
    const auto dumped = table->dump_instr(slice);
    require(dumped == name, std::string("opcode is registered as '") + dumped + "', expected " + name);
  }

  // Occupancy, asserted rather than assumed: a second instruction at either
  // code must be refused by the table.
  vm::OpcodeTable fresh{"collision probe", vm::Codepage::test_cp};
  vm::register_poseidon2_ops(fresh);
  for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
    const bool inserted =
        fresh.insert_bool(vm::OpcodeInstr::mksimple(opcode, 24, "COLLIDE", [](vm::VmState*) { return 0; }));
    require(!inserted, "a second instruction was accepted at an occupied opcode");
  }
}

}  // namespace

int main() {
  const std::pair<const char*, void (*)()> stages[] = {
      {"manifest", check_manifest},
      {"instrument", check_instrument},
      {"vectors", check_vectors},
      {"version gate", check_version_gate},
      {"fail closed", check_fail_closed},
      {"gas", check_gas},
      {"opcode registration", check_opcode_registration},
  };
  // The VM narrates every instruction at info level; only failures matter here.
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  // The dispatch table registers itself only when it is first built.
  vm::init_op_cp0();
  try {
    for (const auto& [name, stage] : stages) {
      std::cout << "-- " << name << std::endl;
      stage();
    }
  } catch (const std::exception& e) {
    std::cerr << "FAIL  unexpected exception: " << e.what() << '\n';
    ++failures;
  }
  if (failures != 0) {
    std::cerr << failures << " check(s) failed\n";
    return 1;
  }
  std::cout << "poseidon2: all checks passed\n";
  return 0;
}
