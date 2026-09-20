/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstring>

#include "vm/excno.hpp"
#include "vm/log.h"
#include "vm/opctable.h"
#include "vm/stack.hpp"
#include "vm/vm.h"

#include "blst.h"
#include "poseidon2-params.h"
#include "poseidon2ops.h"

namespace vm {
namespace poseidon2 {
namespace {

using Fr = blst_fr;

Fr fr_from_be(const unsigned char be[32]) {
  blst_scalar scalar;
  blst_scalar_from_bendian(&scalar, be);
  Fr value;
  blst_fr_from_scalar(&value, &scalar);
  return value;
}

void fr_to_be(unsigned char out[32], const Fr& value) {
  blst_scalar scalar;
  blst_scalar_from_fr(&scalar, &value);
  blst_bendian_from_scalar(out, &scalar);
}

// The constants are stored canonically and converted once. Doing it per call
// would be the same arithmetic repeated, not a different result.
struct Tables {
  Fr diag[state_width];
  Fr rc[rounds_total][state_width];
};

const Tables& tables() {
  static const Tables loaded = [] {
    Tables t{};
    for (int i = 0; i < state_width; ++i) {
      t.diag[i] = fr_from_be(mat_diag8_be[i]);
    }
    for (int r = 0; r < rounds_total; ++r) {
      for (int i = 0; i < state_width; ++i) {
        t.rc[r][i] = fr_from_be(rc8_be[r][i]);
      }
    }
    return t;
  }();
  return loaded;
}

void sbox(Fr& x) {  // x^alpha, alpha = 5
  static_assert(sbox_alpha == 5, "the S-box below is written for alpha = 5");
  Fr squared, quartic, result;
  blst_fr_sqr(&squared, &x);
  blst_fr_sqr(&quartic, &squared);
  blst_fr_mul(&result, &quartic, &x);
  x = result;
}

void doubled(Fr& out, const Fr& x) {
  blst_fr_add(&out, &x, &x);
}

// The cheap 4x4 MDS block, applied to each quarter of the state.
void matmul_m4(Fr* x) {
  Fr t0, t1, t2, t3, t4, t5, t6, t7;
  blst_fr_add(&t0, &x[0], &x[1]);
  blst_fr_add(&t1, &x[2], &x[3]);
  doubled(t2, x[1]);
  blst_fr_add(&t2, &t2, &t1);
  doubled(t3, x[3]);
  blst_fr_add(&t3, &t3, &t0);
  doubled(t4, t1);
  doubled(t4, t4);
  blst_fr_add(&t4, &t4, &t3);
  doubled(t5, t0);
  doubled(t5, t5);
  blst_fr_add(&t5, &t5, &t2);
  blst_fr_add(&t6, &t3, &t5);
  blst_fr_add(&t7, &t2, &t4);
  x[0] = t6;
  x[1] = t5;
  x[2] = t7;
  x[3] = t4;
}

void matmul_external(Fr* s) {
  matmul_m4(s);
  matmul_m4(s + 4);
  Fr stored[4];
  for (int l = 0; l < 4; ++l) {
    blst_fr_add(&stored[l], &s[l], &s[4 + l]);
  }
  for (int i = 0; i < state_width; ++i) {
    blst_fr_add(&s[i], &s[i], &stored[i % 4]);
  }
}

void matmul_internal(Fr* s) {
  const Tables& t = tables();
  Fr sum = s[0];
  for (int i = 1; i < state_width; ++i) {
    blst_fr_add(&sum, &sum, &s[i]);
  }
  for (int i = 0; i < state_width; ++i) {
    Fr scaled;
    blst_fr_mul(&scaled, &s[i], &t.diag[i]);
    blst_fr_add(&s[i], &scaled, &sum);
  }
}

}  // namespace

void permute(unsigned char state[8][32]) {
  const Tables& t = tables();
  Fr s[state_width];
  for (int i = 0; i < state_width; ++i) {
    s[i] = fr_from_be(state[i]);
  }

  matmul_external(s);
  const int partial_end = rounds_f_beginning + rounds_p;
  for (int r = 0; r < rounds_f_beginning; ++r) {
    for (int i = 0; i < state_width; ++i) {
      blst_fr_add(&s[i], &s[i], &t.rc[r][i]);
      sbox(s[i]);
    }
    matmul_external(s);
  }
  for (int r = rounds_f_beginning; r < partial_end; ++r) {
    blst_fr_add(&s[0], &s[0], &t.rc[r][0]);
    sbox(s[0]);
    matmul_internal(s);
  }
  for (int r = partial_end; r < rounds_total; ++r) {
    for (int i = 0; i < state_width; ++i) {
      blst_fr_add(&s[i], &s[i], &t.rc[r][i]);
      sbox(s[i]);
    }
    matmul_external(s);
  }

  for (int i = 0; i < state_width; ++i) {
    fr_to_be(state[i], s[i]);
  }
}

std::string manifest_bytes() {
  std::string out;
  // sizeof() carries the literal's trailing NUL, which the stream includes.
  out.append(manifest_tag, sizeof(manifest_tag));
  out.append(reinterpret_cast<const char*>(modulus_be), 32);
  out.push_back(static_cast<char>(state_width));
  out.push_back(static_cast<char>(sbox_alpha));
  out.push_back(static_cast<char>(rounds_f));
  out.push_back(static_cast<char>(rounds_p));
  for (int i = 0; i < state_width; ++i) {
    out.append(reinterpret_cast<const char*>(mat_diag8_be[i]), 32);
  }
  for (int row = 0; row < state_width; ++row) {
    for (int col = 0; col < state_width; ++col) {
      out.append(reinterpret_cast<const char*>(mat_internal8_be[row][col]), 32);
    }
  }
  for (int r = 0; r < rounds_total; ++r) {
    for (int i = 0; i < state_width; ++i) {
      out.append(reinterpret_cast<const char*>(rc8_be[r][i]), 32);
    }
  }
  return out;
}

}  // namespace poseidon2

namespace {

// Fail closed: anything that is not already a canonical field element is
// refused. Nothing is reduced, because a silent reduction would let two
// different stack values hash the same.
void pop_field_element(Stack& stack, unsigned char out[32]) {
  auto value = stack.pop_int_finite();
  if (value->sgn() < 0) {
    throw VmError{Excno::range_chk, "Poseidon2 input is negative"};
  }
  if (!value->export_bytes(out, 32, false)) {
    throw VmError{Excno::range_chk, "Poseidon2 input does not fit in 256 bits"};
  }
  if (std::memcmp(out, poseidon2::modulus_be, 32) >= 0) {
    throw VmError{Excno::range_chk, "Poseidon2 input is not below the field modulus"};
  }
}

void push_field_element(Stack& stack, const unsigned char value[32]) {
  td::RefInt256 result{true};
  if (!result.write().import_bytes(value, 32, false)) {
    throw VmError{Excno::fatal, "cannot represent a Poseidon2 output"};
  }
  stack.push_int(std::move(result));
}

// Both instructions consume a full state; they differ only in what they return.
void pop_state(Stack& stack, unsigned char state[8][32]) {
  for (int i = poseidon2::state_width - 1; i >= 0; --i) {
    pop_field_element(stack, state[i]);
  }
}

int exec_poseidon2_perm8(VmState* st) {
  VM_LOG(st) << "execute POSEIDON2_PERM8";
  auto& stack = st->get_stack();
  stack.check_underflow(poseidon2::state_width);
  st->consume_gas_chk(poseidon2_perm8_gas_price);
  unsigned char state[8][32];
  pop_state(stack, state);
  poseidon2::permute(state);
  for (int i = 0; i < poseidon2::state_width; ++i) {
    push_field_element(stack, state[i]);
  }
  return 0;
}

int exec_poseidon2_hash7(VmState* st) {
  VM_LOG(st) << "execute POSEIDON2_HASH7";
  auto& stack = st->get_stack();
  stack.check_underflow(poseidon2::state_width);
  st->consume_gas_chk(poseidon2_hash7_gas_price);
  // The domain constant sits in lane 0 and the result is lane 0: no capacity
  // element and no padding rule beyond that.
  unsigned char state[8][32];
  pop_state(stack, state);
  poseidon2::permute(state);
  push_field_element(stack, state[0]);
  return 0;
}

}  // namespace

void register_poseidon2_ops(OpcodeTable& table) {
  table.insert(OpcodeInstr::mksimple(poseidon2_perm8_opcode, 24, "POSEIDON2_PERM8", exec_poseidon2_perm8)
                   ->require_version(poseidon2_min_version));
  table.insert(OpcodeInstr::mksimple(poseidon2_hash7_opcode, 24, "POSEIDON2_HASH7", exec_poseidon2_hash7)
                   ->require_version(poseidon2_min_version));
}

}  // namespace vm
