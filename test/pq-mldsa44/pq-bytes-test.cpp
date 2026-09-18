/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cassert>
#include <cstdio>
#include <string>

#include "crypto/pq/pq-bytes.h"
#include "vm/cells/CellBuilder.h"

using namespace tos::pq;

static std::string roundtrip(const std::string& s, std::size_t max) {
  auto packed = pack_pq_bytes(td::Slice(s), max);
  assert(packed.is_ok());
  auto un = unpack_pq_bytes(packed.move_as_ok(), max);
  assert(un.is_ok());
  return un.move_as_ok().as_slice().str();
}

int main() {
  // round-trip across chunk boundaries + the real ML-DSA-44 sizes
  for (std::size_t n : {std::size_t(0), std::size_t(1), std::size_t(126), std::size_t(127),
                        std::size_t(128), std::size_t(254), std::size_t(1312), std::size_t(2420)}) {
    std::string s(n, '\0');
    for (std::size_t i = 0; i < n; i++) s[i] = char((i * 131 + 7) & 0xff);
    assert(roundtrip(s, 2420) == s);
  }
  // oversize refused on pack and on unpack
  assert(pack_pq_bytes(td::Slice(std::string(2421, 'x')), 2420).is_error());
  {
    auto p = pack_pq_bytes(td::Slice(std::string(2420, 'x')), 2420).move_as_ok();
    assert(unpack_pq_bytes(p, 1312).is_error());
  }
  // canonical negative: a non-last chunk holding 100 bytes instead of a full 127
  {
    std::string s(254, 'a');
    auto c3 = [&] { vm::CellBuilder cb; cb.store_bytes_bool(td::Slice(s).substr(227, 27)); return cb.finalize(); }();
    auto c2 = [&] { vm::CellBuilder cb; cb.store_bytes_bool(td::Slice(s).substr(100, 127)); cb.store_ref(c3); return cb.finalize(); }();
    auto c1 = [&] { vm::CellBuilder cb; cb.store_bytes_bool(td::Slice(s).substr(0, 100)); cb.store_ref(c2); return cb.finalize(); }();
    vm::CellBuilder root; root.store_long(254, 32); root.store_ref(c1);
    assert(unpack_pq_bytes(root.finalize(), 2420).is_error());
  }
  // canonical negative: length says 200 but the snake is shorter
  {
    auto data = [&] { vm::CellBuilder cb; cb.store_bytes_bool(td::Slice(std::string(50, 'q'))); return cb.finalize(); }();
    vm::CellBuilder root; root.store_long(200, 32); root.store_ref(data);
    assert(unpack_pq_bytes(root.finalize(), 2420).is_error());
  }
  printf("PQ_BYTES_N1_OK roundtrips+oversize+canonical-negatives\n");
  return 0;
}
