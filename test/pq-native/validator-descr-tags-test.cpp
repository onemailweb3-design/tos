/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#ifdef NDEBUG
#undef NDEBUG  // test assertions must stay live even in Release (-DNDEBUG)
#endif
#include <cassert>
#include <cstdio>
#include <fstream>
#include <set>
#include <string>

#include "block/block-auto.h"
#include "td/utils/misc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

// The accepted ValidatorDescr constructor set is shared with the Rust reader
// through test/pq-native/validator-descr-tags.tsv. One implementation accepting
// a tag the other rejects is a consensus split, so both read the same file.
//
// The C++ side of that set is generated from block.tlb, so adding a constructor
// to the schema without updating the shared file fails here.
int main() {
  std::set<unsigned> shared_accept, shared_reject;
  {
    std::ifstream f(DESCR_TAGS_FILE);
    assert(f);
    std::string line;
    while (std::getline(f, line)) {
      if (line.empty() || line[0] == '#') continue;
      auto tab = line.find('\t');
      assert(tab != std::string::npos);
      const unsigned tag = std::stoul(line.substr(0, tab), nullptr, 16);
      const auto verdict = line.substr(tab + 1, line.find('\t', tab + 1) - tab - 1);
      if (verdict == "accept") {
        shared_accept.insert(tag);
      } else {
        assert(verdict == "reject");
        shared_reject.insert(tag);
      }
    }
  }
  assert(shared_accept.size() + shared_reject.size() >= 6);

  // 1. The schema's own constructor tags must be exactly the shared accept set.
  std::set<unsigned> schema_tags;
  for (auto t : block::gen::ValidatorDescr::cons_tag) {
    schema_tags.insert(t);
  }
  assert(schema_tags == shared_accept);

  // 2. Behavioural check: a descriptor that is well formed apart from its tag is
  //    accepted or refused purely on the tag, so no case can pass for a bad reason.
  auto descriptor = [](unsigned tag, bool with_adnl) {
    vm::CellBuilder cb;
    cb.store_long(tag, 8);
    cb.store_long(0x8e81278a, 32);              // ed25519_pubkey#8e81278a
    cb.store_bytes(std::string(32, '\x07'));    // pubkey:bits256
    cb.store_long(1234, 64);                    // weight:uint64
    if (with_adnl) {
      cb.store_bytes(std::string(32, '\x09'));  // adnl_addr:bits256
    }
    return cb.finalize();
  };
  for (unsigned tag = 0; tag <= 0xff; tag++) {
    const bool expect = shared_accept.count(tag) != 0;
    // 0x53 carries no adnl_addr; every other shape gets the longer 0x73 body.
    auto cell = descriptor(tag, tag != 0x53);
    vm::CellSlice cs(vm::NoVm(), cell);
    const bool got = block::gen::t_ValidatorDescr.validate_skip(nullptr, cs, false) && cs.empty_ext();
    assert(got == expect);
    if (shared_reject.count(tag)) {
      assert(!got);  // every tag the shared file names as refused really is
    }
  }

  printf("VALIDATOR_DESCR_TAGS_OK schema==shared accept={0x53,0x73} rejected 0x93/0xb3 and all others\n");
  return 0;
}
