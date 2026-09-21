/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "test/pq-native/pq-block-signature-test-common.h"

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "validator/db/rootdb.hpp"
#include "validator/fabric.h"
#include "validator/impl/accept-block.hpp"
#include "validator/impl/check-proof.hpp"
#include "validator/impl/top-shard-descr.hpp"
#include "validator/interfaces/db.h"
#include "validator/pq-finality-verification.h"
#include "validator/validator.h"

#include "crypto/pq/pq-bytes.h"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/filesystem.h"
#include "vm/cells/CellString.h"

#include <array>
#include <mutex>
#include <optional>

namespace {

using namespace pq_block_signature_test;
using namespace tos;
using namespace tos::validator;

td::Ref<ValidatorManagerOptions> make_options() {
  auto opts = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{}, false, 0.0, 0.0, 0.0, 0.0, 0.0, 0, true);
  auto& writable = opts.write();
  writable.set_disable_rocksdb_stats(true);
  writable.set_celldb_compress_depth(0);
  writable.set_celldb_in_memory(false);
  writable.set_celldb_v2(false);
  writable.set_celldb_disable_bloom_filter(true);
  writable.set_permanent_celldb(false);
  writable.set_catchain_broadcast_speed_multiplier(1.0);
  return opts;
}

class RootDbRoundTrip {
 public:
  explicit RootDbRoundTrip(std::string root) : root_(std::move(root)), scheduler_({1}) {
    td::rmrf(root_).ignore();
    td::mkpath(root_ + "/").ensure();
    scheduler_.run_in_context([&] {
      db_ = td::actor::create_actor<RootDb>("pq-signature-rootdb", td::actor::ActorId<ValidatorManager>{}, root_,
                                            make_options());
    });
  }

  ~RootDbRoundTrip() {
    scheduler_.run_in_context([&] {
      db_.reset();
      td::actor::SchedulerContext::get().stop();
    });
    while (scheduler_.run(1)) {
    }
    td::rmrf(root_).ignore();
  }

  void store(BlockHandle handle, td::Ref<block::BlockSignatureSet> signatures,
             td::Ref<block::ValidatorSet> validator_set) {
    ask<td::Unit>([&](td::Promise<td::Unit> promise) {
      td::actor::send_closure(db_.get(), &Db::store_block_signatures, handle, std::move(signatures),
                              std::move(validator_set), std::move(promise));
    });
  }

  td::Ref<block::BlockSignatureSet> load(ConstBlockHandle handle) {
    return ask<td::Ref<block::BlockSignatureSet>>([&](auto promise) {
      td::actor::send_closure(db_.get(), &Db::get_block_signatures, handle, std::move(promise));
    });
  }

 private:
  template <class T, class Send>
  T ask(Send send) {
    std::mutex mutex;
    std::optional<td::Result<T>> result;
    scheduler_.run_in_context([&] {
      send(td::PromiseCreator::lambda([&](td::Result<T> value) {
        std::lock_guard guard(mutex);
        result.emplace(std::move(value));
      }));
    });
    const auto deadline = td::Timestamp::in(60.0);
    while (true) {
      {
        std::lock_guard guard(mutex);
        if (result.has_value()) {
          if (result->is_error()) {
            fail("PQ_SIGNATURE_PERSISTENCE_DB_ERROR: " + result->error().message().str());
          }
          return result->move_as_ok();
        }
      }
      if (deadline.is_in_past()) {
        fail("PQ_SIGNATURE_PERSISTENCE_DB_TIMEOUT");
      }
      if (!scheduler_.run(0.05)) {
        fail("PQ_SIGNATURE_PERSISTENCE_SCHEDULER_STOPPED");
      }
    }
  }

  std::string root_;
  td::actor::Scheduler scheduler_;
  td::actor::ActorOwn<Db> db_;
};

struct LargeFixture {
  std::vector<pq::ValidatorPQKeyStore> stores;
  std::vector<ValidatorId> validator_ids;
  td::Ref<block::ValidatorSet> validator_set;
  BlockIdExt id;
  ValidatorSessionId session;
  td::uint32 slot;

  LargeFixture(std::size_t count, td::uint32 discriminator)
      : id(block_id("pq-persistence-" + std::to_string(count))),
        session(hash_of("pq-persistence-session-" + std::to_string(count))),
        slot(3000 + discriminator) {
    std::vector<ValidatorDescr> descriptors;
    descriptors.reserve(count);
    stores.reserve(count);
    validator_ids.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      std::array<char, 32> seed{};
      for (std::size_t j = 0; j < seed.size(); ++j) {
        seed[j] = static_cast<char>((i * 131 + j * 17 + discriminator) & 0xff);
      }
      auto store = pq::ValidatorPQKeyStore::from_seed(std::string_view(seed.data(), seed.size()));
      if (!store.has_value()) {
        fail("PQ_SIGNATURE_PERSISTENCE_KEY_DERIVATION_FAILED");
      }
      auto validator_id = ValidatorId{hash_of("pq-persistence-validator-" + std::to_string(discriminator) + "-" +
                                                    std::to_string(i))};
      const auto& key = store->consensus_key();
      descriptors.emplace_back(validator_id, static_cast<td::uint16>(key.algorithm_id), key_id_of(key),
                               key.public_key, 1, hash_of("pq-persistence-adnl-" + std::to_string(i)));
      validator_ids.push_back(validator_id);
      stores.push_back(std::move(*store));
    }
    validator_set = td::Ref<block::ValidatorSet>{true, 7000 + discriminator, ShardIdFull{masterchainId},
                                                 std::move(descriptors)};
  }

  td::Ref<block::BlockSignatureSet> signatures() {
    auto candidate_data = candidate(id, "pq-persistence-parent");
    auto message = require_ok(
        block::BlockSignatureSet::build_simplex_data_to_sign(session, slot, candidate_data, true, id), "preimage");
    std::vector<block::PQBlockSignature> pairs;
    pairs.reserve(stores.size());
    for (std::size_t i = 0; i < stores.size(); ++i) {
      auto signed_vote = stores[i].sign_consensus(view(message.as_slice()));
      if (!signed_vote.has_value()) {
        fail("PQ_SIGNATURE_PERSISTENCE_SIGN_FAILED");
      }
      pairs.push_back({validator_ids[i], signed_vote->algorithm_id, td::BufferSlice(signed_vote->signature)});
    }
    return require_ok(block::BlockSignatureSet::create_simplex_pq_final(
                          std::move(pairs), validator_set->get_catchain_seqno(),
                          validator_set->get_validator_set_hash(), session, slot, std::move(candidate_data)),
                      "carrier");
  }
};

struct RawPair {
  ValidatorId validator_id;
  td::uint16 algorithm_id;
  td::Ref<vm::Cell> signature;
};

td::Ref<vm::Cell> candidate_cell(const tos::tl_object_ptr<tos_api::consensus_CandidateHashData>& candidate_data) {
  auto bytes = serialize_tl_object(candidate_data, true);
  return require_ok(vm::CellString::create(bytes.as_slice()), "candidate-cell");
}

td::Ref<vm::Cell> raw_signature_set(const std::vector<RawPair>& pairs, td::uint32 validator_hash,
                                    CatchainSeqno catchain_seqno, ValidatorWeight weight,
                                    ValidatorSessionId session, td::uint32 slot, td::Ref<vm::Cell> candidate_data,
                                    unsigned tag = 0x13) {
  vm::Dictionary dict{16};
  for (std::size_t i = 0; i < pairs.size(); ++i) {
    vm::CellBuilder value;
    if (!(value.store_bits_bool(pairs[i].validator_id.value.cbits(), 256) &&
          value.store_long_bool(pairs[i].algorithm_id, 16) && value.store_ref_bool(pairs[i].signature) &&
          dict.set_builder(td::BitArray<16>{static_cast<unsigned>(i)}, value, vm::Dictionary::SetMode::Add))) {
      fail("PQ_SIGNATURE_PERSISTENCE_RAW_DICTIONARY_FAILED");
    }
  }
  vm::CellBuilder root;
  if (!(root.store_long_bool(tag, 8) && root.store_long_bool(validator_hash, 32) &&
        root.store_long_bool(catchain_seqno, 32) && root.store_long_bool(pairs.size(), 32) &&
        root.store_long_bool(weight, 64) && root.store_maybe_ref(std::move(dict).extract_root_cell()) &&
        root.store_bits_bool(session.cbits(), 256) && root.store_long_bool(slot, 32) &&
        root.store_ref_bool(std::move(candidate_data)))) {
    fail("PQ_SIGNATURE_PERSISTENCE_RAW_ROOT_FAILED");
  }
  return root.finalize_novm();
}

std::vector<RawPair> raw_pairs(const std::vector<block::PQBlockSignature>& pairs) {
  std::vector<RawPair> result;
  result.reserve(pairs.size());
  for (const auto& pair : pairs) {
    auto packed = require_ok(pq::pack_pq_bytes(pair.signature.as_slice(), pq::pq_bytes_hard_max), "pack-signature");
    result.push_back({pair.validator_id, static_cast<td::uint16>(pair.algorithm_id), std::move(packed)});
  }
  return result;
}

void expect_parse_error(td::Ref<vm::Cell> cell, td::Ref<block::ValidatorSet> validator_set,
                        std::string_view expected, std::string_view name) {
  expect_error(block::BlockSignatureSet::fetch(std::move(cell), std::move(validator_set)), expected, name);
  std::fprintf(stderr, "PQ_SIGNATURE_CORRUPTION_OK case=%.*s reason=%.*s\n", static_cast<int>(name.size()),
               name.data(), static_cast<int>(expected.size()), expected.data());
}

void expect_verify_error(td::Ref<vm::Cell> cell, const block::PQFinalityVerificationContext& context,
                         std::string_view expected, std::string_view name) {
  auto parsed = require_ok(block::BlockSignatureSet::fetch(std::move(cell), context.validator_set), name);
  expect_error(block::verify_pq_finality(context, *parsed, block::FinalityRole::Final), expected, name);
  std::fprintf(stderr, "PQ_SIGNATURE_CORRUPTION_OK case=%.*s reason=%.*s\n", static_cast<int>(name.size()),
               name.data(), static_cast<int>(expected.size()), expected.data());
}

void run_corruption_matrix() {
  Fixture fixture;
  const std::vector<std::size_t> signers{0, 1, 2};
  auto candidate_data = candidate(fixture.id);
  auto pairs = fixture.sign(signers, fixture.session, Fixture::slot, candidate_data, true, fixture.id);
  auto entries = raw_pairs(pairs);
  const auto weight = fixture.weight_of(signers);
  const auto context = block::PQFinalityVerificationContext{fixture.validator_set, fixture.id, fixture.session};
  const auto make_root = [&](const std::vector<RawPair>& values, ValidatorWeight claimed_weight,
                             ValidatorSessionId session, td::uint32 slot, td::Ref<vm::Cell> candidate_root,
                             unsigned tag = 0x13) {
    return raw_signature_set(values, fixture.validator_set->get_validator_set_hash(), Fixture::catchain_seqno,
                             claimed_weight, session, slot, std::move(candidate_root), tag);
  };

  expect_parse_error(make_root(entries, weight, fixture.session, Fixture::slot, candidate_cell(candidate_data), 0x12),
                     fixture.validator_set, "unsupported carrier for post-quantum validator set", "constructor");

  auto wrong_id = entries;
  wrong_id[0].validator_id.value.as_slice()[0] ^= 1;
  expect_parse_error(make_root(wrong_id, weight, fixture.session, Fixture::slot, candidate_cell(candidate_data)),
                     fixture.validator_set, "pq signatures: unknown validator_id", "validator_id");

  auto wrong_algorithm = entries;
  wrong_algorithm[0].algorithm_id ^= 1;
  expect_parse_error(
      make_root(wrong_algorithm, weight, fixture.session, Fixture::slot, candidate_cell(candidate_data)),
      fixture.validator_set, "pq signatures: unsupported algorithm", "algorithm_id");

  auto wrong_length = entries;
  auto short_bytes = pairs[0].signature.clone();
  short_bytes.truncate(short_bytes.size() - 1);
  wrong_length[0].signature =
      require_ok(pq::pack_pq_bytes(short_bytes.as_slice(), pq::pq_bytes_hard_max), "pack-short-signature");
  expect_parse_error(make_root(wrong_length, weight, fixture.session, Fixture::slot, candidate_cell(candidate_data)),
                     fixture.validator_set, "pq signatures: signature length 2419, expected 2420", "pqbytes_length");

  auto wrong_signature = clone_pairs(pairs);
  wrong_signature[0].signature.as_slice()[100] ^= 1;
  expect_verify_error(make_root(raw_pairs(wrong_signature), weight, fixture.session, Fixture::slot,
                                candidate_cell(candidate_data)),
                      context, "pq signatures: invalid signature", "signature_chunk");

  auto wrong_session = fixture.session;
  wrong_session.as_slice()[0] ^= 1;
  expect_verify_error(make_root(entries, weight, wrong_session, Fixture::slot, candidate_cell(candidate_data)),
                      context, "carried session_id does not match trusted expected session_id", "session_id");

  expect_verify_error(make_root(entries, weight, fixture.session, Fixture::slot ^ 1, candidate_cell(candidate_data)),
                      context, "pq signatures: invalid signature", "slot");

  auto candidate_bytes = serialize_tl_object(candidate_data, true);
  candidate_bytes.as_slice().back() ^= 1;
  auto wrong_candidate = require_ok(vm::CellString::create(candidate_bytes.as_slice()), "wrong-candidate-cell");
  expect_verify_error(make_root(entries, weight, fixture.session, Fixture::slot, std::move(wrong_candidate)), context,
                      "pq signatures: invalid signature", "candidate_data");

  expect_parse_error(make_root(entries, weight - 1, fixture.session, Fixture::slot, candidate_cell(candidate_data)),
                     fixture.validator_set, "signature weight mismatch", "claimed_weight");
}

td::Ref<vm::Cell> block_proof_cell(const BlockIdExt& block_id, td::Ref<vm::Cell> signatures) {
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(0xc3, 8) && block::tlb::t_BlockIdExt.pack(builder, block_id) &&
        builder.store_ref_bool(vm::CellBuilder{}.finalize_novm()) && builder.store_bool_bool(true) &&
        builder.store_ref_bool(std::move(signatures)))) {
    fail("PQ_SIGNATURE_PERSISTENCE_BLOCK_PROOF_BUILD_FAILED");
  }
  return builder.finalize_novm();
}

td::Ref<vm::Cell> top_block_descr_cell(const BlockIdExt& block_id, td::Ref<vm::Cell> signatures,
                                       td::Ref<vm::Cell> proof) {
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(0xd5, 8) && block::tlb::t_BlockIdExt.pack(builder, block_id) &&
        builder.store_bool_bool(true) && builder.store_ref_bool(std::move(signatures)) &&
        builder.store_long_bool(1, 8) && builder.store_ref_bool(std::move(proof)))) {
    fail("PQ_SIGNATURE_PERSISTENCE_TOP_DESCR_BUILD_FAILED");
  }
  auto root = builder.finalize_novm();
  if (!block::gen::t_TopBlockDescr.validate_ref(root)) {
    fail("PQ_SIGNATURE_PERSISTENCE_TOP_DESCR_SCHEMA_FAILED");
  }
  return root;
}

td::Ref<block::BlockSignatureSet> parse_structural(td::Ref<vm::Cell> root, ValidatorWeight& claimed_weight,
                                                   std::string_view name) {
  return require_ok(block::BlockSignatureSet::fetch(std::move(root), claimed_weight), name);
}

void expect_consumer_error(td::Ref<block::BlockSignatureSet> signatures, ValidatorWeight claimed_weight,
                           const block::PQFinalityVerificationContext& context, std::string_view expected,
                           std::string_view name) {
  expect_error(verify_pq_proof_signatures(context, *signatures, claimed_weight), expected, name);
  std::fprintf(stderr, "PQ_PROOF_CONSUMER_REJECT_OK case=%.*s reason=%.*s\n", static_cast<int>(name.size()),
               name.data(), static_cast<int>(expected.size()), expected.data());
}

void run_proof_consumers() {
  Fixture fixture;
  const std::vector<std::size_t> quorum{0, 1, 2};
  auto candidate_data = candidate(fixture.id);
  auto pairs = fixture.sign(quorum, fixture.session, Fixture::slot, candidate_data, true, fixture.id);
  auto signatures = require_ok(block::BlockSignatureSet::create_simplex_pq_final(
                                   clone_pairs(pairs), Fixture::catchain_seqno,
                                   fixture.validator_set->get_validator_set_hash(), fixture.session, Fixture::slot,
                                   candidate(fixture.id)),
                               "consumer-carrier");
  auto signature_cell = require_ok(signatures->serialize(fixture.validator_set), "consumer-serialize");
  auto context = block::PQFinalityVerificationContext{fixture.validator_set, fixture.id, fixture.session};

  auto accepted_cell = require_ok(
      prepare_accepted_block_signatures(fixture.validator_set, signatures, fixture.id, fixture.session),
      "accept-block-prepare");
  if (accepted_cell->get_hash() != signature_cell->get_hash()) {
    fail("PQ_ACCEPT_BLOCK_SIGNATURE_BYTES_MISMATCH");
  }
  auto wrong_expected_session = fixture.session;
  wrong_expected_session.as_slice()[0] ^= 1;
  expect_error(prepare_accepted_block_signatures(fixture.validator_set, signatures, fixture.id,
                                                 wrong_expected_session),
               "carried session_id does not match trusted expected session_id", "accept_block_wrong_session");
  std::fprintf(stderr, "PQ_ACCEPT_BLOCK_BOUNDARY_OK\n");

  auto proof_root = block_proof_cell(fixture.id, signature_cell);
  auto proof_boc = require_ok(vm::std_boc_serialize(proof_root, 31), "proof-boc");
  auto proof_loaded = require_ok(vm::std_boc_deserialize(proof_boc.as_slice()), "proof-load");
  auto proof_envelope = require_ok(parse_block_proof_signature_envelope(proof_loaded), "proof-envelope");
  if (proof_envelope.block_id != fixture.id || proof_envelope.signatures.is_null()) {
    fail("PQ_BLOCK_PROOF_ENVELOPE_ID_OR_SIGNATURES_MISMATCH");
  }
  require_ok(verify_pq_proof_signatures(context, *proof_envelope.signatures, proof_envelope.claimed_weight),
             "proof-verify");

  auto top_root = top_block_descr_cell(fixture.id, signature_cell, proof_root);
  auto top_boc = require_ok(vm::std_boc_serialize(top_root, 31), "top-descr-boc");
  auto top_loaded = require_ok(vm::std_boc_deserialize(top_boc.as_slice()), "top-descr-load");
  auto top_envelope = require_ok(parse_top_block_descr_signature_envelope(top_loaded), "top-descr-envelope");
  if (top_envelope.block_id != fixture.id || top_envelope.signatures.is_null() ||
      top_envelope.signatures->get_catchain_seqno() != Fixture::catchain_seqno ||
      top_envelope.signatures->get_validator_set_hash() != fixture.validator_set->get_validator_set_hash()) {
    fail("PQ_TOP_BLOCK_DESCR_ENVELOPE_METADATA_MISMATCH");
  }
  require_ok(verify_pq_proof_signatures(context, *top_envelope.signatures, top_envelope.claimed_weight),
             "top-descr-verify");
  std::fprintf(stderr, "PQ_BLOCK_PROOF_ROUNDTRIP_OK bytes=%zu\n", proof_boc.size());
  std::fprintf(stderr, "PQ_TOP_BLOCK_DESCR_ROUNDTRIP_OK bytes=%zu\n", top_boc.size());

  auto legacy = block::BlockSignatureSet::create_ordinary({}, Fixture::catchain_seqno,
                                                          fixture.validator_set->get_validator_set_hash());
  expect_consumer_error(legacy, 0, context, "post-quantum carrier required", "classical_under_pq_set");

  auto entries = raw_pairs(pairs);
  const auto weight = fixture.weight_of(quorum);
  const auto raw = [&](td::uint32 validator_hash, CatchainSeqno cc, ValidatorWeight claimed,
                       const std::vector<RawPair>& values, td::Ref<vm::Cell> candidate_root) {
    return raw_signature_set(values, validator_hash, cc, claimed, fixture.session, Fixture::slot,
                             std::move(candidate_root));
  };
  ValidatorWeight claimed = 0;
  auto wrong_hash = parse_structural(
      raw(fixture.validator_set->get_validator_set_hash() ^ 1, Fixture::catchain_seqno, weight, entries,
          candidate_cell(candidate_data)),
      claimed, "wrong-hash-parse");
  expect_consumer_error(wrong_hash, claimed, context, "validator set hash mismatch", "wrong_validator_set_hash");

  auto wrong_cc = parse_structural(
      raw(fixture.validator_set->get_validator_set_hash(), Fixture::catchain_seqno ^ 1, weight, entries,
          candidate_cell(candidate_data)),
      claimed, "wrong-cc-parse");
  expect_consumer_error(wrong_cc, claimed, context, "catchain seqno mismatch", "wrong_catchain_seqno");

  auto other_id = fixture.id;
  other_id.root_hash.as_slice()[0] ^= 1;
  expect_consumer_error(proof_envelope.signatures, proof_envelope.claimed_weight,
                        {fixture.validator_set, other_id, fixture.session}, "block id mismatch", "wrong_block_id");

  auto damaged = clone_pairs(pairs);
  damaged[0].signature.as_slice()[200] ^= 1;
  auto damaged_set = parse_structural(
      raw(fixture.validator_set->get_validator_set_hash(), Fixture::catchain_seqno, weight, raw_pairs(damaged),
          candidate_cell(candidate_data)),
      claimed, "damaged-signature-parse");
  expect_consumer_error(damaged_set, claimed, context, "pq signatures: invalid signature", "invalid_signature");

  std::vector<std::size_t> minority{3};
  auto minority_pairs = fixture.sign(minority, fixture.session, Fixture::slot, candidate_data, true, fixture.id);
  auto minority_set = parse_structural(
      raw(fixture.validator_set->get_validator_set_hash(), Fixture::catchain_seqno, fixture.weight_of(minority),
          raw_pairs(minority_pairs), candidate_cell(candidate_data)),
      claimed, "sub-quorum-parse");
  expect_consumer_error(minority_set, claimed, context, "pq signatures: insufficient verified weight", "sub_quorum");

  auto wrong_weight = parse_structural(
      raw(fixture.validator_set->get_validator_set_hash(), Fixture::catchain_seqno, weight - 1, entries,
          candidate_cell(candidate_data)),
      claimed, "wrong-weight-parse");
  expect_consumer_error(wrong_weight, claimed, context, "bad signature set weight", "claimed_weight_mismatch");
}

void run_round_trip(std::size_t signer_count, td::uint32 discriminator) {
  LargeFixture fixture(signer_count, discriminator);
  auto signatures = fixture.signatures();
  auto before_cell = require_ok(signatures->serialize(fixture.validator_set), "serialize-before");
  auto before = require_ok(vm::std_boc_serialize(before_cell, 31), "boc-before");

  const auto root = PSTRING() << "tmp-pq-signature-persistence-" << signer_count << "-"
                              << td::Random::fast_uint32();
  RootDbRoundTrip db(root);
  auto handle = create_empty_block_handle(fixture.id);
  db.store(handle, signatures, fixture.validator_set);
  auto loaded = db.load(handle);

  auto after_cell = require_ok(loaded->serialize(fixture.validator_set), "serialize-after");
  auto after = require_ok(vm::std_boc_serialize(after_cell, 31), "boc-after");
  if (before.as_slice() != after.as_slice()) {
    fail(PSTRING() << "PQ_SIGNATURE_PERSISTENCE_BYTES_MISMATCH signers=" << signer_count);
  }
  block::PQFinalityVerificationContext context{fixture.validator_set, fixture.id, fixture.session};
  auto weight = require_ok(block::verify_pq_finality(context, *loaded, block::FinalityRole::Final), "verify-after");
  if (weight != signer_count) {
    fail(PSTRING() << "PQ_SIGNATURE_PERSISTENCE_WEIGHT_MISMATCH signers=" << signer_count << " actual=" << weight);
  }
  std::fprintf(stderr, "PQ_SIGNATURE_PERSISTENCE_OK signers=%zu bytes=%zu\n", signer_count, before.size());
}

}  // namespace

int main() {
  run_round_trip(21, 21);
  run_round_trip(100, 100);
  run_corruption_matrix();
  run_proof_consumers();
  return 0;
}
