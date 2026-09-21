/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "auto/tl/tos_api.h"
#include "crypto/block/block-parse.h"
#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-bytes.h"
#include "crypto/pq/pq-sign-under.h"
#include "td/utils/crypto.h"
#include "tl-utils/tl-utils.hpp"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellString.h"
#include "vm/dict.h"

namespace block_signature_carrier_test {

inline constexpr std::size_t measured_signer_ceiling = 400;
inline constexpr std::uint32_t validator_set_hash = 0x31415926;
inline constexpr std::uint32_t catchain_seqno = 1789434;
inline constexpr std::uint32_t slot = 2718281;
inline constexpr std::uint64_t signature_weight = 1;

inline td::Bits256 hash_of(const std::string& text) {
  td::Bits256 out;
  td::sha256(td::Slice(text), out.as_slice());
  return out;
}

inline tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate() {
  return tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
      tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(-1, static_cast<td::int64>(0x8000000000000000ULL), 42,
                                                              hash_of("carrier-root"), hash_of("carrier-file")),
      tos::create_tl_object<tos::tos_api::consensus_candidateId>(slot - 1, hash_of("carrier-parent")));
}

inline td::Bits256 session_id() {
  return hash_of("persisted-pq-block-signature-session");
}

inline td::BufferSlice signed_message() {
  auto candidate_value = candidate();
  auto candidate_id = tos::create_tl_object<tos::tos_api::consensus_candidateId>(
      slot, td::Bits256{tos::get_tl_object_sha256(candidate_value).raw});
  auto vote = tos::create_serialize_tl_object<tos::tos_api::consensus_simplex_finalizeVote>(std::move(candidate_id));
  return tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(session_id(), std::move(vote));
}

struct SignatureInput {
  td::Bits256 validator_id;
  td::BufferSlice signature;
};

inline td::BufferSlice patterned_signature(std::size_t signer) {
  td::BufferSlice out(tos::pq::mldsa44_signature_bytes);
  std::size_t offset = 0;
  std::string seed = "persisted-pq-signature-" + std::to_string(signer);
  while (offset < out.size()) {
    auto block = hash_of(seed);
    const auto take = std::min<std::size_t>(32, out.size() - offset);
    std::memcpy(out.data() + offset, block.data(), take);
    offset += take;
    seed.assign(reinterpret_cast<const char*>(block.data()), 32);
  }
  return out;
}

inline std::vector<SignatureInput> make_signatures(std::size_t count, bool cryptographically_valid) {
  std::vector<SignatureInput> result;
  result.reserve(count);
  auto message = signed_message();
  std::vector<std::uint8_t> prefix{0, static_cast<std::uint8_t>(tos::pq::simplex_sign_context.size())};
  prefix.insert(prefix.end(), tos::pq::simplex_sign_context.begin(), tos::pq::simplex_sign_context.end());
  for (std::size_t i = 0; i < count; ++i) {
    td::BufferSlice signature;
    if (cryptographically_valid) {
      tos::pq::ConsensusPQKey key;
      std::array<std::uint8_t, MLDSA44_SECRETKEYBYTES> secret{};
      const auto seed = hash_of("persisted-signature-key-" + std::to_string(i));
      if (!tos::pq::detail::derive_from_seed(std::string_view(reinterpret_cast<const char*>(seed.data()), 32), key,
                                             secret.data())) {
        std::fprintf(stderr, "deterministic key derivation failed for signer %zu\n", i);
        std::abort();
      }
      std::array<std::uint8_t, MLDSA_RNDBYTES> randomness{};
      const auto randomness_bits = hash_of("persisted-signature-randomness-" + std::to_string(i));
      std::memcpy(randomness.data(), randomness_bits.data(), randomness.size());
      signature = td::BufferSlice(tos::pq::mldsa44_signature_bytes);
      if (tos_pq_cs_native_signature_internal(reinterpret_cast<std::uint8_t*>(signature.data()),
                                              reinterpret_cast<const std::uint8_t*>(message.data()), message.size(),
                                              prefix.data(), prefix.size(), randomness.data(), secret.data(), 0) != 0) {
        std::fprintf(stderr, "deterministic signing failed for signer %zu\n", i);
        std::abort();
      }
      if (tos::pq::verify_mldsa44(std::string_view(message.data(), message.size()), tos::pq::simplex_sign_context,
                                  std::string_view(signature.data(), signature.size()),
                                  key.public_key) != tos::pq::VerifyResult::valid) {
        std::fprintf(stderr, "deterministic signature verification failed for signer %zu\n", i);
        std::abort();
      }
      OPENSSL_cleanse(secret.data(), secret.size());
    } else {
      signature = patterned_signature(i);
    }
    result.push_back(SignatureInput{hash_of("persisted-validator-" + std::to_string(i)), std::move(signature)});
  }
  return result;
}

inline td::Ref<vm::Cell> signature_set_cell(const std::vector<SignatureInput>& signatures) {
  vm::Dictionary dict{16};
  for (std::size_t i = 0; i < signatures.size(); ++i) {
    auto packed = tos::pq::pack_pq_bytes(signatures[i].signature.as_slice(), tos::pq::mldsa44_signature_bytes);
    if (packed.is_error()) {
      std::abort();
    }
    vm::CellBuilder pair;
    if (!(pair.store_bits_bool(signatures[i].validator_id.cbits(), 256) && pair.store_long_bool(1, 16) &&
          pair.store_ref_bool(packed.move_as_ok()) &&
          dict.set_builder(td::BitArray<16>{static_cast<unsigned>(i)}, pair, vm::Dictionary::SetMode::Add))) {
      std::abort();
    }
  }
  auto dict_root = std::move(dict).extract_root_cell();
  auto candidate_cell = vm::CellString::create(tos::serialize_tl_object(candidate(), true));
  if (candidate_cell.is_error()) {
    std::abort();
  }
  vm::CellBuilder root;
  if (!(root.store_long_bool(0x13, 8) && root.store_long_bool(validator_set_hash, 32) &&
        root.store_long_bool(catchain_seqno, 32) && root.store_long_bool(signatures.size(), 32) &&
        root.store_long_bool(signatures.size() * signature_weight, 64) && root.store_maybe_ref(dict_root) &&
        root.store_bits_bool(session_id().cbits(), 256) && root.store_long_bool(slot, 32) &&
        root.store_ref_bool(candidate_cell.move_as_ok()))) {
    std::abort();
  }
  return root.finalize_novm();
}

inline td::BufferSlice boc(const td::Ref<vm::Cell>& root) {
  auto result = vm::std_boc_serialize(root, 0);
  if (result.is_error()) {
    std::abort();
  }
  return result.move_as_ok();
}

inline td::Ref<vm::Cell> block_proof_cell(const td::Ref<vm::Cell>& signatures) {
  tos::BlockIdExt id{-1, 0x8000000000000000ULL, 42, hash_of("carrier-root"), hash_of("carrier-file")};
  vm::CellBuilder proof_payload;
  proof_payload.store_long(0x51, 8);
  vm::CellBuilder root;
  if (!(root.store_long_bool(0xc3, 8) && block::tlb::t_BlockIdExt.pack(root, id) &&
        root.store_ref_bool(proof_payload.finalize()) && root.store_bool_bool(true) &&
        root.store_ref_bool(signatures))) {
    std::abort();
  }
  return root.finalize_novm();
}

inline void append_u32(td::BufferSlice& out, std::size_t& pos, std::uint32_t value) {
  out.data()[pos++] = static_cast<char>(value);
  out.data()[pos++] = static_cast<char>(value >> 8);
  out.data()[pos++] = static_cast<char>(value >> 16);
  out.data()[pos++] = static_cast<char>(value >> 24);
}

inline std::size_t tl_bytes_field_size(std::size_t size) {
  const std::size_t prefix = size < 254 ? 1 : 4;
  return (prefix + size + 3) & ~std::size_t{3};
}

inline void append_bytes(td::BufferSlice& out, std::size_t& pos, td::Slice value) {
  if (value.size() < 254) {
    out.data()[pos++] = static_cast<char>(value.size());
  } else {
    out.data()[pos++] = static_cast<char>(254);
    out.data()[pos++] = static_cast<char>(value.size());
    out.data()[pos++] = static_cast<char>(value.size() >> 8);
    out.data()[pos++] = static_cast<char>(value.size() >> 16);
  }
  std::memcpy(out.data() + pos, value.data(), value.size());
  pos += value.size();
  while (pos % 4 != 0) {
    out.data()[pos++] = 0;
  }
}

inline td::BufferSlice node_tl(const std::vector<SignatureInput>& signatures) {
  const auto candidate_bytes = tos::serialize_tl_object(candidate(), true);
  const std::size_t pair_size = 4 + 32 + 4 + tl_bytes_field_size(tos::pq::mldsa44_signature_bytes);
  const std::size_t size = 4 + 4 + 4 + 4 + 4 + 4 + signatures.size() * pair_size + 32 + 4 + candidate_bytes.size();
  td::BufferSlice out(size);
  std::size_t pos = 0;
  append_u32(out, pos, 0x590da166);  // tosNode.signatureSet.simplexPq
  append_u32(out, pos, 0x997275b5);  // boolTrue
  append_u32(out, pos, catchain_seqno);
  append_u32(out, pos, validator_set_hash);
  append_u32(out, pos, 0x1cb5c415);  // vector
  append_u32(out, pos, static_cast<std::uint32_t>(signatures.size()));
  for (const auto& signature : signatures) {
    append_u32(out, pos, 0x535666d0);  // tosNode.pqBlockSignature
    std::memcpy(out.data() + pos, signature.validator_id.data(), 32);
    pos += 32;
    append_u32(out, pos, 1);
    append_bytes(out, pos, signature.signature.as_slice());
  }
  std::memcpy(out.data() + pos, session_id().data(), 32);
  pos += 32;
  append_u32(out, pos, slot);
  std::memcpy(out.data() + pos, candidate_bytes.data(), candidate_bytes.size());
  pos += candidate_bytes.size();
  if (pos != out.size()) {
    std::abort();
  }
  return out;
}

inline td::BufferSlice lite_tl(const std::vector<SignatureInput>& signatures) {
  const auto candidate_bytes = tos::serialize_tl_object(candidate(), true);
  const std::size_t pair_size = 4 + 32 + 4 + tl_bytes_field_size(tos::pq::mldsa44_signature_bytes);
  const std::size_t size =
      4 + 4 + 4 + 4 + 4 + signatures.size() * pair_size + 32 + 4 + tl_bytes_field_size(candidate_bytes.size());
  td::BufferSlice out(size);
  std::size_t pos = 0;
  append_u32(out, pos, 0xf9f0b390);  // liteServer.signatureSet.simplexPq
  append_u32(out, pos, catchain_seqno);
  append_u32(out, pos, validator_set_hash);
  append_u32(out, pos, 0x1cb5c415);  // vector
  append_u32(out, pos, static_cast<std::uint32_t>(signatures.size()));
  for (const auto& signature : signatures) {
    append_u32(out, pos, 0xfb759362);  // liteServer.pqSignature
    std::memcpy(out.data() + pos, signature.validator_id.data(), 32);
    pos += 32;
    append_u32(out, pos, 1);
    append_bytes(out, pos, signature.signature.as_slice());
  }
  std::memcpy(out.data() + pos, session_id().data(), 32);
  pos += 32;
  append_u32(out, pos, slot);
  append_bytes(out, pos, candidate_bytes.as_slice());
  if (pos != out.size()) {
    std::abort();
  }
  return out;
}

inline std::size_t certificate_tl_bytes(const std::vector<SignatureInput>& signatures) {
  std::vector<tos::tl_object_ptr<tos::tos_api::consensus_simplex_voteSignature>> votes;
  votes.reserve(signatures.size());
  for (std::size_t i = 0; i < signatures.size(); ++i) {
    votes.push_back(tos::create_tl_object<tos::tos_api::consensus_simplex_voteSignature>(
        static_cast<std::int32_t>(i), signatures[i].signature.clone()));
  }
  auto candidate_value = candidate();
  auto candidate_id = tos::create_tl_object<tos::tos_api::consensus_candidateId>(
      slot, td::Bits256{tos::get_tl_object_sha256(candidate_value).raw});
  auto cert = tos::create_tl_object<tos::tos_api::consensus_simplex_certificate>(
      tos::create_tl_object<tos::tos_api::consensus_simplex_finalizeVote>(std::move(candidate_id)),
      tos::create_tl_object<tos::tos_api::consensus_simplex_voteSignatureSet>(std::move(votes)));
  return tos::serialize_tl_object(cert, true).size();
}

struct Measurement {
  std::size_t signers;
  std::size_t cells;
  std::size_t depth;
  std::size_t signatures_boc_bytes;
  std::size_t block_proof_boc_bytes;
  std::size_t node_tl_bytes;
  std::size_t lite_tl_bytes;
  std::size_t certificate_tl_bytes;
  std::int64_t boc_minus_certificate;
};

inline Measurement measure(std::size_t count, bool valid) {
  auto signatures = make_signatures(count, valid);
  auto root = signature_set_cell(signatures);
  vm::CellStorageStat stat;
  if (stat.add_used_storage(root).is_error()) {
    std::abort();
  }
  const auto signature_boc = boc(root);
  const auto proof_boc = boc(block_proof_cell(root));
  const auto cert_size = certificate_tl_bytes(signatures);
  return Measurement{count,
                     static_cast<std::size_t>(stat.cells),
                     root->get_depth(),
                     signature_boc.size(),
                     proof_boc.size(),
                     node_tl(signatures).size(),
                     lite_tl(signatures).size(),
                     cert_size,
                     static_cast<std::int64_t>(signature_boc.size()) - static_cast<std::int64_t>(cert_size)};
}

}  // namespace block_signature_carrier_test
