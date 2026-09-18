/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "consensus-pq-signer.h"

#include <vector>

#include "mldsa_native.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>

namespace tos::pq {

struct ValidatorPQKeyStore::Secret {
  std::array<std::uint8_t, MLDSA44_SECRETKEYBYTES> sk{};
  ~Secret() { OPENSSL_cleanse(sk.data(), sk.size()); }
};

ValidatorPQKeyStore::ValidatorPQKeyStore(ValidatorPQKeyStore&&) noexcept = default;
ValidatorPQKeyStore& ValidatorPQKeyStore::operator=(ValidatorPQKeyStore&&) noexcept = default;
ValidatorPQKeyStore::~ValidatorPQKeyStore() = default;

std::optional<ValidatorPQKeyStore> ValidatorPQKeyStore::from_seed(std::string_view seed) noexcept {
  if (seed.size() != MLDSA_SEEDBYTES) {
    return std::nullopt;
  }
  ValidatorPQKeyStore store;
  store.secret_ = std::make_unique<Secret>();
  std::array<std::uint8_t, MLDSA44_PUBLICKEYBYTES> pk{};
  if (tos_pq_cs_native_keypair_internal(pk.data(), store.secret_->sk.data(),
                                        reinterpret_cast<const std::uint8_t*>(seed.data())) != 0) {
    return std::nullopt;
  }
  store.key_.algorithm_id = PQAlgorithmId::mldsa44;
  store.key_.public_key.assign(reinterpret_cast<const char*>(pk.data()), pk.size());
  store.key_.key_id = derive_key_id(PQAlgorithmId::mldsa44, store.key_.public_key);
  OPENSSL_cleanse(pk.data(), pk.size());
  return std::optional<ValidatorPQKeyStore>(std::move(store));
}

std::optional<ValidatorPQKeyStore> ValidatorPQKeyStore::generate() noexcept {
  std::array<std::uint8_t, MLDSA_SEEDBYTES> seed{};
  if (RAND_priv_bytes(seed.data(), static_cast<int>(seed.size())) != 1) {
    return std::nullopt;
  }
  auto out = from_seed(std::string_view(reinterpret_cast<const char*>(seed.data()), seed.size()));
  OPENSSL_cleanse(seed.data(), seed.size());
  return out;
}

std::optional<ConsensusPQSignature> ValidatorPQKeyStore::sign_consensus(std::string_view message) const noexcept {
  if (!secret_ || key_.algorithm_id != PQAlgorithmId::mldsa44 ||
      message.size() > mldsa44_max_message_bytes || consensus_sign_context.size() > mldsa44_max_context_bytes) {
    return std::nullopt;
  }
  // ML-DSA "pure" context: domain octet 0x00, context length, the fixed consensus context.
  std::vector<std::uint8_t> prefix;
  prefix.reserve(2 + consensus_sign_context.size());
  prefix.push_back(0);
  prefix.push_back(static_cast<std::uint8_t>(consensus_sign_context.size()));
  prefix.insert(prefix.end(), consensus_sign_context.begin(), consensus_sign_context.end());

  std::array<std::uint8_t, MLDSA_RNDBYTES> rnd{};
  if (RAND_priv_bytes(rnd.data(), static_cast<int>(rnd.size())) != 1) {
    return std::nullopt;
  }
  std::array<std::uint8_t, MLDSA44_BYTES> sig{};
  const int rc = tos_pq_cs_native_signature_internal(
      sig.data(), reinterpret_cast<const std::uint8_t*>(message.data()), message.size(),
      prefix.data(), prefix.size(), rnd.data(), secret_->sk.data(), 0);
  OPENSSL_cleanse(rnd.data(), rnd.size());
  if (rc != 0) {
    return std::nullopt;
  }
  ConsensusPQSignature out;
  out.algorithm_id = PQAlgorithmId::mldsa44;
  out.signature.assign(reinterpret_cast<const char*>(sig.data()), sig.size());
  return out;
}

}  // namespace tos::pq
