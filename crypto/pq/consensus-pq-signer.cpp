/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <vector>

#include "consensus-pq-signer.h"
#include "mldsa_native.h"

namespace tos::pq {

struct ValidatorPQKeyStore::Secret {
  std::array<std::uint8_t, MLDSA44_SECRETKEYBYTES> sk{};
  ~Secret() {
    OPENSSL_cleanse(sk.data(), sk.size());
  }
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
    OPENSSL_cleanse(pk.data(), pk.size());  // wipe on every exit, not just the success path
    return std::nullopt;                    // store's Secret dtor wipes the secret key
  }
  store.key_.algorithm_id = PQAlgorithmId::mldsa44;
  store.key_.public_key.assign(reinterpret_cast<const char*>(pk.data()), pk.size());
  OPENSSL_cleanse(pk.data(), pk.size());
  auto key_id = derive_key_id(PQAlgorithmId::mldsa44, store.key_.public_key);
  if (!key_id) {  // fail closed: no usable identity means no key store
    return std::nullopt;
  }
  store.key_.key_id = *key_id;
  return std::optional<ValidatorPQKeyStore>(std::move(store));
}

std::optional<ValidatorPQKeyStore> ValidatorPQKeyStore::generate() noexcept {
  std::array<std::uint8_t, MLDSA_SEEDBYTES> seed{};
  if (RAND_priv_bytes(seed.data(), static_cast<int>(seed.size())) != 1) {
    OPENSSL_cleanse(seed.data(), seed.size());  // wipe on every exit, including RNG failure
    return std::nullopt;
  }
  auto out = from_seed(std::string_view(reinterpret_cast<const char*>(seed.data()), seed.size()));
  OPENSSL_cleanse(seed.data(), seed.size());
  return out;
}

namespace {

// ML-DSA "pure" signing: domain octet 0x00, the context length, then the context. The
// three authority surfaces differ in that context and in nothing else, so they are one
// routine: a second copy of this is a second chance to get the prefix wrong, and a
// signature made under the wrong context is one nobody can verify and everybody blames
// on the key.
std::optional<ConsensusPQSignature> sign_under(const ConsensusPQKey& key, const std::uint8_t* sk,
                                               std::string_view context, std::string_view message) noexcept {
  if (sk == nullptr || key.algorithm_id != PQAlgorithmId::mldsa44 || message.size() > mldsa44_max_message_bytes ||
      context.size() > mldsa44_max_context_bytes) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> prefix;
  prefix.reserve(2 + context.size());
  prefix.push_back(0);
  prefix.push_back(static_cast<std::uint8_t>(context.size()));
  prefix.insert(prefix.end(), context.begin(), context.end());

  std::array<std::uint8_t, MLDSA_RNDBYTES> rnd{};
  if (RAND_priv_bytes(rnd.data(), static_cast<int>(rnd.size())) != 1) {
    OPENSSL_cleanse(rnd.data(), rnd.size());  // wipe on every exit, including RNG failure
    return std::nullopt;
  }
  std::array<std::uint8_t, MLDSA44_BYTES> sig{};
  const int rc = tos_pq_cs_native_signature_internal(sig.data(), reinterpret_cast<const std::uint8_t*>(message.data()),
                                                     message.size(), prefix.data(), prefix.size(), rnd.data(), sk, 0);
  OPENSSL_cleanse(rnd.data(), rnd.size());
  if (rc != 0) {
    return std::nullopt;
  }
  ConsensusPQSignature out;
  out.algorithm_id = PQAlgorithmId::mldsa44;
  out.signature.assign(reinterpret_cast<const char*>(sig.data()), sig.size());
  return out;
}

}  // namespace

std::optional<ConsensusPQSignature> ValidatorPQKeyStore::sign_consensus(std::string_view message) const noexcept {
  return sign_under(key_, secret_ ? secret_->sk.data() : nullptr, simplex_sign_context, message);
}

std::optional<ConsensusPQSignature> ValidatorPQKeyStore::sign_config_vote(std::string_view message) const noexcept {
  return sign_under(key_, secret_ ? secret_->sk.data() : nullptr, validator_config_vote_context, message);
}

std::optional<ConsensusPQSignature> ValidatorPQKeyStore::sign_election(std::string_view message) const noexcept {
  return sign_under(key_, secret_ ? secret_->sk.data() : nullptr, validator_election_context, message);
}

}  // namespace tos::pq
