/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// In-process experiments only. No node target includes this header. These local
// identifiers, transcript bytes and limits are NOT an allocated network format.
// Keep the immutable registry, authenticated statement, suite provider and quorum
// boundaries separate so a future reviewed profile does not trust peer metadata.
#include "td/utils/crypto.h"
#include "tos/quorum.h"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace tos::validator::auth::experimental {
using Bytes = std::span<const std::uint8_t>;
using Digest = std::array<std::uint8_t, 32>;

// Experimental resource budgets; not a production consensus policy.
inline constexpr std::size_t max_validators = 1024;
inline constexpr std::size_t max_keys = 10;
inline constexpr std::size_t max_key_bytes = 16384;
inline constexpr std::size_t max_signature_bytes = 65536;
inline constexpr std::size_t max_certificate_bytes = 8 * 1024 * 1024;

enum class Role : std::uint8_t { proposal = 1, notarize, finalize, skip, administration };
enum class Phase : std::uint8_t { classical, shadow, hybrid_required, pq_required };
enum class CryptoResult { valid, invalid, unsupported, backend_error };
enum class Error {
  none, policy, registry, quorum, count, unknown_signer, duplicate_signer,
  components, key_binding, resource, signature, backend
};
struct Outcome {
  Error error;
  ValidatorWeight weight = 0;
  bool accepted() const { return error == Error::none; }
};
struct Profile {
  std::uint32_t suite;
  std::uint32_t parameters;
  bool operator==(const Profile&) const = default;
};
struct Policy {
  Phase phase;
  Profile classical;
  Profile pq;
  Digest governance_commitment{};
};
struct Context {
  std::int32_t network = 0;
  Digest genesis{};
  Digest session{};
  std::int32_t workchain = 0;
  std::uint64_t shard = 0;
  std::uint32_t slot = 0;
  Role role = Role::proposal;
  Digest payload{};
};
struct RegisteredKey {
  Profile profile;
  Role role;
  std::uint64_t epoch;
  std::uint32_t first_slot;
  std::uint32_t last_slot;
  bool enabled;
  std::vector<std::uint8_t> bytes;
};
struct ValidatorRecord {
  Digest identity;
  ValidatorWeight weight;
  std::vector<RegisteredKey> keys;
};
struct Component {
  Profile profile;
  std::uint64_t key_epoch;
  Bytes bytes;
};
struct SignedRecord {
  Digest identity;
  std::span<const Component> components;
};

inline td::Slice slice(Bytes bytes) {
  return td::Slice(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}
inline Digest hash(Bytes bytes) {
  Digest out{};
  td::sha256(slice(bytes), td::MutableSlice(reinterpret_cast<char*>(out.data()), out.size()));
  return out;
}
inline bool valid_role(Role role) {
  return role >= Role::proposal && role <= Role::administration;
}
inline bool profile_less(Profile a, Profile b) {
  return a.suite < b.suite || (a.suite == b.suite && a.parameters < b.parameters);
}
inline void integer(std::vector<std::uint8_t>& out, std::uint64_t value, unsigned width) {
  for (unsigned i = width; i != 0; --i) out.push_back(static_cast<std::uint8_t>(value >> ((i - 1) * 8)));
}
inline void append(std::vector<std::uint8_t>& out, Bytes bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}
inline void profile_bytes(std::vector<std::uint8_t>& out, Profile profile) {
  integer(out, profile.suite, 4);
  integer(out, profile.parameters, 4);
}
inline void key_reference(std::vector<std::uint8_t>& out, const RegisteredKey& key) {
  profile_bytes(out, key.profile);
  integer(out, static_cast<std::uint8_t>(key.role), 1);
  integer(out, key.epoch, 8);
  integer(out, key.first_slot, 4);
  integer(out, key.last_slot, 4);
  integer(out, key.enabled ? 1 : 0, 1);
  append(out, hash(key.bytes));
}

// Registry is a trusted snapshot supplied by the local consensus-state owner,
// never by the certificate being verified. It owns its key bytes, preventing
// later mutation of borrowed peer buffers from replacing an admitted key.
class Registry {
 public:
  explicit Registry(std::vector<ValidatorRecord> validators) : validators_(std::move(validators)) {
    if (validators_.empty() || validators_.size() > max_validators) return;
    td::Sha256State digest;
    digest.init();
    digest.feed("TOS-VAL-REGISTRY-EXPERIMENT/v1");
    std::vector<std::uint8_t> encoded;
    integer(encoded, validators_.size(), 4);
    digest.feed(slice(encoded));
    for (std::size_t i = 0; i < validators_.size(); ++i) {
      const auto& record = validators_[i];
      if (i != 0 && !(validators_[i - 1].identity < record.identity)) return;
      if (!tos::checked_add_validator_weight(total_, record.weight)) return;
      if (record.keys.empty() || record.keys.size() > max_keys) return;
      encoded.clear();
      append(encoded, record.identity);
      integer(encoded, record.weight, 8);
      integer(encoded, record.keys.size(), 4);
      for (std::size_t j = 0; j < record.keys.size(); ++j) {
        const auto& key = record.keys[j];
        if (!valid_role(key.role) || key.bytes.empty() || key.bytes.size() > max_key_bytes ||
            key.first_slot > key.last_slot) return;
        if (j != 0) {
          const auto& previous = record.keys[j - 1];
          if (!(previous.role < key.role ||
                (previous.role == key.role && profile_less(previous.profile, key.profile)))) return;
        }
        key_reference(encoded, key);
      }
      digest.feed(slice(encoded));
    }
    digest.extract(td::MutableSlice(reinterpret_cast<char*>(commitment_.data()), commitment_.size()));
    valid_ = true;
  }
  bool valid() const { return valid_; }
  ValidatorWeight total_weight() const { return total_; }
  const Digest& commitment() const { return commitment_; }
  std::size_t size() const { return validators_.size(); }
  const ValidatorRecord* find(const Digest& identity) const {
    std::size_t left = 0, right = validators_.size();
    while (left < right) {
      auto middle = left + (right - left) / 2;
      if (validators_[middle].identity < identity) left = middle + 1;
      else right = middle;
    }
    return left < validators_.size() && validators_[left].identity == identity ? &validators_[left] : nullptr;
  }
 private:
  std::vector<ValidatorRecord> validators_;
  Digest commitment_{};
  ValidatorWeight total_ = 0;
  bool valid_ = false;
};

inline std::vector<Profile> required_profiles(const Policy& policy) {
  switch (policy.phase) {
    case Phase::classical:
    case Phase::shadow: return {policy.classical};
    case Phase::hybrid_required:
      if (policy.classical == policy.pq) return {};
      if (profile_less(policy.classical, policy.pq)) return {policy.classical, policy.pq};
      return {policy.pq, policy.classical};
    case Phase::pq_required: return {policy.pq};
  }
  return {};
}
inline const RegisteredKey* key_for(const ValidatorRecord& record, Profile profile, const Context& context) {
  for (const auto& key : record.keys) {
    if (key.profile == profile && key.role == context.role && key.enabled &&
        context.slot >= key.first_slot && context.slot <= key.last_slot) return &key;
  }
  return nullptr;
}

// Both required components authorize these EXACT same bytes. In particular each
// signature binds the full roster (including absent voters), policy, signer and
// paired key references; two independently signed quorums are not a hybrid one.
// This format is deliberately named EXPERIMENT and has no TL/TL-B constructor.
inline std::vector<std::uint8_t> statement(const Registry& registry, const Policy& policy,
                                          const Context& context, const ValidatorRecord& signer) {
  constexpr char domain[] = "TOS-VALIDATOR-AUTH-EXPERIMENT/v1";
  std::vector<std::uint8_t> out(domain, domain + sizeof(domain) - 1);
  integer(out, static_cast<std::uint32_t>(context.network), 4);
  append(out, context.genesis);
  append(out, registry.commitment());
  append(out, policy.governance_commitment);
  // Observation-only mode must not alter the authoritative classical transcript.
  auto authority = policy.phase == Phase::shadow ? Phase::classical : policy.phase;
  integer(out, static_cast<std::uint8_t>(authority), 1);
  profile_bytes(out, policy.classical);
  profile_bytes(out, policy.pq);
  append(out, context.session);
  integer(out, static_cast<std::uint32_t>(context.workchain), 4);
  integer(out, context.shard, 8);
  integer(out, context.slot, 4);
  integer(out, static_cast<std::uint8_t>(context.role), 1);
  append(out, context.payload);
  append(out, signer.identity);
  const auto profiles = required_profiles(policy);
  integer(out, profiles.size(), 1);
  for (auto profile : profiles) {
    const auto* key = key_for(signer, profile, context);
    if (key == nullptr) return {};
    key_reference(out, *key);
  }
  return out;
}

template <class Provider>
Outcome verify(const Registry& registry, const Policy& policy, const Context& context,
               std::span<const SignedRecord> records, Provider& provider) {
  if (!registry.valid()) return {Error::registry};
  const auto profiles = required_profiles(policy);
  if (profiles.empty() || !valid_role(context.role)) return {Error::policy};
  for (auto profile : profiles) if (!provider.supports(profile)) return {Error::policy};
  if (records.empty() || records.size() > registry.size()) return {Error::count};
  std::size_t bytes = 0;
  ValidatorWeight weight = 0;
  // Complete cheap admission before performing ANY cryptographic verification.
  for (std::size_t i = 0; i < records.size(); ++i) {
    const auto& signed_record = records[i];
    for (std::size_t j = 0; j < i; ++j)
      if (records[j].identity == signed_record.identity) return {Error::duplicate_signer};
    const auto* record = registry.find(signed_record.identity);
    if (record == nullptr) return {Error::unknown_signer};
    if (signed_record.components.size() != profiles.size()) return {Error::components};
    for (std::size_t j = 0; j < profiles.size(); ++j) {
      const auto& component = signed_record.components[j];
      if (component.profile != profiles[j]) return {Error::components};
      const auto* key = key_for(*record, profiles[j], context);
      if (key == nullptr || component.key_epoch != key->epoch) return {Error::key_binding};
      if (component.bytes.empty() || component.bytes.size() > max_signature_bytes ||
          component.bytes.size() > max_certificate_bytes - bytes) return {Error::resource};
      bytes += component.bytes.size();
      if (!provider.canonical(profiles[j], key->bytes, component.bytes)) return {Error::components};
    }
    if (!tos::checked_add_validator_weight(weight, record->weight)) return {Error::registry};
  }
  if (!tos::has_quorum(weight, registry.total_weight())) return {Error::quorum};
  for (const auto& signed_record : records) {
    const auto* record = registry.find(signed_record.identity);
    const auto message = statement(registry, policy, context, *record);
    for (std::size_t j = 0; j < profiles.size(); ++j) {
      const auto& component = signed_record.components[j];
      const auto* key = key_for(*record, profiles[j], context);
      auto outcome = provider.verify(profiles[j], key->bytes, message, component.bytes);
      if (outcome == CryptoResult::backend_error || outcome == CryptoResult::unsupported) return {Error::backend};
      if (outcome != CryptoResult::valid) return {Error::signature};
    }
  }
  return {Error::none, weight};
}

// A diagnostic result has a different type and cannot be supplied as weight or
// authorization. No authoritative verifier invokes this method implicitly.
struct Observation { CryptoResult result; };
template <class Provider>
Observation observe_shadow(Profile profile, Bytes key, Bytes message, Bytes signature, Provider& provider) {
  if (!provider.supports(profile)) return {CryptoResult::unsupported};
  if (!provider.canonical(profile, key, signature)) return {CryptoResult::invalid};
  return {provider.verify(profile, key, message, signature)};
}
}  // namespace tos::validator::auth::experimental
