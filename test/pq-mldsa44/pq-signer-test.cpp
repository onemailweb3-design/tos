/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cassert>
#include <cstdio>
#include <string>

#include "consensus-pq-signer.h"
#include "mldsa44.h"  // production verify-only path

using namespace tos::pq;
int main() {
  auto ks_opt = ValidatorPQKeyStore::generate();
  assert(ks_opt.has_value());
  const auto& ks = *ks_opt;
  const auto& key = ks.consensus_key();
  assert(key.algorithm_id == PQAlgorithmId::mldsa44);
  assert(key.public_key.size() == mldsa44_public_key_bytes);           // 1312
  const std::string msg = "consensus finality vote fixture";
  auto sig_opt = ks.sign_consensus(msg);
  assert(sig_opt.has_value() && sig_opt->signature.size() == mldsa44_signature_bytes);  // 2420
  const std::string& sig = sig_opt->signature;

  // production signer -> production verifier, under the consensus context: VALID
  assert(verify_mldsa44(msg, consensus_sign_context, sig, key.public_key) == VerifyResult::valid);
  // context substitution (the frozen boundary): a consensus sig must NOT verify under a wallet context
  assert(verify_mldsa44(msg, "tos.pq.wallet.v1", sig, key.public_key) == VerifyResult::invalid);
  // tampered signature: invalid
  { std::string bad = sig; bad[0] ^= 1;
    assert(verify_mldsa44(msg, consensus_sign_context, bad, key.public_key) == VerifyResult::invalid); }
  // wrong message: invalid
  assert(verify_mldsa44("different message", consensus_sign_context, sig, key.public_key) == VerifyResult::invalid);

  // deterministic keypair from a fixed seed (test vectors / recovery)
  const std::string seed(mldsa44_public_key_bytes ? 32 : 32, '\x2a');
  auto a = ValidatorPQKeyStore::from_seed(seed), b = ValidatorPQKeyStore::from_seed(seed);
  assert(a.has_value() && b.has_value());
  assert(a->consensus_key().public_key == b->consensus_key().public_key);
  assert(a->consensus_key().key_id == b->consensus_key().key_id);
  assert(!ValidatorPQKeyStore::from_seed(std::string(31, 'x')).has_value());  // bad seed length refused

  printf("PQ_SIGNER_N1_OK signer->verifier valid; context-substitution+tamper+wrongmsg rejected; seed deterministic\n");
  return 0;
}
