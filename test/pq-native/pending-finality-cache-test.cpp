#include <iostream>
#include <string>
#include <vector>

#include "validator/finality-cache-policy.h"

#include "pq-block-signature-test-common.h"

namespace {

using pq_block_signature_test::candidate;
using pq_block_signature_test::clone_pairs;
using pq_block_signature_test::Fixture;
using pq_block_signature_test::require_ok;

struct ProcessingResult {
  bool accepted{false};
  std::vector<const block::BlockSignatureSet*> attempted;
};

ProcessingResult process_finality_candidates(const std::vector<td::Ref<block::BlockSignatureSet>>& arrivals,
                                             const block::PQFinalityVerificationContext& context) {
  tos::validator::PendingFinalityCandidates<td::Ref<block::BlockSignatureSet>, 4> candidates;
  for (const auto& signature_set : arrivals) {
    if (candidates.admit(signature_set, false, true) == tos::validator::PendingFinalityAdmission::Keep) {
      return {};
    }
  }
  ProcessingResult result;
  while (auto candidate = candidates.begin_processing()) {
    result.attempted.push_back(candidate->evidence.get());
    bool accepted = block::verify_pq_finality(context, *candidate->evidence, block::FinalityRole::Final).is_ok();
    candidates.complete_front(accepted);
    if (accepted) {
      result.accepted = true;
      return result;
    }
  }
  return result;
}

}  // namespace

int main() {
  tos::validator::PendingFinalityCandidates<int, 2> bound_check;
  if (bound_check.admit(1, false, true) != tos::validator::PendingFinalityAdmission::Replace ||
      bound_check.admit(2, false, true) != tos::validator::PendingFinalityAdmission::Append ||
      bound_check.admit(3, false, true) != tos::validator::PendingFinalityAdmission::Keep || bound_check.size() != 2) {
    std::cerr << "PENDING_FINALITY_BOUND_FAILURE: unverified candidate bound was not enforced\n";
    return 1;
  }

  Fixture fixture;
  auto candidate_data = candidate(fixture.id);
  const std::vector<std::size_t> quorum_signers{0, 1};
  auto valid_pairs = fixture.sign(quorum_signers, fixture.session, Fixture::slot, candidate_data, true, fixture.id);
  auto weight = fixture.weight_of(quorum_signers);
  auto valid = require_ok(fixture.persisted_final(valid_pairs, fixture.session, Fixture::slot, candidate_data, weight,
                                                  fixture.validator_set->get_validator_set_hash(),
                                                  fixture.validator_set->get_catchain_seqno(), fixture.validator_set),
                          "valid-final");
  auto invalid_pairs = clone_pairs(valid_pairs);
  invalid_pairs.front().signature.data()[0] ^= 1;
  auto invalid = require_ok(fixture.persisted_final(invalid_pairs, fixture.session, Fixture::slot, candidate_data,
                                                    weight, fixture.validator_set->get_validator_set_hash(),
                                                    fixture.validator_set->get_catchain_seqno(), fixture.validator_set),
                            "invalid-final");
  const block::PQFinalityVerificationContext context{fixture.validator_set, fixture.id, fixture.session};
  auto positive_control = block::verify_pq_finality(context, *valid, block::FinalityRole::Final);
  if (positive_control.is_error()) {
    std::cerr << "PENDING_FINALITY_POSITIVE_CONTROL_FAILURE: " << positive_control.error().message().str() << "\n";
    return 1;
  }
  auto negative_control = block::verify_pq_finality(context, *invalid, block::FinalityRole::Final);
  if (negative_control.is_ok() ||
      negative_control.error().message().str().find("pq signatures: invalid signature") == std::string::npos) {
    std::cerr
        << "PENDING_FINALITY_NEGATIVE_CONTROL_FAILURE: corrupted final was not rejected as an invalid signature\n";
    return 1;
  }

  // Check the good-first ordering first. Reversing candidate processing must
  // fail this assertion before the bad-first retry assertion can shadow it.
  auto good_then_bad = process_finality_candidates({valid, invalid}, context);
  if (!good_then_bad.accepted || good_then_bad.attempted.size() != 1 || good_then_bad.attempted[0] != valid.get()) {
    std::cerr << "PENDING_FINALITY_ORDER_FAILURE: later bad final ran before the earlier valid final\n";
    return 1;
  }
  auto bad_then_good = process_finality_candidates({invalid, valid}, context);
  if (!bad_then_good.accepted || bad_then_good.attempted.size() != 2 || bad_then_good.attempted[0] != invalid.get() ||
      bad_then_good.attempted[1] != valid.get()) {
    std::cerr << "PENDING_FINALITY_ORDER_FAILURE: bad final displaced the later valid final\n";
    return 1;
  }
  std::cout << "PENDING_FINALITY_ORDER_OK: first cryptographically valid final accepted in both arrival orders\n";
  return 0;
}
