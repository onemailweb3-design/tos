#include <iostream>
#include <string>
#include <vector>

#include "validator/finality-cache-policy.h"
#include "validator/full-node-serializer.hpp"
#include "validator/pending-finality-ingress.h"

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
  tos::validator::PendingFinalityStore<int, int, td::Ref<block::BlockSignatureSet>> store;
  int sender = 0;
  for (const auto& signature_set : arrivals) {
    auto serialized_bytes = serialize_tl_object(signature_set->tl(), true).size();
    if (!store.admit(0, sender++, signature_set, serialized_bytes, false, true).admitted()) {
      return {};
    }
  }
  auto* candidates = store.get_if_exists(0);
  ProcessingResult result;
  while (auto candidate = candidates->begin_processing()) {
    result.attempted.push_back(candidate->evidence.get());
    bool accepted = block::verify_pq_finality(context, *candidate->evidence, block::FinalityRole::Final).is_ok();
    candidates->complete_front(accepted);
    if (accepted) {
      result.accepted = true;
      return result;
    }
  }
  return result;
}

}  // namespace

int main() {
  if (tos::validator::pending_finality_failure_action(tos::ErrorCode::timeout, 1) !=
      tos::validator::PendingFinalityFailureAction::Retry) {
    std::cerr << "PENDING_FINALITY_TIMEOUT_CLASSIFICATION_FAILURE: verification timeout was treated as permanent\n";
    return 1;
  }
  if (!tos::validator::pending_finality_exceeds_budget(1, 2, 0, 10)) {
    std::cerr << "PENDING_FINALITY_BUDGET_ARITHMETIC_FAILURE: removed bytes exceeded current accounting without rejection\n";
    return 1;
  }

  tos::validator::PendingFinalityStore<int, int, int> permanent_failure;
  permanent_failure.admit(0, 0, 7, 4096, false, true);
  auto* permanent_candidates = permanent_failure.get_if_exists(0);
  permanent_candidates->begin_processing();
  if (permanent_candidates->resolve_front_failure(tos::ErrorCode::protoviolation) !=
          tos::validator::PendingFinalityFailureAction::DiscardPermanent ||
      !permanent_candidates->empty()) {
    std::cerr << "PENDING_FINALITY_PERMANENT_FAILURE: inconsistent evidence was retained for retry\n";
    return 1;
  }

  tos::validator::PendingFinalityStore<int, int, int> exhausted_failure;
  exhausted_failure.admit(0, 0, 7, 4096, false, true);
  auto* exhausted_candidates = exhausted_failure.get_if_exists(0);
  for (std::size_t attempt = 1; attempt <= tos::validator::pending_finality_max_attempts; ++attempt) {
    if (exhausted_candidates->begin_processing() == nullptr) {
      std::cerr << "PENDING_FINALITY_RETRY_BOUND_FAILURE: candidate vanished before the retry bound\n";
      return 1;
    }
    auto action = exhausted_candidates->resolve_front_failure(tos::ErrorCode::notready);
    auto expected = attempt == tos::validator::pending_finality_max_attempts
                        ? tos::validator::PendingFinalityFailureAction::DiscardExhausted
                        : tos::validator::PendingFinalityFailureAction::Retry;
    if (action != expected) {
      std::cerr << "PENDING_FINALITY_RETRY_BOUND_FAILURE: transient candidate did not stop at attempt "
                << tos::validator::pending_finality_max_attempts << "\n";
      return 1;
    }
  }
  if (!exhausted_candidates->empty()) {
    std::cerr << "PENDING_FINALITY_RETRY_BOUND_FAILURE: exhausted candidate retained its sender slot\n";
    return 1;
  }

  auto peer = tos::PublicKeyHash::zero();
  auto missing_remote_bytes = tos::validator::prepare_pending_finality_ingress(&peer, 0);
  if (missing_remote_bytes.admitted() ||
      missing_remote_bytes.rejection != tos::validator::PendingFinalityIngressRejection::MissingRemoteByteCount) {
    std::cerr << "PENDING_FINALITY_INGRESS_ACCOUNTING_FAILURE: remote evidence without received bytes was admitted\n";
    return 1;
  }
  auto remote = tos::validator::prepare_pending_finality_ingress(&peer, 12345);
  if (!remote.admitted() || remote.sender.local || remote.sender.peer != peer || remote.accounted_bytes != 12345) {
    std::cerr << "PENDING_FINALITY_INGRESS_SENDER_FAILURE: authenticated peer was not charged to its own sender\n";
    return 1;
  }
  auto missing_local_measurement = tos::validator::prepare_pending_finality_ingress(nullptr, 0);
  if (missing_local_measurement.admitted() || missing_local_measurement.rejection !=
                                                    tos::validator::PendingFinalityIngressRejection::MissingLocalMeasurement) {
    std::cerr << "PENDING_FINALITY_INGRESS_ACCOUNTING_FAILURE: local evidence without a measurement was admitted\n";
    return 1;
  }
  auto local = tos::validator::prepare_pending_finality_ingress(nullptr, 0, 6789);
  if (!local.admitted() || !local.sender.local || local.accounted_bytes != 6789) {
    std::cerr << "PENDING_FINALITY_INGRESS_SENDER_FAILURE: local evidence did not retain its local attribution\n";
    return 1;
  }

  tos::validator::PendingFinalityStore<int, int, int> policy_rejection_check;
  if (!policy_rejection_check.admit(0, 0, 0, 1, true, true).admitted() ||
      policy_rejection_check.admit(0, 1, 1, 1, false, true).rejection !=
          tos::validator::PendingFinalityRejection::Policy) {
    std::cerr << "PENDING_FINALITY_POLICY_REJECTION_FAILURE: unverified evidence displaced verified finality\n";
    return 1;
  }

  tos::validator::PendingFinalityStore<int, int, int> sender_budget_check;
  if (!sender_budget_check
           .admit(1, 7, 1, tos::validator::pending_finality_sender_budget_bytes, false, true)
           .admitted() ||
      sender_budget_check.admit(2, 7, 2, 1, false, true).rejection !=
          tos::validator::PendingFinalityRejection::SenderBudget) {
    std::cerr << "PENDING_FINALITY_SENDER_BUDGET_FAILURE: one sender exceeded its 1048576-byte share\n";
    return 1;
  }
  tos::validator::PendingFinalityStore<int, int, int> total_budget_check;
  constexpr std::size_t senders_fitting_total = tos::validator::pending_finality_total_budget_bytes /
                                                 tos::validator::pending_finality_sender_budget_bytes;
  for (std::size_t i = 0; i < senders_fitting_total; ++i) {
    if (!total_budget_check
             .admit(static_cast<int>(i), static_cast<int>(i), static_cast<int>(i),
                    tos::validator::pending_finality_sender_budget_bytes, false, true)
             .admitted()) {
      std::cerr << "PENDING_FINALITY_TOTAL_BUDGET_FAILURE: store rejected bytes below its 16777216-byte budget\n";
      return 1;
    }
  }
  if (total_budget_check
          .admit(99, 99, 99, tos::validator::pending_finality_minimum_charge_bytes, false, true)
          .rejection != tos::validator::PendingFinalityRejection::TotalBudget) {
    std::cerr << "PENDING_FINALITY_TOTAL_BUDGET_FAILURE: store exceeded its 16777216-byte budget\n";
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
  auto valid_transport_id = tos::validator::fullnode::block_finality_broadcast_transport_id({fixture.id, valid});
  auto invalid_transport_id = tos::validator::fullnode::block_finality_broadcast_transport_id({fixture.id, invalid});
  if (valid_transport_id == invalid_transport_id) {
    std::cerr << "PENDING_FINALITY_TRANSPORT_DEDUP_FAILURE: invalid finality occupied the honest finality transport id\n";
    return 1;
  }
  const block::PQFinalityVerificationContext context{fixture.validator_set, fixture.id, fixture.session};

  tos::validator::PendingFinalityStore<int, int, td::Ref<block::BlockSignatureSet>> retry_then_accept;
  if (!retry_then_accept.admit(0, 0, valid, 4096, false, true).admitted()) {
    std::cerr << "PENDING_FINALITY_RETRY_FAILURE: valid certificate was not admitted\n";
    return 1;
  }
  auto* retry_candidates = retry_then_accept.get_if_exists(0);
  if (retry_candidates->begin_processing() == nullptr ||
      retry_candidates->resolve_front_failure(tos::ErrorCode::notready) !=
          tos::validator::PendingFinalityFailureAction::Retry ||
      retry_candidates->empty()) {
    std::cerr << "PENDING_FINALITY_RETRY_FAILURE: valid evidence was discarded while required state was not ready\n";
    return 1;
  }
  auto* retried = retry_candidates->begin_processing();
  if (retried == nullptr ||
      block::verify_pq_finality(context, *retried->evidence, block::FinalityRole::Final).is_error()) {
    std::cerr << "PENDING_FINALITY_RETRY_FAILURE: retained evidence was not valid on the later attempt\n";
    return 1;
  }
  retry_candidates->complete_front(true);
  if (!retry_candidates->empty()) {
    std::cerr << "PENDING_FINALITY_RETRY_FAILURE: a later successful attempt did not accept the evidence\n";
    return 1;
  }

  tos::validator::PendingFinalityStore<int, int, td::Ref<block::BlockSignatureSet>> isolated_store;
  auto invalid_bytes = serialize_tl_object(invalid->tl(), true).size();
  auto valid_bytes = serialize_tl_object(valid->tl(), true).size();
  constexpr int old_candidate_limit = 4;
  for (int i = 0; i < old_candidate_limit; ++i) {
    auto admission = isolated_store.admit(0, 1, invalid, invalid_bytes, false, true);
    if ((i == 0 && !admission.admitted()) ||
        (i != 0 && admission.rejection != tos::validator::PendingFinalityRejection::SenderAlreadyPending)) {
      std::cerr << "PENDING_FINALITY_SENDER_ISOLATION_FAILURE: one sender occupied more than one block candidate\n";
      return 1;
    }
  }
  if (!isolated_store.admit(0, 2, valid, valid_bytes, false, true).admitted() ||
      isolated_store.get_if_exists(0)->size() != 2) {
    std::cerr << "PENDING_FINALITY_SENDER_ISOLATION_FAILURE: honest sender was excluded by a Byzantine sender\n";
    return 1;
  }
  bool isolated_accepted = false;
  auto* isolated_candidates = isolated_store.get_if_exists(0);
  while (auto pending = isolated_candidates->begin_processing()) {
    bool accepted = block::verify_pq_finality(context, *pending->evidence, block::FinalityRole::Final).is_ok();
    isolated_candidates->complete_front(accepted);
    if (accepted) {
      isolated_accepted = true;
      break;
    }
  }
  if (!isolated_accepted) {
    std::cerr << "PENDING_FINALITY_SENDER_ISOLATION_FAILURE: honest finality was not accepted after Byzantine evidence\n";
    return 1;
  }
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
  std::cout << "PENDING_FINALITY_RETRY_OK: notready retained valid evidence and a later attempt accepted it\n";
  std::cout << "PENDING_FINALITY_TIMEOUT_CLASSIFICATION_OK: verification timeout remains transient\n";
  std::cout << "PENDING_FINALITY_PERMANENT_OK: protocol violation was discarded without retry\n";
  std::cout << "PENDING_FINALITY_RETRY_BOUND_OK: transient evidence freed its slot after "
            << tos::validator::pending_finality_max_attempts << " attempts\n";
  std::cout << "PENDING_FINALITY_INGRESS_OK: missing accounting fails closed and authenticated senders retain attribution\n";
  std::cout << "PENDING_FINALITY_TRANSPORT_DEDUP_OK: evidence-distinct finalities have distinct transport ids\n";
  std::cout << "PENDING_FINALITY_SENDER_ISOLATION_OK: four bad arrivals from one sender did not exclude another sender\n";
  std::cout << "PENDING_FINALITY_BYTE_BUDGET_OK: total=16777216 per_sender=1048576 minimum_charge=4096\n";
  return 0;
}
