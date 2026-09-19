#!/usr/bin/env python3
"""A guard nothing reaches is decoration, whatever its comment says.

Each mutation below removes one rule the validator-controller work added and requires a
test to go red for it. A mutation that survives is reported as a failure: either the rule
is unreachable, or nothing is holding it.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SMARTCONT = ROOT / "crypto/smartcont"
MANIFEST = ROOT / "tosctl/src/Cargo.toml"

# name, file, the text a rule lives in, what removing it looks like, test binary, filter
MUTANTS = [
    (
        "controller-network",
        "validator-controller-v1.fc",
        "throw_unless(ctl::error::wrong_network, global_id == pq::global_id());",
        "throw_unless(ctl::error::wrong_network, true);",
        "validator_controller_sandbox",
        "every_field_of_an_authorisation",
    ),
    (
        "controller-epoch",
        "validator-controller-v1.fc",
        "throw_unless(ctl::error::stale_epoch, epoch == stored_epoch);",
        "throw_unless(ctl::error::stale_epoch, true);",
        "validator_controller_sandbox",
        "every_field_of_an_authorisation",
    ),
    (
        "controller-nonce",
        "validator-controller-v1.fc",
        "throw_unless(ctl::error::bad_nonce, nonce == stored_nonce);",
        "throw_unless(ctl::error::bad_nonce, true);",
        "validator_controller_sandbox",
        "an_authorised_send_happens_once",
    ),
    (
        "controller-expiry-past",
        "validator-controller-v1.fc",
        "throw_unless(ctl::error::expired, valid_until > now());",
        "throw_unless(ctl::error::expired, true);",
        "validator_controller_sandbox",
        "every_field_of_an_authorisation",
    ),
    (
        "controller-expiry-window",
        "validator-controller-v1.fc",
        "throw_unless(ctl::error::expired, valid_until <= now() + ctl::max_ttl);",
        "throw_unless(ctl::error::expired, true);",
        "validator_controller_sandbox",
        "every_field_of_an_authorisation",
    ),
    (
        "controller-kind",
        "validator-controller-v1.fc",
        "throw_unless(ctl::error::bad_kind, (kind == ctl::kind::send) | (kind == ctl::kind::rotate_root));",
        "throw_unless(ctl::error::bad_kind, true);",
        "validator_controller_sandbox",
        "every_field_of_an_authorisation",
    ),
    (
        "controller-stray-cosignature",
        "validator-controller-v1.fc",
        "throw_unless(ctl::error::bad_cosignature, cell_null?(cosignature));",
        "throw_unless(ctl::error::bad_cosignature, true);",
        "validator_controller_sandbox",
        "every_field_of_an_authorisation",
    ),
    (
        "controller-destroy-mode",
        "validator-controller-v1.fc",
        "throw_if(ctl::error::bad_action, mode & 44);",
        "throw_if(ctl::error::bad_action, false);",
        "validator_controller_sandbox",
        "every_field_of_an_authorisation",
    ),
    (
        "controller-root-signature",
        "validator-controller-v1.fc",
        "    throw(ctl::error::bad_signature);",
        "    return ();",
        "validator_controller_sandbox",
        "every_field_of_an_authorisation",
    ),
    (
        "controller-successor-proof",
        "validator-controller-v1.fc",
        "    throw(ctl::error::bad_cosignature);",
        "    return ();",
        "validator_controller_sandbox",
        "a_root_rotation_needs_both",
    ),
    # ---------------------------------------------------------------------------
    # The birth witness
    #
    # A first stake carries four numbers and the elector rebuilds the state init its
    # sender was deployed with. Each rule below is one the reconstruction rests on, and
    # none of them announces itself when it stops holding: a witness that is believed
    # rather than checked admits an account nobody deployed as a validator controller.
    # ---------------------------------------------------------------------------
    (
        "witness-shape-bits",
        "pq-validator.fc",
        "  if (cs.slice_bits() != pq::witness_bits) {",
        "  if (false) {",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    (
        "witness-shape-refs",
        "pq-validator.fc",
        "  if (cs.slice_refs() != 0) {",
        "  if (false) {",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    # The rule that a witness must be ordinary has no mutation here, because no input
    # kills it. An exotic cell cannot be 544 bits with no references: a pruned branch is
    # 288 or 560, a library reference is 264, and the two Merkle types carry references.
    # So the bit and reference rules refuse every exotic witness first, and the machine
    # refuses a pruned one before the contract sees it at all. The check stays -- it is
    # cheap and says what is meant -- but a mutation of it would survive, and a surviving
    # mutation in the list is worth less than this sentence.
    (
        "witness-code-depth-bound",
        "pq-validator.fc",
        "  if (code_depth > pq::max_child_depth) {",
        "  if (false) {",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    (
        "witness-data-depth-bound",
        "pq-validator.fc",
        "  if (data_depth > pq::max_child_depth) {",
        "  if (false) {",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    (
        "witness-branch-type",
        "pq-validator.fc",
        "    .store_uint(1, 8)      ;; PrunedBranch",
        "    .store_uint(2, 8)      ;; PrunedBranch",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    (
        "witness-branch-level",
        "pq-validator.fc",
        "    .store_uint(1, 8)      ;; one level",
        "    .store_uint(3, 8)      ;; one level",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    (
        "witness-state-init-shape",
        "pq-validator.fc",
        "    .store_uint(pq::state_init_shape, 5)",
        "    .store_uint(0, 5)",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    (
        "witness-address-binding",
        "pq-validator.fc",
        "  if (pq::hash_level0(rebuilt) != expected_address) {",
        "  if (false) {",
        "elector_sandbox",
        "a_stake_carrying_another_accounts_witness",
    ),
    (
        # The reconstruction must commit at level zero. `cell_hash` is the highest-level
        # hash, which for a tree holding pruned branches is a different number, and using
        # it would make every honest witness fail while an attacker's choice of depth
        # stopped mattering.
        "witness-level-zero-hash",
        "pq-validator.fc",
        "  if (pq::hash_level0(rebuilt) != expected_address) {",
        "  if (cell_hash(rebuilt) != expected_address) {",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    (
        "policy-absent-fails-closed",
        "pq-validator.fc",
        "    return (null(), false);",
        "    return (null(), true);",
        "elector_sandbox",
        "a_stake_from_an_unadmitted_controller",
    ),
    (
        "policy-lookup",
        "pq-validator.fc",
        "int pq::controller_admitted?(cell codes, int code_hash) inline {\n  (_, int found) = codes.udict_get?(256, code_hash);\n  return found;\n}",
        "int pq::controller_admitted?(cell codes, int code_hash) inline {\n  (_, int found) = codes.udict_get?(256, code_hash);\n  return true;\n}",
        "elector_sandbox",
        "a_stake_from_an_unadmitted_controller",
    ),
    (
        "elector-witness-required",
        "elector-code.fc",
        "    if (cell_null?(controller_birth_witness)) {\n      return return_stake(s_addr, query_id, 8);\n    }",
        "    if (false) {\n      return return_stake(s_addr, query_id, 8);\n    }",
        "elector_sandbox",
        "a_stake_carrying_another_accounts_witness",
    ),
    (
        "elector-retirement",
        "elector-code.fc",
        "    ifnot (pq::controller_admitted?(admitted_codes, held_code)) {\n      return return_stake(s_addr, query_id, 12);\n    }",
        "    ifnot (true) {\n      return return_stake(s_addr, query_id, 12);\n    }",
        "elector_sandbox",
        "retiring_a_controller_code",
    ),
    (
        "elector-effective-floor",
        "elector-code.fc",
        "  int effective = pq::effective_stake(pq_by_code, admitted_codes);",
        "  int effective = total_stake;",
        "elector_sandbox",
        "a_retired_profile_stops_raising",
    ),
    # One rule, reached by the administrator action and by an accepted proposal alike.
    (
        "config-ceiling",
        "config-code.fc",
        "    ifnot (valid_controller_policy?(param_val)) {",
        "    ifnot (false) {",
        "elector_sandbox",
        "the_controller_policy_cannot_grow",
    ),
    # ---------------------------------------------------------------------------
    # The post-quantum authority cutover
    #
    # Each of these is a rule that, if it stopped holding, would leave the chain
    # authorising validators with something other than the current post-quantum set.
    # None of them announces itself when it breaks: a vote counted for the wrong
    # validator, a set installed that the node cannot read, an operation that quietly
    # comes back.
    # ---------------------------------------------------------------------------
    (
        "vote-signature",
        "config-code.fc",
        "    throw_unless(34, pq_check_mldsa44(\n      pq::config_vote_preimage(vset.cell_hash(), validator_id, idx, phash),",
        "    throw_unless(34, true | pq_check_mldsa44(\n      pq::config_vote_preimage(vset.cell_hash(), validator_id, idx, phash),",
        "elector_sandbox",
        "a_vote_signed_by_a_key_that_is_not_at_that_index_is_refused",
    ),
    (
        "vote-identity-from-the-set",
        "pq-validator.fc",
        "    .store_uint(validator_set_id, 256)\n    .store_uint(validator_id, 256)\n    .store_uint(idx, 16)\n    .store_uint(proposal_hash, 256)",
        "    .store_uint(validator_set_id, 256)\n    .store_uint(idx, 16)\n    .store_uint(proposal_hash, 256)",
        "elector_sandbox",
        "a_validator_votes_for_a_proposal_with_the_key_in_the_current_set",
    ),
    (
        "vote-bound-to-its-set",
        "pq-validator.fc",
        "    .store_uint(pq::tag::config_vote_sign, 32)\n    .store_int(pq::global_id(), 32)\n    .store_uint(validator_set_id, 256)",
        "    .store_uint(pq::tag::config_vote_sign, 32)\n    .store_int(pq::global_id(), 32)\n    .store_uint(0, 256)",
        "elector_sandbox",
        "a_validator_votes_for_a_proposal_with_the_key_in_the_current_set",
    ),
    (
        "vote-funding",
        "config-code.fc",
        "    throw_unless(47, msg_value >= pq::verification_value(-1));\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "    throw_unless(47, true);\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "elector_sandbox",
        "an_underfunded_configuration_vote_is_refused_before_the_verification",
    ),
    (
        "vote-minimum-value",
        "config-code.fc",
        "    throw_unless(47, msg_value >= pq::verification_value(-1));\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "    throw_unless(47, true);\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "elector_sandbox",
        "the_minimum_value_a_configuration_vote_must_carry",
    ),
    (
        "complaint-vote-funding",
        "elector-code.fc",
        "    throw_unless(47, msg_value >= pq::verification_value(-1));\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "    throw_unless(47, true);\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "elector_sandbox",
        "an_underfunded_complaint_vote_is_refused_before_the_verification",
    ),
    (
        "complaint-vote-minimum-value",
        "elector-code.fc",
        "    throw_unless(47, msg_value >= pq::verification_value(-1));\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "    throw_unless(47, true);\n\n    (cell vset, int total_weight, cell list) = get_current_vset();",
        "elector_sandbox",
        "the_minimum_value_a_complaint_vote_must_carry",
    ),
    (
        "complaint-vote-signature",
        "elector-code.fc",
        "    throw_unless(34, pq_check_mldsa44(\n      pq::complaint_vote_preimage(vset.cell_hash(), validator_id, idx, elect_id, chash),",
        "    throw_unless(34, true | pq_check_mldsa44(\n      pq::complaint_vote_preimage(vset.cell_hash(), validator_id, idx, elect_id, chash),",
        "elector_sandbox",
        "a_complaint_vote_signed_by_another_validator_is_refused",
    ),
    (
        "complaint-vote-identity",
        "pq-validator.fc",
        "    .store_uint(validator_set_id, 256)\n    .store_uint(validator_id, 256)\n    .store_uint(idx, 16)\n    .store_uint(election_id, 32)",
        "    .store_uint(validator_set_id, 256)\n    .store_uint(idx, 16)\n    .store_uint(election_id, 32)",
        "elector_sandbox",
        "a_validator_votes_to_punish_a_validator_of_a_past_election",
    ),
    (
        "set-duplicate-validator",
        "config-code.fc",
        "      (_, int duplicate_validator) = seen_validators.udict_get?(256, validator_id);\n      throw_if(9, duplicate_validator);",
        "      (_, int duplicate_validator) = seen_validators.udict_get?(256, validator_id);\n      throw_if(9, false);",
        "elector_sandbox",
        "a_set_the_node_would_refuse_is_refused_before_it_is_installed",
    ),
    (
        "set-duplicate-key",
        "config-code.fc",
        "      (_, int duplicate_key) = seen_keys.udict_get?(256, key_id);\n      throw_if(9, duplicate_key);",
        "      (_, int duplicate_key) = seen_keys.udict_get?(256, key_id);\n      throw_if(9, false);",
        "elector_sandbox",
        "a_set_the_node_would_refuse_is_refused_before_it_is_installed",
    ),
    (
        "set-weight-sum",
        "config-code.fc",
        "  throw_unless(9, weight_sum == total_weight);",
        "  throw_unless(9, true);",
        "elector_sandbox",
        "a_set_the_node_would_refuse_is_refused_before_it_is_installed",
    ),
    (
        "set-count-agreement",
        "config-code.fc",
        "  throw_unless(9, counted == total);",
        "  throw_unless(9, true);",
        "elector_sandbox",
        "a_set_the_node_would_refuse_is_refused_before_it_is_installed",
    ),
    (
        "no-administrator-appointment",
        "config-code.fc",
        "  if (param_id == config::appoint_administrator_param) {\n    return (cfg_dict, false);\n  }",
        "  if (false) {\n    return (cfg_dict, false);\n  }",
        "elector_sandbox",
        "governance_cannot_vote_itself_an_administrator",
    ),
    (
        "no-external-authority",
        "config-code.fc",
        "() recv_external(slice in_msg) impure {\n  throw(32);\n}",
        "() recv_external(slice in_msg) impure {\n  accept_message();\n}",
        "elector_sandbox",
        "an_external_validator_vote_has_no_authorization_path",
    ),
    (
        "readiness-on-effective-stake",
        "elector-code.fc",
        "  if (pq::effective_stake(pq_by_code, admitted_codes) < min_total_stake) {",
        "  if (total_stake < min_total_stake) {",
        "elector_sandbox",
        "a_retired_profile_cannot_make_an_election_look_ready",
    ),
]


def build():
    subprocess.run(
        ["cmake", "--build", "build", "--target", "gen_fif", "-j4"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )


def run(binary, filter_):
    return subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(MANIFEST),
            "-p",
            "contracts",
            "--test",
            binary,
            filter_,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "CARGO_TARGET_DIR": str(ROOT / "tosctl/src/target")},
    ).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--only", default=None, help="run one mutation by name")
    args = parser.parse_args()

    mutants = [m for m in MUTANTS if m[2] is not None]
    if args.only:
        mutants = [m for m in mutants if m[0] == args.only]

    build()
    reports, survivors = [], []
    for name, filename, before, after, binary, filter_ in mutants:
        source = SMARTCONT / filename
        original = source.read_text()
        if original.count(before) != 1:
            raise ValueError(f"{name}: the rule must appear exactly once in {filename}")
        try:
            source.write_text(original.replace(before, after))
            build()  # A contract that no longer compiles is not a killed mutation.
            killed = run(binary, filter_) != 0
        finally:
            source.write_text(original)
        reports.append({"guard": name, "killed": killed, "test": f"{binary}::{filter_}"})
        if not killed:
            survivors.append(name)
        print(f"{'killed  ' if killed else 'SURVIVED'} {name}", flush=True)

    build()
    args.out.write_text(json.dumps(reports, indent=2, sort_keys=True) + "\n")
    if survivors:
        print("surviving mutations: " + ", ".join(survivors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
