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
    (
        "proof-shape-bits",
        "pq-validator.fc",
        "  if (cs.slice_bits() != 5) {",
        "  if (false) {",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    (
        "proof-shape-refs",
        "pq-validator.fc",
        "  if (cs.slice_refs() != 2) {",
        "  if (false) {",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    (
        "proof-shape-tag",
        "pq-validator.fc",
        "  if (cs~load_uint(5) != pq::state_init_shape) {",
        "  if (cs~load_uint(5) == 999) {",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    (
        "proof-pruned-code",
        "pq-validator.fc",
        "  if (pq::cell_level(code) != 1) {",
        "  if (false) {",
        "controller_admission_sandbox",
        "each_refusal_is_reachable",
    ),
    (
        "proof-address-binding",
        "pq-validator.fc",
        "  if (pq::hash_level0(proof) != expected_address) {",
        "  if (false) {",
        "elector_sandbox",
        "a_stake_carrying_another_accounts_proof",
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
        "elector-proof-required",
        "elector-code.fc",
        "    if (cell_null?(controller_proof)) {\n      return return_stake(s_addr, query_id, 8);\n    }",
        "    if (false) {\n      return return_stake(s_addr, query_id, 8);\n    }",
        "elector_sandbox",
        "a_stake_carrying_another_accounts_proof",
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
    (
        "config-ceiling-refusal",
        "config-code.fc",
        "  (cfg_dict, int installed) = install_param(cfg_dict, param_index, param_value);\n    throw_unless(45, installed);",
        "  (cfg_dict, int installed) = install_param(cfg_dict, param_index, param_value);\n    throw_unless(45, true);",
        "elector_sandbox",
        "the_controller_policy_cannot_grow",
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
