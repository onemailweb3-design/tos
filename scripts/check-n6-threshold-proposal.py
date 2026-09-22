#!/usr/bin/env python3
"""Keep the N6 threshold proposal tied to authoritative source facts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"N6_THRESHOLD_PROPOSAL_FAILURE: {message}", file=sys.stderr)
    raise SystemExit(1)


def collapsed(path: Path) -> str:
    """Return source text with formatting-only whitespace made irrelevant."""
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8")).strip()


root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
proposal_path = root / "doc/pq-native/N6-ACCEPTANCE-CRITERIA-PROPOSAL.json"
criteria_path = root / "doc/pq-native/N6-ACCEPTANCE-CRITERIA.json"
proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
criteria = json.loads(criteria_path.read_text(encoding="utf-8"))

if proposal.get("status") != "REVIEW_PROPOSAL_NOT_ACCEPTANCE_CRITERIA":
    fail("proposal can be mistaken for accepted launch criteria")
if set(proposal.get("owner_decisions", {})) != {"release_hardware_profile", "headroom_fractions"}:
    fail("proposal must leave exactly hardware profile and headroom fractions to the owner")
hardware = proposal["owner_decisions"]["release_hardware_profile"]
if hardware.get("status") != "OWNER_DECISION_REQUIRED" or set(
    hardware.get("required_fields", [])
) != {
    "cpu_model",
    "cpu_governor",
    "turbo_or_boost_enabled",
    "memory",
    "storage",
    "network_link",
}:
    fail("release hardware proposal does not pin CPU governor and turbo/boost policy")
if "throttling governor" not in hardware.get("rationale", ""):
    fail("release hardware proposal does not explain why frequency policy affects timing evidence")

headroom = proposal["owner_decisions"]["headroom_fractions"]
expected_headroom = {
    "finality_window": 0.50,
    "block_signature_timeout": 0.50,
    "lite_query_timeout": 0.50,
    "authority_slot": 0.80,
    "cpu": 0.35,
    "rss": 0.30,
    "network": 0.50,
    "disk_busy": 0.40,
    "finalization_backpressure": 0.90,
}
if headroom.get("status") != "OWNER_ACCEPTED" or headroom.get("values") != expected_headroom:
    fail("owner-accepted headroom fractions changed or are not marked accepted")
if set(headroom.get("rationale", {})) != {
    "timing_windows",
    "authority_slot",
    "resources",
    "finalization_backpressure",
}:
    fail("owner-accepted headroom fractions do not carry the required rationale")

required_criteria = set(criteria) - {"threshold_rationale"}
proposed_criteria = proposal.get("proposed_criteria", {})
if set(proposed_criteria) != required_criteria:
    missing = sorted(required_criteria - set(proposed_criteria))
    extra = sorted(set(proposed_criteria) - required_criteria)
    fail(f"criteria coverage differs: missing={missing} extra={extra}")
for name, entry in proposed_criteria.items():
    if not isinstance(entry, dict) or not entry.get("rationale"):
        fail(f"{name} has no threshold rationale")

positive_fields = [
    name
    for name in required_criteria
    if name.startswith("max_") and name != "max_unbounded_memory_slope_bytes_per_hour"
]
if criteria.get("release_hardware_profile") != "OWNER_REVIEW_REQUIRED":
    fail("live criteria no longer carry the owner-review hardware sentinel")
for name in positive_fields:
    if criteria.get(name) != 0:
        fail(f"live criteria field {name} was populated before owner review")

facts = proposal["source_facts"]
expected_facts = {
    "simplex_target_rate_ms": 400,
    "simplex_first_block_timeout_ms": 1000,
    "simplex_slots_per_leader_window": 4,
    "simplex_first_leader_window_ms": 2600,
    "simplex_standstill_timeout_ms": 10000,
    "block_signature_context_timeout_ms": 2000,
    "lite_query_timeout_ms": 10000,
    "maximum_boxed_finality_carrier_bytes": 984260,
    "pending_finality_public_carrier_shares": 16,
    "pending_finality_validator_carrier_shares": 400,
    "pending_finality_minimum_charge_bytes": 4096,
    "pending_finality_total_bytes": 409452160,
    "pending_finality_maximum_candidates": 99963,
}
if facts != expected_facts:
    fail("recorded source facts or their arithmetic changed without review")

zerostate = collapsed(root / "crypto/smartcont/gen-zerostate.fif")
if zerostate.count("<b 400 32 u, b> <s 0 rot 8 udict! drop") != 2:
    fail("authoritative masterchain/shard target_rate is no longer 400 ms")
if zerostate.count("<b 1000 32 u, b> <s 1 rot 8 udict! drop") != 2:
    fail("authoritative masterchain/shard first_block_timeout is no longer 1000 ms")
if zerostate.count("<b x{22} s, 0 5 u, 2 2 u, 1 1 u, 4 32 u, swap dict, b>") != 2:
    fail("authoritative masterchain/shard Simplex v2 leader-window configuration changed")

types = collapsed(root / "tos/tos-types.h")
if "duration_fn(8, standstill_timeout, 10'000)" not in types:
    fail("ConfigParam30 standstill timeout source changed")
manager = (root / "validator/manager.cpp").read_text(encoding="utf-8")
if not re.search(
    r'create_actor<ValidateBroadcast>\("broadcast-sigcheck".*?Timestamp::in\(2\.0\)', manager, re.S
):
    fail("production block-signature context timeout is no longer two seconds")
lite = (root / "lite-client/lite-client.cpp").read_text(encoding="utf-8")
if not re.search(r'ExtClient::send_query, "query".*?Timestamp::in\(10\.0\)', lite, re.S):
    fail("production lite query timeout is no longer ten seconds")
limits = collapsed(root / "crypto/block/pq-signature-limits.h")
if "pq_block_finality_broadcast_max_bytes = 984260" not in limits:
    fail("maximum boxed finality carrier source changed")
policy = collapsed(root / "validator/finality-cache-policy.h")
for marker in (
    "pending_finality_minimum_charge_bytes = 4096",
    "pending_finality_public_candidate_slots = 16",
    "pending_finality_max_validator_senders = tos::pq::PQConsensusLimits{}.max_certificate_signers",
):
    if marker not in policy:
        fail(f"pending-finality resource derivation source changed: {marker}")
pq_consensus = collapsed(root / "crypto/pq/pq-consensus.h")
if "max_certificate_signers = 400" not in pq_consensus:
    fail("structural validator-reserved sender count changed")

if (
    proposed_criteria["max_pending_finality_bytes"]["proposal"]
    != facts["pending_finality_total_bytes"]
):
    fail("pending-finality byte proposal is not the enforced two-pool bound")
if (
    proposed_criteria["max_pending_finality_candidates"]["proposal"]
    != facts["pending_finality_maximum_candidates"]
):
    fail(
        "pending-finality candidate proposal is not derived from the byte pools and minimum charge"
    )

expected_resolved_proposals = {
    "max_p99_persisted_finality_ms": (1300, "floor(2600 * (1 - headroom_fractions.finality_window))"),
    "max_p99_block_signature_verify_ms": (
        1000,
        "floor(2000 * (1 - headroom_fractions.block_signature_timeout))",
    ),
    "max_p99_lite_verify_ms": (5000, "floor(10000 * (1 - headroom_fractions.lite_query_timeout))"),
    "max_authority_classification_p99_ms": (
        80,
        "floor(400 * (1 - headroom_fractions.authority_slot))",
    ),
    "max_finalized_height_stall_ms": (5000, "floor(10000 * (1 - headroom_fractions.finality_window))"),
    "max_cpu_fraction": (0.65, "1 - headroom_fractions.cpu"),
    "max_rss_fraction": (0.70, "1 - headroom_fractions.rss"),
    "max_network_fraction": (0.50, "1 - headroom_fractions.network"),
    "max_disk_busy_fraction": (0.60, "1 - headroom_fractions.disk_busy"),
    "max_finalization_backpressure_fraction": (0.10, "1 - headroom_fractions.finalization_backpressure"),
}
for name, (value, formula) in expected_resolved_proposals.items():
    entry = proposed_criteria[name]
    if entry.get("proposal") != value or entry.get("formula") != formula:
        fail(f"{name} no longer matches the owner-accepted headroom derivation")

print(
    "N6_THRESHOLD_PROPOSAL_OK: owner-accepted headroom is resolved; live criteria remain hardware-profile blocked"
)
