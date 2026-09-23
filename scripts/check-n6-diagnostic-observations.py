#!/usr/bin/env python3
"""Keep open N6 diagnostic observations durable without making them release gates."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REQUIRED_OBSERVATION_IDS = frozenset(
    {"colocated-lite-query-timeouts", "colocated-launch-committee-skip-runs"}
)
REQUIRED_FIELDS = {
    "status",
    "observation",
    "observed_at",
    "diagnostic_question",
    "closure_condition",
}


def fail(message: str) -> None:
    raise RuntimeError(f"N6_DIAGNOSTIC_OBSERVATION_FAILURE: {message}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path = root / "doc/pq-native/N6-OPEN-DIAGNOSTIC-OBSERVATIONS.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        fail("schema_version must be 1")
    declared = set(payload.get("required_observation_ids", []))
    observations = payload.get("observations")
    if not isinstance(observations, dict):
        fail("observations must be an object")
    present = set(observations)
    if declared != present:
        fail(
            "required ids and observations differ; "
            f"missing={sorted(declared - present)} unexpected={sorted(present - declared)}"
        )
    if declared != REQUIRED_OBSERVATION_IDS:
        fail(
            "compiled required observation set changed; "
            f"missing={sorted(REQUIRED_OBSERVATION_IDS - declared)} "
            f"unexpected={sorted(declared - REQUIRED_OBSERVATION_IDS)}"
        )
    for observation_id, entry in observations.items():
        if not isinstance(entry, dict):
            fail(f"{observation_id} must be an object")
        missing_fields = REQUIRED_FIELDS - set(entry)
        if missing_fields:
            fail(f"{observation_id} is missing fields {sorted(missing_fields)}")
        if entry["status"] not in {"OPEN", "RESOLVED"}:
            fail(f"{observation_id} has invalid status {entry['status']!r}")
        for field in ("observation", "diagnostic_question", "closure_condition"):
            if not isinstance(entry[field], str) or not entry[field].strip():
                fail(f"{observation_id}.{field} must be a non-empty string")
        if entry["status"] == "RESOLVED" and not entry.get("resolved_by"):
            fail(f"resolved observation {observation_id} does not name resolved_by evidence")
    print(
        "N6_DIAGNOSTIC_OBSERVATIONS_OK: "
        f"validated {len(observations)} durable diagnostic observation"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
