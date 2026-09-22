#!/usr/bin/env python3
"""Fast contract gate for the N6.3 orchestrator and backend format."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/tostester/src"))

from tostester.n6_cluster import (  # noqa: E402
    analyze_consensus_milestones,
    analyze_live_finality,
    load_latency_profile,
    validate_latency_backend,
    validate_lite_transport_source,
    validate_node_isolation,
)
from tostester.process_backend import LocalProcessBackend, RemoteCommandBackend  # noqa: E402


def event(node: str, trace: str, stage: str, monotonic: int, wall: int, size: int | None = None):
    result = {
        "kind": "trace",
        "node_id": node,
        "trace_id": trace,
        "stage": stage,
        "monotonic_ns": monotonic,
        "wall_unix_ns": wall,
    }
    if size is not None:
        result["exact_bytes"] = size
    return result


async def check_backends(directory: Path) -> None:
    local = LocalProcessBackend()
    process = await local.spawn(
        "node-1", "/bin/sh", ["-c", "printf local"], directory, os.environ, capture_stdout=True
    )
    stdout, _ = await process.communicate()
    assert process.returncode == 0 and stdout == b"local"
    remote = RemoteCommandBackend({"node-1": [sys.executable, "-m", "tostester.remote_process"]})
    process = await remote.spawn(
        "node-1", "/bin/sh", ["-c", "printf remote"], directory, os.environ, capture_stdout=True
    )
    stdout, _ = await process.communicate()
    assert process.returncode == 0 and stdout == b"remote"
    assert local.manifest() == {"kind": "local-process"}
    assert remote.manifest() == {
        "kind": "remote-command",
        "nodes": ["node-1"],
        "provisioning": "external",
    }


def check_latency_profile_binding() -> None:
    launch = load_latency_profile(ROOT / "test/pq-native/n6-scale-profiles/launch-default.json")
    for manifest in (
        LocalProcessBackend().manifest(),
        {"kind": "remote-command"},
    ):
        try:
            validate_latency_backend(launch, manifest)
        except ValueError as error:
            if "declares the applied network profile" not in str(error):
                raise AssertionError(
                    f"unbound launch latency profile reported the wrong refusal: {error}"
                ) from error
        else:
            raise AssertionError(
                f"backend without an applied network profile was accepted: {manifest}"
            )
    validate_latency_backend(
        launch,
        {"kind": "remote-command", "network_profile": "launch-default"},
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        trace = "ab" * 32
        first = root / "node-a.jsonl"
        second = root / "node-b.jsonl"
        first.write_text(
            json.dumps(event("node-a", trace, "finality_broadcast_sent", 10, 100, 984260)) + "\n"
        )
        second.write_text(
            "\n".join(
                json.dumps(item)
                for item in (
                    event("node-b", trace, "peer_finality_broadcast_received", 20, 130, 984260),
                    event("node-b", trace, "peer_finality_verification_started", 27, 137),
                    event("node-b", trace, "peer_finality_broadcast_verified", 39, 149),
                )
            )
            + "\n"
        )
        evidence = analyze_live_finality([first, second])
        assert evidence.sender_node == "node-a" and evidence.verifier_node == "node-b"
        assert evidence.payload_bytes == 984260
        assert (evidence.propagation_ns, evidence.queueing_ns, evidence.verification_ns) == (
            30,
            7,
            12,
        )
        milestones_path = root / "milestones.jsonl"
        milestones_path.write_text(
            "\n".join(
                json.dumps(item)
                for item in (
                    event("node-a", trace, "candidate_generated", 10, 110),
                    event("node-a", trace, "notarization_certificate_observed", 20, 120),
                    event("node-a", trace, "finalization_certificate_observed", 30, 130),
                )
            )
            + "\n"
        )
        milestones = analyze_consensus_milestones([milestones_path], 100)
        assert (
            milestones.time_to_first_proposal_ns,
            milestones.time_to_first_notarization_certificate_ns,
            milestones.time_to_first_final_certificate_ns,
        ) == (10, 20, 30)
        validate_node_isolation(
            [
                {
                    "db_root": f"db-{index}",
                    "adnl_identity": f"adnl-{index}",
                    "ports": [1000 + index * 3 + offset for offset in range(3)],
                    "log": f"log-{index}",
                    "trace": f"trace-{index}",
                    "resource_monitor": f"resource-{index}",
                }
                for index in range(3)
            ]
        )
        validate_lite_transport_source(ROOT)
        asyncio.run(check_backends(root))
        check_latency_profile_binding()
        no_latency = load_latency_profile(
            ROOT / "test/pq-native/n6-scale-profiles/no-simulated-latency.json"
        )
        launch = load_latency_profile(ROOT / "test/pq-native/n6-scale-profiles/launch-default.json")
        assert no_latency.application == "none" and no_latency.one_way_latency_ms == [0.0, 0.0]
        assert launch.application == "external-network-shaping"
    print(
        "N6_CLUSTER_RUNNER_OK: local and remote-command backends share the manifest and evidence contract"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, RuntimeError, ValueError) as error:
        print(f"N6_CLUSTER_RUNNER_FAILURE: {error}", file=sys.stderr)
        raise SystemExit(1) from error
