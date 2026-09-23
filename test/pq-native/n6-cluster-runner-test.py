#!/usr/bin/env python3
"""Fast contract gate for the N6.3 orchestrator and backend format."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/tostester/src"))

from tostester.n6_cluster import (  # noqa: E402
    ObservedBlock,
    SustainedObservationConfig,
    _is_lite_transport_error,
    _masterchain_heights,
    _wait_all_heights,
    analyze_consensus_milestones,
    analyze_live_finality,
    load_latency_profile,
    require_agreed_masterchain_block,
    summarize_sustained_observation,
    validate_latency_backend,
    validate_lite_transport_source,
    validate_node_isolation,
)
from tostester.process_backend import LocalProcessBackend, RemoteCommandBackend  # noqa: E402


class ToslibError(Exception):
    __module__ = "toslib.toslibjson"

    def __init__(self, result):
        super().__init__()
        self.result = result

    @property
    def code(self):
        return self.result.code

    def __str__(self):
        return self.result.message


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


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
    require(
        process.returncode == 0 and stdout == b"local",
        "local process backend did not execute the requested command",
    )
    remote = RemoteCommandBackend({"node-1": [sys.executable, "-m", "tostester.remote_process"]})
    process = await remote.spawn(
        "node-1", "/bin/sh", ["-c", "printf remote"], directory, os.environ, capture_stdout=True
    )
    stdout, _ = await process.communicate()
    require(
        process.returncode == 0 and stdout == b"remote",
        "remote-command backend did not execute the requested command",
    )
    require(
        local.manifest() == {"kind": "local-process"},
        "local process backend manifest changed",
    )
    require(
        remote.manifest()
        == {
            "kind": "remote-command",
            "nodes": ["node-1"],
            "provisioning": "external",
        },
        "remote-command backend manifest changed",
    )


class FakeBlockClient:
    def __init__(
        self,
        root_hash: bytes,
        *,
        height: int = 7,
        info_transport_failures: int | None = 0,
    ):
        self.root_hash = root_hash
        self.height = height
        self.info_transport_failures = info_transport_failures
        self.info_calls = 0
        self.lookup_calls = 0

    def _transport_failure(self):
        return ToslibError(
            SimpleNamespace(
                code=500,
                message="LITE_SERVER_NETWORKtimeout for adnl query query",
            )
        )

    async def get_masterchain_info(self):
        self.info_calls += 1
        if self.info_transport_failures is None:
            raise self._transport_failure()
        if self.info_transport_failures > 0:
            self.info_transport_failures -= 1
            raise self._transport_failure()
        return SimpleNamespace(last=SimpleNamespace(seqno=self.height))

    async def lookup_block(self, *, workchain: int, shard: int, seqno: int):
        self.lookup_calls += 1
        return SimpleNamespace(
            workchain=workchain,
            shard=shard,
            seqno=seqno,
            root_hash=self.root_hash,
            file_hash=bytes([seqno]) * 32,
        )


async def check_sustained_agreement() -> None:
    canonical = bytes.fromhex("11" * 32)
    clients = {name: FakeBlockClient(canonical) for name in ("node-a", "node-b", "node-c")}
    block_id = await require_agreed_masterchain_block(clients, 7)
    require(",7):" in block_id, "agreed block id does not identify the requested height")

    clients["node-c"] = FakeBlockClient(bytes.fromhex("22" * 32))
    calls_before_disagreement = {name: client.lookup_calls for name, client in clients.items()}
    try:
        await require_agreed_masterchain_block(clients, 7)
    except RuntimeError as error:
        require(
            "block-id disagreement at height 7" in str(error),
            "block disagreement refusal does not name its height",
        )
        require(
            "node-a=" in str(error) and "node-c=" in str(error),
            "block disagreement refusal does not name the conflicting nodes",
        )
    else:
        raise AssertionError("nodes on different masterchain blocks were reported as agreeing")
    require(
        all(
            client.lookup_calls == calls_before_disagreement[name] + 1
            for name, client in clients.items()
        ),
        "block-id disagreement was retried instead of failing immediately",
    )


async def check_sustained_transport_retry() -> None:
    flaky = FakeBlockClient(bytes.fromhex("11" * 32), info_transport_failures=1)
    healthy = FakeBlockClient(bytes.fromhex("11" * 32))
    retry_counts: dict[str, dict[str, int]] = {}
    heights = await _masterchain_heights(
        {"flaky-node": flaky, "healthy-node": healthy},
        transport_retry_counts=retry_counts,
        transport_retry_budget_seconds=1.0,
        transport_retry_delay_seconds=0,
    )
    require(
        heights == {"flaky-node": 7, "healthy-node": 7} and flaky.info_calls == 2,
        "one transport timeout did not recover inside the retry budget",
    )
    require(
        retry_counts == {"flaky-node": {"get_masterchain_info": 1}},
        "recovered transport timeout was not counted by node and operation",
    )

    wrong_code = ToslibError(
        SimpleNamespace(code=400, message="LITE_SERVER_NETWORKtimeout for adnl query query")
    )
    require(
        not _is_lite_transport_error(wrong_code),
        "lite transport classifier ignored the production status code",
    )

    silent = FakeBlockClient(bytes.fromhex("11" * 32), info_transport_failures=None)
    try:
        await _masterchain_heights(
            {"silent-node": silent},
            transport_retry_budget_seconds=0,
            transport_retry_delay_seconds=0,
        )
    except TimeoutError as error:
        require("silent-node" in str(error), "transport exhaustion did not name the silent node")
        require(
            "transport retry budget" in str(error),
            "transport exhaustion was not classified as a transport failure",
        )
    else:
        raise AssertionError("persistent lite transport failure was accepted")

    class InvalidReplyClient:
        def __init__(self):
            self.calls = 0

        async def get_masterchain_info(self):
            self.calls += 1
            raise ValueError("invalid lite reply")

    invalid = InvalidReplyClient()
    try:
        await _masterchain_heights(
            {"invalid-node": invalid},
            transport_retry_budget_seconds=1.0,
            transport_retry_delay_seconds=0,
        )
    except ValueError as error:
        require(str(error) == "invalid lite reply", "non-transport error identity changed")
        require(invalid.calls == 1, "non-transport error was retried")
    else:
        raise AssertionError("non-transport lite error was accepted")


async def check_startup_transport_retry() -> None:
    client = FakeBlockClient(bytes.fromhex("11" * 32), info_transport_failures=1)

    class FakeNode:
        name = "startup-node"

        async def toslib_client(self):
            return client

    retry_counts = {"startup-node": {"get_masterchain_info": 0}}
    heights = await _wait_all_heights(
        [FakeNode()],
        minimum=7,
        timeout=1.0,
        transport_retry_counts=retry_counts,
        transport_retry_budget_seconds=1.0,
        transport_retry_delay_seconds=0,
    )
    require(heights == [7], "startup height wait did not recover from a transport timeout")
    require(
        retry_counts == {"startup-node": {"get_masterchain_info": 1}},
        "startup height wait did not expose its transport retry",
    )


def check_sustained_summary() -> None:
    config = SustainedObservationConfig(
        blocks=2,
        seconds=None,
        target_block_rate_ms=400,
        slow_interval_factor=3.0,
    )
    summary = summarize_sustained_observation(
        config=config,
        start_height=5,
        observed=[
            ObservedBlock(5, "block-5", 0),
            ObservedBlock(6, "block-6", 400_000_000),
            ObservedBlock(7, "block-7", 1_700_000_000),
        ],
        per_node_final_height={"node-a": 7, "node-b": 8},
        checked_from_height=0,
        agreed_block_ids={5: "block-5", 6: "block-6", 7: "block-7"},
        transport_retry_counts={
            "node-a": {"get_masterchain_info": 1, "lookup_block": 2},
            "node-b": {"get_masterchain_info": 0, "lookup_block": 0},
        },
    )
    require(summary["masterchain_blocks_produced"] == 2, "produced block count changed")
    require(
        summary["per_node_final_height"] == {"node-a": 7, "node-b": 8},
        "per-node final heights were not retained",
    )
    require(
        summary["lite_transport_retries"]
        == {
            "total": 3,
            "per_node_operation": {
                "node-a": {"get_masterchain_info": 1, "lookup_block": 2},
                "node-b": {"get_masterchain_info": 0, "lookup_block": 0},
            },
        },
        "lite transport retries were not retained by node and operation",
    )
    require(
        summary["agreement"]["same_block_per_height"] is True,
        "same-block-per-height agreement was not recorded",
    )
    require(
        summary["agreement"]["checked_through_height"] == 7,
        "agreement range does not reach the final observed height",
    )
    require(
        summary["observation_interval_distribution_ms"]
        == {
            "count": 2,
            "minimum": 400.0,
            "p50": 400.0,
            "p95": 1300.0,
            "maximum": 1300.0,
            "transport_retries_during_observation": 3,
            "includes_catch_up_after_transport_retry": True,
        },
        "sustained observation interval distribution changed",
    )
    require(
        summary["slow_observation_intervals"]
        == [{"from_height": 6, "to_height": 7, "observation_interval_ms": 1300.0}],
        "slow observation interval was not retained individually",
    )
    require(
        summary["release_evidence_eligible"] is False,
        "co-located sustained observation became release eligible",
    )


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
        require(
            evidence.sender_node == "node-a" and evidence.verifier_node == "node-b",
            "live finality evidence does not cross distinct sender and verifier nodes",
        )
        require(evidence.payload_bytes == 984260, "live finality payload size changed")
        require(
            (evidence.propagation_ns, evidence.queueing_ns, evidence.verification_ns)
            == (30, 7, 12),
            "live finality timing stages changed",
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
        require(
            (
                milestones.time_to_first_proposal_ns,
                milestones.time_to_first_notarization_certificate_ns,
                milestones.time_to_first_final_certificate_ns,
            )
            == (10, 20, 30),
            "consensus milestones are not distinct and ordered",
        )
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
        asyncio.run(check_sustained_agreement())
        asyncio.run(check_sustained_transport_retry())
        asyncio.run(check_startup_transport_retry())
        check_sustained_summary()
        check_latency_profile_binding()
        no_latency = load_latency_profile(
            ROOT / "test/pq-native/n6-scale-profiles/no-simulated-latency.json"
        )
        launch = load_latency_profile(ROOT / "test/pq-native/n6-scale-profiles/launch-default.json")
        require(
            no_latency.application == "none" and no_latency.one_way_latency_ms == [0.0, 0.0],
            "no-simulated-latency profile changed",
        )
        require(
            launch.application == "external-network-shaping",
            "launch latency profile is no longer externally applied",
        )
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
