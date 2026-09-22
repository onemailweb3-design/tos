"""N6 diagnostic cluster orchestration and evidence analysis."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

EVIDENCE_CLASS = "DIAGNOSTIC_SCAFFOLDING_ONLY"
PROOF_BYTES = re.compile(r"got block proof .* \((?P<bytes>[0-9]+) bytes\)")


@dataclass(frozen=True)
class FinalityRouteEvidence:
    trace_id: str
    sender_node: str
    verifier_node: str
    payload_bytes: int
    propagation_ns: int
    queueing_ns: int
    verification_ns: int


@dataclass(frozen=True)
class ConsensusMilestones:
    time_to_first_proposal_ns: int
    time_to_first_notarization_certificate_ns: int
    time_to_first_final_certificate_ns: int


@dataclass(frozen=True)
class SustainedObservationConfig:
    blocks: int | None
    seconds: float | None
    target_block_rate_ms: int
    slow_interval_factor: float


@dataclass(frozen=True)
class ObservedBlock:
    height: int
    block_id: str
    observed_monotonic_ns: int


@dataclass(frozen=True)
class LatencyProfile:
    name: str
    one_way_latency_ms: list[float]
    application: str


def load_latency_profile(path: Path) -> LatencyProfile:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("N6_SCALE_SWEEP_FAILURE: latency profile schema_version is not 1")
    name = value.get("name")
    latency = value.get("one_way_latency_ms")
    application = value.get("application")
    if not isinstance(name, str) or not name:
        raise ValueError("N6_SCALE_SWEEP_FAILURE: latency profile has no name")
    if (
        not isinstance(latency, list)
        or len(latency) != 2
        or any(isinstance(item, bool) or not isinstance(item, (int, float)) for item in latency)
        or latency[0] < 0
        or latency[0] > latency[1]
    ):
        raise ValueError("N6_SCALE_SWEEP_FAILURE: latency profile has an invalid range")
    if application not in ("none", "external-network-shaping"):
        raise ValueError("N6_SCALE_SWEEP_FAILURE: latency profile has an invalid application")
    if application == "none" and latency != [0, 0]:
        raise ValueError(
            "N6_SCALE_SWEEP_FAILURE: an unapplied latency profile must be exactly zero"
        )
    return LatencyProfile(name, [float(item) for item in latency], application)


def validate_latency_backend(profile: LatencyProfile, backend_manifest: dict[str, Any]) -> None:
    if profile.application != "external-network-shaping":
        return
    if (
        backend_manifest["kind"] != "remote-command"
        or backend_manifest.get("network_profile") != profile.name
    ):
        raise ValueError(
            "N6_SCALE_SWEEP_FAILURE: launch latency requires a remote-command backend "
            "that declares the applied network profile"
        )


def read_trace(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def analyze_live_finality(trace_paths: list[Path]) -> FinalityRouteEvidence:
    events = [
        event for path in trace_paths for event in read_trace(path) if event.get("kind") == "trace"
    ]
    traces: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        traces.setdefault(event["trace_id"], []).append(event)
    for trace_id, current in traces.items():
        sent = [event for event in current if event["stage"] == "finality_broadcast_sent"]
        for received in (
            event for event in current if event["stage"] == "peer_finality_broadcast_received"
        ):
            verifier = received["node_id"]
            started = [
                event
                for event in current
                if event["node_id"] == verifier
                and event["stage"] == "peer_finality_verification_started"
            ]
            verified = [
                event
                for event in current
                if event["node_id"] == verifier
                and event["stage"] == "peer_finality_broadcast_verified"
            ]
            sender = next((event for event in sent if event["node_id"] != verifier), None)
            if sender is None or not started or not verified:
                continue
            start = min(started, key=lambda event: event["monotonic_ns"])
            finish = min(
                (event for event in verified if event["monotonic_ns"] >= start["monotonic_ns"]),
                key=lambda event: event["monotonic_ns"],
                default=None,
            )
            if finish is None:
                continue
            sent_bytes = sender.get("exact_bytes")
            received_bytes = received.get("exact_bytes")
            if not isinstance(sent_bytes, int) or sent_bytes <= 0 or sent_bytes != received_bytes:
                continue
            propagation = received["wall_unix_ns"] - sender["wall_unix_ns"]
            queueing = start["monotonic_ns"] - received["monotonic_ns"]
            verification = finish["monotonic_ns"] - start["monotonic_ns"]
            if min(propagation, queueing, verification) < 0:
                continue
            return FinalityRouteEvidence(
                trace_id=trace_id,
                sender_node=sender["node_id"],
                verifier_node=verifier,
                payload_bytes=sent_bytes,
                propagation_ns=propagation,
                queueing_ns=queueing,
                verification_ns=verification,
            )
    raise RuntimeError(
        "N6_LIVE_FINALITY_OVERLAY_FAILURE: no finality payload crossed from one process "
        "through Plumtree to a different process and completed trusted PQ verification"
    )


def analyze_consensus_milestones(
    trace_paths: list[Path], measurement_started_wall_ns: int
) -> ConsensusMilestones:
    events = [
        event for path in trace_paths for event in read_trace(path) if event.get("kind") == "trace"
    ]

    def elapsed(stage: str) -> int:
        timestamps = [event.get("wall_unix_ns") for event in events if event.get("stage") == stage]
        if not timestamps or any(not isinstance(value, int) for value in timestamps):
            raise RuntimeError(f"N6_SCALE_SWEEP_FAILURE: no {stage} milestone was observed")
        result = min(timestamps) - measurement_started_wall_ns
        if result < 0:
            raise RuntimeError(
                f"N6_SCALE_SWEEP_FAILURE: {stage} predates the recorded measurement start; "
                "remote hosts require synchronized clocks"
            )
        return result

    result = ConsensusMilestones(
        time_to_first_proposal_ns=elapsed("candidate_generated"),
        time_to_first_notarization_certificate_ns=elapsed("notarization_certificate_observed"),
        time_to_first_final_certificate_ns=elapsed("finalization_certificate_observed"),
    )
    if not (
        result.time_to_first_proposal_ns
        < result.time_to_first_notarization_certificate_ns
        < result.time_to_first_final_certificate_ns
    ):
        raise RuntimeError(
            "N6_SCALE_SWEEP_FAILURE: proposal, notarization and FinalCert milestones are not distinct"
        )
    return result


def validate_node_isolation(nodes: list[dict[str, Any]]) -> None:
    fields = ("db_root", "adnl_identity", "log", "trace", "resource_monitor")
    for field in fields:
        values = [node[field] for node in nodes]
        if len(values) != len(set(values)):
            raise RuntimeError(f"N6_CLUSTER_ISOLATION_FAILURE: nodes share {field}")
    ports = [port for node in nodes for port in node["ports"]]
    if len(ports) != len(set(ports)):
        raise RuntimeError("N6_CLUSTER_ISOLATION_FAILURE: nodes share transport ports")


def validate_lite_transport_source(source_root: Path) -> None:
    ext_client = " ".join(
        (source_root / "lite-client/ext-client.cpp").read_text(encoding="utf-8").split()
    )
    lite_client = " ".join(
        (source_root / "lite-client/lite-client.cpp").read_text(encoding="utf-8").split()
    )
    if "AdnlExtClient::create" not in ext_client or "AdnlExtClient::send_query" not in ext_client:
        raise RuntimeError(
            "N6_LITE_FRAMED_TCP_FAILURE: release lite-client no longer uses AdnlExtClient"
        )
    if "get_block_proof" not in lite_client or "envelope_send_query" not in lite_client:
        raise RuntimeError(
            "N6_LITE_FRAMED_TCP_FAILURE: block-proof command no longer reaches the external client query route"
        )


def block_id_text(block: Any) -> str:
    shard = block.shard if block.shard >= 0 else block.shard + 2**64
    return (
        f"({block.workchain},{shard:016x},{block.seqno}):"
        f"{block.root_hash.hex()}:{block.file_hash.hex()}"
    )


async def _resource_monitor(node: Any, output: Path, stop: asyncio.Event) -> None:
    pid = node.process_id
    if pid is None:
        raise RuntimeError(f"node {node.name} has no process for resource monitoring")
    with output.open("w") as stream:
        while not stop.is_set():
            status: dict[str, str] = {}
            try:
                for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        if key in {"VmRSS", "VmHWM", "Threads"}:
                            status[key] = value.strip()
                stat = Path(f"/proc/{pid}/stat").read_text().split()
                io = Path(f"/proc/{pid}/io").read_text()
            except FileNotFoundError:
                break
            stream.write(
                json.dumps(
                    {
                        "monotonic_ns": time.monotonic_ns(),
                        "wall_unix_ns": time.time_ns(),
                        "status": status,
                        "cpu_ticks": int(stat[13]) + int(stat[14]),
                        "io": io,
                    },
                    sort_keys=True,
                )
                + "\n"
            )
            stream.flush()
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.2)
            except TimeoutError:
                pass


async def _wait_all_heights(nodes: list[Any], minimum: int, timeout: float) -> list[int]:
    deadline = time.monotonic() + timeout
    last: list[int] = []
    while time.monotonic() < deadline:
        try:
            values = []
            for node in nodes:
                info = await (await node.toslib_client()).get_masterchain_info()
                values.append(info.last.seqno)
            last = values
            if min(values) >= minimum:
                return values
        except Exception:
            pass
        await asyncio.sleep(0.25)
    raise TimeoutError(f"nodes did not reach masterchain height {minimum}; last={last}")


async def _masterchain_heights(clients: dict[str, Any]) -> dict[str, int]:
    infos = await asyncio.gather(*(client.get_masterchain_info() for client in clients.values()))
    return {name: info.last.seqno for name, info in zip(clients, infos, strict=True)}


async def require_agreed_masterchain_block(clients: dict[str, Any], height: int) -> str:
    blocks = await asyncio.gather(
        *(
            client.lookup_block(workchain=-1, shard=-(2**63), seqno=height)
            for client in clients.values()
        )
    )
    by_node = {name: block_id_text(block) for name, block in zip(clients, blocks, strict=True)}
    distinct = set(by_node.values())
    if len(distinct) != 1:
        details = ", ".join(f"{name}={block_id}" for name, block_id in by_node.items())
        raise RuntimeError(
            f"N6_SUSTAINED_CONSENSUS_FAILURE: masterchain block-id disagreement "
            f"at height {height}: {details}"
        )
    return next(iter(distinct))


def _nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def summarize_sustained_observation(
    *,
    config: SustainedObservationConfig,
    start_height: int,
    observed: list[ObservedBlock],
    per_node_final_height: dict[str, int],
    checked_from_height: int,
    agreed_block_ids: dict[int, str] | None = None,
) -> dict[str, Any]:
    if len(observed) < 3:
        raise RuntimeError(
            "N6_SUSTAINED_CONSENSUS_FAILURE: fewer than two masterchain intervals were observed"
        )
    intervals = [
        {
            "from_height": previous.height,
            "to_height": current.height,
            "interval_ms": (current.observed_monotonic_ns - previous.observed_monotonic_ns)
            / 1_000_000,
        }
        for previous, current in zip(observed, observed[1:], strict=False)
    ]
    if any(item["to_height"] != item["from_height"] + 1 for item in intervals):
        raise RuntimeError(
            "N6_SUSTAINED_CONSENSUS_FAILURE: sustained observation skipped a masterchain height"
        )
    values = [item["interval_ms"] for item in intervals]
    slow_threshold_ms = config.target_block_rate_ms * config.slow_interval_factor
    return {
        "evidence_class": "COLOCATED_DIAGNOSTIC_ONLY",
        "release_evidence_eligible": False,
        "configured_blocks": config.blocks,
        "configured_seconds": config.seconds,
        "target_block_rate_ms": config.target_block_rate_ms,
        "slow_interval_factor": config.slow_interval_factor,
        "slow_interval_threshold_ms": slow_threshold_ms,
        "start_height": start_height,
        "final_common_height": observed[-1].height,
        "masterchain_blocks_produced": observed[-1].height - start_height,
        "agreement": {
            "same_block_per_height": True,
            "checked_from_height": checked_from_height,
            "checked_through_height": observed[-1].height,
            "block_ids": {
                str(height): block_id for height, block_id in (agreed_block_ids or {}).items()
            },
        },
        "per_node_final_height": per_node_final_height,
        "intervals": intervals,
        "interval_distribution_ms": {
            "count": len(values),
            "minimum": min(values),
            "p50": _nearest_rank(values, 0.50),
            "p95": _nearest_rank(values, 0.95),
            "maximum": max(values),
        },
        "slow_intervals": [item for item in intervals if item["interval_ms"] > slow_threshold_ms],
        "scope": (
            "Co-located diagnostic stability only; block intervals are the times at which all "
            "nodes exposed an agreed block, not release-grade persisted-finality latency."
        ),
    }


async def observe_sustained_consensus(
    nodes: list[Any], config: SustainedObservationConfig, zerostate_block_id: str
) -> dict[str, Any]:
    if (config.blocks is None) == (config.seconds is None):
        raise ValueError(
            "N6_SUSTAINED_CONSENSUS_FAILURE: configure exactly one of blocks or seconds"
        )
    if config.blocks is not None and config.blocks < 2:
        raise ValueError("N6_SUSTAINED_CONSENSUS_FAILURE: blocks must be at least two")
    if config.seconds is not None and config.seconds <= 0:
        raise ValueError("N6_SUSTAINED_CONSENSUS_FAILURE: seconds must be positive")
    if config.target_block_rate_ms <= 0 or config.slow_interval_factor <= 1:
        raise ValueError(
            "N6_SUSTAINED_CONSENSUS_FAILURE: target rate and slow-interval factor are invalid"
        )

    clients = {node.name: await node.toslib_client() for node in nodes}
    heights = await _masterchain_heights(clients)
    start_height = min(heights.values())
    if not zerostate_block_id:
        raise ValueError("N6_SUSTAINED_CONSENSUS_FAILURE: zerostate block id is missing")
    block_ids: dict[int, str] = {0: zerostate_block_id}
    for height in range(1, start_height + 1):
        block_ids[height] = await require_agreed_masterchain_block(clients, height)

    observed = [ObservedBlock(start_height, block_ids[start_height], time.monotonic_ns())]
    next_height = start_height + 1
    started = time.monotonic()
    expected_seconds = (
        config.blocks * config.target_block_rate_ms / 1000
        if config.blocks is not None
        else config.seconds
    )
    assert expected_seconds is not None
    deadline = started + max(120.0, expected_seconds * config.slow_interval_factor * 4)
    final_heights = heights

    while True:
        final_heights = await _masterchain_heights(clients)
        common_height = min(final_heights.values())
        while next_height <= common_height:
            block_id = await require_agreed_masterchain_block(clients, next_height)
            block_ids[next_height] = block_id
            observed.append(ObservedBlock(next_height, block_id, time.monotonic_ns()))
            next_height += 1

        elapsed = time.monotonic() - started
        if config.blocks is not None and observed[-1].height - start_height >= config.blocks:
            break
        if config.seconds is not None and elapsed >= config.seconds:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError(
                "N6_SUSTAINED_CONSENSUS_FAILURE: sustained observation did not reach its bound; "
                f"start={start_height} heights={final_heights}"
            )
        await asyncio.sleep(0.05)

    return summarize_sustained_observation(
        config=config,
        start_height=start_height,
        observed=observed,
        per_node_final_height=final_heights,
        checked_from_height=0,
        agreed_block_ids=block_ids,
    )


async def run_cluster(
    install: Any,
    artifact_dir: Path,
    backend: Any,
    validators: int,
    base_port: int,
    require_lite: bool,
    latency_profile_path: Path | None = None,
    sustained: SustainedObservationConfig | None = None,
) -> dict[str, Any]:
    from .network import Network, StartOptions

    if validators < 4:
        raise ValueError("N6.3 diagnostic Genesis requires at least four PQ validators")
    latency_profile = load_latency_profile(
        latency_profile_path
        or install.source_dir / "test/pq-native/n6-scale-profiles/no-simulated-latency.json"
    )
    validate_latency_backend(latency_profile, backend.manifest())
    artifact_dir.mkdir(parents=True, exist_ok=False)
    network_dir = artifact_dir / "network"
    network_dir.mkdir()
    trace_paths: list[Path] = []
    resource_paths: list[Path] = []
    monitor_stop = asyncio.Event()
    monitors: list[asyncio.Task[None]] = []
    commit = subprocess.check_output(
        ["git", "-C", install.source_dir, "rev-parse", "HEAD"], text=True
    ).strip()
    criteria = install.source_dir / "doc/pq-native/N6-ACCEPTANCE-CRITERIA.json"
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "evidence_class": EVIDENCE_CLASS,
        "release_evidence_eligible": False,
        "git_commit": commit,
        "acceptance_criteria_sha256": hashlib.sha256(criteria.read_bytes()).hexdigest(),
        "backend": backend.manifest(),
        "validators": validators,
        "base_port": base_port,
        "latency_profile": asdict(latency_profile),
        "clock_domain": {
            "queueing_and_verification": "per-process monotonic",
            "local_propagation": "same-host wall clock",
            "remote_propagation": "requires externally synchronized host clocks",
        },
        "n5_closure": "PARKED_GAPS_PREVENT_RELEASE_EVIDENCE",
        "sustained_observation": asdict(sustained) if sustained is not None else None,
    }
    (artifact_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    validate_lite_transport_source(install.source_dir)

    async with Network(
        install, network_dir, base_port=base_port, process_backend=backend
    ) as network:
        network.config.shard_validators = validators
        if sustained is not None:
            consensus = network.config.mc_consensus
            if (
                consensus is None
                or consensus.target_block_rate_ms != sustained.target_block_rate_ms
            ):
                raise ValueError(
                    "N6_SUSTAINED_CONSENSUS_FAILURE: observation target does not match "
                    "the Genesis masterchain target block rate"
                )
        dht = network.create_dht_node()
        validator_nodes: list[Any] = []
        for index in range(validators):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f"n6-validator-id-{index}".encode()).digest(),
                hashlib.sha256(f"n6-validator-seed-{index}".encode()).digest(),
            )
            node.announce_to(dht)
            validator_nodes.append(node)
        verifier = network.create_full_node()
        verifier.announce_to(dht)
        all_nodes = [*validator_nodes, verifier]
        for key_file in network_dir.glob("node*/keyring/*"):
            key_file.chmod(0o600)
        measurement_started_wall_ns = time.time_ns()
        await dht.run(StartOptions(threads=1, verbosity=3))
        for node in all_nodes:
            trace_path = node.directory / "n6-trace.jsonl"
            resource_path = node.directory / "n6-resource.jsonl"
            trace_paths.append(trace_path)
            resource_paths.append(resource_path)
            await node.run(
                StartOptions(
                    threads=2,
                    verbosity=4,
                    env={"TOS_N6_RESOURCE_JSONL": str(resource_path)},
                    args=(
                        "--measurement-jsonl",
                        str(trace_path),
                        "--measurement-node-id",
                        node.name,
                    ),
                )
            )
            if backend.manifest()["kind"] == "local-process":
                monitors.append(
                    asyncio.create_task(_resource_monitor(node, resource_path, monitor_stop))
                )

        await _wait_all_heights(all_nodes, 3, 120.0)
        sustained_result = (
            await observe_sustained_consensus(
                all_nodes, sustained, block_id_text(network.zerostate.as_block())
            )
            if sustained is not None
            else None
        )
        deadline = time.monotonic() + 60.0
        evidence: FinalityRouteEvidence | None = None
        while time.monotonic() < deadline:
            try:
                evidence = analyze_live_finality(trace_paths)
                break
            except RuntimeError:
                await asyncio.sleep(0.25)
        if evidence is None:
            evidence = analyze_live_finality(trace_paths)
        milestones = analyze_consensus_milestones(trace_paths, measurement_started_wall_ns)

        lite: dict[str, Any] | None = None
        if require_lite:
            config_path = verifier.directory / "n6-lite-client.json"
            config_path.write_text(verifier.liteserver_config.to_json())
            command = f"blkproofchain {block_id_text(network.zerostate.as_block())}"
            started_ns = time.monotonic_ns()
            process = await backend.spawn(
                verifier.name,
                install.lite_client_exe,
                ["-C", str(config_path), "-r", "-t", "30", "-c", command],
                verifier.directory,
                os.environ.copy(),
                capture_stdout=True,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=45.0)
            elapsed_ns = time.monotonic_ns() - started_ns
            output = (stdout or b"").decode(errors="replace") + (stderr or b"").decode(
                errors="replace"
            )
            (artifact_dir / "lite-client.log").write_text(output)
            match = PROOF_BYTES.search(output)
            if (
                process.returncode != 0
                or match is None
                or "valid complete proof chain" not in output
            ):
                raise RuntimeError(
                    "N6_LITE_FRAMED_TCP_FAILURE: release lite-client did not fetch and verify a proof "
                    "over its ADNL external framed-TCP route"
                )
            lite = {
                "route": "AdnlExtClient/AdnlExtServer framed TCP",
                "proof_bytes": int(match.group("bytes")),
                "query_and_verification_ns": elapsed_ns,
                "verified": True,
            }

        node_results = [
            {
                "name": node.name,
                "role": "validator" if index < validators else "non-validator-verifier",
                "db_root": str(node.directory),
                "adnl_identity": node.adnl_identity.hex(),
                "ports": list(node.transport_ports),
                "log": str(node.log_path),
                "trace": str(trace_paths[index]),
                "resource_monitor": str(resource_paths[index]),
            }
            for index, node in enumerate(all_nodes)
        ]
        validate_node_isolation(node_results)
        if any(not path.is_file() or path.stat().st_size == 0 for path in resource_paths):
            raise RuntimeError(
                "N6_CLUSTER_ISOLATION_FAILURE: a node has no resource-monitor output"
            )
        result = {
            "schema_version": 1,
            "evidence_class": EVIDENCE_CLASS,
            "release_evidence_eligible": False,
            "backend": backend.manifest(),
            "nodes": node_results,
            "live_finality": asdict(evidence),
            "consensus_milestones": asdict(milestones),
            "sustained_observation": sustained_result,
            "lite": lite,
            "consensus_correctness_verdict": "NOT_MADE_MERKLE_DIAGNOSIS_OPEN",
        }
        (artifact_dir / "result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n"
        )
        monitor_stop.set()
        await asyncio.gather(*monitors)
        return result


async def run_scale_sweep(
    install: Any,
    artifact_dir: Path,
    backend: Any,
    scales: list[int],
    profile_path: Path,
    base_port: int,
    allow_local_diagnostic_scales: bool = False,
) -> dict[str, Any]:
    if not scales or len(scales) != len(set(scales)) or any(scale < 4 for scale in scales):
        raise ValueError("N6_SCALE_SWEEP_FAILURE: scales must be unique integers of at least four")
    profile = load_latency_profile(profile_path)
    local_multi_scale = backend.manifest()["kind"] == "local-process" and scales != [4]
    if local_multi_scale and not allow_local_diagnostic_scales:
        raise ValueError(
            "N6_SCALE_SWEEP_FAILURE: this local host is restricted to the 4-validator minimum-BFT tier"
        )
    criteria = json.loads(
        (install.source_dir / "doc/pq-native/N6-ACCEPTANCE-CRITERIA.json").read_text(
            encoding="utf-8"
        )
    )
    required_release_scales = criteria.get("required_scales")
    if required_release_scales != [21]:
        raise ValueError(
            "N6_SCALE_SWEEP_FAILURE: the precommitted release scale requirement changed"
        )
    artifact_dir.mkdir(parents=True, exist_ok=False)
    points: list[dict[str, Any]] = []
    for index, scale in enumerate(scales):
        point = await run_cluster(
            install,
            artifact_dir / f"validators-{scale}",
            backend,
            scale,
            base_port + index * 1000,
            False,
            profile_path,
        )
        booted_validators = sum(1 for node in point["nodes"] if node["role"] == "validator")
        if booted_validators != scale:
            raise RuntimeError(
                f"N6_SCALE_SWEEP_FAILURE: requested scale {scale} booted {booted_validators} validators"
            )
        points.append(
            {
                "requested_validators": scale,
                "booted_validators": booted_validators,
                "fault_tolerance": (scale - 1) // 3,
                **point["consensus_milestones"],
            }
        )
    result = {
        "schema_version": 1,
        "evidence_class": "MINIMUM_BFT_FUNCTIONAL_DIAGNOSTIC",
        "release_evidence_eligible": False,
        "latency_profile": asdict(profile),
        "scale_points": points,
        "required_release_scales": required_release_scales,
        "required_release_scales_measured": [],
        "full_required_matrix_executed": False,
        "local_colocation_diagnostic_override": local_multi_scale,
        "consensus_correctness_verdict": "NOT_MADE_MERKLE_DIAGNOSIS_OPEN",
    }
    (artifact_dir / "scale-sweep-result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result
