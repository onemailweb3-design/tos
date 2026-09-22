#!/usr/bin/env python3
"""Write the reproducible manifest that precedes every PQ measurement run.

This module deliberately does not start validators.  It validates and writes the
contract a later runner must satisfy before doing so.  Diagnostic manifests are
never release evidence; release manifests additionally require a clean tree and
an exact-commit N5 closure artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

REQUIRED_PATHS: tuple[tuple[str, ...], ...] = (
    ("schema_version",),
    ("run_id",),
    ("mode",),
    ("release_evidence_eligible",),
    ("git_commit",),
    ("git_tree",),
    ("dirty_tree",),
    ("build", "build_type"),
    ("build", "compiler"),
    ("build", "compiler_version"),
    ("build", "linker"),
    ("build", "cmake_options"),
    ("build", "pq_algorithm"),
    ("build", "pq_backend_version"),
    ("build", "n5_carrier_tag"),
    ("build", "n5_format_version"),
    ("host", "os"),
    ("host", "kernel"),
    ("host", "cpu_model"),
    ("host", "physical_cores"),
    ("host", "logical_cpus"),
    ("host", "cpu_affinity"),
    ("host", "cgroup_cpu_quota"),
    ("host", "numa_topology"),
    ("host", "memory_bytes"),
    ("host", "swap_enabled"),
    ("host", "allocator"),
    ("host", "malloc_conf"),
    ("host", "disk_model"),
    ("host", "filesystem"),
    ("host", "mount_options"),
    ("host", "network_nic"),
    ("host", "network_link_speed"),
    ("chain", "global_id"),
    ("chain", "node_count"),
    ("chain", "masterchain_committee_count"),
    ("chain", "shard_committee_count"),
    ("chain", "validator_pool_count"),
    ("chain", "config_param_16"),
    ("chain", "config_param_28"),
    ("chain", "config_param_30"),
    ("chain", "block_limits"),
    ("chain", "gas_limits"),
    ("chain", "collated_data_limits"),
    ("network", "profile_name"),
    ("network", "latency_matrix_sha256"),
    ("network", "jitter"),
    ("network", "loss"),
    ("network", "bandwidth_cap"),
    ("workload", "profile"),
    ("workload", "warmup_duration_seconds"),
    ("workload", "measurement_duration_seconds"),
    ("workload", "fault_schedule_sha256"),
    ("resources", "pending_finality", "maximum_boxed_carrier_bytes"),
    ("resources", "pending_finality", "public_pool_bytes"),
    ("resources", "pending_finality", "validator_reserved_pool_bytes"),
    ("resources", "pending_finality", "total_pool_bytes"),
    ("resources", "pending_finality", "sender_across_blocks_bytes"),
    ("resources", "pending_finality", "retention_seconds"),
    ("resources", "pending_finality", "authority_memo_entries"),
    ("acceptance_criteria_sha256",),
    ("test_matrix_sha256",),
)


class ManifestError(RuntimeError):
    pass


def _run_git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise ManifestError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _memory_and_swap() -> tuple[int, bool]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            name, raw = line.split(":", 1)
            values[name] = int(raw.strip().split()[0]) * 1024
    except OSError, ValueError:
        return 0, False
    return values.get("MemTotal", 0), values.get("SwapTotal", 0) != 0


def observed_host() -> dict[str, Any]:
    memory_bytes, swap_enabled = _memory_and_swap()
    affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
    logical = os.cpu_count() or 0
    # physical core topology is platform-specific.  Release profiles override
    # this observed fallback with their reviewed hardware inventory.
    physical = len(affinity) if affinity else logical
    return {
        "os": platform.platform(),
        "kernel": platform.release(),
        "cpu_model": _cpu_model(),
        "physical_cores": physical,
        "logical_cpus": logical,
        "cpu_affinity": affinity,
        "cgroup_cpu_quota": "unknown",
        "numa_topology": "unknown",
        "memory_bytes": memory_bytes,
        "swap_enabled": swap_enabled,
        "allocator": "unknown",
        "malloc_conf": os.environ.get("MALLOC_CONF", "unset"),
        "disk_model": "unknown",
        "filesystem": "unknown",
        "mount_options": "unknown",
        "network_nic": "unknown",
        "network_link_speed": "unknown",
    }


def validate_n5_closure(path: Path, commit: str) -> None:
    try:
        closure = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"N5 closure artifact is unreadable: {exc}") from exc
    if closure.get("status") != "CLOSED":
        raise ManifestError("N5 closure artifact does not say CLOSED")
    if closure.get("commit") != commit:
        raise ManifestError("N5 closure artifact does not name the measured commit")
    gaps = closure.get("gaps", {})
    if gaps.get("validator_manager_actor") is not True:
        raise ManifestError("N5 closure artifact lacks ValidatorManager actor integration")
    if gaps.get("crash_restart_cuts") != 5:
        raise ManifestError("N5 closure artifact lacks all five crash/restart cuts")
    if gaps.get("check_proof_actor") is not True:
        raise ManifestError("N5 closure artifact lacks production CheckProof actor coverage")


def _lookup(manifest: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = manifest
    for component in path:
        if not isinstance(value, dict) or component not in value:
            raise ManifestError(f"manifest missing required field {'.'.join(path)}")
        value = value[component]
    return value


def validate_manifest(manifest: dict[str, Any]) -> None:
    for path in REQUIRED_PATHS:
        value = _lookup(manifest, path)
        if value is None or value == "":
            raise ManifestError(f"manifest has empty required field {'.'.join(path)}")
    for field in ("acceptance_criteria_sha256", "test_matrix_sha256"):
        value = manifest[field]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(ch not in "0123456789abcdef" for ch in value)
        ):
            raise ManifestError(f"manifest field {field} is not a SHA-256 digest")
    if manifest["mode"] == "release" and manifest["dirty_tree"]:
        raise ManifestError("release-grade measurement refuses a dirty git tree")
    if manifest["mode"] != "release" and manifest["release_evidence_eligible"]:
        raise ManifestError("diagnostic manifest cannot claim release eligibility")


def create_manifest(
    *,
    repo: Path,
    config: dict[str, Any],
    criteria_path: Path,
    matrix_path: Path,
    mode: str,
    n5_closure_path: Path | None,
) -> dict[str, Any]:
    if mode not in ("diagnostic", "release"):
        raise ManifestError(f"unknown measurement mode {mode}")
    commit = _run_git(repo, "rev-parse", "HEAD")
    tree = _run_git(repo, "rev-parse", "HEAD^{tree}")
    dirty = bool(_run_git(repo, "status", "--porcelain", "--untracked-files=all"))
    if mode == "release":
        if n5_closure_path is None:
            raise ManifestError(
                f"release-grade measurement refuses commit {commit}: "
                "no N5 closure artifact was supplied for that exact commit"
            )
        validate_n5_closure(n5_closure_path, commit)
        if dirty:
            raise ManifestError("release-grade measurement refuses a dirty git tree")

    host = observed_host()
    host.update(config.get("host", {}))
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": config.get("run_id") or str(uuid.uuid4()),
        "mode": mode,
        "release_evidence_eligible": mode == "release",
        "git_commit": commit,
        "git_tree": tree,
        "dirty_tree": dirty,
        "build": config.get("build", {}),
        "host": host,
        "chain": config.get("chain", {}),
        "network": config.get("network", {}),
        "workload": config.get("workload", {}),
        "resources": config.get("resources", {}),
        "acceptance_criteria_sha256": sha256_file(criteria_path),
        "test_matrix_sha256": sha256_file(matrix_path),
    }
    validate_manifest(manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--acceptance-criteria", type=Path, required=True)
    parser.add_argument("--test-matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("diagnostic", "release"), required=True)
    parser.add_argument("--n5-closure", type=Path)
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        manifest = create_manifest(
            repo=args.repo.resolve(),
            config=config,
            criteria_path=args.acceptance_criteria,
            matrix_path=args.test_matrix,
            mode=args.mode,
            n5_closure_path=args.n5_closure,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, json.JSONDecodeError, ManifestError) as exc:
        print(f"MEASUREMENT_MANIFEST_FAILURE: {exc}", file=sys.stderr)
        return 1
    print(f"MEASUREMENT_MANIFEST_OK: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
