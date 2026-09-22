#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message: str) -> None:
    print(f"N6_MANIFEST_FAILURE: {message}", file=sys.stderr)
    raise SystemExit(1)


repo_root = Path(__file__).resolve().parents[2]
module_path = repo_root / "scripts" / "pq_measurement_manifest.py"
spec = importlib.util.spec_from_file_location("pq_measurement_manifest", module_path)
if spec is None or spec.loader is None:
    fail("could not load manifest module")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def run(*args: str, cwd: Path) -> None:
    subprocess.run(
        args, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )


def complete_config() -> dict[str, object]:
    return {
        "run_id": "manifest-contract-test",
        "build": {
            "build_type": "RelWithDebInfo",
            "compiler": "test-compiler",
            "compiler_version": "1",
            "linker": "test-linker",
            "cmake_options": ["TOS_USE_ROCKSDB=ON"],
            "pq_algorithm": "ML-DSA-44",
            "pq_backend_version": "test-backend",
            "n5_carrier_tag": 19,
            "n5_format_version": 1,
        },
        "host": {
            "cgroup_cpu_quota": "unlimited",
            "numa_topology": "node0",
            "allocator": "system",
            "disk_model": "test-disk",
            "filesystem": "ext4",
            "mount_options": "rw",
            "network_nic": "test0",
            "network_link_speed": "1Gbps",
        },
        "chain": {
            "global_id": -239,
            "node_count": 4,
            "masterchain_committee_count": 4,
            "shard_committee_count": 4,
            "validator_pool_count": 4,
            "config_param_16": {
                "max_validators": 400,
                "max_main_validators": 100,
                "min_validators": 4,
            },
            "config_param_28": {"shard_validators_num": 100},
            "config_param_30": {"protocol_version": 2},
            "block_limits": {"bytes": 1},
            "gas_limits": {"gas": 1},
            "collated_data_limits": {"bytes": 1},
        },
        "network": {
            "profile_name": "fixture",
            "latency_matrix_sha256": "a" * 64,
            "jitter": "0ms",
            "loss": "0%",
            "bandwidth_cap": "1Gbps",
        },
        "workload": {
            "profile": "consensus-isolation",
            "warmup_duration_seconds": 1,
            "measurement_duration_seconds": 1,
            "fault_schedule_sha256": "b" * 64,
        },
        "resources": {
            "pending_finality": {
                "maximum_boxed_carrier_bytes": 984_260,
                "public_pool_bytes": 15_748_160,
                "validator_reserved_pool_bytes": 393_704_000,
                "total_pool_bytes": 409_452_160,
                "sender_across_blocks_bytes": 3_937_040,
                "retention_seconds": 60,
                "authority_memo_entries": 8,
            }
        },
    }


def complete_criteria() -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_hardware_profile": "test-hardware",
        "required_scales": [21, 32, 64, 100],
        "required_network_profiles": ["baseline", "launch-wan", "degraded"],
        "required_workloads": ["consensus-isolation", "target-load", "high-load"],
        "max_p99_persisted_finality_ms": 1,
        "max_p99_block_signature_verify_ms": 1,
        "max_p99_lite_verify_ms": 1,
        "max_cpu_fraction": 0.5,
        "max_rss_fraction": 0.5,
        "max_network_fraction": 0.5,
        "max_disk_busy_fraction": 0.5,
        "max_finalization_backpressure_fraction": 0.5,
        "max_pending_finality_bytes": 1,
        "max_pending_finality_candidates": 1,
        "max_authority_classification_p99_ms": 1,
        "max_unbounded_memory_slope_bytes_per_hour": 0,
        "max_finalized_height_stall_ms": 1,
        "safety_violations_allowed": 0,
        "process_crashes_allowed": 0,
        "invalid_proofs_accepted": 0,
    }


with tempfile.TemporaryDirectory(prefix="measurement-manifest-") as raw:
    root = Path(raw)
    run("git", "init", "-q", cwd=root)
    run("git", "config", "user.email", "measurement@example.invalid", cwd=root)
    run("git", "config", "user.name", "Measurement Test", cwd=root)
    (root / "tracked").write_text("clean\n", encoding="utf-8")
    run("git", "add", "tracked", cwd=root)
    run("git", "commit", "-q", "-m", "fixture", cwd=root)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    criteria = root / "criteria.json"
    matrix = root / "matrix.json"
    criteria.write_text(json.dumps(complete_criteria()) + "\n", encoding="utf-8")
    matrix.write_text('{"schema_version":1}\n', encoding="utf-8")
    closure = root / "closure.json"
    closure.write_text(
        json.dumps(
            {
                "status": "CLOSED",
                "commit": commit,
                "gaps": {
                    "validator_manager_actor": True,
                    "crash_restart_cuts": 5,
                    "check_proof_actor": True,
                },
            }
        ),
        encoding="utf-8",
    )
    # Criteria/matrix are measurement inputs, so commit them before the clean
    # release-grade creation.
    run("git", "add", "criteria.json", "matrix.json", "closure.json", cwd=root)
    run("git", "commit", "-q", "-m", "measurement inputs", cwd=root)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    closure.write_text(
        json.dumps(
            {
                "status": "CLOSED",
                "commit": commit,
                "gaps": {
                    "validator_manager_actor": True,
                    "crash_restart_cuts": 5,
                    "check_proof_actor": True,
                },
            }
        ),
        encoding="utf-8",
    )
    run("git", "add", "closure.json", cwd=root)
    run("git", "commit", "-q", "-m", "bind closure", cwd=root)
    # The artifact commits to HEAD, so amend is deliberately avoided: make the
    # final fixture artifact untracked outside the repository and bind to the
    # actual clean commit.
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    closure_external = Path(raw).parent / f"closure-{Path(raw).name}.json"
    closure_external.write_text(
        json.dumps(
            {
                "status": "CLOSED",
                "commit": commit,
                "gaps": {
                    "validator_manager_actor": True,
                    "crash_restart_cuts": 5,
                    "check_proof_actor": True,
                },
            }
        ),
        encoding="utf-8",
    )
    try:
        # This branch deliberately has no exact-commit N5 closure artifact.  Its
        # release refusal is the live precondition for all scaffolding work, not
        # a synthetic malformed fixture.  Check it before dirty-tree state so a
        # developer checkout cannot make the refusal pass for the wrong reason.
        try:
            module.create_manifest(
                repo=repo_root,
                config=complete_config(),
                criteria_path=criteria,
                matrix_path=matrix,
                mode="release",
                n5_closure_path=None,
            )
            fail("current branch without an N5 closure artifact was release eligible")
        except module.ManifestError as exc:
            expected = "no N5 closure artifact was supplied for that exact commit"
            if expected not in str(exc):
                fail(f"current N5-open branch reported the wrong release refusal: {exc}")

        diagnostic = module.create_manifest(
            repo=repo_root,
            config=complete_config(),
            criteria_path=criteria,
            matrix_path=matrix,
            mode="diagnostic",
            n5_closure_path=None,
        )
        if diagnostic["release_evidence_eligible"]:
            fail("diagnostic scaffolding claimed release eligibility")

        manifest = module.create_manifest(
            repo=root,
            config=complete_config(),
            criteria_path=criteria,
            matrix_path=matrix,
            mode="release",
            n5_closure_path=closure_external,
        )
        module.validate_manifest(manifest)

        missing_commit = dict(manifest)
        missing_commit.pop("git_commit")
        try:
            module.validate_manifest(missing_commit)
            fail("manifest without git_commit was accepted")
        except module.ManifestError as exc:
            if "git_commit" not in str(exc):
                fail(f"missing git commit reported the wrong reason: {exc}")

        missing_criteria = dict(manifest)
        missing_criteria.pop("acceptance_criteria_sha256")
        try:
            module.validate_manifest(missing_criteria)
            fail("manifest without acceptance criteria hash was accepted")
        except module.ManifestError as exc:
            if "acceptance_criteria_sha256" not in str(exc):
                fail(f"missing criteria hash reported the wrong reason: {exc}")

        (root / "dirty-untracked").write_text("dirty\n", encoding="utf-8")
        try:
            module.create_manifest(
                repo=root,
                config=complete_config(),
                criteria_path=criteria,
                matrix_path=matrix,
                mode="release",
                n5_closure_path=closure_external,
            )
            fail("release-grade run accepted a dirty tree")
        except module.ManifestError as exc:
            if "dirty git tree" not in str(exc):
                fail(f"dirty tree reported the wrong reason: {exc}")
    finally:
        closure_external.unlink(missing_ok=True)

print("N6_MANIFEST_OK: complete manifest, exact hashes, N5 closure, and dirty-tree refusal")
