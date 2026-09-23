#!/usr/bin/env python3
"""Keep retained chain E2E entry points on one deterministic PQ validator helper."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

HELPER_MODULE = "tostester.pq_initial_validator"
HELPER_NAME = "make_deterministic_pq_initial_validator"
EXPECTED_CALLS = {
    "test/integration/test_simplex2_release.py": 1,
    "scripts/localnet-jsonrpc.py": 1,
    "scripts/agent-wallet-account-e2e.py": 1,
    "scripts/agent-query-api-e2e.py": 1,
    "scripts/agent-chain-index-e2e.py": 1,
    "scripts/agent-task-escrow-e2e.py": 1,
    "scripts/proof-attestation-e2e.py": 1,
    "scripts/capability-registry-e2e.py": 1,
    "scripts/agent-economy-composed-e2e.py": 1,
    "scripts/validator-election-stage-a.py": 1,
    "scripts/dispute-e2e.py": 1,
    "scripts/service-actor-e2e.py": 1,
    "scripts/wc0-token-index-e2e.py": 1,
    "scripts/dns-e2e.py": 2,
    "scripts/nominator-pool-lifecycle-e2e.py": 1,
}


def fail(message: str) -> None:
    raise RuntimeError(f"PQ_E2E_INITIAL_VALIDATOR_FAILURE: {message}")


def imported_helper(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == HELPER_MODULE
        and any(alias.name == HELPER_NAME and alias.asname is None for alias in node.names)
        for node in ast.walk(tree)
    )


def main() -> int:
    root = (
        Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path(__file__).resolve().parents[1]
    )
    failures: list[str] = []
    for relative, expected_count in EXPECTED_CALLS.items():
        path = root / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if not imported_helper(tree):
            failures.append(f"{relative}: does not import {HELPER_MODULE}.{HELPER_NAME}")
        helper_calls = 0
        forbidden: list[tuple[str, int]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id == HELPER_NAME:
                helper_calls += 1
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "make_initial_validator",
                "make_initial_pq_validator",
            }:
                forbidden.append((node.func.attr, node.lineno))
        if helper_calls != expected_count:
            failures.append(
                f"{relative}: has {helper_calls} shared helper calls, expected {expected_count}"
            )
        failures.extend(
            f"{relative}:{line}: bypasses the shared helper via {name}" for name, line in forbidden
        )
    if failures:
        fail("; ".join(failures))
    print(
        "PQ_E2E_INITIAL_VALIDATOR_OK: "
        f"{len(EXPECTED_CALLS)} retained entry points use "
        f"{sum(EXPECTED_CALLS.values())} shared deterministic PQ validator calls"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, SyntaxError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
