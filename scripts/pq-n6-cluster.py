#!/usr/bin/env python3
"""Run the N6.3 diagnostic multi-process PQ cluster scaffold."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from tostester.install import Install
from tostester.n6_cluster import run_cluster
from tostester.process_backend import LocalProcessBackend, RemoteCommandBackend


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--validators", type=int, default=4)
    parser.add_argument("--base-port", type=int, default=29400)
    parser.add_argument("--scenario", choices=("live-finality", "lite-framed-tcp"), required=True)
    parser.add_argument("--remote-command-inventory", type=Path)
    return parser.parse_args()


async def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.remote_command_inventory is None:
        backend = LocalProcessBackend()
    else:
        inventory = json.loads(args.remote_command_inventory.read_text())
        backend = RemoteCommandBackend(inventory["commands"])
    result = await run_cluster(
        Install(args.build_dir.resolve(), root),
        args.artifact_dir.resolve(),
        backend,
        args.validators,
        args.base_port,
        args.scenario == "lite-framed-tcp",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except (RuntimeError, TimeoutError, ValueError) as error:
        print(error)
        raise SystemExit(1) from error
