#!/usr/bin/env python3
"""Keep every current tosctl stake producer behind the shared local PQ refusal."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise RuntimeError(f"TOSCTL_PQ_STAKE_BUILDER_FAILURE: {message}")


def collapsed(path: Path) -> str:
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
    callers = {
        "election daemon": (
            root / "tosctl/src/node-control/elections/src/runner.rs",
            r"let body = nominator::new_stake\(&nominator::NewStakeParams \{.*?signature: signature\.as_slice\(\),.*?\}\)\?;",
        ),
        "interactive bid command": (
            root / "tosctl/src/node-control/commands/src/commands/nodectl/vote_cmd.rs",
            r"let payload = nominator::new_stake\(&nominator::NewStakeParams \{.*?signature: signature\.as_slice\(\),.*?\}\)\?;",
        ),
        "config-wallet pool command": (
            root / "tosctl/src/node-control/commands/src/commands/nodectl/config_wallet_cmd.rs",
            r"let payload = nominator::new_stake\(&nominator::NewStakeParams \{.*?signature: &signature,.*?\}\)\?;",
        ),
    }

    for name, (path, pattern) in callers.items():
        matches = re.findall(pattern, collapsed(path))
        if len(matches) != 1:
            fail(f"{name} reaches the shared new_stake refusal {len(matches)} times, expected 1")

    print("TOSCTL_PQ_STAKE_BUILDER_OK: all three tosctl stake producers propagate the shared refusal")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
