#!/usr/bin/env python3
"""Forbid treating a transport key hash as a validator identity."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


FORBIDDEN = re.compile(
    r"\bValidatorId\s*[({][^;]{0,300}?\b[A-Za-z_][A-Za-z0-9_]*\.bits256_value\s*\(",
    re.MULTILINE,
)
SOURCE_SUFFIXES = frozenset({".cpp", ".cc", ".cxx", ".h", ".hh", ".hpp"})


def violations(root: Path) -> list[str]:
    found: list[str] = []
    for source_root in (root / "validator", root / "crypto"):
        if not source_root.is_dir():
            raise RuntimeError(
                f"validator-id key-hash check failed: scan root does not exist: {source_root}"
            )
        for path in sorted(source_root.rglob("*")):
            if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
                continue
            text = path.read_text(errors="replace")
            for match in FORBIDDEN.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                excerpt = " ".join(match.group(0).split())
                found.append(f"{path.relative_to(root)}:{line}: {excerpt}")
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    found = violations(args.root.resolve())
    if found:
        raise RuntimeError(
            "validator-id key-hash check failed: a transport key hash was constructed "
            "as ValidatorId; use local_consensus_descriptor so PQ custody decides "
            "membership:\n  "
            + "\n  ".join(found)
        )
    print("validator-id key-hash check passed: no transport key hash is used as ValidatorId")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
