#!/usr/bin/env python3
"""The consensus layer must not build a legacy block signature set at all.

The end-to-end gate can see that no block was accepted and no finalized marker was
written, but it cannot see an object that was constructed and thrown away. A seam that
built the legacy carrier and then returned the N5 refusal would satisfy every runtime
assertion while doing exactly what the seam exists to forbid -- copying post-quantum
signatures into a carrier whose encoding is a fixed 64 bytes.

That property is structural, so it is checked structurally: no source file under the
consensus layer may name a BlockSignatureSet constructor. N5 replaces the refusal with a
post-quantum carrier and will need this list updated to name that one instead.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONSENSUS = ROOT / "validator" / "consensus"

# Every way the legacy carrier can come into existence.
FORBIDDEN = re.compile(r"BlockSignatureSet::(create\w*|fetch)")


def main() -> int:
    if not CONSENSUS.is_dir():
        sys.exit(f"consensus sources not found at {CONSENSUS}")
    offenders = []
    scanned = 0
    for path in sorted(CONSENSUS.rglob("*")):
        if path.suffix not in (".cpp", ".h", ".hpp"):
            continue
        scanned += 1
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if FORBIDDEN.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    if scanned == 0:
        sys.exit("scanned no consensus sources; the guard is not looking at anything")
    if offenders:
        print("the consensus layer constructs a legacy block signature set:", file=sys.stderr)
        for offender in offenders:
            print("  " + offender, file=sys.stderr)
        return 1
    print(f"OK: {scanned} consensus sources, none constructs a legacy block signature set")
    return 0


if __name__ == "__main__":
    sys.exit(main())
