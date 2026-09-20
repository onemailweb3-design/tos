#!/usr/bin/env python3
"""The consensus layer must have no way back to the classical primitives.

Two of the no-fallback invariants are properties of the source, not of any run, and a
runtime test cannot see either of them. A seam that built a legacy block signature set
and then threw it away would satisfy every end-to-end assertion while doing exactly what
the seam forbids; and a keyring signature that is produced but discarded leaves nothing
for a test to observe either. So both are checked where they exist: in the code.

The third invariant in that list -- that a transport identity is never derived from a
post-quantum public key -- is not checked here, because it is not a name to forbid. It is
enforced by `block::validator_adnl_identity` being the single accessor and by decoding
refusing a post-quantum descriptor with no address at all, which the membership tests
cover; and the inventory in scripts/check-descriptor-classical-key.sh keeps the classical
readers honest. Naming a grep for it would add a guard no input can trip.

N5 replaces the refusal with a post-quantum carrier and will need the first rule below to
name that one instead.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONSENSUS = ROOT / "validator" / "consensus"

RULES = [
    (
        re.compile(r"BlockSignatureSet::(create\w*|fetch)"),
        "constructs a legacy block signature set",
    ),
    (
        # The keyring signs for the transport plane. Consensus signs with the custodied
        # post-quantum store and nothing else.
        re.compile(r"\bsign_message\b|\bsign_messages\b|\bsign_add_get_public_key\b"),
        "asks the keyring to sign",
    ),
]


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
            for pattern, what in RULES:
                if pattern.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}: {what}: {line.strip()}")
    if scanned == 0:
        sys.exit("scanned no consensus sources; the guard is not looking at anything")
    if offenders:
        print("the consensus layer has a path back to the classical primitives:", file=sys.stderr)
        for offender in offenders:
            print("  " + offender, file=sys.stderr)
        return 1
    print(f"OK: {scanned} consensus sources, {len(RULES)} no-fallback rules, no offenders")
    return 0


if __name__ == "__main__":
    sys.exit(main())
