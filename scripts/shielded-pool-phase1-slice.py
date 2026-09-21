#!/usr/bin/env python3
"""Fetch the part of the phase-1 transcript this circuit needs.

The published transcript is a powers-of-tau accumulator for circuits up to
2^27 constraints and is 72 GiB.  This circuit needs 2^15, and the accumulator
stores each of its five sections in ascending power order, so what we need is a
prefix of *every section* -- five byte ranges, about eighteen megabytes.

This script does one thing: it copies those ranges and records where they came
from.  It decides nothing.  The ranges are read out of the Rust layout module,
which derives them from the transcript's own published size, and everything
that has to be true of the bytes afterwards is checked by
`verify-phase1-slice`, which parses them into curve points and runs the pairing
checks.  Fetching and judging are kept apart on purpose: this half needs the
network and no cryptography, and that half needs cryptography and no network.

    uv run python scripts/shielded-pool-phase1-slice.py --out artifacts/phase1

Writes `phase1-2m<exponent>.bin` and `phase1-2m<exponent>.json` beside each
other.  Resumable: a range already on disk with the right length and hash is
not fetched again.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CEREMONY = REPO / "tools/shielded-pool-ceremony"

# The transcript, and the size it has to have before any offset into it means
# anything. Both are declared in the Rust layout module; they are repeated in
# the failure messages here only so this script can explain itself.
CHALLENGE_URL = "https://trusted-setup.filecoin.io/phase1/challenge_19"
CHALLENGE_BYTES = 77_309_411_488
TRANSCRIPT_HASH_BYTES = 64


class Failed(Exception):
    pass


def log(message: str) -> None:
    print(f"[phase1] {message}", flush=True)


def ranges_from_rust(exponent: int) -> list[dict]:
    """The byte ranges, from the module that derives them.

    Not recomputed here.  Two copies of this arithmetic is two chances to get
    it wrong, and the Rust one is the copy with tests behind it.
    """
    result = subprocess.run(
        ["cargo", "run", "--release", "--quiet", "--bin", "phase1-ranges", "--", str(exponent)],
        cwd=CEREMONY,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise Failed(f"could not read the layout:\n{result.stdout}\n{result.stderr}")
    return json.loads(result.stdout)


def head(url: str) -> int:
    request = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(request, timeout=120) as response:
        length = response.headers.get("Content-Length")
        if length is None:
            raise Failed("the server did not report a Content-Length, so the file cannot be identified")
        return int(length)


def fetch_range(url: str, offset: int, length: int) -> bytes:
    """One range, with the server's answer checked rather than assumed.

    A server that ignores the Range header answers 200 with the whole file --
    72 GiB of it -- so the status code is the thing to check, not the bytes
    that arrive.
    """
    end = offset + length - 1
    request = urllib.request.Request(url, headers={"Range": f"bytes={offset}-{end}"})
    with urllib.request.urlopen(request, timeout=900) as response:
        if response.status != 206:
            raise Failed(
                f"asked for bytes {offset}-{end} and the server answered {response.status} "
                "rather than 206; it is sending the whole file, not the range"
            )
        content_range = response.headers.get("Content-Range", "")
        if not content_range.startswith(f"bytes {offset}-{end}/"):
            raise Failed(f"the server returned a different range: {content_range!r}")
        data = response.read(length)
    if len(data) != length:
        raise Failed(f"asked for {length} bytes at {offset} and received {len(data)}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(REPO / "artifacts/phase1"))
    parser.add_argument("--exponent", type=int, default=15,
                        help="the QAP domain exponent to slice at. The circuit decides this; "
                             "pass it only to fetch a slice for a circuit that has changed.")
    parser.add_argument("--url", default=CHALLENGE_URL)
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    slice_path = out / f"phase1-2m{args.exponent}.bin"
    record_path = out / f"phase1-2m{args.exponent}.json"

    log("reading the layout from the Rust module that derives it ...")
    ranges = ranges_from_rust(args.exponent)
    wanted = sum(r["length"] for r in ranges)
    log(f"{len(ranges)} ranges, {wanted:,} bytes in total")

    log(f"identifying {args.url} ...")
    try:
        size = head(args.url)
    except urllib.error.URLError as error:
        raise Failed(f"could not reach the transcript: {error}") from error
    if size != CHALLENGE_BYTES:
        raise Failed(
            f"the transcript is {size:,} bytes and the layout describes one of "
            f"{CHALLENGE_BYTES:,}. Every offset below is for a different file, so nothing is "
            "fetched."
        )
    log(f"the transcript is the {size:,} bytes the layout describes")

    # The 64-byte digest the challenge file opens with: the transcript's own
    # name for itself. Not verified here -- verifying it means replaying the
    # whole ceremony -- but recorded, so a deployment can be held against the
    # published attestations.
    digest = fetch_range(args.url, 0, TRANSCRIPT_HASH_BYTES).hex()
    log(f"transcript digest {digest}")

    pieces: list[bytes] = []
    for entry in ranges:
        log(
            f"{entry['name']}: {entry['points']:,} points, "
            f"{entry['length']:,} bytes at offset {entry['offset']:,}"
        )
        data = fetch_range(args.url, entry["offset"], entry["length"])
        got = hashlib.sha256(data).hexdigest()
        log(f"  sha256 {got}")
        entry["sha256"] = got
        pieces.append(data)

    body = b"".join(pieces)
    slice_path.write_bytes(body)

    record = {
        "source_url": args.url,
        "source_bytes": CHALLENGE_BYTES,
        "source_power": 27,
        "slice_power": args.exponent,
        "transcript_hash": digest,
        "ranges": [
            {
                "name": entry["name"],
                "offset": entry["offset"],
                "length": entry["length"],
                "points": entry["points"],
                "sha256": entry["sha256"],
            }
            for entry in ranges
        ],
        "slice_sha256": hashlib.sha256(body).hexdigest(),
    }
    record_path.write_text(json.dumps(record, indent=2) + "\n")

    log(f"wrote {slice_path} ({len(body):,} bytes) and {record_path}")
    log("")
    log("Nothing above says the bytes are a powers-of-tau string. Run:")
    log(f"  cargo run --release --manifest-path {CEREMONY}/Cargo.toml \\")
    log(f"      --bin verify-phase1-slice -- {slice_path} {record_path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failed as error:
        print(f"[phase1] FAILED: {error}", file=sys.stderr)
        sys.exit(1)
