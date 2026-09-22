#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"

python3 - "$root/crypto/CMakeLists.txt" <<'PY'
import pathlib
import re
import sys

cmake_path = pathlib.Path(sys.argv[1])
source = cmake_path.read_text()
embedders = (
    "embed-tos-service-native-registry-v1.sh",
    "embed-tos-service-stablecoin-escrow-v1.sh",
    "embed-tos-service-stablecoin-escrow-v2.sh",
)
pattern = re.compile(
    r"COMMAND \$\{CMAKE_COMMAND\} -E env\s+"
    r"FUNC_BIN=\$<TARGET_FILE:func>\s+"
    r"FIFT_BIN=\$<TARGET_FILE:fift>\s+"
    r"\$\{CMAKE_SOURCE_DIR\}/scripts/(?P<script>[^\s]+)"
)
resolved = [match.group("script") for match in pattern.finditer(source)]
for embedder in embedders:
    count = resolved.count(embedder)
    if count != 1:
        raise SystemExit(
            "FROZEN_BOC_TOOLCHAIN_SOURCE_FAILURE: "
            f"{embedder} has {count} target-resolved CMake commands, expected 1"
        )

for embedder in embedders:
    bare = re.search(
        rf"COMMAND\s+\$\{{CMAKE_SOURCE_DIR\}}/scripts/{re.escape(embedder)}",
        source,
    )
    if bare:
        raise SystemExit(
            "FROZEN_BOC_TOOLCHAIN_SOURCE_FAILURE: "
            f"{embedder} is still invoked without target-resolved compilers"
        )

print(
    "FROZEN_BOC_TOOLCHAIN_SOURCE_OK: all 3 CMake frozen-artifact rules use "
    "$<TARGET_FILE:func> and $<TARGET_FILE:fift>"
)
PY
