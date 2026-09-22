#!/usr/bin/env bash
set -euo pipefail

repo=${1:-$(cd "$(dirname "$0")/.." && pwd)}

require_exact() {
  local file=$1
  local marker=$2
  local count
  count=$(rg -Fxc "$marker" "$repo/$file" || true)
  count=${count:-0}
  if [[ "$count" != 1 ]]; then
    echo "BENCHMARK_EXCLUSION_SOURCE_FAILURE: $file marker '$marker' count=$count" >&2
    exit 1
  fi
}

# The runner's substring filter is case-sensitive. Keep benchmark names in the
# spelling that -Bench excludes, and pin the two binaries that previously ran
# their benchmarks without any exclusion at all.
require_exact crypto/test/test-db.cpp 'TEST(Cell, BenchSha) {'
require_exact crypto/test/test-db.cpp 'TEST(Cell, BenchShaThreaded) {'
require_exact crypto/test/Ed25519.cpp 'TEST(Crypto, BenchEd25519) {'
require_exact tdutils/test/crypto.cpp 'TEST(Crypto, BenchCrc32c) {'
require_exact CMakeLists.txt 'tos_test(test-ed25519 ${BENCHMARK_FILTER})'
require_exact CMakeLists.txt 'tos_test(test-tdutils ${BENCHMARK_FILTER})'

if rg -n 'TEST\([^,]+, [^)]*(sha_benchmark|ed25519_benchmark|crc32c_benchmark)' \
    "$repo/crypto/test/test-db.cpp" "$repo/crypto/test/Ed25519.cpp" "$repo/tdutils/test/crypto.cpp"; then
  echo "BENCHMARK_EXCLUSION_SOURCE_FAILURE: a benchmark still escapes the case-sensitive -Bench filter" >&2
  exit 1
fi

echo "BENCHMARK_EXCLUSION_SOURCE_OK"
