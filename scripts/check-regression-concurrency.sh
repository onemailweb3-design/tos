#!/usr/bin/env bash
set -euo pipefail

root=${1:-.}
build=${2:-$root/build}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

for binary in test-fift test-cells; do
  if [[ ! -x "$build/$binary" ]]; then
    echo "REGRESSION_CONCURRENCY_FAILURE: $binary is not built" >&2
    exit 1
  fi
  printf 'abce\n' >"$scratch/expected-$binary.ans"
  "$build/$binary" --regression "$scratch/expected-$binary.ans" \
    --regression-cache "$scratch/cache-expected-$binary" --filter -Bench >/dev/null 2>&1
done

{ tail -n +2 "$scratch/expected-test-fift.ans"; tail -n +2 "$scratch/expected-test-cells.ans"; } \
  | sort >"$scratch/expected"

printf 'abce\n' >"$scratch/shared.ans"
"$build/test-fift" --regression "$scratch/shared.ans" --regression-cache "$scratch/cache-shared-fift" \
  --filter -Bench >"$scratch/fift.log" 2>&1 &
fift_pid=$!

# Wait until the slow writer has loaded the empty record and begun executing.
# The fast writer then necessarily starts from the same dirty snapshot; without
# the locked reload-and-merge, whichever process renames last drops the other.
for _ in $(seq 1 200); do
  if grep -q '^Running test ' "$scratch/fift.log"; then
    break
  fi
  if ! kill -0 "$fift_pid" 2>/dev/null; then
    wait "$fift_pid" || true
    echo "REGRESSION_CONCURRENCY_FAILURE: test-fift exited before the concurrent writer started" >&2
    exit 1
  fi
  sleep 0.01
done
if ! grep -q '^Running test ' "$scratch/fift.log"; then
  kill "$fift_pid" 2>/dev/null || true
  wait "$fift_pid" 2>/dev/null || true
  echo "REGRESSION_CONCURRENCY_FAILURE: test-fift did not reach its first test" >&2
  exit 1
fi

"$build/test-cells" --regression "$scratch/shared.ans" --regression-cache "$scratch/cache-shared-cells" \
  --filter -Bench >"$scratch/cells.log" 2>&1 &
cells_pid=$!
wait "$cells_pid"
wait "$fift_pid"

tail -n +2 "$scratch/shared.ans" | sort >"$scratch/actual"
if ! cmp -s "$scratch/expected" "$scratch/actual"; then
  echo "REGRESSION_CONCURRENCY_FAILURE: concurrent dirty writers did not preserve both answer sets" >&2
  diff -u "$scratch/expected" "$scratch/actual" >&2 || true
  exit 1
fi

echo "REGRESSION_CONCURRENCY_OK: concurrent dirty writers preserved both answer sets"
