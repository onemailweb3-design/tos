#!/usr/bin/env bash
# Runs the recorded answers, and requires the record to name only tests that exist.
#
# `REGRESSION_VERIFY` compares a test's output against a hash in
# `test/regression-tests.ans` -- but only when the binary is given `--regression`.
# Without it the macro logs a line and returns success, so for as long as no job passed
# the flag, every one of these tests reported on nothing. The record drifted
# accordingly: four of its entries named tests that had been deleted, and four more
# held hashes from before the contracts they cover were rewritten.
#
# Both halves are checked here. Running the tests catches an answer that changed;
# comparing the names catches a test that went away, which is the failure the record
# cannot report by itself, because a hash nobody asks about never disagrees with
# anything.
set -euo pipefail

root="${1:-.}"
build="${2:-$root/build}"
answers="$root/test/regression-tests.ans"
failed=0

# The binaries whose tests record an answer. A binary added here without its tests in
# the record simply records them on the first run; a binary left out is the way a test
# stops being checked, so the list is compared against the record below.
binaries="test-fift test-cells test-vm test-smartcont"

for binary in $binaries; do
  if [ ! -x "$build/$binary" ]; then
    echo "regression check failed: $build/$binary is not built" >&2
    failed=1
    continue
  fi
done
[ "$failed" -eq 0 ] || exit 1

# A copy, so a run cannot quietly record a new answer over a changed one.
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
cp "$answers" "$scratch/answers.ans"
cp -r "$root/test/regression-tests.cache" "$scratch/answers.cache"

for binary in $binaries; do
  if ! "$build/$binary" --regression "$scratch/answers.ans" >"$scratch/$binary.log" 2>&1; then
    echo "regression check failed: $binary" >&2
    grep -oE "Test [A-Za-z_0-9]+ changed: \[[^]]*\]\[[^]]*\]" "$scratch/$binary.log" >&2 || true
    failed=1
  fi
done

if ! cmp -s "$answers" "$scratch/answers.ans"; then
  echo "regression check failed: the run recorded an answer that was not in the record" >&2
  diff -u "$answers" "$scratch/answers.ans" >&2 || true
  failed=1
fi

# Every recorded name must belong to a test that still runs. Without this a deleted test
# leaves its answer behind, and the record slowly becomes a list of things nobody checks.
live="$scratch/live"
: >"$live"
for binary in $binaries; do
  grep -oE "^Running test [A-Za-z_0-9]+" "$scratch/$binary.log" | sed 's/Running test //' >>"$live"
done
sort -u -o "$live" "$live"

while read -r name _; do
  case "$name" in ''|'#'*) continue ;; esac
  test_name="${name%_default}"
  if ! grep -qxF "$test_name" "$live"; then
    echo "regression check failed: $test_name has an answer but no test" >&2
    failed=1
  fi
done < <(tail -n +2 "$answers")

if [ "$failed" -eq 0 ]; then
  echo "every recorded answer belongs to a test, and every test still gives it"
fi
exit "$failed"
