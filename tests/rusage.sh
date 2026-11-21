#!/bin/bash
# The CPU accounting: getrusage for the process, a thread and the children, wait4's rusage, times.
#
# There is no native oracle for these: how much a program has cost is the host's answer, and a real
# kernel would give its own. The guest asserts the properties a kernel owes it - that the counters
# move, that the split stays inside the wall clock, that a reaped child's time reaches its parent -
# so the test requires every check to pass and the run to exit 0.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    if ! ./target/release/koinevm translate tests/guest/rusage.elf -o "$work/rusage.$mode.wasm" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL rusage bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    node run.mjs "$work/rusage.$mode.wasm" > "$work/out" 2> "$work/err"
    code=$?
    if grep -q '^FAIL' "$work/out"; then
        echo "FAIL rusage bounds=$mode:"; grep '^FAIL' "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if ! grep -q '^rusage: all checks passed$' "$work/out"; then
        echo "FAIL rusage bounds=$mode: no summary"; cat "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL rusage bounds=$mode, exit $code"; fail=1; continue
    fi
    echo "ok   rusage bounds=$mode"
done

[ "$fail" -eq 0 ]
