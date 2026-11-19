#!/bin/bash
# The pages the guest is not allowed to touch: a store to a page it made read-only or PROT_NONE, a
# load from one it unmapped, a call into a page mapped without execute, a store to the null page and
# one to the page table the machine keeps at 0x1000.
#
# Each case is a child, and the parent checks the wait status says a signal ended it. `faults.expected`
# is what the same source prints on a real kernel: a signal is a signal there too, so this fixture is
# one of the few that a native run can answer for.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    if ! ./target/release/armjit translate tests/guest/faults.elf -o "$work/faults.$mode.wasm" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL faults bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    timeout 120 node run.mjs "$work/faults.$mode.wasm" > "$work/out" 2> "$work/err"
    code=$?
    if ! diff -q tests/guest/faults.expected "$work/out" > /dev/null; then
        echo "FAIL faults bounds=$mode: output differs from the native run"
        diff tests/guest/faults.expected "$work/out" | head -20
        cat "$work/err"
        fail=1
        continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL faults bounds=$mode, exit $code"
        cat "$work/err"
        fail=1
        continue
    fi
    echo "ok   faults bounds=$mode"
done

[ "$fail" -eq 0 ]
