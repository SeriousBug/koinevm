#!/bin/bash
# A guest that stays inside a loop while the world moves: a signal that arrives mid-loop, and a child
# that spins for ever while its parent still gets a turn. Both need the preemption point at a backward
# branch, and `poll.expected` is what the same source prints on a real kernel.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    if ! ./target/release/armjit translate tests/guest/poll.elf -o "$work/poll.$mode.wasm" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL poll bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    timeout 120 node run.mjs "$work/poll.$mode.wasm" > "$work/out" 2> "$work/err"
    code=$?
    if ! diff -q tests/guest/poll.expected "$work/out" > /dev/null; then
        echo "FAIL poll bounds=$mode: output differs from the native run"
        diff tests/guest/poll.expected "$work/out" | head -20
        cat "$work/err"
        fail=1
        continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL poll bounds=$mode, exit $code"
        cat "$work/err"
        fail=1
        continue
    fi
    echo "ok   poll bounds=$mode"
done

[ "$fail" -eq 0 ]
