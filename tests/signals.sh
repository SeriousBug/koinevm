#!/bin/bash
# The signals a process sends itself and its children, against the same binary on a real kernel: what
# ends a process, the wait status its parent reads, and the dispositions that need no handler.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    wasm="$work/signals.$mode.wasm"
    if ! ./target/release/koinevm translate tests/guest/signals.elf -o "$wasm" --bounds="$mode" \
            > "$work/translate.log" 2>&1; then
        echo "FAIL signals bounds=$mode, translate:"
        cat "$work/translate.log"
        fail=1
        continue
    fi
    timeout 120 node run.mjs "$wasm" > "$work/out" 2> "$work/err"
    code=$?
    if ! diff -q tests/guest/signals.expected "$work/out" > /dev/null; then
        echo "FAIL signals bounds=$mode: output differs from the native run"
        diff tests/guest/signals.expected "$work/out" | head -20
        cat "$work/err"
        fail=1
        continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL signals bounds=$mode, exit $code"
        cat "$work/err"
        fail=1
        continue
    fi
    echo "ok   signals bounds=$mode"
done

[ "$fail" -eq 0 ]
