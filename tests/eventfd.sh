#!/bin/bash
# eventfd: the counter a thread adds to and another one waits on. Nothing in the tree used one until
# libuv did, and without the syscall the handle it starts never initialised - so the crash came much
# later, on a thread, as a load from a null pointer.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    wasm="$work/eventfd.$mode.wasm"
    if ! ./target/release/armjit translate tests/guest/eventfd.elf -o "$wasm" --bounds="$mode" \
            > "$work/translate.log" 2>&1; then
        echo "FAIL eventfd bounds=$mode, translate:"
        cat "$work/translate.log"
        fail=1
        continue
    fi
    timeout 120 node run.mjs "$wasm" > "$work/out" 2> "$work/err"
    code=$?
    if ! diff -q tests/guest/eventfd.expected "$work/out" > /dev/null; then
        echo "FAIL eventfd bounds=$mode: output differs from the recorded run"
        diff tests/guest/eventfd.expected "$work/out" | head -20
        cat "$work/err"
        fail=1
        continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL eventfd bounds=$mode, exit $code"
        cat "$work/err"
        fail=1
        continue
    fi
    echo "ok   eventfd bounds=$mode"
done

[ "$fail" -eq 0 ]
