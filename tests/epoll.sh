#!/bin/bash
# epoll over the descriptors a guest watches: what is ready, what is level-triggered, and what a
# closed descriptor stops being watched. The output is the native run, byte for byte.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    wasm="$work/epoll.$mode.wasm"
    if ! ./target/release/koinevm translate tests/guest/epoll.elf -o "$wasm" --bounds="$mode" \
            > "$work/translate.log" 2>&1; then
        echo "FAIL epoll bounds=$mode, translate:"
        cat "$work/translate.log"
        fail=1
        continue
    fi
    timeout 120 node run.mjs "$wasm" > "$work/out" 2> "$work/err"
    code=$?
    if ! diff -q tests/guest/epoll.expected "$work/out" > /dev/null; then
        echo "FAIL epoll bounds=$mode: output differs from the native run"
        diff tests/guest/epoll.expected "$work/out" | head -20
        cat "$work/err"
        fail=1
        continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL epoll bounds=$mode, exit $code"
        cat "$work/err"
        fail=1
        continue
    fi
    echo "ok   epoll bounds=$mode"
done

[ "$fail" -eq 0 ]
