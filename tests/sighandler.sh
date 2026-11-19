#!/bin/bash
# A signal handler that is the guest's own code: the kernel writes a frame on the stack, starts the
# guest at the handler, and the restorer the frame names puts the machine back. `sighandler.expected`
# is what the same source prints on a real kernel, which answers for all of it.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    if ! ./target/release/armjit translate tests/guest/sighandler.elf -o "$work/sighandler.$mode.wasm" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL sighandler bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    timeout 120 node run.mjs "$work/sighandler.$mode.wasm" > "$work/out" 2> "$work/err"
    code=$?
    if ! diff -q tests/guest/sighandler.expected "$work/out" > /dev/null; then
        echo "FAIL sighandler bounds=$mode: output differs from the native run"
        diff tests/guest/sighandler.expected "$work/out" | head -20
        cat "$work/err"
        fail=1
        continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL sighandler bounds=$mode, exit $code"
        cat "$work/err"
        fail=1
        continue
    fi
    echo "ok   sighandler bounds=$mode"
done

[ "$fail" -eq 0 ]
