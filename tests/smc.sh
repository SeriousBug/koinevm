#!/bin/bash
# A guest that writes an instruction into its own text and runs it: the page is made writable, the
# words are replaced and flushed, and the call has to run the new code rather than the translation of
# what was there before. `smc.expected` is what the same source prints on a real kernel.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    if ! ./target/release/armjit translate tests/guest/smc.elf -o "$work/smc.$mode.wasm" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL smc bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    timeout 120 node run.mjs "$work/smc.$mode.wasm" > "$work/out" 2> "$work/err"
    code=$?
    if ! diff -q tests/guest/smc.expected "$work/out" > /dev/null; then
        echo "FAIL smc bounds=$mode: output differs from the native run"
        diff tests/guest/smc.expected "$work/out" | head -20
        cat "$work/err"
        fail=1
        continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL smc bounds=$mode, exit $code"
        cat "$work/err"
        fail=1
        continue
    fi
    echo "ok   smc bounds=$mode"
done

[ "$fail" -eq 0 ]
