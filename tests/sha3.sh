#!/bin/bash
# The SHA-3 instructions: eor3, bcax, xar and rax1, the four Keccak's round is written with.
#
# There is no native oracle: a Mac has no FEAT_SHA3, so a fixture built for it would be an illegal
# instruction. The guest computes the reference in scalar C from the definitions and reports each
# check, so the test requires every check to pass and the run to exit 0.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    if ! ./target/release/armjit translate tests/guest/sha3.elf -o "$work/sha3.$mode.wasm" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL sha3 bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    node run.mjs "$work/sha3.$mode.wasm" > "$work/out" 2> "$work/err"
    code=$?
    if grep -q '^FAIL' "$work/out"; then
        echo "FAIL sha3 bounds=$mode:"; grep '^FAIL' "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if ! grep -q '^sha3: all checks passed$' "$work/out"; then
        echo "FAIL sha3 bounds=$mode: no summary"; cat "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL sha3 bounds=$mode, exit $code"; fail=1; continue
    fi
    echo "ok   sha3 bounds=$mode"
done

[ "$fail" -eq 0 ]
