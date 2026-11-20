#!/bin/bash
# An address space bigger than one wasm memory: 8 GiB is two of them, and every access above the
# first 4 GiB is a different instruction sequence than one below it.
#
# There is no native oracle: the answer is the host's. The guest asserts the properties a kernel
# owes a program that lives above the boundary and reports each one, so the test requires every
# check to pass and the run to exit 0.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
PAGES=${PAGES:-131072}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    if ! ./target/release/armjit translate tests/guest/big.elf -o "$work/big.$mode.wasm" \
            --bounds="$mode" --mem-pages="$PAGES" > "$work/translate.log" 2>&1; then
        echo "FAIL big bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    node run.mjs "$work/big.$mode.wasm" > "$work/out" 2> "$work/err"
    code=$?
    if grep -q '^FAIL' "$work/out"; then
        echo "FAIL big bounds=$mode:"; grep '^FAIL' "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if ! grep -q '^big: all checks passed$' "$work/out"; then
        echo "FAIL big bounds=$mode: no summary"; cat "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL big bounds=$mode, exit $code"; fail=1; continue
    fi
    echo "ok   big bounds=$mode"
done

[ "$fail" -eq 0 ]
