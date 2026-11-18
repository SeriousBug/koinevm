#!/bin/bash
# The dynamically linked path: a PIE program whose PT_INTERP names a stand-in loader.
#
# Nothing native can run this pair, so the assertions are the two halves of the contract: the loader
# sees an initial stack that describes the program it was started for (AT_BASE, AT_ENTRY, AT_PHDR,
# AT_PAGESZ), and the program then runs to its own exit status with its own output.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    wasm="$work/hello_pie.$mode.wasm"
    if ! ./target/release/armjit translate tests/guest/hello_pie.elf -o "$wasm" \
            --interp=tests/guest/interp.elf --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL hello_pie bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    node run.mjs "$wasm" > "$work/out" 2> "$work/err"
    code=$?
    # marker proves the loader image really moved to its own base; the rest is the auxv it was given.
    if ! head -1 "$work/out" | grep -qE \
            '^ld-fake: marker=0x[0-9a-f]+ base=0x0*10000000 entry=0x0*401000 phdr=0x0*400040 pagesz=0x0*1000$'; then
        echo "FAIL hello_pie bounds=$mode, loader line:"; head -1 "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if ! tail -n +2 "$work/out" | diff -q tests/guest/hello.expected - > /dev/null; then
        echo "FAIL hello_pie bounds=$mode, program output:"
        tail -n +2 "$work/out" | diff tests/guest/hello.expected - | head -20
        fail=1; continue
    fi
    if [ "$code" != "$(cat tests/guest/hello.expected_exit)" ]; then
        echo "FAIL hello_pie bounds=$mode, exit $code"; fail=1; continue
    fi
    echo "ok   hello_pie bounds=$mode"
done

[ "$fail" -eq 0 ]
