#!/bin/bash
# A dynamically linked guest against its own native run: the rootfs's glibc, translated, must print
# what it prints on a real machine.
#
# This is the test that catches a mis-emitted instruction in library code the fixtures cannot reach
# on their own. `tools/build-dyn-guest.sh` builds the binary in a container and records the oracle
# from the same binary running natively there.
set -uo pipefail
cd "$(dirname "$0")/.."

GUESTS=${GUESTS:-"fmt procs str vops argv cxx neon threads resolve afamily gai sha512dyn"}
MODES=${MODES:-"check trust"}
rootfs=rootfs/debian

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for g in $GUESTS; do
    for mode in $MODES; do
        wasm="$work/$g.$mode.wasm"
        if ! ./target/release/armjit translate "tests/guest/${g}_dyn.elf" -o "$wasm" \
                --rootfs=$rootfs --bounds="$mode" --trace \
                --argv=./tests/guest/${g}_dyn.elf > "$work/translate.log" 2>&1; then
            echo "FAIL $g bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
        fi
        ARMJIT_ROOTFS=$rootfs timeout "${GUEST_TIMEOUT:-300}" node run.mjs "$wasm" > "$work/out" 2> "$work/err"
        code=$?
        if ! diff -q "tests/guest/$g.expected" "$work/out" > /dev/null; then
            echo "FAIL $g bounds=$mode, output:"
            diff "tests/guest/$g.expected" "$work/out" | head -20
            head -5 "$work/err"
            fail=1
            continue
        fi
        if [ "$code" != 0 ]; then
            echo "FAIL $g bounds=$mode, exit $code"; head -5 "$work/err"; fail=1; continue
        fi
        echo "ok   $g bounds=$mode"
    done
done

[ "$fail" -eq 0 ]
