#!/bin/bash
# Debian's dash, translated, against the same binary on a real kernel: the oracle is `chroot` in a
# container, so a case is whatever that dash prints and however it exits.
#
# The cases live in tests/guest/shell-cases.txt. Each one is a whole `-c` script, which means one
# translation per case, because argv is part of the initial stack the translator builds. A run that
# never returns is killed, since a guest spinning inside one wasm call is not something the watchdog
# in host/pages.mjs can see.
set -uo pipefail
cd "$(dirname "$0")/.."

CASES=${CASES:-tests/guest/shell-cases.txt}
MODES=${MODES:-"check"}
LIMIT=${LIMIT:-20}
rootfs=rootfs/debian
dash="$rootfs/bin/dash"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
n=0
while IFS= read -r script; do
    case "$script" in
        '' | '#'*) continue ;;
    esac
    n=$((n + 1))

    docker run --rm -v "$PWD/$rootfs":/r debian:bookworm chroot /r /bin/dash -c "$script" \
        > "$work/native.out" 2> "$work/native.err"
    native_code=$?

    for mode in $MODES; do
        wasm="$work/dash.$mode.wasm"
        if ! ./target/release/armjit translate "$dash" -o "$wasm" --rootfs="$rootfs" \
                --bounds="$mode" --argv=/bin/dash,-c,"$script" > "$work/translate.log" 2>&1; then
            echo "FAIL [$script] bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
        fi

        ARMJIT_ROOTFS=$rootfs node run.mjs "$wasm" > "$work/out" 2> "$work/err" &
        pid=$!
        {
            sleep "$LIMIT"
            kill -9 "$pid" 2> /dev/null
        } &
        dog=$!
        wait "$pid"
        code=$?
        kill "$dog" 2> /dev/null
        wait "$dog" 2> /dev/null

        if [ "$code" = 137 ]; then
            echo "FAIL [$script] bounds=$mode, killed after ${LIMIT}s"
            head -3 "$work/err"
            fail=1; continue
        fi
        if ! diff -q "$work/native.out" "$work/out" > /dev/null; then
            echo "FAIL [$script] bounds=$mode, stdout:"
            diff "$work/native.out" "$work/out" | head -10
            fail=1; continue
        fi
        if ! diff -q "$work/native.err" "$work/err" > /dev/null; then
            echo "FAIL [$script] bounds=$mode, stderr:"
            diff "$work/native.err" "$work/err" | head -10
            fail=1; continue
        fi
        if [ "$code" != "$native_code" ]; then
            echo "FAIL [$script] bounds=$mode, exit $code not $native_code"
            fail=1; continue
        fi
        echo "ok   [$script] bounds=$mode"
    done
done < "$CASES"

echo "$n cases"
[ "$fail" -eq 0 ]
