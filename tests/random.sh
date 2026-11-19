#!/bin/bash
# The bytes a program gets from /dev/random, /dev/urandom, getrandom and AT_RANDOM. The guest
# checks its sample against distribution tests; this runs the same module twice and compares the
# printed samples, because a generator seeded the same way every run is uniform and still
# predictable.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    wasm="$work/randomness.$mode.wasm"
    if ! ./target/release/armjit translate tests/guest/randomness.elf -o "$wasm" --bounds="$mode" \
            > "$work/translate.log" 2>&1; then
        echo "FAIL randomness bounds=$mode, translate:"
        cat "$work/translate.log"
        fail=1
        continue
    fi
    sample=""
    auxv=""
    ok=1
    for run in 1 2; do
        timeout 120 node run.mjs "$wasm" > "$work/out$run" 2> "$work/err$run"
        code=$?
        if grep -q '^FAIL' "$work/out$run"; then
            echo "FAIL randomness bounds=$mode, run $run:"
            grep '^FAIL' "$work/out$run"
            cat "$work/err$run"
            ok=0
            break
        fi
        if ! grep -q '^randomness: all checks passed$' "$work/out$run"; then
            echo "FAIL randomness bounds=$mode, run $run: no summary"
            cat "$work/out$run"
            cat "$work/err$run"
            ok=0
            break
        fi
        if [ "$code" != 0 ]; then
            echo "FAIL randomness bounds=$mode, run $run, exit $code"
            cat "$work/err$run"
            ok=0
            break
        fi
        got_sample=$(sed -n 's/^sample //p' "$work/out$run")
        got_auxv=$(sed -n 's/^auxv //p' "$work/out$run")
        if [ -z "$got_sample" ] || [ -z "$got_auxv" ]; then
            echo "FAIL randomness bounds=$mode, run $run: no sample to compare"
            ok=0
            break
        fi
        if [ "$run" = 1 ]; then
            sample=$got_sample
            auxv=$got_auxv
        else
            if [ "$got_sample" = "$sample" ]; then
                echo "FAIL randomness bounds=$mode: both runs read the same bytes from /dev/urandom"
                ok=0
            fi
            if [ "$got_auxv" = "$auxv" ]; then
                echo "FAIL randomness bounds=$mode: both runs got the same AT_RANDOM"
                ok=0
            fi
        fi
    done
    if [ "$ok" = 1 ]; then
        echo "ok   randomness bounds=$mode"
    else
        fail=1
    fi
done

[ "$fail" -eq 0 ]
