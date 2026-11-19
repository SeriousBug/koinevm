#!/bin/bash
# Regression matrix: every fixture, at every optimisation level, in both address-validation modes.
# Guest stdout and exit status must match the native oracle byte for byte.
#
# GUESTS=hello OPTS=-O0 MODES=check tests/run.sh   narrows the matrix.
set -uo pipefail
cd "$(dirname "$0")/.."

GUESTS=${GUESTS:-"hello call flags simd bits stack fp sha512"}
OPTS=${OPTS:-"-O0 -O1 -O2 -O3 -Os"}
MODES=${MODES:-"check trust"}

work=$(mktemp -d)
trap 'rm -rf "$work"; OPT=-O2 bash tools/build-guest.sh > /dev/null 2>&1' EXIT

if ! cargo build --release --quiet > "$work/cargo.log" 2>&1; then
    echo "FAIL cargo build"
    tail -40 "$work/cargo.log"
    exit 1
fi

pass=0
fail=0

report_fail() {
    local label=$1
    shift
    echo "FAIL $label"
    for line in "$@"; do echo "     $line"; done
    fail=$((fail + 1))
}

for opt in $OPTS; do
    if ! OPT="$opt" bash tools/build-guest.sh > "$work/build$opt.log" 2>&1; then
        echo "FAIL build $opt (see below)"
        cat "$work/build$opt.log"
        exit 1
    fi
    for g in $GUESTS; do
        elf=tests/guest/$g.elf
        want=tests/guest/$g.expected
        want_exit=$(cat tests/guest/$g.expected_exit)
        for mode in $MODES; do
            label="$g $opt bounds=$mode"
            wasm="$work/$g.$opt.$mode.wasm"
            if ! ./target/release/armjit translate "$elf" -o "$wasm" --bounds="$mode" \
                    > "$work/translate.log" 2>&1; then
                report_fail "$label" "translate:" $(cat "$work/translate.log")
                continue
            fi
            node run.mjs "$wasm" > "$work/out" 2> "$work/err"
            got_exit=$?
            if ! diff -q "$want" "$work/out" > /dev/null; then
                report_fail "$label" "stdout differs:" $(diff "$want" "$work/out" | head -20)
                continue
            fi
            if [ "$got_exit" != "$want_exit" ]; then
                report_fail "$label" "exit $got_exit, want $want_exit"
                continue
            fi
            pass=$((pass + 1))
            echo "ok   $label"
        done
    done
done

for extra in dyn mem files net dns signals epoll faults sighandler poll smc console pty eventfd; do
    extra_out=$(MODES="$MODES" bash "tests/$extra.sh")
    extra_code=$?
    [ -n "$extra_out" ] && echo "$extra_out"
    pass=$((pass + $(echo "$extra_out" | grep -c '^ok ')))
    [ "$extra_code" -eq 0 ] || fail=$((fail + 1))
done

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
