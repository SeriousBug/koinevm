#!/bin/bash
# A guest that generates machine code and jumps into it: a page it wrote and then made executable,
# a second write to a page that had already run, an RWX page, a branch that leaves one page for the
# next, a call from generated code into the translated image, a syscall made from generated code, and
# code in a page above the first 4 GiB, where the pc is a different key in the dispatcher.
#
# There is no native oracle: macOS needs `MAP_JIT` and a per-thread write-protect toggle for what a
# Linux program does with `mprotect`. The guest asserts what a kernel owes a JIT and reports each
# check, so the test requires every check to pass and the run to exit 0.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    if ! ./target/release/armjit translate tests/guest/jit.elf -o "$work/jit.$mode.wasm" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL jit bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    timeout 120 node run.mjs "$work/jit.$mode.wasm" > "$work/out" 2> "$work/err"
    code=$?
    if grep -q '^FAIL' "$work/out"; then
        echo "FAIL jit bounds=$mode:"; grep '^FAIL' "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if ! grep -q '^jit: all checks passed$' "$work/out"; then
        echo "FAIL jit bounds=$mode: no summary"; cat "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL jit bounds=$mode, exit $code"; fail=1; continue
    fi
    echo "ok   jit bounds=$mode"
done

[ "$fail" -eq 0 ]
