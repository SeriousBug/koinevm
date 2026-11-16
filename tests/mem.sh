#!/bin/bash
# The memory syscalls: mmap, munmap, mprotect, brk.
#
# There is no native oracle for these: the numbers and the initial map are Linux's, and the host
# provides them. The guest asserts the properties a kernel owes it and reports each one, so the test
# requires every check to pass and the run to exit 0.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
for mode in $MODES; do
    if ! ./target/release/armjit translate tests/guest/mem.elf -o "$work/mem.$mode.wasm" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL mem bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    node run.mjs "$work/mem.$mode.wasm" > "$work/out" 2> "$work/err"
    code=$?
    if grep -q '^FAIL' "$work/out"; then
        echo "FAIL mem bounds=$mode:"; grep '^FAIL' "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if ! grep -q '^mem: all checks passed$' "$work/out"; then
        echo "FAIL mem bounds=$mode: no summary"; cat "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL mem bounds=$mode, exit $code"; fail=1; continue
    fi
    echo "ok   mem bounds=$mode"
done

[ "$fail" -eq 0 ]
