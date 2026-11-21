#!/bin/bash
# The file syscalls against a root filesystem directory, which is how the guest will see a Debian
# userland. The guest asserts each property; this builds the tree it expects and requires every
# check to pass.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

root="$work/root"
mkdir -p "$root/sub"
printf 'hello from the rootfs\n' > "$root/data.txt"
ln -s data.txt "$root/link"

fail=0
for mode in $MODES; do
    if ! ./target/release/koinevm translate tests/guest/files.elf -o "$work/files.$mode.wasm" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL files bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    KOINEVM_ROOTFS="$root" node run.mjs "$work/files.$mode.wasm" > "$work/out" 2> "$work/err"
    code=$?
    if grep -q '^FAIL' "$work/out"; then
        echo "FAIL files bounds=$mode:"; grep '^FAIL' "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if ! grep -q '^files: all checks passed$' "$work/out"; then
        echo "FAIL files bounds=$mode: no summary"; cat "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL files bounds=$mode, exit $code"; fail=1; continue
    fi
    echo "ok   files bounds=$mode"
done

[ "$fail" -eq 0 ]
