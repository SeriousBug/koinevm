#!/bin/bash
# The devices a kernel keeps in `/dev`: the ones that answer with nothing, with zeros, with a
# failure, with random bytes and with the terminal, and the links a program reaches its own
# descriptors through.
#
# There is no native oracle: `/dev` on the machine that builds the fixtures is macOS's. The guest
# asserts the properties a kernel owes and reports each one, so the test requires every check to
# pass, the bytes written through `/dev/stdout` to have come out, and the run to exit 0.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The tree is empty except for the directory shared memory lives in: `/dev/shm` is a directory the
# filesystem holds, so a file written there is a file.
root="$work/root"
mkdir -p "$root/dev/shm"

fail=0
for mode in $MODES; do
    if ! ./target/release/koinevm translate tests/guest/dev.elf -o "$work/dev.$mode.wasm" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL dev bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    KOINEVM_ROOTFS="$root" timeout 120 node run.mjs "$work/dev.$mode.wasm" > "$work/out" 2> "$work/err"
    code=$?
    if grep -q '^FAIL' "$work/out"; then
        echo "FAIL dev bounds=$mode:"; grep '^FAIL' "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if ! grep -q '^dev: wrote through /dev/stdout$' "$work/out"; then
        echo "FAIL dev bounds=$mode: nothing came out of /dev/stdout"; cat "$work/out"; fail=1; continue
    fi
    if ! grep -q '^dev: all checks passed$' "$work/out"; then
        echo "FAIL dev bounds=$mode: no summary"; cat "$work/out"; cat "$work/err"; fail=1; continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL dev bounds=$mode, exit $code"; fail=1; continue
    fi
    echo "ok   dev bounds=$mode"
done

[ "$fail" -eq 0 ]
