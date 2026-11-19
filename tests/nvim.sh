#!/bin/bash
# An editor on top of the whole stack. `nvim` is the biggest libuv program in the tree, and what it
# asks the kernel for is what any program that waits, counts and buffers asks for: a loop started
# with `eventfd`, a clock with a resolution, and a file read through `readv`. Without them libuv
# leaves the async handle of a loop half-built and the failure surfaces much later, on a thread, as
# a load through a null pointer - so the version line and the written file are the checks.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
out="rootfs/debian/tmp/nvim-check.txt"
trap 'rm -rf "$work"; rm -f "$out"' EXIT

# `neovim` is not something the tree puts in the image: it is there because an editor is what
# showed the syscalls that libuv needs. Without it there is nothing to run.
if [ ! -x rootfs/debian/usr/bin/nvim ]; then
    echo "skip nvim: the image has no neovim"
    exit 0
fi

fail=0
for mode in $MODES; do
    wasm="$work/nvim.$mode.wasm"
    if ! ./target/release/armjit translate rootfs/debian/usr/bin/nvim -o "$wasm" \
            --rootfs=rootfs/debian --argv="/usr/bin/nvim,--headless,-i,NONE,--version" \
            --env="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,HOME=/root" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL nvim bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    ARMJIT_ROOTFS=rootfs/debian timeout 300 node run.mjs "$wasm" > "$work/version" 2>&1
    code=$?
    if ! grep -q "^NVIM v" "$work/version"; then
        echo "FAIL nvim bounds=$mode: no version line"; head -10 "$work/version"; fail=1; continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL nvim bounds=$mode, --version exited $code"; fail=1; continue
    fi

    # The same binary, writing a file it had to open, fill and close, and then exiting on its own.
    rm -f "$out"
    if ! ./target/release/armjit translate rootfs/debian/usr/bin/nvim -o "$work/write.$mode.wasm" \
            --rootfs=rootfs/debian \
            --argv="/usr/bin/nvim,--headless,-i,NONE,-c,put ='nvim wrote this',-c,write /tmp/nvim-check.txt,-c,quit" \
            --env="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,HOME=/root" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL nvim bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    ARMJIT_ROOTFS=rootfs/debian timeout 300 node run.mjs "$work/write.$mode.wasm" > "$work/write" 2>&1
    code=$?
    want="nvim wrote this"
    got=$(head -1 "$out" 2>/dev/null)
    if [ "$got" != "$want" ]; then
        echo "FAIL nvim bounds=$mode: wrote '$got', want '$want'"; head -10 "$work/write"; fail=1; continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL nvim bounds=$mode, the write exited $code"; fail=1; continue
    fi
    echo "ok   nvim bounds=$mode"
done

[ "$fail" -eq 0 ]
