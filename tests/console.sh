#!/bin/bash
# The console: an interactive shell reading the host's own input.
#
# `ARMJIT_CONSOLE=1` is what makes fd 0 the host's input and `isatty(0)` true, so bash starts as an
# interactive shell: it prints its prompt, readline echoes what it reads and edits the line, and a
# `read` builtin takes the next line the way it does at a terminal. `console.expected` is what this
# guest session prints and not a native run, because what a native run prints depends on the
# terminal it is in; the assertion is that the guest's own prompt, echo, `read` and pipeline come out
# in this order.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Typing, one line at a time. A console hands over a line at a time, and a line editor reads
# whatever has arrived: feeding the whole script at once would let readline take the next commands
# into its own buffer, where the `read` builtin cannot see them, which is not what typing does.
feed() {
    printf '%s\n' "$1"
    sleep 0.5
}

fail=0
for mode in $MODES; do
    if ! ./target/release/armjit translate rootfs/debian/bin/bash -o "$work/bash.$mode.wasm" \
            --rootfs=rootfs/debian --argv="/bin/bash,-i" \
            --env="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,HOME=/root" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL console bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    {
        feed 'echo one'
        feed 'read x'
        feed 'hello there'
        feed 'echo "read:$x"'
        feed '[ -t 0 ] && echo console-0 || echo pipe-0'
        feed '[ -t 1 ] && echo console-1 || echo pipe-1'
        feed 'printf x | { read -r y; [ -t 0 ] || echo not-a-tty; }'
        feed 'printf "%s\n" a b c | wc -l'
        feed 'nosuchcommand 2>/dev/null || echo "status:$?"'
        feed 'exit'
    } | ARMJIT_ROOTFS=rootfs/debian ARMJIT_CONSOLE=1 timeout 120 node run.mjs "$work/bash.$mode.wasm" \
        > "$work/out" 2>&1
    code=$?
    if ! diff -q tests/guest/console.expected "$work/out" > /dev/null; then
        echo "FAIL console bounds=$mode: the session differs"
        diff tests/guest/console.expected "$work/out" | head -20
        fail=1
        continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL console bounds=$mode, exit $code"
        cat "$work/err"
        fail=1
        continue
    fi
    echo "ok   console bounds=$mode"
done

[ "$fail" -eq 0 ]
