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
        feed 'read -u 2 y; echo "e:$y"'
        feed 'stderr there'
        feed '[ -t 0 ] && echo console-0 || echo pipe-0'
        feed '[ -t 1 ] && echo console-1 || echo pipe-1'
        feed 'printf x | { read -r y; [ -t 0 ] || echo not-a-tty; }'
        # Not `feed`: `dd` is translated on its way in, and the read has to find the console empty
        # for the non-blocking one to answer at once, so the next line waits for it to be running.
        printf 'dd iflag=nonblock bs=1 count=1 2>&1 | head -1\n'
        sleep 3
        feed 'printf "%s\n" a b c | wc -l'
        feed 'nosuchcommand 2>/dev/null || echo "status:$?"'
        feed 'sleep 30'
        sleep 1
        # The interrupt character, straight in: the line discipline turns it into a signal to the
        # command that is running, which is what a terminal does with `Ctrl-C`.
        printf '\003'
        sleep 1
        feed 'echo "status:$?"'
        # The same interrupt, this time to a command that catches it: `dash` runs its own handler,
        # which is the case a libc's dispositions are about.
        feed "dash -c 'trap \"echo caught\" INT; sleep 30'"
        sleep 3
        printf '\003'
        sleep 1
        feed 'echo "status:$?"'
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
