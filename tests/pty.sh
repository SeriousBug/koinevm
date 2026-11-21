#!/bin/bash
# A pseudo-terminal: the two ends of one terminal, the name it has, and the program that waits on it.
#
# `script` is the test because it is a real program that insists on a terminal of its own: it makes a
# pty, runs the command on the slave and copies what comes back out of the master. `tty` then asks
# the slave what it is called, which is the whole chain - `isatty`, `st_rdev`, the name of the device
# - and `stty size` asks for the window the master was given. `ls /dev/pts` is the number the slave
# is known by, and it is the third pty of the session because the first two are closed and gone from
# the listing. `script` only exits when it hears that its child is gone, so a run that does not
# answer `SIGCHLD` or keeps a reaped child in the table hangs here instead of printing the end.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

events='script -q -c "/usr/bin/tty" /dev/null
script -q -c "/bin/echo through the pty" /dev/null
script -q -c "/usr/bin/ls /dev/pts" /dev/null
script -q -c "/usr/bin/stty size" /dev/null'

fail=0
for mode in $MODES; do
    if ! ./target/release/koinevm translate rootfs/debian/bin/bash -o "$work/bash.$mode.wasm" \
            --rootfs=rootfs/debian --argv="/bin/bash,-c,$events" \
            --env="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,HOME=/root" \
            --bounds="$mode" > "$work/translate.log" 2>&1; then
        echo "FAIL pty bounds=$mode, translate:"; cat "$work/translate.log"; fail=1; continue
    fi
    KOINEVM_ROOTFS=rootfs/debian timeout 120 node run.mjs "$work/bash.$mode.wasm" \
        > "$work/out" 2>&1
    code=$?
    if ! diff -q tests/guest/pty.expected "$work/out" > /dev/null; then
        echo "FAIL pty bounds=$mode: the session differs"
        diff tests/guest/pty.expected "$work/out" | head -20
        fail=1
        continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL pty bounds=$mode, exit $code"
        cat "$work/out"
        fail=1
        continue
    fi
    echo "ok   pty bounds=$mode"
done

[ "$fail" -eq 0 ]
