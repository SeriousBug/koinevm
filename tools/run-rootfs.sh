#!/bin/bash
# Run a Debian userland program the way `apt install ...` would leave it: translate the binary as
# `rootfs/debian` holds it, then run it with that rootfs as its filesystem.
#
#   tools/run-rootfs.sh /bin/ls -l /etc
#
# Translation is cached in target/tmp by the argument list, so a repeat run is only the run itself.
set -uo pipefail
cd "$(dirname "$0")/.."

rootfs=${ARMJIT_ROOTFS:-rootfs/debian}
# The runtime needs the same rootfs the translation saw, and it reads it from the environment.
export ARMJIT_ROOTFS=$rootfs
# The environment a Debian program expects to find. A process started by a shell inherits one, and
# a package manager checks for `PATH` before it does anything.
env=${ARMJIT_ENV:-PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,HOME=/root}
# A program that formats for a terminal reads TERM to learn what the terminal can be sent: without
# one readline cannot place its cursor, and it scrolls a long line sideways instead of wrapping it.
# A console run names the host's own terminal, and an xterm when the host has none or names `dumb`:
# the console is a terminal all the same, and the rootfs carries the terminfo for that name.
if [[ -n ${ARMJIT_CONSOLE:-} ]]; then
    case ${TERM:-} in
        "" | dumb) env="$env,TERM=xterm-256color" ;;
        *) env="$env,TERM=$TERM" ;;
    esac
fi
prog=$1
shift

# The translator takes the arguments comma-separated, which no argument in a shell command has.
argv=$prog
for a in "$@"; do argv="$argv,$a"; done

# How much address space the guest is given, in 64 KiB pages: a property of the run, because the
# module declares its memories and the page table that covers them.
pages=${ARMJIT_MEM_PAGES:-}
key=$(printf '%s_' "$prog" "$@" "$env" "$pages" | tr -c 'A-Za-z0-9_.-' '_')${ARMJIT_TRACE:+_trace}${ARMJIT_TRACE_LOOPS:+_loops}
wasm="target/tmp/rootfs_$key.wasm"
mkdir -p target/tmp

if [[ ! -f $wasm || -n ${ARMJIT_RETRANSLATE:-} ]]; then
    if ! ./target/release/armjit translate "$rootfs$prog" -o "$wasm" --rootfs="$rootfs" \
            --argv="$argv" --env="$env" ${ARMJIT_TRACE:+--trace} ${ARMJIT_TRACE_LOOPS:+--trace-loops} \
            ${pages:+--mem-pages=$pages} \
            > "target/tmp/rootfs_$key.log" 2>&1; then
        echo "translate failed:" >&2
        tail -20 "target/tmp/rootfs_$key.log" >&2
        exit 2
    fi
fi

exec node run.mjs "$wasm"
