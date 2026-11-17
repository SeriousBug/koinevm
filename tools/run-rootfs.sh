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
prog=$1
shift

# The translator takes the arguments comma-separated, which no argument in a shell command has.
argv=$prog
for a in "$@"; do argv="$argv,$a"; done

key=$(printf '%s_' "$prog" "$@" "$env" | tr -c 'A-Za-z0-9_.-' '_')${ARMJIT_TRACE:+_trace}${ARMJIT_TRACE_LOOPS:+_loops}
wasm="target/tmp/rootfs_$key.wasm"
mkdir -p target/tmp

if [[ ! -f $wasm || -n ${ARMJIT_RETRANSLATE:-} ]]; then
    if ! ./target/release/armjit translate "$rootfs$prog" -o "$wasm" --rootfs="$rootfs" \
            --argv="$argv" --env="$env" ${ARMJIT_TRACE:+--trace} ${ARMJIT_TRACE_LOOPS:+--trace-loops} \
            > "target/tmp/rootfs_$key.log" 2>&1; then
        echo "translate failed:" >&2
        tail -20 "target/tmp/rootfs_$key.log" >&2
        exit 2
    fi
fi

exec node run.mjs "$wasm"
