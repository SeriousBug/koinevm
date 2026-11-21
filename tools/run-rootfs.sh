#!/bin/bash
# Run a Debian userland program the way `apt install ...` would leave it: translate the binary as
# `rootfs/debian` holds it, then run it with that rootfs as its filesystem.
#
#   tools/run-rootfs.sh /bin/ls -l /etc
#
# Translation is cached in target/tmp by the argument list and the build of the translator that
# produced it, so a repeat run is only the run itself and a rebuild costs a translation.
set -uo pipefail
cd "$(dirname "$0")/.."

rootfs=${KOINEVM_ROOTFS:-rootfs/debian}
# The runtime needs the same rootfs the translation saw, and it reads it from the environment.
export KOINEVM_ROOTFS=$rootfs
# The environment a Debian program expects to find. A process started by a shell inherits one, and
# a package manager checks for `PATH` before it does anything.
env=${KOINEVM_ENV:-PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,HOME=/root}
# A program that formats for a terminal reads TERM to learn what the terminal can be sent: without
# one readline cannot place its cursor, and it scrolls a long line sideways instead of wrapping it.
# A console run names the host's own terminal, and an xterm when the host has none or names `dumb`:
# the console is a terminal all the same, and the rootfs carries the terminfo for that name.
if [[ -n ${KOINEVM_CONSOLE:-} ]]; then
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

# How much address space the guest is given, in bytes with an optional unit like `8GiB`: a property
# of the run, because the module declares its memories and the page table that covers them.
limit=${KOINEVM_MEM_LIMIT:-}
key=$(printf '%s_' "$prog" "$@" "$env" "$limit" | tr -c 'A-Za-z0-9_.-' '_')${KOINEVM_TRACE:+_trace}${KOINEVM_TRACE_LOOPS:+_loops}
wasm="target/tmp/rootfs_$key.wasm"
mkdir -p target/tmp

# A cached module is the output of one build of the translator, so a rebuild makes every cached one
# stale: the layout, the metadata and the conventions the host shares with the translator all move.
# The build is named by what it produced, and a different name is a different cache.
build=$(shasum -a 256 target/release/koinevm 2> /dev/null | cut -d' ' -f1)
if [[ -z $build ]]; then build=$(sha256sum target/release/koinevm 2> /dev/null | cut -d' ' -f1); fi
if [[ -z $build ]]; then build="$(wc -c < target/release/koinevm)-$(date -r target/release/koinevm +%s)"; fi
if [[ $(cat target/tmp/rootfs.build 2> /dev/null) != "$build" ]]; then
    rm -f target/tmp/rootfs_*.wasm target/tmp/rootfs_*.wasm.json target/tmp/rootfs_*.log
    printf '%s\n' "$build" > target/tmp/rootfs.build
fi

if [[ ! -f $wasm || -n ${KOINEVM_RETRANSLATE:-} ]]; then
    if ! ./target/release/koinevm translate "$rootfs$prog" -o "$wasm" --rootfs="$rootfs" \
            --argv="$argv" --env="$env" ${KOINEVM_TRACE:+--trace} ${KOINEVM_TRACE_LOOPS:+--trace-loops} \
            ${limit:+--mem-limit=$limit} \
            > "target/tmp/rootfs_$key.log" 2>&1; then
        echo "translate failed:" >&2
        tail -20 "target/tmp/rootfs_$key.log" >&2
        exit 2
    fi
fi

exec node run.mjs "$wasm"
