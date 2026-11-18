#!/bin/bash
# The socket syscalls against a host that answers: a UDP echo server on loopback stands in for the
# network. The guest asserts each property itself and its output has to match the same binary run
# on a real kernel, byte for byte.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
server=""
trap 'rm -rf "$work"; [ -n "$server" ] && kill "$server" 2>/dev/null' EXIT

portfile="$work/port"
node -e '
const dgram = require("node:dgram");
const s = dgram.createSocket("udp4");
s.on("message", (m, r) => s.send(Buffer.concat([Buffer.from("echo:"), m]), r.port, r.address));
s.bind(0, "127.0.0.1", () => console.log(s.address().port));
' > "$portfile" 2> "$work/server.err" &
server=$!

port=""
for _ in $(seq 100); do
    port=$(head -1 "$portfile" 2>/dev/null)
    [ -n "$port" ] && break
    sleep 0.05
done
if [ -z "$port" ]; then
    echo "FAIL the echo server did not start"
    cat "$work/server.err"
    exit 1
fi

fail=0
for mode in $MODES; do
    wasm="$work/net.$mode.wasm"
    if ! ./target/release/armjit translate tests/guest/net.elf -o "$wasm" --bounds="$mode" \
            --argv=net,"$port" > "$work/translate.log" 2>&1; then
        echo "FAIL net bounds=$mode, translate:"
        cat "$work/translate.log"
        fail=1
        continue
    fi
    timeout 120 node run.mjs "$wasm" > "$work/out" 2> "$work/err"
    code=$?
    if ! diff -q tests/guest/net.expected "$work/out" > /dev/null; then
        echo "FAIL net bounds=$mode: output differs from the native run"
        diff tests/guest/net.expected "$work/out" | head -20
        cat "$work/err"
        fail=1
        continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL net bounds=$mode, exit $code"
        cat "$work/err"
        fail=1
        continue
    fi
    echo "ok   net bounds=$mode"
done

[ "$fail" -eq 0 ]
