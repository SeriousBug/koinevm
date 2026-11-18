#!/bin/bash
# The socket syscalls against a host that answers: a UDP echo server and a TCP one on loopback stand
# in for the network. Each guest asserts its own properties and its output has to match the same
# binary run on a real kernel, byte for byte.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
server=""
trap 'rm -rf "$work"; [ -n "$server" ] && kill "$server" 2>/dev/null' EXIT

fail=0

# One echo server per protocol, each printing the port it was given.
udp_portfile="$work/udp-port"
node -e '
const dgram = require("node:dgram");
const s = dgram.createSocket("udp4");
s.on("message", (m, r) => s.send(Buffer.concat([Buffer.from("echo:"), m]), r.port, r.address));
s.bind(0, "127.0.0.1", () => console.log(s.address().port));
' > "$udp_portfile" 2> "$work/udp.err" &
udp_server=$!

# A line of bytes comes back as "echo:" and the line, and then the server ends the connection, so a
# client that half-closes sees the end of the stream.
tcp_portfile="$work/tcp-port"
node -e '
const net = require("node:net");
const s = net.createServer((sock) => {
  let line = "";
  sock.on("data", (d) => {
    line += d.toString("latin1");
    if (!line.includes("\n")) return;
    sock.write("echo:" + line);
    sock.end();
  });
});
s.listen(0, "127.0.0.1", () => console.log(s.address().port));
' > "$tcp_portfile" 2> "$work/tcp.err" &
tcp_server=$!
server="$udp_server $tcp_server"

wait_port() {
    local file=$1 port=""
    for _ in $(seq 100); do
        port=$(head -1 "$file" 2>/dev/null)
        [ -n "$port" ] && { echo "$port"; return 0; }
        sleep 0.05
    done
    return 1
}

udp_port=$(wait_port "$udp_portfile") || { echo "FAIL the UDP echo server did not start"; cat "$work/udp.err"; exit 1; }
tcp_port=$(wait_port "$tcp_portfile") || { echo "FAIL the TCP echo server did not start"; cat "$work/tcp.err"; exit 1; }

for guest in net tcp; do
    if [ "$guest" = net ]; then port=$udp_port; else port=$tcp_port; fi
    for mode in $MODES; do
        wasm="$work/$guest.$mode.wasm"
        if ! ./target/release/armjit translate "tests/guest/$guest.elf" -o "$wasm" --bounds="$mode" \
                --argv="$guest","$port" > "$work/translate.log" 2>&1; then
            echo "FAIL $guest bounds=$mode, translate:"
            cat "$work/translate.log"
            fail=1
            continue
        fi
        timeout 120 node run.mjs "$wasm" > "$work/out" 2> "$work/err"
        code=$?
        if ! diff -q "tests/guest/$guest.expected" "$work/out" > /dev/null; then
            echo "FAIL $guest bounds=$mode: output differs from the native run"
            diff "tests/guest/$guest.expected" "$work/out" | head -20
            cat "$work/err"
            fail=1
            continue
        fi
        if [ "$code" != 0 ]; then
            echo "FAIL $guest bounds=$mode, exit $code"
            cat "$work/err"
            fail=1
            continue
        fi
        echo "ok   $guest bounds=$mode"
    done
done

[ "$fail" -eq 0 ]
