#!/bin/bash
# The host's name service, as the guest's own: a query written by hand to the address the guest's
# resolver file names is answered from the machine's resolver, and a rootfs that names servers of
# its own keeps them.
set -uo pipefail
cd "$(dirname "$0")/.."

MODES=${MODES:-"check trust"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A rootfs with nothing in it: no /etc/resolv.conf, which is what an `apt`-unpacked tree looks like.
root="$work/root"
mkdir -p "$root/etc"

fail=0

# The policy: the file is provided only when the tree does not name a server itself.
own="$work/own"
mkdir -p "$own/etc"
printf 'nameserver 10.9.9.9\n' > "$own/etc/resolv.conf"
policy=$(node --input-type=module -e "
import { Resolver } from './host/dns.mjs';
const files = (root) => [...new Resolver().files(root).keys()].join(',') || 'none';
console.log(files('$own'), files('$root'), files(null));
")
if [ "$policy" = "none /etc/resolv.conf /etc/resolv.conf" ]; then
    echo "ok   a tree with its own nameserver keeps it"
else
    echo "FAIL the resolver file policy: $policy"
    fail=1
fi

for mode in $MODES; do
    wasm="$work/dns.$mode.wasm"
    if ! ./target/release/koinevm translate tests/guest/dns.elf -o "$wasm" --bounds="$mode" \
            > "$work/translate.log" 2>&1; then
        echo "FAIL dns bounds=$mode, translate:"
        cat "$work/translate.log"
        fail=1
        continue
    fi
    KOINEVM_ROOTFS="$root" timeout 120 node run.mjs "$wasm" > "$work/out" 2> "$work/err"
    code=$?
    if grep -q '^FAIL' "$work/out"; then
        echo "FAIL dns bounds=$mode:"
        grep '^FAIL' "$work/out"
        cat "$work/err"
        fail=1
        continue
    fi
    if ! grep -q '^dns: all checks passed$' "$work/out"; then
        echo "FAIL dns bounds=$mode: no summary"
        cat "$work/out" "$work/err"
        fail=1
        continue
    fi
    if [ "$code" != 0 ]; then
        echo "FAIL dns bounds=$mode, exit $code"
        cat "$work/err"
        fail=1
        continue
    fi
    echo "ok   dns bounds=$mode"
done

[ "$fail" -eq 0 ]
