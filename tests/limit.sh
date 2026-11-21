#!/bin/bash
# `--mem-limit` as bytes with an optional unit. The address space is a count of 64 KiB pages, so a
# limit between two of them takes the higher one: the metadata says which count it became.
set -uo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
# limit, the page count it must become.
check() {
    local limit=$1 want=$2
    if ! ./target/release/koinevm translate tests/guest/hello.elf -o "$work/a.wasm" \
            --mem-limit="$limit" > "$work/log" 2>&1; then
        echo "FAIL mem-limit=$limit: $(cat "$work/log")"; fail=1; return
    fi
    local got
    got=$(python3 -c "import json; print(json.load(open('$work/a.wasm.json'))['mem_pages'])")
    if [[ $got != "$want" ]]; then
        echo "FAIL mem-limit=$limit: $got pages, want $want"; fail=1; return
    fi
    echo "ok   mem-limit=$limit -> $got pages"
}

check 8GiB 131072
check 4GB 61036
check 262144 4
check 262144B 4
check 1GiB 16384
# One byte past a page is a second page, and so is one byte below one.
check 65537 2
check 131072 2

# A unit nothing writes, and a limit that maps no page, are both refusals.
for bad in 0 4XB 4G; do
    if ./target/release/koinevm translate tests/guest/hello.elf -o "$work/a.wasm" \
            --mem-limit="$bad" > "$work/log" 2>&1; then
        echo "FAIL mem-limit=$bad: accepted"; fail=1; continue
    fi
    echo "ok   mem-limit=$bad refused"
done

[ "$fail" -eq 0 ]
