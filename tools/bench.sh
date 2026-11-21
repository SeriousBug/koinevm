#!/bin/bash
# Translate the integer benchmark and compare it with the same source compiled natively.
# Prints wall-clock milliseconds, so it is a shape-of-the-gap measurement, not a microbenchmark.
set -euo pipefail
cd "$(dirname "$0")/.."

CFLAGS="-O2 -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -mgeneral-regs-only"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cargo build --release --quiet 2>/dev/null

clang --target=aarch64-unknown-linux-gnu $CFLAGS -fno-pic -nostdlib -c tests/guest/bench.c -o "$work/bench.o"
python3 tools/minilink.py "$work/bench.o" "$work/bench.elf" _start > /dev/null

clang $CFLAGS -c tests/guest/bench.c -o "$work/bench_macos.o"
printf 'void bench_main(void);\nint main(void) { bench_main(); return 0; }\n' > "$work/main.c"
clang $CFLAGS -o "$work/bench_native" "$work/bench_macos.o" "$work/main.c"

run_native() {
    python3 - "$work/bench_native" <<'EOF'
import subprocess, sys, time

def once():
    t0 = time.monotonic()
    subprocess.run([sys.argv[1]], check=True, stdout=subprocess.DEVNULL)
    return time.monotonic() - t0

print(f"{min(once() for _ in range(3)) * 1000:.0f}")
EOF
}

run_wasm() {
    local mode=$1 pages=$2
    ./target/release/koinevm translate "$work/bench.elf" -o "$work/bench.$mode.wasm" \
        --bounds="$mode" --mem-pages="$pages" > /dev/null
    KOINEVM_TIME=1 node run.mjs "$work/bench.$mode.wasm" 2>&1 > /dev/null \
        | sed -n 's/^guest run \(.*\) ms$/\1/p' | head -1
}

native=$(run_native)
echo "native arm64: ${native} ms"
for spec in "trust 65535" "check 65535" "check 16384"; do
    set -- $spec
    ms=$(run_wasm "$1" "$2")
    ratio=$(python3 -c "print(f'{$ms / $native:.2f}')")
    echo "wasm bounds=$1 mem=$(( $2 / 16 )) MiB: ${ms} ms (${ratio}x)"
done
