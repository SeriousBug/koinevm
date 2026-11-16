#!/bin/bash
# Build the guest aarch64 Linux ELF and the native macOS oracle for it.
set -euo pipefail
cd "$(dirname "$0")/.."

CFLAGS_COMMON="-O2 -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -mgeneral-regs-only"

for g in hello call; do
    case $g in
        hello) entry=_start; oracle_entry=guest_main ;;
        call)  entry=_start; oracle_entry=call_main ;;
    esac

    echo "== guest: $g, static aarch64 linux ELF =="
    clang --target=aarch64-unknown-linux-gnu $CFLAGS_COMMON -fno-pic -nostdlib \
        -c tests/guest/$g.c -o tests/guest/$g.o
    python3 tools/minilink.py tests/guest/$g.o tests/guest/$g.elf $entry

    echo "== oracle: native macos arm64, same source =="
    clang $CFLAGS_COMMON -c tests/guest/$g.c -o /tmp/${g}_macos.o
    cat > /tmp/oracle_main_$g.c <<EOF
void $oracle_entry(void);
int main(void) { $oracle_entry(); return 0; }
EOF
    clang $CFLAGS_COMMON -o /tmp/${g}_native /tmp/${g}_macos.o /tmp/oracle_main_$g.c

    set +e
    /tmp/${g}_native > tests/guest/$g.expected
    code=$?
    set -e
    echo "oracle exit=$code stdout:"; cat tests/guest/$g.expected
    echo "$code" > tests/guest/$g.expected_exit
done
