#!/bin/bash
# Build the guest aarch64 Linux ELF and the native macOS oracle for it.
set -euo pipefail
cd "$(dirname "$0")/.."

CFLAGS_COMMON="-O2 -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -mgeneral-regs-only"

echo "== guest: static aarch64 linux ELF =="
clang --target=aarch64-unknown-linux-gnu $CFLAGS_COMMON -fno-pic -nostdlib \
    -c tests/guest/hello.c -o tests/guest/hello.o
python3 tools/minilink.py tests/guest/hello.o tests/guest/hello.elf _start

echo "== oracle: native macos arm64, same source =="
clang $CFLAGS_COMMON -c tests/guest/hello.c -o tests/guest/hello_macos.o
cat > /tmp/oracle_main.c <<'EOF'
void guest_main(void);
int main(void) { guest_main(); return 0; }
EOF
clang $CFLAGS_COMMON -o /tmp/hello_native tests/guest/hello_macos.o /tmp/oracle_main.c

/tmp/hello_native > tests/guest/hello.expected
code=$?
echo "oracle exit=$code stdout:"; cat tests/guest/hello.expected
