#!/bin/bash
# Build the guest aarch64 Linux ELF and the native macOS oracle for it.
# OPT selects the optimisation level for both, so tests/run.sh can sweep them.
set -euo pipefail
cd "$(dirname "$0")/.."

OPT=${OPT:--O2}
GUESTS=${GUESTS:-"hello call flags"}

CFLAGS_COMMON="$OPT -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -mgeneral-regs-only"

for g in $GUESTS; do
    case $g in
        hello) entry=_start; oracle_entry=guest_main ;;
        call)  entry=_start; oracle_entry=call_main ;;
        flags) entry=_start; oracle_entry=flags_main ;;
    esac

    echo "== guest: $g $OPT, static aarch64 linux ELF =="
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

# The memory syscalls have no oracle: tests/mem.sh requires the guest's own checks to pass.
echo "== guest: mem (mmap/munmap/mprotect/brk) =="
clang --target=aarch64-unknown-linux-gnu $CFLAGS_COMMON -fno-pic -nostdlib \
    -c tests/guest/mem.c -o tests/guest/mem.o
python3 tools/minilink.py tests/guest/mem.o tests/guest/mem.elf _start

echo "== guest: files (openat/read/pread/stat/readlinkat) =="
clang --target=aarch64-unknown-linux-gnu $CFLAGS_COMMON -fno-pic -nostdlib \
    -c tests/guest/files.c -o tests/guest/files.o
python3 tools/minilink.py tests/guest/files.o tests/guest/files.elf _start

# The dynamically linked path: a PIE program and a stand-in for ld.so. No native oracle can run
# these, so tests/dyn.sh asserts the loader's view of the initial stack instead.
echo "== guest: ld-fake interpreter (ET_DYN) =="
clang --target=aarch64-unknown-linux-gnu $CFLAGS_COMMON -fpie -nostdlib \
    -c tests/guest/interp.c -o tests/guest/interp.o
python3 tools/minilink.py tests/guest/interp.o tests/guest/interp.elf _start --type=dyn --base=0

echo "== guest: hello_pie (ET_DYN, PT_INTERP=/lib/ld-fake.so) =="
clang --target=aarch64-unknown-linux-gnu $CFLAGS_COMMON -fpie -nostdlib \
    -c tests/guest/hello.c -o tests/guest/hello_pie.o
python3 tools/minilink.py tests/guest/hello_pie.o tests/guest/hello_pie.elf _start \
    --type=dyn --base=0 --interp=/lib/ld-fake.so
