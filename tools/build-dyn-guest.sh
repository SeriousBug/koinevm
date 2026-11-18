#!/bin/bash
# Build the fixtures that need a real glibc, in a container, and record what they print natively.
#
# These are about what the rootfs's own libc does, so they link against bookworm's libc and the
# oracle is that same libc running natively. No compiler on the host can link a dynamically linked
# aarch64 binary against the rootfs, and the fixtures must be dynamically linked or they cannot
# reach the code under test.
set -euo pipefail
cd "$(dirname "$0")/.."

GUESTS=${GUESTS:-"fmt resolve afamily gai sha512dyn"}

for g in $GUESTS; do
    # A C++ fixture needs the other compiler and library, and its own source suffix.
    src="tests/guest/$g.c"
    cc="gcc"
    pkgs="gcc libc6-dev"
    if [ -f "tests/guest/$g.cc" ]; then
        src="tests/guest/$g.cc"
        cc="g++"
        pkgs="g++ libstdc++-12-dev"
    fi
    # A fixture with a `.lib.c` beside it keeps the code under test in a library the program
    # loads, so the guest translates it a page at a time instead of with the image. The library
    # has to be at the same path in the container and in the rootfs, which is what rpath /tmp
    # gives both of them.
    lib=""
    link=""
    if [ -f "tests/guest/$g.lib.c" ]; then
        lib="gcc -O2 -fPIC -shared -o tests/guest/lib$g.so tests/guest/$g.lib.c &&
            cp tests/guest/lib$g.so /tmp/ &&"
        link="-L/tmp -l$g -Wl,-rpath,/tmp"
    fi

    echo "== guest: $g, dynamically linked against bookworm's glibc =="
    docker run --rm -v "$PWD":/w -w /w debian:bookworm sh -c "
        apt-get update -qq >/dev/null &&
        apt-get install -y -qq $pkgs >/dev/null &&
        $lib
        $cc -O2 -fno-builtin -D_FORTIFY_SOURCE=2 -fno-stack-protector \
            -o tests/guest/${g}_dyn.elf $src $link &&
        ./tests/guest/${g}_dyn.elf > tests/guest/$g.expected
    "
    echo "oracle output:"
    cat "tests/guest/$g.expected"
done
