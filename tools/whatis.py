#!/usr/bin/env python3
"""Name the instructions at guest addresses, using llvm-objdump from Xcode.

Reads addresses on stdin, one per line (hex with or without 0x), and prints the disassembly at each.
A guest address maps to a linked address by subtracting the base the translator placed the image at,
so this needs the image and that base:

    koinevm gaps dash --rootfs=rootfs/debian | awk '{print $NF}' | cut -d= -f2 \\
        | python3 tools/whatis.py rootfs/debian/bin/dash:0x400000 \\
                                 rootfs/debian/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1:0x10000000
"""
import os
import re
import subprocess
import sys

OBJDUMP = "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-objdump"


def load(image, base):
    """address -> disassembly line, for every instruction objdump prints."""
    out = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", image],
                         capture_output=True, text=True).stdout
    table = {}
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\s+(.*)$", line)
        if m:
            table[int(m.group(1), 16)] = m.group(2).strip()
    return base, table


def main():
    if not os.path.exists(OBJDUMP):
        raise SystemExit(f"no llvm-objdump at {OBJDUMP}")
    images = [load(a.rsplit(":", 1)[0], int(a.rsplit(":", 1)[1], 0)) for a in sys.argv[1:]]
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        addr = int(line, 0)
        shown = None
        for base, table in images:
            if addr >= base and (addr - base) in table:
                shown = table[addr - base]
                break
        print(f"0x{addr:x}  {shown or '?'}")


if __name__ == "__main__":
    main()
