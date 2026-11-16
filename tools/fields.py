#!/usr/bin/env python3
"""Print the encoding fields of every instruction in an assembled AArch64 object.

Used to derive the decoder's field layouts: the assembler gives the encoding, this prints the bits
the decoder is about to match on, so the mapping is read off a table instead of from memory.

    tools/fields.py <file.s>        # assembles with clang, prints one row per instruction
"""
import subprocess
import sys
import tempfile
import os

OBJDUMP = "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-objdump"


def main():
    src = sys.argv[1]
    with tempfile.TemporaryDirectory() as work:
        obj = os.path.join(work, "in.o")
        subprocess.run(["clang", "--target=aarch64-unknown-linux-gnu", "-c", src, "-o", obj], check=True)
        out = subprocess.run([OBJDUMP, "-d", obj], capture_output=True, text=True).stdout
    for line in out.splitlines():
        f = line.split()
        if len(f) < 3 or not f[0].endswith(":") or not all(c in "0123456789abcdef" for c in f[1].lower()):
            continue
        if len(f[1]) != 8:
            continue
        w = int(f[1], 16)
        text = " ".join(f[2:]).split("//")[0].strip()
        fields = (
            f"Q={(w >> 30) & 1} U={(w >> 29) & 1} sz={(w >> 22) & 3} "
            f"b28_24={(w >> 24) & 0x1f:05b} b23={((w >> 23) & 1)} b22={((w >> 22) & 1)} "
            f"b21={(w >> 21) & 1} b20_16={(w >> 16) & 0x1f:02d} b19={(w >> 19) & 1} "
            f"op11={(w >> 11) & 0x1f:05b} b10={(w >> 10) & 1} b15_12={(w >> 12) & 0xf:04b} "
            f"b14_11={(w >> 11) & 0xf:04b} imm9={((w >> 12) & 0x1ff)} imm12={(w >> 10) & 0xfff}"
        )
        print(f"{w:08x}  {fields}   {text}")


if __name__ == "__main__":
    main()
