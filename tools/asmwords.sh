#!/bin/bash
# Assemble AArch64 source and print one "word<TAB>mnemonic operands" line per instruction.
#
# This is how the decoder's field layouts are checked: the encoding comes from the assembler, not
# from memory. It is also how the SIMD fixture's instruction shapes are pinned down.
#
#   tools/asmwords.sh <file.s>            # every instruction in the file
#   echo 'movi v0.4s, #1' | tools/asmwords.sh -
set -euo pipefail
src=${1:?usage: asmwords.sh <file.s>|-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ "$src" = "-" ]; then
    cat > "$work/in.s"
else
    cp "$src" "$work/in.s"
fi

clang --target=aarch64-unknown-linux-gnu -c "$work/in.s" -o "$work/in.o"
OBJDUMP=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-objdump
$OBJDUMP -d "$work/in.o" | awk '$1 ~ /^[0-9a-f]+:$/ && $2 ~ /^[0-9a-f]+$/ {print $2, $3, $4, $5, $6, $7, $8}'
