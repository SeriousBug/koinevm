# The gaps

What the translator refuses, measured over a whole Debian userland instead of the fixtures. A
refusal is one word the emitter will not turn into wasm. The region around it is still translated,
and the word becomes a `REFUSED` trap: a guest that reaches one stops with the pc trail, the
register dump and the memory around it, rather than computing a wrong answer.

## Measuring

    bash tools/sweep.sh                              # every ELF in the tree, statically
    bash tools/sweep-run.sh /bin/bash /tmp/load.sh   # what a run reaches

`tools/sweep.sh` translates each of the tree's 913 ELFs as a whole and adds the refusals up by
encoding and by reason. `KOINEVM_LOG_GAPS=1` makes a run log the refusals of the pages it translates,
which is what `tools/sweep-run.sh` ranks. `koinevm gaps <elf> [--tsv]` is one file, `koinevm decode
<word>` names a word, `koinevm dump <elf>` lists an image's instructions as decoded.

A refusal is recorded at the word that raised it and its message does not repeat the address, so
every row is a word, an address and a reason. Three faults in that reporting came out of the sweep
and are fixed: a word in the crypto space (`sha256h` starts `0101 1110`) was claimed by the scalar
FP one-source group and reported as a floating point opcode; a by-element multiply (`mul v0.4h,
v0.4h, v1.h[0]`) was claimed by the shift-by-immediate group, because bit 23 was taken as the
separator where bit 10 is the one that separates them; and a failure raised inside a helper aborted
the whole region with the entry's address instead of refusing the one instruction.

## What is there, statically

12996 refusals in 1054 encodings, in 69 of the 913 files. (14843 before the four families below
were translated.)

| refusals | files | family | words | why it does not matter, or does |
|---:|---:|---|---|---|
| 9500 | 3 | crypto: `aese`/`aesmc`/`sha1*`/`sha256*`/`eor3` | `4e286800`, `5e104020`, `ce1236fc` | `ID_AA64ISAR0` is 0, so the loader and openssl pick the plain paths |
| 760 | 3 | `pmull`, the polynomial multiply | `0ee3e280` | the crypto group again |
| 639 | 43 | padding and `.rodata` inside an executable segment | `00000000` | not instructions |
| 583 | 18 | SVE: predicated load/store, `whilelo`, `ptrue` | `a400a020` (`ld1b`), `e400e000` (`st1b`), `25221fe0` | `ID_AA64PFR0` advertises no SVE |
| 368 | 9 | by-element vector arithmetic: `fmul`/`mul`/`fmla` by lane | `4fc29000`, `0f418000` | **a gap** |
| 235 | 3 | saturating add/sub: `sqadd`/`uqadd`/`sqsub`/`uqsub` | `4e200c21`, `6e202c21` | **a gap** |
| 223 | 3 | MTE: `ldg`/`gmi`/`irg`/`stz2g` | `d9600000`, `9ac11000`, `d9ffe860` | no HWCAP2_MTE |
| 167 | 4 | fp16: `fabs`/`fsqrt`/`frint*`/`scvtf` and the conversions | `4ef8f820`, `4e79d820` | no fp16 advertised |
| 112 | 33 | LSE atomics: `ldaddal`/`swpal`/`casal` | `b8e00020`, `b8e08020` | `-moutline-atomics` guards them on the same HWCAP |
| 85 | 13 | `cntd`/`cnt` | `04e0e3e0` | **a gap** in gcc's own popcount |
| 74 | 4 | across-lane `saddlv`/`uaddlv`, `fmaxnmv`/`fminnmv` | `6e703800`, `6e30c800` | **a gap** |
| 61 | 6 | long multiply of the byte form, `usubl` | `0e32c020`, `2e2020a4` | **a gap** |
| 41 | 2 | pairwise accumulate `uadalp`/`uaddlp` | `6e2068c4` | **a gap** |
| 32 | 5 | single opcodes nothing uses: `permute`, `shift-immediate`, `three-different` corners, `mrs` of `CNTFRQ_EL0` | | `CNTFRQ_EL0` is answered as 0 |
| 6 | 3 | `uaddw`/`saddw`/`usubw`/`ssubw` | `2e211063` | **a gap** |

## What a run reaches

`tools/run-rootfs.sh /bin/bash /tmp/load.sh` — `ls`, `sort`, `grep`, `awk`, `sed`, `find`, `gzip`,
`ldconfig`, `python3` doing `sha256`/`sha512`/`crc32`/`random`, and `gcc -O2` compiling and running a
program — logs 3175 refusals, and every one is a `ldg`/`gmi`/`irg`/`stz2g`, an SVE word, an `aes` or
`sha` word, an fp16 word in a width nothing asks for, or padding: all of them in code this run's
HWCAP keeps it out of. The run exits 0.

`python3 /tmp/np.py` (the numpy suite) is bit-identical to native numpy and holds no refusal the
workload does not: its `fcvtzs`, `saddlv`, `fcmge`/`fcmgt`/`fcmeq`, `fmaxnmp` and `uaddw` are
translated now, and the suite is what proves the translation of the first four.

## The four families that were implemented

`fcmeq`/`fcmge`/`fcmgt`/`facge`/`facgt` (1236 words), the vector float-to-integer conversions in
every rounding but away-from-zero (553), the compare-against-zero group in both its float and
integer halves (125), and with them a bug: `cmlt #0` was emitted as `le`, which answers true for a
lane that is zero.

wasm carries most of this already. A comparison answers all ones or zero per lane and treats NaN as
unordered, which is what ARM's quiet comparisons do; FZ flushes the operands first, since a mask is
not a number to flush. `i32x4.trunc_sat_f32x4_s` is the saturating truncation ARM's conversion is,
NaN and out-of-range included, so the rounding the opcode names is the only extra step. The 64-bit
form is the exception: the one wasm opcode that truncates from f64 makes 32-bit integers, so a `2d`
lane goes through the scalar instruction one at a time. Away-from-zero is refused; adding half and
truncating is wrong above 2^22, and nothing in the tree reaches it.

## What is left, in the order the numbers suggest

1. The by-element forms (368) and `cntd` (85): a table of lane selections, and one popcount.
2. Saturating add/sub (235), across-lane (74), long multiply (61), pairwise accumulate (41),
   `uaddw` (6).
3. Nothing for SVE, MTE, LSE, fp16 or crypto until something needs them: the guest is told they do
   not exist, so nothing should pick them, and the day one does the trap names it.

One known wart in that third group: the fp16 forms that share their opcodes with the integer vector
instructions are refused by name, but the fp16 forms of the *three-same* group (`fadd`, `fmul`,
`fmax`, `fmla` on `.8h`) land in the copy, `ext` and permute corner of the decoding and would be
translated as those rather than refused. Nothing reaches them, because no guest is told the machine
has fp16, and the fix is a rule for that space when it is needed.
