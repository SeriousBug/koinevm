# The gaps

What the translator refuses, measured over a whole Debian userland instead of the fixtures. A
refusal is one word the emitter will not turn into wasm. The region around it is still translated,
and the word becomes a `REFUSED` trap: a guest that reaches one stops with the pc trail, the
register dump and the memory around it, rather than computing a wrong answer.

## Measuring

    bash tools/sweep.sh                              # every ELF in the tree, statically
    bash tools/sweep-run.sh /bin/bash /tmp/load.sh   # what a run reaches

`tools/sweep.sh` translates each of the tree's 913 ELFs as a whole and adds the refusals up by
encoding and by reason. `ARMJIT_LOG_GAPS=1` makes a run log the refusals of the pages it translates,
which is what `tools/sweep-run.sh` ranks. `armjit gaps <elf> [--tsv]` is one file, `armjit decode
<word>` names a word, `armjit dump <elf>` lists an image's instructions as decoded.

A refusal is recorded at the word that raised it and its message does not repeat the address, so
every row is a word, an address and a reason. Three faults in that reporting came out of the sweep
and are fixed: a word in the crypto space (`sha256h` starts `0101 1110`) was claimed by the scalar
FP one-source group and reported as a floating point opcode; a by-element multiply (`mul v0.4h,
v0.4h, v1.h[0]`) was claimed by the shift-by-immediate group, because bit 23 was taken as the
separator where bit 10 is the one that separates them; and a failure raised inside a helper aborted
the whole region with the entry's address instead of refusing the one instruction.

## What is there, statically

14843 refusals in 1278 encodings, in 71 of the 913 files.

| refusals | files | family | words | why it does not matter, or does |
|---:|---:|---|---|---|
| 9500 | 3 | crypto: `aese`/`aesmc`/`sha1*`/`sha256*`/`eor3` | `4e286800`, `5e104020`, `ce1236fc` | `ID_AA64ISAR0` is 0, so the loader and openssl pick the plain paths |
| 1236 | 4 | vector float compare against a register: `fcmeq`/`fcmge`/`fcmgt`/`fcmle`/`fcmlt`, `facge`/`facgt` | `6ee0e420`, `0e22e400` | **a gap** |
| 760 | 3 | `pmull`, the polynomial multiply | `0ee3e280` | the crypto group again |
| 639 | 4 | padding and `.rodata` inside an executable segment | `00000000` | not instructions |
| 583 | 18 | SVE: predicated load/store, `whilelo`, `ptrue` | `a400a020` (`ld1b`), `e400e000` (`st1b`), `25221fe0` | `ID_AA64PFR0` advertises no SVE |
| 457 | 5 | vector `fcvtzs`/`fcvtzu` | `4ee1b800`, `0ea1b800` | **a gap** |
| 368 | 9 | by-element vector arithmetic: `fmul`/`mul`/`fmla` by lane | `4fc29000`, `0f418000` | **a gap** |
| 235 | 3 | saturating add/sub: `sqadd`/`uqadd`/`sqsub`/`uqsub` | `4e200c21`, `6e202c21` | **a gap** |
| 223 | 3 | MTE: `ldg`/`gmi`/`irg`/`stz2g` | `d9600000`, `9ac11000`, `d9ffe860` | no HWCAP2_MTE |
| 125 | 5 | compare against zero: `fcmeq #0.0`, `cmle`/`cmge #0` | `0ee0d800`, `2e209800` | **a gap** |
| 112 | 33 | LSE atomics: `ldaddal`/`swpal`/`casal` | `b8e00020`, `b8e08020` | `-moutline-atomics` guards them on the same HWCAP |
| 96 | 1 | fp16 arithmetic and conversions | `1e23c000` (`fcvt h0, s0`) | no fp16 advertised |
| 96 | 4 | vector `fcvtns`/`fcvtas`/`fcvtms`/`fcvtps` and their `u` forms | `4e61a800`, `4e21a882` | **a gap** |
| 85 | 13 | `cntd`/`cnt` | `04e0e3e0` | **a gap** in gcc's own popcount |
| 74 | 4 | across-lane `saddlv`/`uaddlv`, `fmaxnmv`/`fminnmv` | `6e703800`, `6e30c800` | **a gap** |
| 61 | 6 | long multiply of the byte form, `usubl` | `0e32c020`, `2e2020a4` | **a gap** |
| 42 | 2 | pairwise accumulate `uadalp`/`uaddlp` | `6e2068c4` | **a gap** |
| 6 | 3 | `uaddw`/`saddw`/`usubw`/`ssubw` | `2e211063` | **a gap** |
| 13 | — | `permute` and `shift-immediate` opcodes nothing uses, SVE's `addvl`/`incb`, `mrs` of `CNTFRQ_EL0` | | `CNTFRQ_EL0` is answered as 0 |

## What a run reaches

`tools/run-rootfs.sh /bin/bash /tmp/load.sh` — `ls`, `sort`, `grep`, `awk`, `sed`, `find`, `gzip`,
`ldconfig`, `python3` doing `sha256`/`sha512`/`crc32`/`random`, and `gcc -O2` compiling and running a
program — logs 3143 refusals, and every one is a `ldg`/`gmi`/`irg`/`stz2g`, an SVE word, an `aes` or
`sha` word, or padding: all of them in code this run's HWCAP keeps it out of.

`python3 /tmp/np.py` (the numpy suite) adds the ones numpy's own code holds: `fcvtzs v0.2d`,
`saddlv`/`uaddlv`, `fcmge`/`fcmgt`/`fcmeq`, `fmaxnmp`, `uaddw`. None of them is reached by the suite
as it stands, which is why numpy is bit-identical; anything that reaches one stops on the trap
instead of computing.

## Next, in the order the numbers suggest

1. The vector float compares (1236) and the two families of vector conversions (457 truncating, 96
   rounding): neither is subtle, both are in numpy's dispatch code, and a wrong rounding there is a
   wrong answer rather than a crash.
2. The by-element forms (368) and `cntd` (85): a table of lane selections, and one popcount.
3. Saturating add/sub (235), compare with zero (125), across-lane (74), long multiply (61),
   pairwise accumulate (42), `uaddw` (6).
4. Nothing for SVE, MTE, LSE, fp16 or crypto until something needs them: the guest is told they do
   not exist, so nothing should pick them, and the day one does the trap names it.
