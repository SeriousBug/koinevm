# PoC results

What exists now: a translator that takes a statically linked AArch64 Linux ELF and emits a wasm
module, plus a host that provides the syscall boundary. `node run.mjs out.wasm` runs the guest.

## What it does

- ELF64 loader: `PT_LOAD` segments mapped at their link addresses, program headers inside the first
  segment so `AT_PHDR` names mapped memory, initial stack built as a kernel builds it (argc, argv,
  envp, auxv with `AT_PHDR`/`AT_ENTRY`/`AT_PAGESZ`/`AT_RANDOM`/`AT_HWCAP`/`AT_SECURE`), fixed layout.
- Decoder for the whole compiler-reachable A64 integer subset: move-wide, adr/adrp, add/sub
  (immediate, shifted, extended, with carry), logical (immediate with full `DecodeBitMasks`,
  shifted), bitfield (`sbfm`/`bfm`/`ubfm` and therefore `lsl`/`lsr`/`asr`/`sxt*`/`uxt*`/`ubfx`), extr,
  cond-select, cond-compare, 1/2/3-source arithmetic (`madd`, `msub`, `umulh`, `smulh`, `sdiv`,
  `udiv`, `clz`, `rbit`, `rev*`), every load/store form (unsigned offset, unscaled, pre/post index,
  register offset with extend, pairs, literal), all branches (`b`, `bl`, `b.cond`, `cbz`, `tbz`,
  `br`, `blr`, `ret`), `svc`, `mrs`/`msr tpidr_el0`, hints and barriers.
- Guest state in wasm locals: x0-x30, sp and a packed NZCV word are parameters and results of every
  translated region, so the engine is the register allocator. Flags are materialised as real
  `NZCV` state, so `ccmp`, `adcs` and flags live across blocks all work.
- One wasm function per region, one nested block per guest block, `br_table` on a local pc. Direct
  branches are plain `br`s. Calls, returns and computed jumps return the next pc to a dispatcher
  that indexes a word per 4 bytes of code, so wasm stack depth is constant and guest recursion is
  bounded by the guest stack in linear memory.
- Syscall boundary shaped like a Linux ABI layer: number in x8, args in x0-x5, result or `-errno` in
  x0, unknown numbers answer `-ENOSYS`. `write`, `read`, `exit`, `exit_group` implemented; the rest
  is a switch away.

## Correctness

Three guests, each built twice from one source: the aarch64 Linux ELF (translated) and a native
macOS arm64 program (the oracle). Output and exit status compared byte for byte.

| guest | what it covers | result |
|---|---|---|
| `hello` | string setup, a loop, integer division by magic multiply, `umulh`, `strb`, exit code | exact |
| `call` | recursion (`fib(20)`), a function pointer table called through `blr`, `stp`/`ldp` frames, signed division, printing | exact, exit 7 |
| `bench` | 500M xorshift iterations plus an array sweep | exact checksum |

20/20 combinations pass: both guests at `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, each with explicit address
checks on and off.

## Performance

Integer kernel, 500M mix iterations + 2000 array sweeps, on an M4 Pro. Native is the same source
compiled with clang `-O2`; wasm time excludes node startup and module compilation.

| configuration | time | vs native |
|---|---|---|
| native arm64 | 790 ms | 1.00x |
| wasm, 4 GiB memory, per-access checks off | 1068 ms | 1.35x |
| wasm, 4 GiB memory, per-access checks on | 1577 ms | 2.00x |
| wasm, 64 MiB memory, per-access checks on | 1547 ms | 1.96x |

Translation cost: 161 instructions of 1 region in 74 us, 40 KB of wasm from 37 KB of guest. V8
compiles that module in 0.2 ms.

Two things follow.

1. The register-in-locals thesis holds. 1.35x native with a naive template translation, no peephole
   pass, no flag liveness, no block linking, and a dispatcher round trip per call and return. That is
   already inside the band that makes a browser VM usable, and near CheerpX's self-reported *best*
   case (2x-3x) rather than its typical case (5x-10x).
2. Address validation is the single biggest cost, at 46% of runtime. With a 4 GiB linear memory the
   engine's own bounds check guards every access for free, which is why the 4 GiB row is as fast as
   the 64 MiB one, but it does not catch 64-bit wrap: an address at or above 4 GiB truncates and
   aliases low memory. Catching that needs a compare per access, which is what the `check` rows pay
   for. This is the clearest first optimization target: prove addresses in range where the source of
   the address makes it provable, and check only the rest.

## What this does not prove, in order of how much it matters

- **Dynamic linking.** The loader refuses `PT_INTERP`. An off-the-shelf Debian binary needs `ld.so`,
  `mmap`, `mprotect` and a page table. This is the next milestone and the biggest one.
- **Self-modifying code and guest JITs.** Nothing invalidates a translation. Node-in-the-tab needs
  page-granular invalidation, which the design allows for but does not implement.
- **Signals.** A trap kills the run instead of being delivered to a guest handler.
- **Threads, `fork`/`exec`, file I/O, a real block device.** Single process, stdout/stderr only.
- **FP and NEON.** Decoded as `Undefined` and refused at the instruction that reaches them, which is
  honest but means most real code will stop at its first float.
- **Instruction coverage is compiler output, not the ISA.** Hand-written or obfuscated code that uses
  `rmif`, `setf*`, `ldraa`, pointer authentication, `mrs` of anything else, exclusive/atomic
  accesses, or `SVE` is refused rather than mistranslated. That is the right failure mode but it is
  not coverage.
- **Untranslated indirect targets.** Translation is ahead of time over the whole executable range
  plus symbols and call targets. A computed jump to code that is neither is reported, not translated
  on demand. Real stripped binaries need the translate-on-demand tier.
- **No optimisation tier.** Flags are always materialised, direct calls always go through the
  dispatcher, blocks are never linked or inlined, no branch hints. The IR exists to make those
  passes additive.
