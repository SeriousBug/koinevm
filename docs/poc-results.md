# PoC results

What exists now: a translator that takes an AArch64 Linux ELF (static or dynamically linked, with its
interpreter) and emits one wasm module, plus a host that provides the kernel: syscalls, a soft page
table, a root filesystem. `node run.mjs out.wasm` runs the guest. The translator also stays alive for
the length of the run, answering requests for the pages the guest jumps into as it jumps into them,
so a library the loader maps while it runs executes without being known in advance.

## What it does

- ELF64 loader: `ET_EXEC` at its link addresses, `ET_DYN` at a chosen base with the bias applied to
  segments, entry and symbols, program headers inside the first segment so `AT_PHDR` names mapped
  memory. `PT_INTERP` loads the interpreter as a second image in the same module: the kernel would
  have started the loader, not the program, so `AT_BASE` names the loader while `AT_ENTRY`/`AT_PHDR`
  keep describing the program, and the swap between them is a jump. Initial stack built as a kernel
  builds it (argc, argv, envp, auxv with `AT_PHDR`/`AT_BASE`/`AT_ENTRY`/`AT_PAGESZ`/`AT_RANDOM`/
  `AT_PLATFORM`/`AT_HWCAP`/`AT_SECURE`), fixed layout.
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
  that looks the pc up in an open-addressed table (a slot is `pc >> 2`'s tag plus `region, block`),
  so wasm stack depth is constant, guest recursion is bounded by the guest stack in linear memory,
  and code from images at unrelated addresses costs nothing extra.
- A fixed address space plan, because the guest's whole map is the linear memory: control block,
  a soft page table of one byte per 4 KiB page, the dispatch table, images from 4 MiB, heap above
  the images, stack at the top. The translator fills in the page table for what it maps; `mmap` and
  `mprotect` will maintain the rest.
- Translation on demand: `armjit page` reads `page <elf> <base> <address>` requests and answers with a
  module that imports the host's memory and exports the regions it found, plus the block starts of
  each. The host puts those functions in the running image's table, patches the dispatch table with
  the same open-addressing probe the translator uses, and resumes: `run(entry, sp, resume)` reloads
  the guest state the previous run stored in the shadow. Which pages run is only known while the guest
  runs, so this is the only way a `libc.so.6` mapped by `ld.so` can be executed.
- Syscall boundary shaped like a Linux ABI layer: number in x8, args in x0-x5, result or `-errno` in
  x0, unknown numbers answer `-ENOSYS` and say so once on stderr with `ARMJIT_SYSCALLS=1`. Memory:
  `brk`, `mmap` (anonymous and file-backed, `MAP_FIXED`), `munmap`, `mprotect`, with a free-span
  allocator and the page table maintained in guest memory. Files: `openat`, `close`, `read`,
  `pread64`, `write`, `writev`, `lseek`, `fstat`, `newfstatat`, `readlinkat`, `faccessat`, `getcwd`,
  `ioctl`, resolved inside a root filesystem directory. Start-up: `set_tid_address`,
  `set_robust_list`, `uname`, `clock_gettime`, `getrandom` (deterministic), `prlimit64`,
  `sched_getaffinity`, `getuid` family, `rt_sigaction`, `rt_sigprocmask`, `futex`, `madvise`,
  `membarrier`, `sched_yield`.

## Correctness

Each oracle-backed guest is built twice from one source: the aarch64 Linux ELF (translated) and a
native macOS arm64 program (the oracle). Output and exit status compared byte for byte.

| guest | what it covers | result |
|---|---|---|
| `hello` | string setup, a loop, integer division by magic multiply, `umulh`, `strb`, exit code | exact |
| `call` | recursion (`fib(20)`), a function pointer table called through `blr`, `stp`/`ldp` frames, signed division, printing | exact, exit 7 |
| `flags` | `tst`/`ccmp` chains, `adcs`/`sbc` multi-word arithmetic, `csel`/`cset` over a matrix, `b.hi` | exact |
| `simd` | 838 vector cases: load/store widths, three-same, two-misc, across, three-different, shifts by immediate, copy/permute/`tbl`/`tbx`/`ext`, and every conversion between general and FP registers | exact |
| `bits` | `rbit`, `clz`, `cls`, `rev`, `rev32`, `rev16` over 76 patterns, and the `rbit; clz; lsr #2` sequence glibc finds a byte with | exact |
| `stack` | frames sized at run time: `sub sp, sp, xN` in the shifted and extended forms, `and sp, xn, #-16`, `alloca` with calls while the frame is open, recursion with a buffer per level | exact |
| `bench` | 500M xorshift iterations plus an array sweep | exact checksum |

58 oracle cases pass: six guests at `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, each with explicit address
checks on and off. Eight more cases have no native oracle and assert the ABI themselves: the loader
handoff (`tests/dyn.sh`), the memory syscalls (`tests/mem.sh`) and the file syscalls
(`tests/files.sh`), each in both address-check modes. `bash tests/run.sh` runs all 66.

Two suites are about a real libc rather than about a fixture. `bash tests/fmt.sh` runs a
`printf`-and-`strlen` program built against bookworm's glibc (`tools/build-dyn-guest.sh` builds it in
a container and records the oracle there) through the translated `ld-linux` and `libc.so.6`, in both
address-check modes. `bash tests/shell.sh` runs Debian's own `dash` under 33 `-c` scripts, translated
and inside `chroot` on a container's kernel, and compares stdout, stderr and exit status of each.

## Performance

`bash tools/bench.sh` measures this: an integer kernel, 500M mix iterations + 2000 array sweeps, on
an M4 Pro. Native is the same source compiled with clang `-O2`; wasm time excludes node startup and
module compilation. Run it on an idle machine: contention moved every number here by 2x.

| configuration | time | vs native |
|---|---|---|
| native arm64 | 820 ms | 1.00x |
| wasm, 4 GiB memory, per-access checks off | 1139 ms | 1.39x |
| wasm, 4 GiB memory, per-access checks on | 1662 ms | 2.03x |
| wasm, 64 MiB memory, per-access checks on | 1652 ms | 2.01x |

Translation cost: 161 instructions of 1 region in 0.7 ms, 43 KB of wasm from 37 KB of guest. V8
compiles that module in 0.2 ms. Most of the 0.7 ms is one pass over the 1 MiB page table, which is a
one-off per image.

Two things follow.

1. The register-in-locals thesis holds. 1.39x native with a naive template translation, no peephole
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

- **A shell prompt.** Debian's own `ld-linux-aarch64.so.1` is translated with dash and runs from
  `_dl_start` through the tunable scan, `/etc/ld.so.preload`, the library search path, the mapping of
  `libc.so.6` (its segments at the addresses the loader chose, its relocations applied, its `relro`
  protected) and into glibc's start-up, then `main`, then dash's own command loop. It now behaves like
  dash: `-c true` exits 0, `-c 'echo hi'` prints `hi`, `-c 'nosuchcommand'` prints
  `dash: 1: nosuchcommand: not found` and exits 127, `-c ':;exit 7'` exits 7, all matching the same
  binary on a real kernel.
- **Variable expansion and control flow.** Parameters, substrings, defaults, assignments,
  arithmetic, quotes, `if`/`while`/`for`/`case`, functions and `printf` all behave: 33 `-c` scripts
  print what the same binary prints on a real kernel and exit the same way. What is left is what
  needs a second process: a pipe, a subshell, or any external command other than a builtin.
- **Scalar floating point.** Every shape is translated and compared against the oracle: `fadd`,
  `fsub`, `fmul`, `fdiv`, `fnmul`, `fmax`/`fmin` and their number forms (with the NaN each of them
  hands back, bit for bit), `fabs`, `fneg`, `fsqrt`, `fmov` with a register and with the eight-bit
  immediate, `fcvt` both ways, every `frint*`, `fcmp`/`fcmpe` including the zero form and the
  unordered result, `fcsel` over all sixteen conditions, `fcvtzs`/`fcvtzu` with a fraction-bit count,
  and the fused multiply-add group. `tests/guest/fp.c` is 5403 values over the two zeros, the
  infinities, a quiet and a signalling NaN, a denormal and values that only differ in the last bit.
  One known inexactness: wasm has no fused multiply-add, so `fmadd` and its siblings round twice and
  can differ from the instruction in the last bit.
  `fadd`, `fmul`, `fdiv`, `fsqrt`, `fcmp`, `fcsel`, `fneg`/`fabs`/`fmax`/`fmin` and `fcvt` between
  precisions are refused at the instruction that reaches them, and glibc's own pages already report
  them: `scalar floating point arithmetic is not translated yet` at `0x4004cec8`.
- **Instruction coverage of a big library.** Threads of libc build (a page of `strlen` variants) that
  are unreachable from the entries the translator finds report `undecoded instruction`, up to 116
  words in one page. They are where the `-mgeneral-regs-only` gap and the crypto/atomics gap would
  show up in real code rather than in a fixture.
- **Page permissions.** The page table records them and `mprotect` maintains them, but a translated
  store does not consult them: a write to a read-only page lands instead of faulting.
- **Self-modifying code and guest JITs.** Nothing invalidates a translation. Adding a page module is
  already dynamic, so invalidation has somewhere to live, but it is not implemented.
- **Signals.** A trap kills the run instead of being delivered to a guest handler.
- **Threads, `fork`/`exec`, a real block device.** One process, one thread, and files come from a host
  directory rather than a disk image. `wait4`, `execve`, `clone` and `getdents64` are not there, so a
  shell would have nothing to run and nothing to list.
- **The kernel's own memory is guest-addressable.** Guest virtual addresses are linear-memory
  offsets, so the shadow register file and the page table sit in low memory where a wild guest write
  can reach them, and a relocation written with a zero bias would land there silently instead of
  faulting. A real kernel keeps them out of the address space entirely.
- **Instruction coverage is compiler output, not the ISA.** Hand-written or obfuscated code that uses
  `rmif`, `setf*`, `ldraa`, pointer authentication, `mrs` of anything else, the LSE atomics, or `SVE`
  is refused rather than mistranslated. That is the right failure mode but it is not coverage.
- **Untranslated indirect targets.** A jump into an image is translated on demand now, so an entry
  the ahead-of-time scan misses costs a page translation instead of stopping the run. The ahead-of-time
  pass still decides what a region is, so a wrong guess about where code starts costs a page: the
  region is emitted as a trap and its later blocks are left out, which is what turns a bad entry into
  a run-time translation of the address that is really there.
- **No optimisation tier.** Flags are always materialised, direct calls always go through the
  dispatcher, blocks are never linked or inlined, no branch hints. The IR exists to make those
  passes additive, and a page translated on demand is emitted by the same code as an ahead-of-time
  region, so nothing here is a special case.
