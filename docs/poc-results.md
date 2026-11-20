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
- A fixed address space plan, because the guest's whole map is linear memory: control block, the
  dispatch table, images from 4 MiB, heap above the images, `mmap` arena from 1 GiB, a soft page
  table of one byte per 4 KiB page and the stack just below the top. The translator fills in the
  page table for what it maps; `mmap` and `mprotect` maintain the rest.
- More than 4 GiB of address space, which one wasm32 memory cannot hold: a chunk is exactly 2^32
  bytes and the address space is a sequence of them, with the top bits of an address naming the
  memory and the low 32 bits the offset inside it. The module imports one memory per chunk and
  exports each of them, the page table is one table for all of them (a chunk is exactly 2^20 pages,
  so `addr >> 12` indexes it whatever chunk the address is in), and the arena of every chunk above
  the first is all of it. An access inside the first 4 GiB is the inline sequence; past it the
  chunk number picks the memory, which wasm names in the instruction rather than taking off the
  stack, so the access becomes a call to one helper per access shape. A page translated while the
  guest runs imports those helpers from the image rather than carrying its own copy: the jump table
  has an arm per chunk, and that, not the page's own code, is what a page module's bytes mostly
  were. A mapping is free to cross from one memory into the next, because the chunk comes out of
  the address and not out of the mapping: the allocator hands out a range only where every chunk it
  crosses has that part of it free, and the only thing that a boundary breaks is an access that
  straddles it, which copies its bytes through the engine's scratch a byte at a time. The
  default is four chunks.
- Translation on demand: `armjit page` reads `page <elf> <base> <address>` requests and answers with a
  module that imports the host's memory and exports the regions it found, plus the block starts of
  each. The host puts those functions in the running image's table, patches the dispatch table with
  the same open-addressing probe the translator uses, and resumes: `run(entry, sp, resume)` reloads
  the guest state the previous run stored in the shadow. Which pages run is only known while the guest
  runs, so this is the only way a `libc.so.6` mapped by `ld.so` can be executed. A page the guest
  wrote where no file is mapped asks with `-` in place of the image and carries the page's bytes:
  that is code a program generated, and the bytes are all there is to translate from.
- Syscall boundary shaped like a Linux ABI layer: number in x8, args in x0-x5, result or `-errno` in
  x0, unknown numbers answer `-ENOSYS` and say so once on stderr with `ARMJIT_SYSCALLS=1`. Memory:
  `brk`, `mmap` (anonymous and file-backed, `MAP_FIXED`), `munmap`, `mprotect`, `madvise` (the
  advices that take a page back zero it, or read it from the file again), with a free-span allocator
  and the page table maintained in guest memory, and `sysinfo` answering the ranges a run can still
  allocate. Files: `openat`, `close`, `read`, `pread64`, `readv`, `preadv`, `write`, `writev`,
  `lseek`, `fstat`, `newfstatat`, `readlinkat`, `faccessat`, `getcwd`, `ioctl`, resolved inside a
  root filesystem directory. `/proc` is synthesized rather than read: `self/stat` with its fifty-two
  fields, `self/statm`, `self/status`, `self/cmdline` and `self/environ` read back out of the stack a
  kernel built them on, `self/maps` from the address space, and the machine's own `cpuinfo`, `stat`,
  `meminfo`, `uptime`, `version`, `loadavg` and `sys/kernel` and `sys/vm`. The resident count is the
  pages the page table has mapped, kept as the table changes, which is what a space that does not
  swap has. A number in the name is another process of the same run, and survives until its parent
  reaps it. Waiting and counting: `pipe2`, `eventfd`/`eventfd2`, `signalfd4`,
  `/dev` is synthesized too: `null`, `zero`, `full`, `random` and `urandom` as the devices they are,
  `tty` and `console` as the terminal the run was started at, `ptmx` and `pts` for the terminals a
  program makes, `shm` for the directory it shares memory in, and `fd/N`, `stdin`, `stdout` and
  `stderr` as the links a program reaches its own descriptors through.
  `ppoll`, `epoll_*`, `futex` with both shapes of deadline and the requeue forms, `getrusage`,
  `times`. Start-up: `set_tid_address`, `set_robust_list`, `uname`, `clock_gettime`,
  `clock_getres`, `getrandom`, `prlimit64`, `sched_getaffinity`, `getuid` family, `rt_sigaction`,
  `rt_sigprocmask`, `membarrier`, `sched_yield`.

## Correctness

Each oracle-backed guest is built twice from one source: the aarch64 Linux ELF (translated) and a
native macOS arm64 program (the oracle). Output and exit status compared byte for byte.

| guest | what it covers | result |
|---|---|---|
| `hello` | string setup, a loop, integer division by magic multiply, `umulh`, `strb`, exit code | exact |
| `call` | recursion (`fib(20)`), a function pointer table called through `blr`, `stp`/`ldp` frames, signed division, printing | exact, exit 7 |
| `flags` | `tst`/`ccmp` chains, `adcs`/`sbc` multi-word arithmetic, `csel`/`cset` over a matrix, `b.hi` | exact |
| `simd` | load/store widths, three-same, two-misc, across, three-different, shifts by immediate, copy/permute/`tbl`/`tbx`/`ext`, every conversion between general and FP registers and every rounding on the way back, the vector rounding family, the minimums and maximums, the narrowing and widening float conversions, and the one-lane scalar forms | exact |
| `bits` | `rbit`, `clz`, `cls`, `rev`, `rev32`, `rev16`, every shift and `ror` by an immediate and by a register, over 76 patterns, and the `rbit; clz; lsr #2` sequence glibc finds a byte with | exact |
| `stack` | frames sized at run time: `sub sp, sp, xN` in the shifted and extended forms, `and sp, xn, #-16`, `alloca` with calls while the frame is open, recursion with a buffer per level | exact |
| `bench` | 500M xorshift iterations plus an array sweep | exact checksum |

80 oracle cases pass: eight guests at `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, each with explicit address
checks on and off. Thirty-five more assert the ABI itself: the loader handoff (`tests/dyn.sh`), the
memory syscalls (`tests/mem.sh`), a wait that times out and the wake that ends one
(`tests/futex.sh`), an address space of more than 4 GiB (`tests/big.sh`, every access width past the
boundary), the file syscalls (`tests/files.sh`, which makes two names that differ only in case and
checks they stay two files), the pages a guest may not touch
(`tests/faults.sh`), the handler a caught signal runs (`tests/sighandler.sh`), a signal and another
process reaching a spinning guest (`tests/poll.sh`), a guest patching its own code (`tests/smc.sh`),
the console an interactive shell reads (`tests/console.sh`), a pseudo-terminal a program makes for a
child of its own (`tests/pty.sh`), a counted wakeup one process writes and another reads
(`tests/eventfd.sh`), the bytes `/dev/random`, `/dev/urandom` and `getrandom` hand out
(`tests/random.sh`), the CPU a process, a thread and its children have used (`tests/rusage.sh`), the
SHA-3 instructions of Keccak's round (`tests/sha3.sh`, which has no oracle because a Mac has no
`FEAT_SHA3`, so the reference is the definitions in scalar C), an editor on top of the whole stack
(`tests/nvim.sh`), and the socket, epoll, signal and resolver paths, each in both address-check
modes. `bash tests/run.sh` runs all 116; `tests/nvim.sh` skips when the image has no `neovim` in
it.

The console is what makes the whole thing usable by hand: `ARMJIT_CONSOLE=1 tools/run-rootfs.sh
/bin/bash -i` gives a prompt at the terminal it was started from. File descriptor 0 is the host's own
input, so a read parks the thread and the bytes node delivers answer it; `isatty` is true and
`tcgetattr`/`tcsetattr` carry the flags a Linux tty starts with. The host's terminal is in raw mode
for the whole session, because the process holding it is this one, so the line discipline is here
instead: the interrupt and quit characters become signals, a carriage return becomes a newline, the
erase and kill characters edit the line, and a canonical console echoes what is typed and hands over
one line at a time - which is what a terminal does and what a guest reading a line does not. A guest
that turns off `ICANON` and `ECHO`, which is what readline does before it reads one keystroke at a
time and draws the line itself, gets the bytes as they come and does its own echo, so the up arrow
recalls what was run, backspace edits it, `Ctrl-C` ends the command that is running and `Ctrl-D` at
the prompt ends the shell. `read x` takes the next line the way it does at a terminal, and `python3`
prints its banner and a `>>>` prompt. A console run also names the host's `TERM`, or an xterm when
the host has none: without a terminal type readline cannot place its cursor, and it scrolls a long
line sideways instead of wrapping it.

Two things a package manager taught the console. `dpkg` hands `dpkg-deb`'s output to `tar` on a
pipe, and `tar` refuses an archive that arrives from a terminal, so `isatty` has to be false on a
pipe: only the descriptors that name the console answer `tcgetattr`, and everything else answers
`ENOTTY`. And `apt-get` empties the terminal before it starts `dpkg`, by setting fd 0 non-blocking
and reading until a read fails, so `O_NONBLOCK` has to stick to a console descriptor the way it
sticks to any other: the standard descriptors carry an open file description for it. With both,
`apt-get install` unpacks and configures on the console, and the `[Y/n]` it asks before a removal is
answered with `y` or declined with `n`.

A signal the guest catches runs the guest's own code, because the interrupt reaches every process
that has not ignored it - the shell and the command it waits for, which is one process group's worth.
`Ctrl-C` ends the `sleep` a shell is waiting for, prints `KeyboardInterrupt` and a fresh prompt from
a Python REPL, and runs a `trap` in a `dash` script. A handler that a libc installs names no
restorer, because an aarch64 kernel ends every handler at its own trampoline in the vDSO: this
machine recognises that return as `rt_sigreturn` and puts the frame the signal left back on the
stack. A pager wants all of it: `less /etc/os-release` takes the screen, pages on a space, quits on
`q`, and gives the shell its terminal back.

Terminals beget terminals. `posix_openpt` and `/dev/ptmx` make a pseudo-terminal pair, `/dev/pts/N`
names its slave, and the two ends carry data with the line discipline, the window size and the flags
between them, so the `E: Can not write log (Is /dev/pts mounted?)` that `apt` used to print while it
ran `dpkg` is gone: it has a terminal of its own for the package manager now, and the escapes of the
progress bar come back out of the master. A terminal also has a name to the program inside it:
`/proc/self/fd/N` is a link to what N holds, `st_rdev` of a slave says which UNIX98 device it is,
`/dev/pts` lists the ones that are open, and `TIOCGPTPEER` hands over a slave without a name in
between, so a program can make a pair without racing another opener for it. `signalfd` is where
`script` waits for its child, a read of one is a `struct signalfd_siginfo`, and a child that ends
wakes its parent, so `script` sees the command it ran finish and exits on its own. Debconf is the
other half of an interactive install: with `whiptail` in the tree its Dialog frontend draws the
question on the console (the image ships neither it nor `Term::ReadLine`, so it had fallen back to
the Teletype frontend, whose yes/no prompt wants the word, not the letter).

An editor is the biggest libuv program in the tree, and it runs: `nvim` draws its screen at the
console, takes `ihello there`, writes the file with `:wq` and exits with zero, and the ShaDa file it
leaves behind is one it reads back. What it was missing was three syscalls, and the shape of the
failure is the lesson. `eventfd` is what libuv starts an async handle with; without it the handle is
left half-built, the caller ignores the error, and the first `uv_async_send` from a thread loads
through a null `loop` - a crash nowhere near the syscall that was missing. `readv` is how the ShaDa
file is read, and `clock_getres` left `errno` at `ENOSYS`, which made the next failure the program
reported name the wrong thing entirely.

Two suites are about a real libc rather than about a fixture. `bash tests/fmt.sh` runs thirteen
programs built against bookworm's glibc (`tools/build-dyn-guest.sh` builds them in a container and
records their oracles there) through the translated `ld-linux` and `libc.so.6`, in both
address-check modes; one of them keeps its buffers above 4 GiB and fills and reads them from a
library, so the pages translated while it runs are the ones that reach past the first memory and
across the seam between two. `bash tests/shell.sh` runs Debian's own `dash` under 50 `-c` scripts,
translated and inside `chroot` on a container's kernel, and compares stdout, stderr and exit
status of each.

The toolchain is the other test, because it is the thing that exercises every instruction the way
real code does. `apt-get install` unpacks and configures Debian's own packages inside the guest -
`gcc`, `g++`, `make`, `python3-dev`, `linux-libc-dev` and what they pull in - and `gcc -O2` then
compiles a C file to assembly that is byte for byte what the same gcc 12.2 emits natively, with every
pass of `-fdump-tree-all` and `-fdump-rtl-all` matching apart from the addresses the compiler's own
allocator landed on. `pip install --no-binary :all: msgpack` compiles a C extension with that gcc and
imports it: a shared object built and `dlopen`ed inside the guest.

`python3-numpy` is the last one, and it is what the floating point work is checked against now. It
imports, builds its dispatch tables and runs `dot`, `matmul`, `fft`, `exp`, `sin` and the float32
reductions, and prints what the same numpy 1.24.2 prints natively, down to the last bit of a
16-point `fft` and of a 100x100 product. Three bugs came out of it. `import numpy` hung because
`fcvtzu`/`fcvtas` and the other roundings were decoded as `fsqrt`, which made `_Py_HashDouble` loop
forever. `sin` was about 1e-6 off between 0.126 and 0.855 because `fmsub` took the accumulator from
the wrong side. A cast of an array to `float32` runs numpy's `fcvtn` loop, which was not translated
and trapped.

## Performance

`bash tools/bench.sh` measures this: an integer kernel, 500M mix iterations + 2000 array sweeps, on
an M4 Pro. Native is the same source compiled with clang `-O2`; wasm time excludes node startup and
module compilation. Run it on an idle machine: contention moved every number here by 2x.

| configuration | time | vs native |
|---|---|---|
| native arm64 | 871 ms | 1.00x |
| wasm, 4 GiB of address space (1 chunk), checks off | 1535 ms | 1.76x |
| wasm, 8 GiB of address space (2 chunks), checks off | 1434 ms | 1.65x |
| wasm, 16 GiB of address space (4 chunks), checks off | 1444 ms | 1.66x |
| wasm, 32 GiB of address space (8 chunks), checks off | 1489 ms | 1.71x |
| wasm, 16 GiB of address space (4 chunks), checks on | 1538 ms | 1.77x |

The chunk a program is not using costs nothing at run time. Every access carries one compare
against 4 GiB when there is more than one chunk, and the branch predictor never misses it, so the
rows above are flat from 1 to 8 chunks within the noise this machine measures at (the same
configuration moves by 10% between runs). What grows is the image: 46 KiB at one chunk, 55 at
four, 64 at eight and 191 at sixty-four, for the arms of the helpers' jump tables and the
byte-at-a-time path across a boundary. That is one module, compiled once at startup.

A page translated while the guest runs does not grow with the chunk count, because it calls the
image's helpers instead of carrying a copy of them. One Python workload, 652 page modules, mean
page module and wall time:

| chunks | page module | run |
|---|---|---|
| 4 | 63 KiB, from 71 | 4424 ms, from 4549 |
| 64 | 64 KiB, from 207 | 4558 ms, from 7347 |

A page now costs what its own code costs at any chunk count, and 256 GiB of address space runs 3%
slower than 16 GiB where it used to run 61% slower. The absolute numbers here are slower than the
run that stood in this table before, on a busier machine; the shape is what it measures.

Translation cost: 161 instructions of 1 region in 0.7 ms, 43 KB of wasm from 37 KB of guest. V8
compiles that module in 0.2 ms. Most of the 0.7 ms is one pass over the 1 MiB page table, which is a
one-off per image.

Two things follow.

1. The register-in-locals thesis holds. 1.39x native with a naive template translation, no peephole
   pass, no flag liveness, no block linking, and a dispatcher round trip per call and return. That is
   already inside the band that makes a browser VM usable, and near CheerpX's self-reported *best*
   case (2x-3x) rather than its typical case (5x-10x).
2. Address validation is the single biggest cost, at 46% of runtime, and catching 64-bit wrap needs
   a compare per access, which is what the `check` rows pay for. A chunk past the first is now what
   an address above 4 GiB means, so such an address can no longer truncate and alias: it names a
   memory this machine has or traps, and the descriptor of a program that only uses the first memory
   pays one predictable branch. This is still the clearest first optimization target: prove
   addresses in range where the source of the address makes it provable, and check only the rest.

## What this does not prove, in order of how much it matters

- **A shell prompt.** Debian's own `ld-linux-aarch64.so.1` is translated with dash and runs from
  `_dl_start` through the tunable scan, `/etc/ld.so.preload`, the library search path, the mapping of
  `libc.so.6` (its segments at the addresses the loader chose, its relocations applied, its `relro`
  protected) and into glibc's start-up, then `main`, then dash's own command loop. It now behaves like
  dash: `-c true` exits 0, `-c 'echo hi'` prints `hi`, `-c 'nosuchcommand'` prints
  `dash: 1: nosuchcommand: not found` and exits 127, `-c ':;exit 7'` exits 7, all matching the same
  binary on a real kernel.
- **Variable expansion and control flow.** Parameters, substrings, defaults, assignments,
  arithmetic, quotes, `if`/`while`/`for`/`case`, functions and `printf` all behave: 50 `-c` scripts
  print what the same binary prints on a real kernel and exit the same way. Pipes, command
  substitution, subshells, background jobs with `wait` and external commands are in that set. A pipe
  is two processes over one descriptor table, which is what `fork` and `execve` are here.
- **Scalar floating point, and the FPCR.** Every shape is translated and compared against the
  oracle: `fadd`, `fsub`, `fmul`, `fdiv`, `fnmul`, `fmax`/`fmin` and their number forms (with the
  NaN each of them hands back, bit for bit), `fabs`, `fneg`, `fsqrt`, `fmov` with a register and
  with the eight-bit immediate, `fcvt` both ways, every `frint*`, `fcmp`/`fcmpe` including the zero
  form and the unordered result, `fcsel` over all sixteen conditions, `fcvtzs`/`fcvtzu` with a
  fraction-bit count, and the fused multiply-add group. `tests/guest/fp.c` is 8880 values over the
  two zeros, the infinities, a quiet and a signalling NaN, a denormal and values that only differ
  in the last bit. FPCR is honoured: RMode rounds `scvtf`/`ucvtf` (with and without a fraction-bit
  count), `fcvt` both ways, `frintx`/`frinti` and `fcvtn`/`fcvtn2`, FZ flushes denormal operands
  and results of the scalar and vector arithmetic and of the conversions, and DN makes every NaN
  result the default one. What is not: the exception flags in FPSR, which a guest that reads them
  sees as zeros; the across-lane vector forms, which keep the denormal they were given;
  `fcvtxn`'s round-to-odd; the float-to-integer conversions, whose denormal input is not flushed;
  and the fraction-bit conversions, which round the integer rather than the scaled value, so a
  result that lands in the denormal range can be a step out. One known inexactness: wasm has no
  fused multiply-add, so `fmadd` and its siblings round twice and can differ from the instruction in
  the last bit.
- **Instruction coverage of a big library.** The parts of libc that nothing reaches (a page of
  `strlen` variants, the MTE paths in `malloc`) report `undecoded instruction`, and the words are SVE
  and MTE: the loader does not pick them because `ID_AA64PFR0` and `ID_AA64ISAR0` are a baseline
  model. `docs/gaps.md` is that measurement over the whole tree.
- **Page permissions.** Every translated load and store consults the page table, which is what says
  a page is mapped, readable, writable and executable; the check is always emitted, because a
  program's correctness depends on the fault rather than on its speed. A store to a read-only page,
  a load from an unmapped one and a call into a page without execute all end the process with
  `SIGSEGV`, which `tests/faults.sh` compares against a real kernel. What is still missing is the
  handler: a synchronous fault cannot be caught yet, so a program with a `SIGSEGV` handler dies.
- **Self-modifying code, and code the guest generates.** A `mprotect` that makes a page holding
  translated code writable drops that page's translations, and the next run of it is translated from
  the bytes the guest holds rather than from the file, which `tests/smc.sh` checks by patching a
  function and calling it. A page in no image is code the guest wrote itself: the host asks the
  translator for it with the bytes the page holds, and the translator decodes them with no file,
  symbols or unwind tables behind them, so the only function starts are the ones the page calls. A
  branch or a call that leaves the page reaches the dispatcher, which translates the page it lands
  in when the run gets there. `tests/jit.sh` covers a written page made executable, a second write
  to a page that had already run, an RWX page, a branch across a page boundary, a call from
  generated code into the translated image, and a syscall made from generated code.
- **Signals.** A handler of the guest's own runs, with the frame, the mask and the restorer a kernel
  gives it, when a syscall is where the signal can be taken; a signal that arrives while the guest is
  in the middle of a computation waits for the next syscall. A fault is still fatal, so a `SIGSEGV`
  handler does not run.
- **What `/proc` and `/dev` do not have.** Both are trees a program can walk and a process can read
  another process's files out of, but neither is everything a kernel keeps there: `/proc/<pid>/task`
  and the `net`, `sys/net` and `fs` subtrees are not there, a process sees no `stat` of a zombie's
  state (it says `R` for anything still in the table), and `/dev` has the character devices and the
  terminal links rather than block devices, `loop*`, `tty1..N` or the framebuffer a machine with a
  console would have.
- **Code has to live below 4 GiB.** A dispatch word is keyed by the low 32 bits of `pc >> 2` and
  the shadow's pc is 32 bits wide, so a jump above 4 GiB lands in the slot of the address 4 GiB
  below it. The second memory holds heap, and a heap is not run: a program that maps an
  executable page at 8 GiB and calls into it does not get there, measured with a page written at 8
  GiB and called. A JIT whose own code range lands above the boundary would break; node's has not,
  which is why `tests/jit.sh` passes at every address it uses.
- **Job control.** One console and one process group: `Ctrl-Z`, `fg`, `jobs`, and a window that is
  resized (`SIGWINCH`) are not there, so a stopped job cannot be resumed. And the console's interrupt
  reaches the processes that take the default action for it: the shell catches it so that it can
  tidy up after the command it waits for, and with one process group the disposition is what stands
  in for "the foreground job", so a program that handles `SIGINT` itself - a Python REPL, say - does
  not see the `Ctrl-C`.
- **Threads are coroutines, and nothing has a disk.** `clone` makes a thread inside one instance with
  its own registers and stack. A guest that spins without a syscall gives the CPU back at a backward
  branch, so it no longer stalls the others, but a thread is switched only there and at a syscall:
  there is no timer interrupt. Files come from a host directory rather than a block device or an
  ext4 image, which is what `docs/fs.md` is about.
  `ptrace` is not implemented, so a debugger cannot attach.
- **The kernel's own memory is guest-addressable.** Guest virtual addresses are offsets into the
  same memories, so the shadow register file, the dispatch table and the page table sit in the first
  one where a wild guest write can reach them, and a relocation written with a zero bias would land
  there silently instead of faulting. The page table says those pages are unmapped, so a translated
  access faults, which is what `tests/faults.sh` checks; a real kernel keeps them out of the address
  space entirely, and giving the engine a memory of its own is the way to that.
- **A reservation is bounded by the space, and starts above the first memory.** A mapping can cross
  a chunk boundary, so the ten gigabytes a wasm engine asks for fit in the default space, guard
  region and all. Two things still answer `ENOMEM`: a reservation bigger than everything above the
  first memory (twelve of the default sixteen gigabytes), and one that would have to cross *out* of
  the first memory, whose top holds the page table and the stack. The real 2^47 user range, a
  sanitizer's shadow, is out of reach until an engine ships 64-bit memories.
- **A program the size of `cc1` is a 285 MB module.** `gcc` installs, and `cc1` translates to 1373914
  blocks and 5.1 million instructions in 42039 wasm functions. The engine compiles that, but not as
  one function per region: its per-function bookkeeping grows with the square of the blocks in the
  function, and a region of the 48 thousand blocks here is a function it refuses with `Fatal process
  out of memory: Zone`. A region is emitted in pieces of at most 512 blocks now, which took the
  largest function from 2 MB to 193 KB. `gcc` compiles and runs in the guest; the module is still a
  quarter of a gigabyte to translate, compile and read, next to `python3.11` at 40 MB.
- **Instruction coverage is compiler output, not the ISA.** Hand-written or obfuscated code that uses
  `rmif`, `setf*`, `ldraa`, pointer authentication, `mrs` of anything else, the LSE atomics, or `SVE`
  is refused rather than mistranslated. That is the right failure mode but it is not coverage.
  `docs/gaps.md` counts it: 14843 refused words in 1278 encodings across 71 of the tree's 913 ELFs,
  nearly all of them in code the guest's HWCAP keeps it out of. The real ones, ranked: the vector
  float compares, the two families of vector float-to-integer conversions, the by-element
  arithmetic, `cntd`, the saturating forms and the pairwise ones.
- **Untranslated indirect targets.** A jump into an image is translated on demand now, so an entry
  the ahead-of-time scan misses costs a page translation instead of stopping the run. The ahead-of-time
  pass still decides what a region is, so a wrong guess about where code starts costs a page: the
  region is emitted as a trap and its later blocks are left out, which is what turns a bad entry into
  a run-time translation of the address that is really there.
- **No optimisation tier.** Flags are always materialised, direct calls always go through the
  dispatcher, blocks are never linked or inlined, no branch hints. The IR exists to make those
  passes additive, and a page translated on demand is emitted by the same code as an ahead-of-time
  region, so nothing here is a special case.
