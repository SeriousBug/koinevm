# Prior art: AArch64 → WebAssembly translation

Surveyed 2026-11-16. Claims are sourced; numbers are quoted as the source gives them. Anything I
could not confirm is marked **unverified**.

Problem: run AArch64 Linux ELF binaries in a browser (or a wasm runtime) by translating machine code
to wasm, AOT and/or JIT. Reference product: CheerpX (x86 → wasm).

## 1. CheerpX (Leaning Technologies)

Closed source and proprietary — `leaningtech/cheerpx-meta` holds only docs and examples, and the CTO
states CheerpX "is proprietary" while WebVM is FOSS
([HN](https://news.ycombinator.com/item?id=42135204)). Shipped as a JS blob from
`cxrtnc.leaningtech.com`.

Licensing, verbatim from [licensing](https://cheerpx.io/docs/licensing): the Community License is
free for *individuals* (explicitly including one-person companies and revenue-generating personal
projects), *FOSS projects* and *technical evaluations*, against credit; it "allows unlimited,
unmetered use of CheerpX from the `cxrtnc.leaningtech.com` domain", and self-hosting is a Commercial
License feature. A commercial licence is required for "any *business use* (with exception of
one-person companies), *redistribution* and *OEM use*". So: not open core, not source-available, no
self-host tier, no vendoring. The licence trigger is headcount — a solo founder may ship a commercial
product on the Community License, the second employee makes it a commercial use. The open-source
asset in Leaning Tech's stack is the Cheerp C++→JS compiler; both VMs (CheerpX, CheerpJ) are
proprietary. Consequence for testing: a shipped test suite or benchmark cannot use CheerpX as an
oracle, since that would depend on their CDN and their terms.

| Aspect | As publicly described |
|---|---|
| Shape | "two-tier emulator for the x86 architecture implemented in C++ and compiled to JavaScript and WebAssembly": interpreter + JIT that generates wasm for hot code ([overview](https://cheerpx.io/docs/overview)) |
| ISA | 32-bit x86 user mode on a Linux-compatible syscall layer, not a real kernel ([overview](https://cheerpx.io/docs/overview)) |
| Codegen unit | "all the code reachable via direct jumps and hot enough from a given entry point will become 1 Wasm function"; direct branches via their CFGStackifier; calls → wasm calls; PLT jumps devirtualised ([Extreme WASM 1](https://labs.leaningtech.com/blog/extreme-webassembly-1-pushing-browsers-to-their-absolute-limits)) |
| Indirect jumps | Not a pure call chain (wasm stack overflow); solved with tail calls ([Extreme WASM 2](https://labs.leaningtech.com/blog/extreme-webassembly-2-the-sad-state-of-webassembly-tail-calls)) |
| Self-modifying code | Claimed supported, no mechanism published. **Unverified.** They championed branch hinting (Yuri Iozzelli is its CG champion, [finished proposals](https://github.com/WebAssembly/proposals/blob/main/finished-proposals.md)) |
| Filesystem | HTTP `WebDevice` (read-only, needs `index.list`), IndexedDB `IDBDevice`, in-memory `DataDevice`, `HttpBytesDevice` (ext2 over HTTP byte ranges), `OverlayDevice`. OPFS is not a documented backend ([File-System-support](https://cheerpx.io/docs/guides/File-System-support)) |
| Disk | "up to 2GB", on-demand chunk download, IndexedDB cache *and* persistence; cloud backend is WebSocket+CDN ([cx-10](https://labs.leaningtech.com/blog/cx-10), [FAQ](https://cheerpx.io/docs/faq)) |
| Networking | Tailscale over WebSocket, not an open proxy ([FAQ](https://cheerpx.io/docs/faq)) |
| Browser needs | `SharedArrayBuffer`, so COOP `same-origin` + COEP `require-corp` ([FAQ](https://cheerpx.io/docs/faq)) |
| Memory ceiling | "In the best case scenario it would be 4GB, but it's unlikely this can be achieved on all devices"; explicitly not a memory64 issue but the practical allocation limit; WebVM ships 700MB ([HN](https://news.ycombinator.com/item?id=42135204)) |

Performance (vendor, methodology unpublished): expected "5x-10x slower than native, with the slowdown
being as low as 2x-3x for binaries that only stress the best optimized parts"; target "at most 5x"
([cx-10](https://labs.leaningtech.com/blog/cx-10)). Integer-heavy tests only; Box2D (FP) is the slow
case. These are the most-quoted numbers for an ISA→wasm JIT and are self-reported.

## 2. v86 (copy.sh/v86)

Open source, BSD-2-Clause ([LICENSE](https://github.com/copy/v86/blob/master/LICENSE)); full-system
x86 PC emulator plus an x86→wasm JIT, documented by its author in
[how-it-works.md](https://github.com/copy/v86/blob/master/docs/how-it-works.md):

- Interpreted first, recording entry points (call/indirect-jump targets) and per-page hotness. When a
  page is hot, code is generated "for the entire page and up to `MAX_PAGES` that are directly
  reachable from it".
- Each module is "a single function with a big switch statement (brtable)" so every target is
  reachable; the rest of the control flow uses the **stackifier**.
- **No cross-module block linking**: "At the moment, there is no linking of wasm modules. The current
  module is exited, and the main loop detects if a new module can be entered."
- Page invalidation: a 4MB TLB-like cache holding physical address, read-only bit, a "page contains
  code" bit and an MMIO bit; writes to code pages take the slow path, which invalidates that page's
  compiled code.
- Stated wasm limits for JITs: no arbitrary jumps, no registers across functions, no `mmap`, no
  patching, slow module generation, and "some memory overhead per module, so you can't generate more
  than a few thousand". Deep brtables with cross-block locals degrade badly in browsers, so
  `MAX_PAGES` must stay low.
- Codegen is 1:1 x86→wasm with one peephole (compare+branch fusion), lazy flags in both tiers, x87
  via softfloat.

Performance: the project publishes no throughput number. Circulating figures ("100-200 MHz on x86-64
hosts") are third-party blogs. **Unverified — do not cite.**

## 3. QEMU: TCG, TCI, wasm builds

- **TCG** lowers guest basic blocks ("translation blocks", TBs) to a host-independent IR plus a host
  backend that emits code, with a TB cache and chaining
  ([TCG docs](https://www.qemu.org/docs/master/devel/tcg.html)).
- **TCI** is a TCG *backend* emitting bytecode for a small VM instead of native code, so QEMU runs on
  hosts without runtime codegen; "The only difference from running QEMU with TCI to running without
  TCI should be speed" ([tcg/tci/README](https://fossies.org/linux/qemu/tcg/tci/README),
  [Features/TCI](https://wiki.qemu.org/Features/TCI)).
- [ktock/qemu-wasm](https://github.com/ktock/qemu-wasm), now
  [cloud-native-webassembly/qemu-wasm](https://github.com/cloud-native-webassembly/qemu-wasm): QEMU
  built with Emscripten; `qemu-system-x86_64`, `-aarch64` (Raspberry Pi demo) and `-riscv64` run in
  the browser with MTTCG. "TBs run on TCI by default, with frequently executed TBs compiled into
  WebAssembly" — each hot TB becomes its own wasm module importing the main module's memory and
  helpers, because "browsers don't look like capable of creating thousands of modules"; threshold is
  "e.g. 1000" executions.
- Upstream: "Experimental support for compiling to WASM using Emscripten" is in
  [QEMU 10.1](https://wiki.qemu.org/ChangeLog/10.1); per the fork README, TCI for 32-bit guests is
  upstreamed in 10.1 while 64-bit TCI and the TCG wasm backend are still patchsets under discussion.
  The wasm64 TCG backend is
  [[PATCH 00/35] wasm: Add Wasm TCG backend based on wasm64](https://www.mail-archive.com/qemu-devel@nongnu.org/msg1133198.html)
  (Aug 2025), on `--cpu=wasm64` plus `--enable-wasm64-32bit-address-limit` for engines without
  memory64 (they name Safari).
- No published performance numbers for the QEMU wasm work. **Unverified.**
- Related: [container2wasm](https://github.com/Clause-Logic/container2wasm) packs a container with
  QEMU/Bochs/TinyEMU inside wasm for WASI runtimes and browsers; recommends x86-64/riscv64/AArch64.

## 4. FEX-Emu and box64/box86 (x86-64 on AArch64)

Same host/target pair as us, reversed direction. Their flag handling, block boundaries and cache
invalidation transfer directly; their emitters do not.

**FEX-Emu** ([FEXCore/Readme.md](https://github.com/FEX-Emu/FEX/blob/main/FEXCore/Readme.md)): goal
"25% - 50% lower performance than native"; x86-64 → Arm64-flavoured IR → SSA → Arm64 JIT, tiered
recompiler, userspace only, includes x86 TSO on weak memory. The x86-64 JIT and IR interpreter were
*deleted* to restructure the Arm64 JIT around a new flags representation
([FEX-2310](https://newreleases.io/project/github/FEX-Emu/FEX/release/FEX-2310)) — flags drove the
architecture, not the other way round.

- Flags: keep guest SF/ZF/CF/OF resident in host NZCV instead of computing them per instruction;
  PF/AF get dedicated GPRs because they are costly (popcount, no CSSC on most ARM)
  ([FEX-2312](https://fex-emu.com/FEX-2312/)). Unused flags are eliminated (stated, pass undocumented).
- SMC: historically "purely at a block level using memory protection: an SMC write would invalidate
  all cached code in the touched page", then finish the current block. Inline SMC (Denuvo-style)
  forced recompiling just the modifying instruction's block and jumping into it
  ([FEX-2501](https://fex-emu.com/FEX-2501/)).
- Code buffers are shared by all threads so code is JITed once; on one thread-churning game that
  alone moved 30 → 60 FPS ([FEX-2506](https://fex-emu.com/FEX-2506/)).

**box64** ([dynarec writeup](https://box86.org/2024/07/revisiting-the-dynarec/),
[manpage](https://manpages.debian.org/testing/box64/box64.1.en.html)): one "dynablock" per unit,
built in ~7 passes — decode and block-extend decisions, predecessors, **backward flags-need
propagation with Kildall's algorithm**, dead-code cleanup, NEON allocation, instruction counting,
`memalign`+`mprotect` allocation, emit. DynaRec is "5 to 10 times faster than using only the
interpreter" (vendor claim). Options that mark the hard edges: `DYNAREC_SAFEFLAGS` (may CALL/RET
assume flags?), `DYNAREC_BIGBLOCK` (how far to extend past branches, against threaded/JIT-heavy
programs), `DYNAREC_STRONGMEM` (TSO levels), `DYNACACHE` (persist blocks). Code pages are
write-protected; the SIGSEGV handler classifies write-to-code vs guest signal and invalidates the
affected dynablocks, with a hot-page/NEVERCLEAN state for pages that keep being written
([deepwiki](https://deepwiki.com/ptitSeb/box64)).

## 5. ISA → portable bytecode: precedent

- **NestedVM** (2003–06): GCC → MIPS → Java `.class`, so C/C++/Fortran runs as pure bytecode. Memory
  is "a giant `int[][]` array indexed by page, then address"; the `syscall` instruction maps to a
  `Runtime` method ([nestedvm.ibex.org](http://nestedvm.ibex.org/),
  [contemporary summary](https://www.digitalmars.com/d/archives/digitalmars/D/announce/From_the_Department_of_Insane_Ideas_D_on_the_JVM_6264.html)).
  Closest historical analogue: constant-cost per-instruction translation, pages as host arrays,
  syscalls as host calls, host JIT does the optimisation.
- **Lift to a real IR and reuse its backend**: remill-based [elfconv](https://github.com/yomaytk/elfconv)
  lifts AArch64 to LLVM IR, then LLVM/Emscripten/WASI-SDK emits wasm — instruction selection and CFG
  structurisation for free.
- Academic: I found **no peer-reviewed paper whose subject is translating a native ISA to
  WebAssembly**. Verifiable items are elfconv (WASM I/O'24 + FOSDEM'24 talk,
  [slides](https://www.slideshare.net/slideshow/elfconv-aot-compiler-that-translates-linuxaarch64-elf-binary-to-webassemblywasm-io2024pdf/266964474)),
  [Not So Fast (USENIX ATC'19)](https://www.usenix.org/conference/atc19/presentation/jangda), and the
  structurisation papers in §6. Queries like "binary translation to WebAssembly" return tooling only.

## 6. Structured control flow recovery

| Approach | Source | Notes |
|---|---|---|
| **Relooper** | [Zakai 2012](http://mozakai.blogspot.com/2012/05/reloop-all-blocks.html) | Greedy heuristic over the CFG, falls back to a label variable. Wasm design claims "guaranteed low code size overhead, and typically minimal throughput overhead (except for pathological cases of irreducible control flow)" ([Rationale](https://github.com/WebAssembly/design/blob/main/Rationale.md)) |
| **Stackifier** | first in LLVM's wasm backend ([WebAssemblyCFGStackify.cpp](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/WebAssembly/WebAssemblyCFGStackify.cpp)); explained by [Iozzelli 2019](https://labs.leaningtech.com/blog/control-flow) ([Medium](https://medium.com/leaningtech/solving-the-structured-control-flow-problem-once-and-for-all-5123117b1ee2)) | Forward-edge targets become `block`s, loops `loop`s, flow via `br`; label variable only when needed. Used by v86 and CheerpX |
| **Beyond Relooper** | Norman Ramsey, ICFP 2022, [PDF](https://www.cs.tufts.edu/~nr/pubs/relooper.pdf), [DOI](https://dl.acm.org/doi/abs/10.1145/3547621) | Reimplements Peterson/Kasami/Tokura 1973 as one recursive pass over the dominator tree using reverse postorder; provably minimal, handles irreducible CFGs; being adopted by GHC. **Our brief's attribution (Heejin Ahn, Sam Webster, wasm CG) is wrong** — no such CG talk found, **unverified** |
| **Node splitting + dispatch loop** | common fallback | Always correct; costs an inner loop and an indirect call per block boundary |

Forward-looking: the **funclets** proposal adds `funclet_region` and branches into arbitrary
funclets, i.e. intraprocedural goto that keeps linear-time validation and fast SSA construction
([Overview](https://github.com/WebAssembly/funclets/blob/main/proposals/funclets/Overview.md),
[design#1227](https://github.com/WebAssembly/design/issues/1227)). Phase 0/1, not shippable.

Practical read: structurisation is solved for reducible CFGs, which is what compiler output is.
Real AArch64 still contains irreducible shapes (computed gotos, asm, obfuscation) and indirect
branches into the middle of regions, so robustness beats optimality.

## 7. Existing AArch64 → wasm work

It exists and it is thin — the most decision-relevant finding here.

| Project | What it is | Status / licence | Numbers |
|---|---|---|---|
| [elfconv](https://github.com/yomaytk/elfconv) (NTT Labs) | AOT: AArch64 ELF → LLVM IR (remill) → wasm (Emscripten or WASI-SDK); static syscall runtime; experimental `fork`/`execve` | Open, WIP; AArch64 only, **static binaries only, no shared objects**, partial syscalls | vs source→wasm, not vs native: sieve 82% (Emscripten) / 60% (WASI), LINPACK 78% / 56% MFLOPS, mnist 96% / 96%, i.e. 1.04x–1.8x the cost of compiling the same source straight to wasm ([README](https://github.com/yomaytk/elfconv#performance)) |
| [gex](https://github.com/HeyPuter/gex) (Puter) | AOT+JIT: AArch64/x86-64 → SSA "GIR" → wasm; tier 1 = one wasm function per basic block, `gex-fjit` = function-level JIT, `gex-cgen` = GIR→C→clang; own Linux personality in Rust/wasm; browser and wasmtime hosts | AGPL-3.0, very new (12 stars); also Windows via Wine | No benchmarks. Key idea: "guest virtual address equals linear-memory offset" because the translator is also the kernel — a guest load is a wasm load |
| [arm64-jit-vm-wasm](https://github.com/lbguilherme/arm64-jit-vm-wasm) | "translate instructions on the fly (JIT) to WebAssembly", full ARM64 OS, v86-inspired | "very early prototype … not yet functional" | none |
| [Warm64](https://warmvirtual.com/) | AArch64 system emulator in Rust+wasm, QEMU-compatible CLI, boots Linux in browser/Node | **Closed**, conditional-free + commercial | none |
| [arm64js-sdk](https://github.com/kooler/arm64js-sdk) | arm64 in wasm booting Alpine | open | none |
| [payback2-web](https://github.com/MSedgeMC/payback2-web) | AArch64→wasm with in-module block dispatcher | small project | self-reported 3,043 vs ~2M guest instr/s vs its interpreter (**unverified**) |

No open-source, JIT-quality, general-purpose AArch64→wasm translator with published performance
exists. elfconv is AOT-only with hard ABI limits; gex is the most complete design and is brand new;
the rest are prototypes.

## 8. Wasm proposals that matter

Phase from [proposals](https://github.com/WebAssembly/proposals/blob/main/README.md) and
[finished-proposals](https://github.com/WebAssembly/proposals/blob/main/finished-proposals.md);
engine support from [webassembly.org/features](https://webassembly.org/features/) (`features.json`,
read 2026-11-16; `-` = not listed).

| Feature | Status | Chrome | Firefox | Safari | Node | Wasmtime | Why it matters |
|---|---|---|---|---|---|---|---|
| Tail calls | finished, 3.0 | 112 | 121 | 18.2 | 20.0 | 22 | Indirect guest branches without growing the wasm stack |
| Memory64 | finished, 3.0 | 133 | 134 | TP 251 flag | 24.0 | 30 | 64-bit guest space without masking; Safari missing |
| Multi-memory | finished, 3.0 | 120 | 125 | - | 22.0 | 15 | Guest memory separate from scratch/shadow memories |
| Threads (atomics, SAB) | **phase 4** | 74 | 79 | 14.1 | 16.4 | 15 | Guest pthreads; needs cross-origin isolation ([MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer)) |
| Relaxed SIMD | finished, 3.0 | 114 | 145 | flag | 21.0 | 15 | NEON lane ops without exactness penalties |
| Exception handling | finished, 3.0 | 95 | 100 | 15.2 | 17.0 | - | Guest traps/signals without a check after every op |
| Stack switching | **phase 3** | flag | - | - | - | - | Cheap context switches instead of CPS |
| Shared-everything threads | **phase 1** | - | - | - | - | - | Far off |
| Custom page sizes | **phase 3** | - | - | - | - | flag | AArch64 4K/16K pages vs wasm's 64K |
| Wide arithmetic | **phase 4** | flag | flag | TP 254 | flag | flag | 128-bit mul/div, checksums, crypto |
| Branch hinting | finished, 3.0 | 137 | flag | 16 | flag | flag | Hot/cold layout of translated blocks |

A browser translator can rely on tail calls, memory64 (Chrome/Firefox only), multi-memory, relaxed
SIMD, exceptions. It cannot rely on stack switching, custom page sizes, or Safari memory64. Threads
work everywhere but force COOP/COEP on the embedding page.

## 9. Runtimes outside the browser

| Engine | Tiers | Published numbers |
|---|---|---|
| V8 | Liftoff single-pass baseline (code emitted while decoding/validating) → TurboFan ([blog](https://v8.dev/blog/liftoff)) | Liftoff compiles much faster; code quality "secondary" |
| JavaScriptCore | BBQ → OMG (B3, background, hot-patched in) | "BBQ compiles code about 4× as fast as OMG, but produces code that executes roughly 2× as slow as OMG" ([WebKit](https://webkit.org/blog/7691/webassembly/)) |
| SpiderMonkey | baseline (RabaldrMonkey) + Ion, per the Winch RFC comparison set | see next row |
| Wasmtime | Cranelift or Winch single-pass, `--compiler=winch\|cranelift` ([RFC](https://github.com/bytecodealliance/rfcs/blob/main/accepted/wasmtime-baseline-compilation.md), [docs](https://docs.wasmtime.dev/)) | baseline compilers "on average … 15x to 20x faster compilation while producing code that is on average 1.1x to 1.5x slower" |

Generated wasm vs native:
- AOT wasm vs native, SPEC CPU: "slower by an average of 45% (Firefox) to 55% (Chrome), with peak
  slowdowns of 2.08× (Firefox) and 2.5× (Chrome)"
  ([Jangda et al.](https://www.usenix.org/conference/atc19/presentation/jangda)). The earlier
  near-parity figure was measured on ~100-line kernels.
- JIT-emitted wasm running an emulated ISA: CheerpX, 2x–3x best case, 5x–10x typical (§1).
- AOT-lifted AArch64 (elfconv) vs source-compiled wasm: 1.04x–1.8x (§7). Since source→wasm is itself
  1.45x–1.55x native, a lifted AArch64 binary should land near 1.5x–2.8x native — inference, not a
  published measurement.

## What this means for us

- **Copy FEX's flag model, not box64's.** Keep condition codes as block state, propagate flag
  liveness backwards across blocks, and make laziness a per-block decision like
  `BOX64_DYNAREC_SAFEFLAGS`. AArch64→AArch64 is the easy case: 4 flags, one mapping, no PF/AF.
- **One process-wide code cache keyed by guest PC**, shared across Workers where the runtime allows.
  FEX's 30→60 FPS came from that alone. Pair it with page-granular invalidation: FEX, box64 and v86
  independently converged on write-protect-a-code-page → invalidate every block in it.
- **Neither one wasm function nor one wasm module per block.** v86 reports deep brtables with
  cross-block locals degrade badly; QEMU-wasm avoids per-TB modules for hot code because module
  counts cap out "in the thousands". Emit per translation unit, and use a `brtable` dispatcher only
  as the fallback for indirect targets.
- **Indirect branches: tail calls plus a guest-PC-keyed function table**, which is CheerpX's
  published fix for blowing the wasm stack, plus their devirtualisation of PLT-style "quasi-direct"
  jumps. Both are standard now everywhere except old Safari.
- **Ship on wasm32, design for memory64.** Memory64 shipped in Chrome 133 / Firefox 134 / Wasmtime 30
  but Safari is TP-only, and CheerpX's own data point is that allocatable memory (~4GB best case) is
  the binding constraint, not address width. Keep the address model behind one switch, and use
  "guest VA == linear offset" (gex) as the fast path when we control the loader.
- **Structurise with the LLVM stackifier or Ramsey's algorithm; always keep a dispatch-loop
  fallback.** Relooper heuristics fail on exactly the shapes emulators produce. Undiscovered code
  should land on a stub that translates on demand (gex: "discovery is never load-bearing"), never on
  a branch to nowhere.
- **AOT is the performance story.** elfconv is 1.04x–1.8x off source-compiled wasm while doing zero
  optimisation; the JIT path (CheerpX) pays 5x–10x. Order: correct AOT → hot-region JIT →
  optimisation (flags, redundancy elimination, guest registers into wasm locals).
- **What nobody has done:** no open-source, general-purpose, JIT-quality AArch64→wasm translator with
  measured performance. Unpublished anywhere: modelling AArch64 exception levels and `SVC` from
  translated code, and self-modifying guest code once a wasm module is already compiled. Those are
  the open problems.
