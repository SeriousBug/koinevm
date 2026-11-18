# Running a static AArch64 Linux ELF in wasm

Scope: one statically linked AArch64 Linux ELF, integer instructions only, one process, no threads, no signals, no dynamic linking. Target: bytes on stdout and an exit code, as a real kernel produces them. Tags: **(a)** the ABI any implementation must match, **(b)** one implementation's choice we need not copy, **(c)** unknown or unverified.

## 1. Process start

**(a)** At the first instruction only two things are defined: `pc` is the ELF entry, and `sp`. `x0`–`x30` are unspecified; a program that reads them before writing them is entitled to garbage. `sp` is 16-byte aligned and points at this block, all fields 8 bytes:

```
sp + 0   argc (u64)
sp + 8   argv[0..argc-1], then 0
         envp[0..n-1], then 0
         auxv: (type, value) pairs, terminated by (0, 0)
```
Strings for argv, envp, the platform name and a 16-byte random blob sit above the vectors, and the auxv values are addresses of those bytes. The auxv starts right after the second NULL, so every field stays 8-byte aligned. [S1]

**(a)** Auxv entries a static program reads, with the values it must see: `AT_PHDR 3` (address of the program header table in memory), `AT_PHENT 4` (=56), `AT_PHNUM 5`, `AT_PAGESZ 6` (=4096), `AT_BASE 7` (=0 when static), `AT_ENTRY 9`, `AT_UID 11`, `AT_EUID 12`, `AT_GID 13`, `AT_EGID 14`, `AT_HWCAP 16`, `AT_SECURE 23` (=0), `AT_RANDOM 25` (16 readable bytes), `AT_EXECFN 31`, `AT_NULL 0`. The musl startup path is the evidence: it walks `AT_PHDR`/`AT_PHNUM`/`AT_PHENT` first to find the TLS segment, takes the page size from `AT_PAGESZ`, the stack canary from `AT_RANDOM`, and takes a different (fatal) path unless `AT_UID==AT_EUID && AT_GID==AT_EGID && AT_SECURE==0`. It also **writes** the auxv in place, so it must be writable, which it is on the stack. [S8]

**(a)** `AT_HWCAP` bits: FP `1<<0`, ASIMD `1<<1`, ATOMICS `1<<8`, CPUID `1<<11` [S3]. Advertise only what is implemented: for an integer-only slice 0 is honest, since claiming ASIMD invites vector code and a trap on the first vector instruction is then our bug, not the program's.

**(a)** Before the first instruction memory must already hold every `PT_LOAD` at its address, the program header table readable at `AT_PHDR` (at `p_vaddr - p_offset + e_phoff` of the segment containing it, which for a normal binary is the first segment), the stack block, and the strings and blob it points at.

**(b)** All general registers zeroed, `x0` = 0; fixed `AT_RANDOM` bytes so runs reproduce; the stack top placed well below the top of the address space so the memory is not allocated up to it. **(c)** Whether a given kernel zeroes registers at exec, and which of `AT_ENTRY`/`AT_BASE` a given binary consults, are unverified.

## 2. Image loading

**(a)** ELF64, little-endian, `e_machine` 183, `e_type` `ET_EXEC`. Every `PT_LOAD` is mapped at its `p_vaddr` with no bias: a static non-PIE image is placed where it was linked. Bytes `[p_offset, p_offset+p_filesz)` are copied to `p_vaddr`, `[p_filesz, p_memsz)` reads as zero (`.bss`), and `p_memsz >= p_filesz`. Permissions come from `p_flags` (`R`=4, `W`=2, `X`=1). [S10]

**(a)** Alignment: mapping boundaries round to 4096, and the ABI requires `p_vaddr ≡ p_offset (mod p_align)`, so page-granular placement works only when that congruence holds at 4096. AArch64 toolchains usually use `p_align` 0x10000 and link text near 0x200000 or 0x400000, which is fine. `e_entry` and each `p_vaddr` must be exactly what the file says; nothing is relocated.

**(a)** May be ignored: section headers, symbol tables, debug sections, `PT_NOTE`, `PT_GNU_EH_FRAME` (until unwinding exists), `PT_GNU_RELRO` (its protection is an `mprotect`, not loading), `PT_GNU_STACK` (only a size hint), `PT_PHDR` (reachable through `AT_PHDR`). Must be kept: the segment bytes including the program headers, `e_entry`, `p_flags`, `p_memsz`.

**(a)** Refuse, with a diagnostic and no execution: not ELF, not 64-bit, not little-endian, not AArch64, no `PT_LOAD`, no executable segment, a segment past the addressable range, two images overlapping, or a `PT_INTERP` (dynamic, out of scope). The initial break is the page-aligned end of the highest `PT_LOAD`, and must be readable, writable and zero before the first `brk`, because libc's allocator starts there.

## 3. The syscall boundary

**(a)** The guest puts the number in `x8`, up to six arguments in `x0`–`x5`, and executes `svc #0` (word `0xD4000001`). The result is in `x0`. Failure is a negative errno in `x0` and never a separate channel: any value in `[-4095, -1]` means the call failed with that error. Every other register and the flags are unchanged, memory effects are visible, and execution resumes at `svc` address + 4. [S5]

**(b)** A translated `svc` ends its translation unit and hands the host the register file and the `svc`'s address. The host must place the result in `x0`, leave every other register and flag as it was, and return. Nothing on the guest stack is touched, so the register file is all the state that needs saving around the call.

Numbers verified against the generic table [S5], structures against [S6] [S7], error cases against [S9].

| nr | name | args | returns | errors |
|---|---|---|---|---|
| 64 | write | (fd, buf, count) | bytes written | EBADF, EFAULT, EPIPE; count is clamped to 0x7ffff000 |
| 66 | writev | (fd, iovec*, iovcnt) | bytes written | EINVAL (iovcnt > 1024, length overflow), EBADF, EFAULT |
| 63 | read | (fd, buf, count) | bytes read, 0 = EOF | EBADF, EFAULT, EAGAIN |
| 93 | exit | (status) | does not return | none |
| 94 | exit_group | (status) | does not return | none |
| 222 | mmap | (addr, len, prot, flags, fd, offset) | address | EINVAL, ENOMEM, EEXIST |
| 215 | munmap | (addr, len) | 0 | EINVAL |
| 226 | mprotect | (addr, len, prot) | 0 | EINVAL, ENOMEM, EACCES |
| 214 | brk | (addr) | the resulting break | none reaches the guest |
| 216 | mremap | (addr, oldlen, newlen, flags, newaddr) | address | EINVAL, ENOMEM |
| 80 | fstat | (fd, buf) | 0 | EBADF, EFAULT |
| 79 | newfstatat | (dirfd, path, buf, flags) | 0 | EBADF, ENOENT, EFAULT, ENOTDIR |
| 278 | getrandom | (buf, len, flags) | bytes written | EAGAIN, EINVAL, EFAULT |
| 160 | uname | (buf) | 0 | EFAULT |
| 113 | clock_gettime | (clockid, timespec*) | 0 | EINVAL, EFAULT |
| 123 | sched_getaffinity | (pid, len, mask*) | bytes written | EINVAL, ESRCH |
| 96 | set_tid_address | (int *tidptr) | the caller's tid | none |
| 99 | set_robust_list | (head*, len) | 0 | EINVAL |
| 134 | rt_sigaction | (signo, act*, oldact*, sigsetsize) | 0 | EINVAL, EFAULT |
| 98 | futex | (uaddr, op, val, timeout, uaddr2, val3) | op-dependent | EAGAIN, EINTR, ETIMEDOUT, ENOSYS |

Non-obvious semantics:

- `exit` ends the calling thread, `exit_group` all threads; with one thread they are identical, and the low 8 bits of the status become the exit status. Neither returns: the run ends and the host reports it.
- `mmap`'s `offset` is in **bytes** on AArch64 (not pages, as 32-bit `mmap2` takes it), `len` rounds up to a page, and `addr` is a hint unless `MAP_FIXED` (0x10): `MAP_PRIVATE` 0x02, `MAP_ANONYMOUS` 0x20, `MAP_FIXED_NOREPLACE` 0x100000. `len` 0 is `EINVAL`. The kernel returns the address; libc turns `-errno` into `MAP_FAILED`.
- `munmap` rounds `len` up, requires a page-aligned `addr`, and succeeds on an unmapped range. Partial unmap is legal.
- `mprotect` requires a page-aligned `addr` and fails with `ENOMEM` if any page in the range is unmapped. `PROT_NONE` is 0.
- `mremap` grows a mapping in place when the pages after it are free, and otherwise moves it: `MREMAP_MAYMOVE` 1 and `MREMAP_FIXED` 2, with 4 the flag that asks for the move. `oldlen` and `newlen` round up to pages, the answered address is the mapping's own, and the bytes the old range held are the bytes the new one holds.
- `brk` returns the break the kernel now holds, not a status, and on failure returns the unchanged break, so the caller compares the answer with the request. It never reports an error, and the reservation behind it is page-granular, so the value need not match the pages it covers [S9].
- `fstat` fills 128 bytes: dev 0, ino 8, mode 16 (u32), nlink 20, uid 24, gid 28, rdev 32, pad 40, size 48, blksize 56 (u32), pad 60, blocks 64, atime 72, atime_nsec 80, mtime 88, mtime_nsec 96, ctime 104, ctime_nsec 112, unused 120 and 124 [S6]. There is no `stat` number on AArch64: libc builds `stat` from `newfstatat`.
- `getrandom` writes at most 32 MiB per call; flags are `GRND_NONBLOCK` 1, `GRND_RANDOM` 2, `GRND_INSECURE` 4.
- `uname` fills six 65-byte NUL-padded arrays (390 bytes): sysname, nodename, release, version, machine, domainname. `machine` must read `aarch64`.
- `clock_gettime` writes `{i64 sec, i64 nsec}` with `nsec < 1e9`; REALTIME 0, MONOTONIC 1, PROCESS_CPUTIME 2, THREAD_CPUTIME 3, BOOTTIME 7.
- `sched_getaffinity` returns **the number of bytes written**, not 0, and fails with `EINVAL` when the buffer is smaller than the kernel's CPU mask. Truthfulness about CPUs is optional here; size is not.
- `set_tid_address` returns the caller's tid, positive, and always succeeds.
- `set_robust_list` fails with `EINVAL` unless `len` is exactly 24 on a 64-bit guest.
- `rt_sigaction`'s fourth argument is the sigset size and must be 8 here, else `EINVAL`; the structure is 32 bytes with handler 0, flags 8, restorer 16, mask 24; `SIGKILL`/`SIGSTOP` are `EINVAL` [S7].
- `futex`'s op is a command plus flags: `WAIT` 0, `WAKE` 1, `PRIVATE_FLAG` 128, `CLOCK_REALTIME` 256. `WAIT` returns 0 on a wake, `EAGAIN` when the word already differs from `val`, `ETIMEDOUT`, `EINTR`; `WAKE` returns how many waiters it woke, so 0 when there are none; `WAIT`'s timeout is relative.
- An unknown number answers `-ENOSYS`. Trapping on it turns a compatibility gap into a crash.

What a static hello-world touches: a hand-written entry uses `write` (64) and `exit_group` (94) and nothing else. A musl static binary uses `set_tid_address` (96) during thread-pointer setup, then **`writev` (66)** rather than `write`, because musl's stdio flushes through a vector write, then `exit_group` (94); it also executes a system-register write to `TPIDR_EL0` (an instruction, not a syscall) and treats failure as fatal; `mmap` appears only if its TLS block exceeds the libc's built-in buffer, which for a small program it does not [S8] **(c)** read from the libc, not traced. glibc static touches many more at startup (break, protection, robust list, restartable sequences, limits, randomness) and is out of scope; **(c)** not enumerated.

## 4. Memory model

**(b)** The simplest correct rule is that a guest virtual address *is* the offset in linear memory: a guest load becomes one host load with the guest address in the immediate, the memory's own bounds check is the guard, and no address arithmetic happens per access.

**(a)** The ceiling is 65536 pages, 4 GiB [S11]. Two consequences. Any address ≥ 2^32 must lose bits to become an index, so it aliases: 0x1_0000_0000 becomes 0, 0xFFFF_FFFF_F000 becomes 0xFFFF_F000. And a guest cannot have both a mapping at the top of its 32-bit range and the full 4 GiB. An implementation must choose: reserve the top page (memory of 0xFFFF_0000 bytes) so that anything steered to the highest address traps; check each computed address against the limit before the access; or accept silent aliasing. Only the first keeps a wild 64-bit pointer off low memory.

**(a)** Where truncation can alias silently, and so where a check is needed if fidelity is wanted: a 64-bit `add`/`sub` whose result leaves `[0, 2^32)`; a 32-bit load of a size or offset added to a base; and an effective address of base + immediate folded into the access, where the guard must cover base + offset, not base alone.

**(a)** Unmapped addresses cannot be detected inside a flat memory: wasm knows only where its memory ends. A wild pointer into a hole is not a fault; it reads zeroes or stale bytes and writes land. That is a deviation from Linux and must be stated as one. What must still hold: memory the guest was told is its own reads as zero (bss, fresh break, anonymous mappings); a page unmapped and mapped again reads zero, not its old contents; guest writes cannot reach the implementation's own bookkeeping, which must sit where no guest address names it; and the set of nameable addresses is fixed and documented.

**(a)** The stack: `sp` at entry lies in a mapped writable region and holds the block from section 1. Linux grows the stack on fault up to a limit; a flat memory does not, so an implementation chooses between checking `sp` at unit boundaries and reporting an overflow, or letting an overrun silently corrupt what lies below. Two ABI rules are hard regardless: keep `sp` 16-byte aligned at every public interface, and never let the image or a mapping overlap the stack region. **(c)** What an overrun looks like to the guest when signals are out of scope is a product decision, not an ABI fact.

**(a)** The ceiling also forces a fixed layout with no address randomisation (there is no room to spread mappings over the real 2^47 user range), an arena for `mmap` that the implementation chooses and enforces, and an answer for programs that need more than 4 GiB, which is wasm's 64-bit memory, a different feature set that not every engine offers.

## 5. Code translation and dispatch

A translation unit is a maximal straight run of instructions with one entry and one exit, the exit being a terminator: direct branch, indirect branch, call, return, syscall, or an instruction the implementation refuses. Units are cut by the decoder, not by the binary's symbols, and a unit is identified by the address of its first instruction.

A direct branch to a translated unit transfers control without re-entering the dispatcher; to an untranslated address it takes the same path an indirect branch does. An indirect branch's target exists only at run time, so some total map from address to code is needed, with slot granularity (per instruction, per 4 bytes, per page) traded against table size, and a defined answer for a target that is unmapped, mapped but not yet translated, or not decodable. The last two must be distinguishable, or "not found" cannot be told from "illegal".

Reaching an untranslated address means translating it and retrying the transfer. The retry must not repeat work: everything the unit did before the branch is already committed, so the transfer must be the unit's last action and the retry starts at the target, not at the branch.

A call has `x30` holding the return address and the guest's own stack holding its frames. Two constructions are legal and differ observably. A host call per guest call keeps host stack depth equal to guest call depth, so deep guest recursion fails at a host-dependent depth where Linux would deliver a stack fault. A guest-side push plus dispatch through the indirect path keeps host depth constant and fails only where the guest stack does. The tradeoff, not an implementation detail.

Other tradeoffs to record: translating more ahead of time means fewer run-time misses, but a pre-pass that follows every aligned word pointing into executable memory also translates data as code, so the decoder must survive garbage; per-page indirection keeps tables proportional to mapped code but costs a dependent load per indirect branch; one host function per unit keeps the mapping simple but charges a host frame per guest frame on call-heavy programs.

The other project, for contrast: it translates basic blocks, one host function each, ahead of time from the entry point, from function symbols, from direct branch targets and from whole words anywhere in the image that point into executable memory; anything it missed is translated on the first indirect branch reaching it, so a wrong discovery guess costs time and never a wrong branch. It has two further tiers, one turning a recovered guest function into a host function and one compiling it ahead of time, and it splits dispatch into per-page directories pointing into several fixed-size function tables. Our slice needs one tier and one table.

## 6. What the other project does not do, or does differently

- An unknown syscall number answers `-ENOSYS` and is recorded; restartable sequences answer `ENOSYS` deliberately.
- Refused images: not ELF, not 64-bit little-endian, wrong machine, no loadable segment, no executable segment, a segment outside its address space, two images overlapping, an interpreter it cannot load, and a fixed-address image whose segments land in its own low bookkeeping region (it keeps tables below about 0x30_0000, so a non-PIE binary linked there is refused rather than loaded over them).
- Memory is one page short of 4 GiB so that a wild 32-bit-overflowing address traps; a process needing more address space moves to a 64-bit memory of 16 GiB, a different wasm feature set; one function table is capped at ten million entries by V8, so it uses eight tables.
- Protection is bookkeeping only: `PROT_NONE`, writing to code, and executing data do not fault, because wasm has no per-page permissions. **(c)** An access into an in-bounds hole: by design it cannot fault, but I did not observe it.
- Its auxv random blob is a fixed constant, so canaries and hash seeds repeat across runs. Deliberate reproducibility, at the cost of every run being identical.
- Beyond our slice it supports or claims threads, `fork`, `exec`, signals, glibc with a dynamic loader, thread-local storage, self-modifying code with page-granular invalidation, floating point and vector code, and a graphics stack. Each is a separate milestone for us.
- Guest programs known to fail: not enumerated in anything public; its behavioural test suite is the only evidence and it is not in the public tree. **(c)**

## 7. Minimum viable slice

| syscall | needed by | status |
|---|---|---|
| 64 write | assembly entry, or libc with stdio bypassed | load-bearing |
| 66 writev | any libc's buffered stdout (musl flushes with it) | load-bearing unless the binary avoids stdio |
| 94 exit_group (and 93 exit) | every C runtime | load-bearing |
| 96 set_tid_address | libc thread-pointer setup | load-bearing for a libc-built binary |
| 222 mmap | libc TLS block exceeding the built-in buffer | have it ready; it is one allocator |
| 80 fstat, 79 newfstatat | stdio asking whether a descriptor is a file | incidental, cheap, common |
| 113 clock_gettime, 278 getrandom, 160 uname | not touched by a hello | omit; answer `-ENOSYS` if reached |

Plus one instruction that is not a syscall: the system-register write to `TPIDR_EL0`, which libc performs unconditionally and treats as fatal if it fails. Accept it, keep the value, answer reads with it.

Instruction classes. L = load-bearing, I = emitted incidentally and needed only when it appears. Constant and address materialisation: L `movz`, `movk`, `movn`, `mov`; L `adrp` with `add` immediate, which is how a string address is formed. Arithmetic: L `add`/`sub` immediate and shifted register; L `adds`/`subs` and so `cmp`, `cmn`, `tst`; I `madd`, `msub`, `mul`, `sdiv`, `udiv`, `csel`, `csinc`, `csneg`, `ccmp`, `cset`. Logic and shifts: L `and`, `orr`, `eor`; L `lsl`/`lsr`/`asr` immediate and register; I `ubfm`, `sbfm`, `bfm`, `clz`, `rbit`, `rev`. Extension: L `sxtw`, `uxtw`, `sxtb`, `sxth`, `uxtb`, `uxth`, for the 32/64 mixing of sizes and offsets. Memory: L `ldr`/`str` 32- and 64-bit, unsigned-offset, unscaled and register-offset forms; L `ldrb`/`strb`, `ldrh`/`strh`; L `ldp`/`stp` for prologue, epilogue and filling the initial stack; L pre- and post-index addressing, which a libc's push/pop uses; I `ldr` literal. Control: L `b`, `b.cond`, `cbz`/`cbnz`, `ret`; L `bl` if the binary calls anything; L `blr` for indirect calls; I `br`, `tbz`/`tbnz`. Boundary and padding: L `svc #0`; I `nop`, `hint`, `brk`. Floating point and vector are not in the slice, though a compiler emits them incidentally (auto-vectorised memory moves, floating point in a `printf` of a float): build the reference binary so it cannot, or expect a trap at the first such instruction.

Semantics that are load-bearing and easy to get wrong: bit 4 of the encoding of register 31 selects `sp` or the zero register, and getting it backwards corrupts the stack; `sp` stays 16-byte aligned across every call; a `w`-width operation zeroes the upper 32 bits of its destination; loads and stores are little-endian, and unaligned accesses must either be allowed or trapped, decided once.

## Open questions for the user

1. Which binary is the reference: a hand-written assembly entry (two syscalls, auxv nearly irrelevant) or a libc-built static binary (also `writev`, `set_tid_address`, `TPIDR_EL0`, and auxv entries that must be exactly right)? Which libc, which compiler, and does the build forbid floating point and vector instructions?
2. Is a wild access into an in-bounds hole acceptable as "no fault", or must every access be checked? The first is faster and documents a deviation; the second is closer to Linux and costs a comparison per access.
3. Stack overflow with signals out of scope: trap on an `sp` check at unit boundaries, let it corrupt memory, or end the run with an error, and what does the host report?
4. Reserve the top page so a 32-bit address overflow traps, or take the whole 4 GiB and accept that such addresses alias low memory?
5. One fixed layout must be chosen and written down: image at its link address, break above it, stack below the used range, arena for `mmap`. It need not be the other project's, but it must be fixed, since 4 GiB leaves no room for address randomisation.

## Sources

[S1] `create_elf_tables`, initial stack and auxv: https://raw.githubusercontent.com/torvalds/linux/master/fs/binfmt_elf.c
[S2] `start_thread`, AArch64 entry state: https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/kernel/process.c
[S3] AArch64 HWCAP bits: https://www.kernel.org/doc/html/latest/arch/arm64/elf_hwcaps.html
[S4] AArch64 boot ABI, kernel entry not userspace: https://www.kernel.org/doc/html/latest/arch/arm64/booting.html
[S5] syscall numbers: https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/unistd.h
[S6] `struct stat`: https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/stat.h
[S7] `struct sigaction`, sigset size, `SA_RESTORER`: https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/include/uapi/asm/signal.h
[S8] musl startup, thread pointer, stdio: https://git.musl-libc.org/cgit/musl/plain/src/env/__libc_start_main.c , https://git.musl-libc.org/cgit/musl/plain/src/env/__init_tls.c , https://git.musl-libc.org/cgit/musl/plain/src/thread/aarch64/__set_thread_area.c , https://git.musl-libc.org/cgit/musl/plain/src/stdio/__stdio_write.c
[S9] per-syscall conventions: https://man7.org/linux/man-pages/man2/mmap.2.html , https://man7.org/linux/man-pages/man2/brk.2.html , https://man7.org/linux/man-pages/man2/futex.2.html , https://man7.org/linux/man-pages/man2/getrandom.2.html , https://man7.org/linux/man-pages/man2/sched_getaffinity.2.html , https://man7.org/linux/man-pages/man2/rt_sigaction.2.html , https://man7.org/linux/man-pages/man3/set_robust_list.3.html
[S10] AArch64 ELF ABI: https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
[S11] wasm limits and memory: https://webassembly.github.io/spec/core/syntax/types.html#limits
