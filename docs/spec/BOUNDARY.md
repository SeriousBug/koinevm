# Clean-room boundary

Agreed 2026-11-16, before anything of the original was read.

## What is being rebuilt, and how much of it

One capability, as a PoC: take a statically linked AArch64 Linux ELF that writes to stdout and
exits, and run it in a wasm runtime from our own implementation.

Cast and wall:

| Role | Who | May see |
|---|---|---|
| Reader | agent `reader-gex` | the original (source, docs, CLI behaviour), and the authoritative ABI documents |
| Implementer | this chat | the spec only, and the user's answers |
| Gate | the user | the spec, and both of the above |

The only channel between reader and implementer is `docs/spec/arm64-linux-runtime.md`. The
implementer never opens the original's source, symbols, assets or names, and never asks the reader
for code. Where the spec turns out to be silent or ambiguous, the implementer asks the user, not the
reader.

## What the original is, and our rights over it

The original studied is HeyPuter/gex, published under AGPL-3.0, so studying it is licensed. This is
an **independent implementation of a documented ABI** (the Linux AArch64 userspace contract), with
that project as the thing studied rather than ported. The PoC reuses none of its expression: not its
code, its translation IR, its crate or symbol names, its wasm ABI, its assets or its text. Clean room
is a claim about process; the premise is that the ABI we implement is public and documented, which it
is. This is not a clone for resale, and not licence, DRM or paywall defeat.

Licence of the result: MIT (see `LICENSE`).

## Must match exactly

- bytes written to stdout, in order, and nothing else on stdout
- exit code, via `exit` and `exit_group`
- initial guest state as the ABI defines it: `sp` points at `argc`, `argv[]` and `envp[]` are
  NULL-terminated, page size reads 4096, `x0` content unspecified
- the syscall numbers, argument registers and return convention for the syscalls in scope, including
  errors returned as `-errno` in `x0`

## May differ

- performance, module layout, internal ABI, tiering, file and function layout, diagnostics, tooling
- the syscalls listed as out of scope may fail with `-ENOSYS` where the original does something else
- the original may support more than the PoC; that is expected and is not a compatibility failure

## Must not be touched

- the original's source, identifiers, crate names, IR, wasm ABI, doc text or assets
- any expression carried over from an AGPL implementation

## Out of scope for the PoC, each with its reason

| Left out | Why |
|---|---|
| dynamic linking / `ld.so` | needs `mmap`, `mprotect` and relocation processing; next milestone |
| TLS / `TPIDR_EL0` | only glibc needs it, and glibc needs `ld.so` |
| signals | needs wasm exception handling wired to guest `sigaction` |
| threads | needs `SharedArrayBuffer` and cross-origin isolation |
| self-modifying code | needs page-granular translation invalidation |
| file I/O beyond stdout/stderr | needs the block device |
| FP and NEON | integer subset only for the first slice |
| `fork`/`exec` | needs a process model; single process only |

## The spec

`docs/spec/arm64-linux-runtime.md`, written by the reader in the language of behaviour: inputs,
outputs, side effects, state, numbers and error cases. No source, no identifiers, no pseudocode.
Where a fact comes from the public ABI rather than from the original, it is cited.

The user approves the spec. That approval opens the clean room and nothing is implemented before it.
