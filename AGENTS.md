# Working on armjit

## Every AArch64 Linux program runs here unmodified

The guest is a program built for AArch64 Linux, and this VM is the CPU and the kernel it was
written for. A program that asks for something the VM cannot do is a gap in the VM, and the gap is
the work. There is no acceptable answer in which the program is asked to change.

That rules out, in particular:

- Any flag or environment that switches a feature off to get past a gap: `--jitless`,
  `--no-sparkplug`, `-Xint`, `--single-threaded`, `--no-wasm`, `UV_THREADPOOL_SIZE`, or anything
  else that trades the program's own behaviour for the VM's convenience. A program that generates
  code and runs it is expected to work here, because that is what the program does on a real
  kernel.
- Recommending a different build, a patched source, or a smaller heap as the fix.
- Writing off a missing syscall, an undeliverable signal, a page that cannot be executed, a
  virtual reservation that does not fit, or a thread that cannot be preempted as a documented
  limitation. Each of them is a defect with a cause, and it gets fixed.

So the shape of the work is: run the program, watch where it stops, and fix the VM until it runs
the way it does on Linux. When the program has a native oracle, the comparison is the test; when it
has none, the assertion is the kernel property the program depends on.

## Notes that go with that

- `docs/poc-results.md` measures the state of this, including the list of what does not work yet.
  That list is a work order, not a licence.
- New behaviour gets a test. A guest syscall's semantics belong in a property fixture under
  `tests/guest` with a `tests/<area>.sh` that requires every check in it to pass.
