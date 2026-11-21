# KoineVM

This is a project to build an arm64/aarch64 to wasm JIT compiler plus a host environment providing Linux 
to run it in.
The goal is to run any Linux aarch64 program, unmodified.

- We never require special flags or environment variables like `--jitless`, `--no-sparkplug`, `-Xint`, `--single-threaded`, etc.
- We never require different builds or patches

When possible, run the program and watch for any warnings, crashes, or hangs.
Fix the VM until the program runs like it does on Linux, sans any performance impact.

Add tests under `tests/guest` with a `tests/<name>.sh`

