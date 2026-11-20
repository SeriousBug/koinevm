# armjit

An AArch64 to WebAssembly translator: takes a statically linked arm64 Linux ELF and emits a wasm
module that a host can run, with the guest's x0-x30, sp and NZCV living in wasm locals and the
browser engine acting as register allocator.

Proof of concept, not a product. See `docs/poc-results.md` for measured numbers and the list of what
it does not do, `docs/spec/BOUNDARY.md` and `docs/spec/arm64-linux-runtime.md` for the clean-room
process and the ABI contract, and `docs/prior-art.md` for the survey.

## Use

    bash tools/build-guest.sh                       # builds the guests and their native oracles
    cargo build --release
    ./target/release/armjit translate tests/guest/call.elf -o /tmp/call.wasm
    node run.mjs /tmp/call.wasm                     # prints, exits with the guest's exit code
    just console                                    # a bash prompt at this terminal

Flags: `--bounds=check|trust` (per-access address checks), `--mem-pages=N` (default 262144, i.e.
16 GiB of address space in four wasm memories of 4 GiB each), `--trace` (per-instruction pc and
register trace on a trap), `--argv=a,b`, `--env=k=v`.
`armjit dump <elf>` prints the decoded instruction stream, `ARMJIT_DUMP_REGIONS=1` prints regions and
blocks.

The guest fixtures are freestanding C built for `aarch64-unknown-linux-gnu` and linked by
`tools/minilink.py`, since this machine has no `lld`. Each is also built natively for macOS arm64 from
the same source, which is the oracle: output and exit status must match byte for byte.

MIT.
