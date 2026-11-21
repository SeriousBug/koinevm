# KoineVM

An AArch64 to WebAssembly JIT compiler plus a host environment to emulate a Linux kernel.

# How to use

    bash tools/build-guest.sh # Guest image based on Debian Docker container
    cargo build --release
    just console              # Launch bash inside VM

## Flags

- `--bounds` with `check` or `trust`
- `--mem-limit` with unit like `4GB` or `8GiB`
- `--trace` for per-instruction pc and register trace on a trap
- `--argv`, `--env`

`koinevm dump <elf>` prints the decoded instruction stream, `KOINEVM_DUMP_REGIONS=1` prints regions and
blocks.

The guest fixtures are freestanding C built for `aarch64-unknown-linux-gnu` and linked by
`tools/minilink.py`, since this machine has no `lld`. Each is also built natively for macOS arm64 from
the same source, which is the oracle: output and exit status must match byte for byte.

MIT.
