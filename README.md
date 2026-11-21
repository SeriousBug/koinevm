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

Open source, MIT license.

