# Translate the guest and run it at this terminal.
#
# `just console` is a bash prompt at the terminal it was started from, `just console /bin/dash -i` is
# another shell there, and `just console /usr/bin/apt-get install hello` is one command. The host puts
# the terminal in raw mode for the whole session, so `exit` or `Ctrl-D` gives it back. A trace is set
# on the environment before `just`: `ARMJIT_TRACE_PROCESSES=1 just console`.

build:
    cargo build --release

console prog='/bin/bash' *args='-i': build
    ARMJIT_CONSOLE=1 tools/run-rootfs.sh {{prog}} {{args}}
