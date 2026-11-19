# A Docker-compatible runtime on this VM

Status: an idea, not a plan. Nothing here is implemented.

## The shape

Every Docker client, the `docker` CLI, compose, testcontainers, `cri-docker`, is a client of one
HTTP API spoken over `/var/run/docker.sock`. Implement the server side of that socket on top of this
VM and those clients work unmodified. A container is then a wasm instance running a guest ELF
against a rootfs directory, which is what `node run.mjs` already does.

The endpoints a first version needs: `/_ping` and `/version` (clients gate on them and on the
version they parse out), images (`POST /images/create` to pull, `GET /images/json`), containers
(`create`, `start`, `stop`, `wait`, `logs`, `exec`), and `/events`, which every client holds open.

Three parts of the API do not fit request and response:

| | |
|---|---|
| `/attach`, `/exec` | upgrade to a bidirectional stream (hijacked, or `Upgrade: tcp`), and that stream is the container's stdio |
| `/logs?follow=1`, `/events` | long-lived streams, one per client |
| `docker build` | BuildKit, a separate gRPC session, not this API. Build lands after run |

## What "all Docker images" costs

Pulling and unpacking OCI layers is mechanical. Running what is inside them is the work.

- Architecture. The translator takes AArch64 ELF. `linux/arm64` images run. `linux/amd64` images do
  not, and they are most of Docker Hub. Either a second decoder on the same host ABI, or the image's
  qemu-user running under the VM as an ordinary guest, which is slow but is one more translated
  binary instead of one more toolchain.
- Syscalls. `docs/poc-results.md` lists what exists and `docs/gaps.md` what the translator refuses.
  Missing before even a Debian entrypoint is credible: `clone` with threads at the ABI level,
  `fork` of a whole process tree, `renameat2`, `utimensat`, `prctl`, `/proc`, cgroup files that
  runtimes read, `mount` (images expect `/proc`, `/dev`, sometimes `/sys`), and a `/dev` with more
  than the console in it.
- Docker semantics the CLI notices: image IDs and digests, layer caching, `HEALTHCHECK`, restart
  policies, port publishing, volumes, a bridge that does real DNAT, `FROM scratch`, and forwarding
  `SIGTERM` on `docker stop`.
- Namespaces and capabilities are not needed. Everything is a wasm instance in a host process.

## Why the host matters

| host | why Docker is not available | what this needs |
|---|---|---|
| iOS, browser | no Linux kernel to virtualize, no privileged process | the host layer is already JS; a tab runs the instance, and "the socket" is a fetch endpoint or a service worker |
| macOS | Docker Desktop and OrbStack reserve a VM | no VM, the instance lives in the host process |
| CI, Docker-in-docker | privileged containers or a socket sidecar | the daemon is a process the build step starts |
| tighter than Docker | a second layer under a hostile image | the image's syscalls land in this VM's syscall layer, never the host's |

The isolation claim needs care: a wasm instance cannot make a syscall the host did not implement,
which is stronger than a seccomp profile only while every path stays inside the instance. Whatever
the host layer exposes, the rootfs directory, DNS, the socket itself, is attack surface.

## Moveable containers

The idea makes sense, and the reason it does not work for Docker is the reason it can work here: a
container is a live process with an fd table the kernel owns, while a VM snapshot is memory plus
device state. Here the guest's whole address space, page table included, is one linear memory, and
the other half of the state is this repo's own host code.

A snapshot has to contain:

1. Linear memory: the address space, the soft page table, heap, stack.
2. Guest registers. They live in wasm locals, and a wasm instance cannot be read from outside, so a
   paused instance does not give them up. The emitter needs a spill-to-memory safepoint, storing
   x0-x30, sp and NZCV into the shadow, which is the shape `run(entry, sp, resume)` already
   reloads from.
3. Every thread at its own safepoint, each with its own registers and guest stack.
4. Host state: the fd table, pipes, eventfds, timers, pending signals, ptys, and which translation
   modules are registered for which pages.

The quiesce point exists in a weak form already: nothing polls, and the host's event loop gets a turn
only when no thread can run and one is waiting on the network (`docs/net.md`). Migration uses the
same door: park every thread, spill, dump, send, load, resume.

What does not move:

- Sockets. A TCP connection belongs to the host that opened it. Either connections break and the
  guest sees resets on resume, which is fine for a queued job and not for a listening server, or a
  proxy holds the client connections and re-dials the instance after it lands. Userspace live
  migration does the second.
- Resources named by path: a terminal fd, a bind mount, a resolver. The snapshot carries a
  description and the destination refuses the load until it can satisfy it, rather than resuming
  into a half-open world.
- Clocks. A paused guest's monotonic clock jumps, so timers carry an offset, and a guest blocked in
  `ppoll` with 3 s left resumes with 3 s left.
- Version coupling. Module and host syscall layer must match, so a snapshot names both and the
  runtime refuses a load it cannot honour. CRIU has the same constraint.

The same snapshot format then buys `docker pause` that costs no memory, container start from a warm
snapshot, and forking a running container in two.

## The cheap experiment

Before any Docker surface: add a flag to `run.mjs` that parks every thread, dumps linear memory and
the shadow to a file and exits, and a flag that loads one back. Try it on a guest holding a pipe and
an eventfd open, in both address-check modes. If that round-trips, migration becomes a question of
host state and connections. If the translation modules turn out to be per-instance and not
reloadable at their original addresses, that is the blocker to find first, and it is findable in a
day.

## Open questions

- One wasm instance per container, or one host process holding many? The first is the isolation
  story, the second is what lets the fd table and the scheduler be shared.
- Does a container need a real IP for the first version, or is `--network=host` plus a proxy enough
  to be useful?
- Is amd64 worth a second decoder, or does qemu-user inside the VM carry the compatibility claim?
