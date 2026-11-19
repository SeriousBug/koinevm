# Processes, threads and signals

A process is one WebAssembly instance: its own linear memory, page table and descriptor table. A
thread is a coroutine inside that instance, with its own registers and stack, and the scheduler runs
whichever thread asks the host for nothing. Neither can be preempted: a process gives up the CPU at
a syscall, which is enough for a fork, a pipe and a wait, and is not enough for a busy loop to be
interrupted by anything but its own syscalls.

`fork` copies the memory and the state beside it; `execve` builds a new instance of a newly
translated image and keeps the descriptor table and the ids. `wait4` answers the pid and a status
word in the shape the ABI defines: an exit code in bits 8-15, or the signal in the low seven bits
when a signal is what ended the process.

## The ids

There is one user and one group in the tree, and nothing checks a permission against them. The ids
are still per process, because programs look: a package manager's download method drops to `_apt`
before it talks to the network, then reads the ids back and refuses to continue if they still say
root. The setters move them, the getters report them, `fork` copies them, and `exec` keeps them.

## Signals

`kill`, `tkill` and `tgkill` are implemented, and what a signal does is what its *target* asked for:

- a signal number of zero asks whether a process is there, and answers `ESRCH` if it is not. A
  process that has ended but has not been reaped is still there, and the signal is discarded.
- a disposition of *ignore* is nothing at all.
- a disposition of *catch* runs the guest's own handler. The signal is queued, and the handler is
  entered by writing the frame the kernel builds on the guest's stack - `siginfo`, a `ucontext` with
  the registers, sp and pc, and the FP state beside them - and starting the guest at the handler with
  the signal number, and with the `siginfo` and `ucontext` pointers when the disposition asked for
  them. The restorer in that frame calls `rt_sigreturn`, which puts the machine back where it was.
  A call that was parked when the signal arrived answers `EINTR`.
- the default action of a terminating signal ends the process, and its parent's `wait4` reports that
  signal. `SIGKILL` and `SIGSTOP` have no disposition: asking about one succeeds and setting one is
  `EINVAL`, as on Linux.
- `SIGCHLD`, `SIGURG` and `SIGWINCH` do nothing, and so do the stop signals: a coroutine cannot be
  stopped where it stands, so `SIGSTOP`, `SIGTSTP`, `SIGTTIN` and `SIGTTOU` are accepted and have no
  effect.

`rt_sigprocmask` blocks and unblocks, `sigaltstack` is remembered, and `SA_ONSTACK`, `SA_SIGINFO`
and the mask a handler runs under are honoured; a signal sent while one of the same number is
already pending is coalesced, as a kernel does everything below the realtime range. What is missing
is the point in the middle of a computation: a signal is taken at a syscall, so a guest that never
calls one keeps running, which is the poll below. A `SIGPIPE` is not raised when a guest writes to a
pipe nobody reads: the write answers `EPIPE` instead, which is what a program that had ignored
`SIGPIPE` would see. A fault cannot be caught yet either: `SIGSEGV` ends the process, because the
registers a fault would have to save are the ones the wasm call it unwinds is holding.

## Preemption

Nothing outside a running wasm function can stop it: V8's epoch interruption is not available to an
embedder that is not a browser, so a preemption point has to be in the translated code. It goes at
backward branches, which is the only place a guest can stay in one region for ever: a decrement of a
counter held in a wasm global, a branch past the rest while it is not zero, and a call into the host
at zero, where a pending signal is delivered or another coroutine is picked. Straight-line code is
finite, and a call or a return already leaves the region through the dispatcher, which is a safe
point for free.

Preempting anywhere else would mean splitting an `ldxr`/`stxr` pair or a lock acquisition from its
release, which the ABI lets a kernel do only because it can look at the instruction it interrupted.

The cost is a few instructions per taken back edge, and it is not always necessary: a loop whose
bound is provable at translation time cannot run for ever, so it can be emitted twice, once
instrumented and once not, behind a test that picks the version whose bound it established. That is
worth doing where the loop body is small enough that the poll is a measurable share of it, and it is
not written yet.

## Waiting for descriptors

`ppoll`, `pselect6` and `epoll_pwait` ask the same question - is this descriptor ready - and the
answer comes from one place, so a pipe, a file, a socket and an epoll descriptor all report
themselves the same way. `epoll` is level-triggered and reports `EPOLLERR` and `EPOLLHUP` whatever
the registration asked for; `EPOLLONESHOT` goes quiet after it has been reported, and an
edge-triggered registration is reported whenever it is ready, which is more often than the flag
promises and never less.

`struct epoll_event` here is sixteen bytes - the mask, four bytes of padding, the guest's own value -
because only x86-64 packs it. A descriptor that is closed stops being watched, whichever way it was
closed, and a descriptor that is not an epoll answers `EINVAL` where a number that names nothing
answers `EBADF`.

## The clock and the machine

`clock_gettime` reads the host's clock: `CLOCK_REALTIME` is the wall clock and moves when the machine's
does, while the monotonic clocks count from a fixed origin, so a program that measures an interval
gets one and a program that stamps a file gets a time the host would recognise. `gettimeofday` is the
same clock in the older structure; libgcrypt calls it during self-test and treats a missing number as
a fatal `BUG()`, which is why a program that looks like it never needs it still does.

`nanosleep` and `clock_nanosleep` wait on the host's timer, and one process means nothing runs while
the thread that asked is waiting: the deadline is the whole of the wait, and the answer is already
success by the time it passes. An absolute request is read against the clock it names, which is the
same clock `clock_gettime` answers for. Nothing interrupts a sleep, so the timespec a signal would
leave behind is never written.

`sysinfo` reports the memory the guest was given - its own linear memory - and nothing about the
host. A program that sizes a buffer from the free memory has to hear a number a run can back: `sort`
asked for a quarter of a machine's memory, spilled every few lines into temporary files, and its
names for them collided.

## What is not modelled

Process groups and sessions (a `kill` with a negative pid reaches every process but the caller), job
control, `ptrace`, and the rusage a `wait4` caller can ask for, which is zeroed.
