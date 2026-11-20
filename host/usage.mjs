// The CPU a process has used, in nanoseconds, split the way a kernel splits it: `user` is the
// guest's own translated code and `sys` is what this kernel does for it inside a syscall. Time that
// is neither - a page being translated, a module being compiled - is charged to nothing, because a
// guest that runs the same program natively never pays for it, and the clock simply jumps as it
// would on a machine that was suspended.
//
// The clock is the one `clock_gettime` answers with, so a program that measures itself sees one
// timebase. A run is CPU bound while it is inside the wasm, and a wait returns from the module and
// is measured nowhere: `real` then exceeds the two together, as it does natively.

const NS = 1_000_000;

export class Usage {
  constructor() {
    this.user = 0n;
    this.sys = 0n;
    /// `RUSAGE_CHILDREN`: what children that were waited for have used, their own children included.
    this.childUser = 0n;
    this.childSys = 0n;
    /// The counters of the thread whose registers are live, so `RUSAGE_THREAD` answers with its own.
    this.thread = null;
    /// Wall clock the guest is not charged for, and how deep the suspension is.
    this.suspended = 0;
    this.suspending = 0;
    /// The run that has not returned yet. A guest checks its own counters from inside one, and what
    /// it did in that run so far has to be charged before the answer is built, or it reads a stale
    /// number: a program that measures itself would see nothing until it stopped measuring.
    this.running = null;
  }

  now() {
    return performance.now();
  }

  /// A reading of the clock and of the counters at that instant: a charge is a pair of readings, and
  /// what costs one is a syscall or a run, both rare enough for the reading to be free.
  mark() {
    return { at: this.now(), sys: this.sys, suspended: this.suspended };
  }

  /// The nanoseconds since `mark`, without the part the guest does not pay for.
  since(mark) {
    const ns = Math.round((this.now() - mark.at - (this.suspended - mark.suspended)) * NS);
    return ns > 0 ? BigInt(ns) : 0n;
  }

  spend(user, sys) {
    this.user += user;
    this.sys += sys;
    if (this.thread) {
      this.thread.user += user;
      this.thread.sys += sys;
    }
  }

  /// What the kernel did for the guest since `mark`: the part of a syscall that belongs to `sys`.
  charge(mark) {
    this.spend(0n, this.since(mark));
  }

  /// What the guest's own code did since `mark`: a run, less the syscalls charged inside it.
  chargeRun(mark) {
    const ns = this.since(mark) - (this.sys - mark.sys);
    if (ns > 0n) this.spend(ns, 0n);
  }

  /// One entry into the guest, charged to its user time whatever the body answers or throws.
  run(body) {
    const mark = this.mark();
    const outer = this.running;
    this.running = mark;
    try {
      return body();
    } finally {
      // A `flush` inside the run moved the mark forward and charged the part before it, so what is
      // left to charge is what has happened since, not the whole run again.
      const pending = this.running;
      this.running = outer;
      this.chargeRun(pending);
    }
  }

  /// Charge the part of the current run that has happened, and start the rest of it from now. A
  /// syscall that answers with these counters calls this first, so its answer is not stale.
  flush() {
    if (!this.running) return;
    const mark = this.running;
    this.chargeRun(mark);
    this.running = this.mark();
  }

  /// Work the guest does not pay for. A charge that encloses it loses exactly its duration, and one
  /// that starts and ends inside it charges nothing at all.
  suspend(body) {
    const at = this.now();
    this.suspending++;
    const done = () => {
      this.suspending--;
      this.suspended += this.now() - at;
    };
    let answer;
    try {
      answer = body();
    } catch (e) {
      done();
      throw e;
    }
    if (answer && typeof answer.then === "function") return answer.finally(done);
    done();
    return answer;
  }

  /// The tick count `times` returns, off the same clock the counters come from.
  ticksNow() {
    return BigInt(Math.round(this.now() * NS)) / 10_000_000n;
  }
}

/// CPU time in the unit `times(2)` reports: `clock_t` ticks of USER_HZ, which the ABI fixes at 100
/// per second whatever the kernel's own tick rate is. A native kernel divides its nanoseconds by the
/// same 10 000 000, so its counters only move in these steps too.
export function ticks(ns) {
  return ns / 10_000_000n;
}

/// The `struct rusage` a guest reads: two `timeval`s and fourteen counters, of which only these two
/// have anything behind them here. A caller that asks for `ru_maxrss` or the fault counts is told
/// zero, which is what a process that never faulted would be told.
export function rusageBytes(user, sys) {
  const bytes = Buffer.alloc(144);
  const timeval = (at, ns) => {
    bytes.writeBigInt64LE(ns / 1_000_000_000n, at);
    bytes.writeBigInt64LE((ns % 1_000_000_000n) / 1000n, at + 8);
  };
  timeval(0, user);
  timeval(16, sys);
  return bytes;
}

/// The `struct tms` a `times` caller reads: four tick counts, the last two cumulative over the
/// children, as a kernel's are.
export function tmsBytes(usage) {
  const bytes = Buffer.alloc(32);
  bytes.writeBigInt64LE(ticks(usage.user), 0);
  bytes.writeBigInt64LE(ticks(usage.sys), 8);
  bytes.writeBigInt64LE(ticks(usage.childUser), 16);
  bytes.writeBigInt64LE(ticks(usage.childSys), 24);
  return bytes;
}
