// The process table, and the scheduling that lets one wasm call express a fork.
//
// A guest process is one WebAssembly instance with its own linear memory, so `fork` is a copy of
// that memory plus the state the kernel keeps beside it, and `execve` is a new instance of a newly
// translated image in the same process. Neither can finish inside the syscall import: the import
// runs inside the guest's own wasm call and cannot wait for another process to run. So a syscall
// that needs the host returns to the host instead, the host does the work and resumes the process
// with x0 as the answer, and the scheduler runs whichever process is unimpeded next.
//
// This is cooperative, which a real kernel's fork is not: a process only gives up the CPU at a
// syscall. A guest that blocks on a pipe its child has yet to write is therefore fine as long as
// the child can run, and a deadlock is reported as one instead of hanging.

import fs from "node:fs";
import { Kernel, ECHILD, EBADF, EFAULT, ESRCH, EINTR } from "./syscall.mjs";
import { WOULD_BLOCK, ENOENT, EACCES, ELOOP } from "./files.mjs";
import { Net, EAGAIN } from "./net.mjs";
import { Resolver } from "./dns.mjs";
import { Mach } from "./pages.mjs";
import { PTE } from "./addressspace.mjs";
import { SIGFRAME, SA_ONSTACK, SA_SIGINFO, SA_RESTORER, SI_USER, SS_DISABLE } from "./syscall.mjs";

const SHADOW = 0x0;
const SHADOW_PC = 0x108;
const SHADOW_RESUME = 0x118;
const SHADOW_TP = 0x110;
/// The part of the control block a thread owns: x0..x30, sp, nzcv, pc, tls and the resume address.
const THREAD_STATE = 0x118 + 8;
const SHADOW_V0 = 0x600;
const NVEC = 32;

const CLONE_VFORK = 0x4000;
const CLONE_SETTLS = 0x00080000;
const CLONE_PARENT_SETTID = 0x00100000;
const CLONE_CHILD_CLEARTID = 0x00200000;
const CLONE_CHILD_SETTID = 0x01000000;
const WNOHANG = 1;
const ENOEXEC = 8;

/// The signals whose default action is to end the process. The rest either do nothing - SIGCHLD,
/// SIGURG, SIGWINCH - or stop it, which a coroutine has no way to be.
const FATAL = new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 25, 26, 31]);
for (let sig = 32; sig <= 64; sig++) FATAL.add(sig);

/// Where a handler returns to when its disposition names no restorer. An aarch64 kernel puts its
/// own trampoline at the end of every handler - the one in the vDSO - and a real libc leaves
/// `sa_restorer` empty because it expects it there. This address is no image's code: the run
/// recognises it and puts back the frame the signal left, which is what the trampoline asks for.
/// It sits below the arena's first byte, where neither the heap nor a mapping can reach.
const SIGTRAMP = 0x3ffff000;

export class Session {
  constructor({ translator, rootfs, makeImports }) {
    this.translator = translator;
    this.rootfs = rootfs;
    this.makeImports = makeImports;
    this.processes = [];
    /// Where the last `pick` stopped, so the scheduler is round robin rather than first come.
    this.nextPick = 0;
    this.nextPid = 1;
    this.root = null;
    /// The host's name service, behind the address the guest's own resolver file names.
    /// `ARMJIT_DNS=raw` leaves the guest's file and the guest's servers alone.
    this.resolver = process.env.ARMJIT_DNS === "raw" ? null : new Resolver();
    /// The sockets of the session, shared by every process in it: a fork's descriptors point at
    /// the same descriptions, and the host object behind one is the one the fork shares too.
    this.net = new Net({ wake: () => this.poll(), resolver: this.resolver });
  }

  /// A process running an image from its entry point. Its first thread has the process's own id,
  /// the way `gettid` reports one for a program that never asked for a second.
  spawn({ module, meta }, parent = null) {
    const proc = {
      pid: this.nextPid++,
      ppid: parent ? parent.pid : 0,
      module,
      meta,
      state: "runnable",
      code: null,
      threads: [],
      current: null,
    };
    this.instantiate(proc);
    proc.threads.push(this.newThread(proc, proc.pid, { entry: true }));
    proc.current = proc.threads[0];
    this.processes.push(proc);
    if (!parent) this.root = proc;
    return proc;
  }

  /// A thread of a process: its own registers, its own place in the code, and its own reason to be
  /// waiting. The memory, the descriptor table and the page table are the process's, not its own.
  newThread(proc, tid, { entry = false, clearTid = 0 } = {}) {
    return {
      tid,
      entry,
      clearTid,
      state: "runnable",
      code: null,
      blockedOn: 0,
      waitingFor: null,
      pending: null,
      regs: new Uint8Array(THREAD_STATE),
      vecs: new Uint8Array(16 * NVEC),
    };
  }

  /// The registers of the thread that is in the wasm instance are the control block's, so a thread
  /// switch is a copy of them out and the next one's in. A resumed run reads all of it back, which
  /// is the same path a page translation resumes through.
  saveThread(proc, t) {
    const bytes = new Uint8Array(proc.memory.buffer);
    t.regs.set(bytes.subarray(0, THREAD_STATE));
    t.vecs.set(bytes.subarray(SHADOW_V0, SHADOW_V0 + 16 * NVEC));
  }

  loadThread(proc, t) {
    const bytes = new Uint8Array(proc.memory.buffer);
    bytes.set(t.regs, 0);
    bytes.set(t.vecs, SHADOW_V0);
  }

  /// Make `t` the thread whose registers the instance holds, saving the one that had them. The
  /// thread that is already current is the one whose registers are live in the control block, so
  /// loading it back from the copy would restore the state from before its last run.
  switchTo(proc, t) {
    if (proc.current === t) return;
    if (proc.current) this.saveThread(proc, proc.current);
    this.loadThread(proc, t);
    proc.current = t;
  }

  /// Build the instance for a process's current image, and the kernel state that goes with it. An
  /// exec keeps the descriptor table by passing it in, because those outlive the address space.
  instantiate(proc, files = null) {
    const imports = this.makeImports(proc);
    const instance = new WebAssembly.Instance(proc.module, { env: imports });
    proc.instance = instance;
    proc.memory = instance.exports.mem;
    proc.imports = imports;
    proc.kernel = new Kernel(proc.memory, proc.meta, {
      rootfs: this.rootfs,
      pid: proc.pid,
      ppid: proc.ppid,
      files,
      net: this.net,
      resolver: this.resolver,
      signal: (request) => this.signal(request),
      wake: () => this.poll(),
      futexWake: (addr, n) => this.futexWake(proc, addr, n),
    });
    for (const image of proc.meta.images ?? []) proc.kernel.space.images.push(image);
    // A page the guest changes is a page this process has to translate again.
    proc.kernel.space.forget = (lo, hi) => proc.mach?.forgetRange(lo, hi);
    proc.mach = new Mach({
      instance,
      memory: proc.memory,
      meta: proc.meta,
      kernel: proc.kernel,
      translator: this.translator,
      imports,
    });
    return proc;
  }

  /// Run until the process that started the session exits.
  async run() {
    const after = process.env.ARMJIT_WATCHDOG ? Number(process.env.ARMJIT_WATCHDOG) * 1000 : 0;
    const startedAt = Date.now();
    for (;;) {
      if (this.root.state === "exited") return this.root.signal ? 128 + this.root.signal : this.root.code;
      const pick = this.pick();
      if (!pick) {
        // Nothing can run, but a packet still can arrive: the host's event loop only turns while
        // this waits, and a guest blocked on a socket would otherwise never be woken.
        if (this.waiting()) {
          await this.net.next(this.idleWait());
          this.poll();
          continue;
        }
        return this.stuck();
      }
      if (after && Date.now() - startedAt > after) return 4;
      const verdict = await this.step(pick.proc, pick.thread);
      if (verdict !== 0) return verdict;
    }
  }

  /// Whether any thread is parked on something the host has to wait for: a packet that may arrive,
  /// or a deadline a timer will pass.
  waiting() {
    return this.processes.some((p) =>
      p.threads.some(
        (t) =>
          t.state === "blocked" &&
          (t.waitingFor === "socket" || t.waitingFor === "sleep" || t.waitingFor === "stdin"),
      ),
    );
  }

  /// How long the host may wait with nothing to run: until the nearest deadline a thread is parked
  /// on, and no longer than a tick, which is what gives traffic a chance to arrive.
  idleWait() {
    let wait = 200;
    for (const proc of this.processes) {
      for (const thread of proc.threads) {
        if (thread.state !== "blocked") continue;
        const deadline = thread.pending?.deadline;
        if (deadline) wait = Math.min(wait, Math.max(0, deadline - Date.now()));
        // Typing is a fact the host's event loop knows before anything here does, so a console
        // read is asked again on a short timer rather than the long one.
        if (thread.waitingFor === "stdin") wait = Math.min(wait, 20);
      }
    }
    return wait;
  }

  /// The next thread to run, and the process it belongs to. Threads are what a scheduler picks:
  /// a process whose threads are all waiting is waiting, and one with a runnable thread runs it.
  /// The next thread to run, from where the last pick left off: a guest that gives the CPU back at
  /// a poll has to come out behind the one that was waiting for it, or two runnable threads in a
  /// loop of their own would starve each other exactly as they did before there was a poll.
  pick() {
    const n = this.processes.length;
    for (let k = 0; k < n; k++) {
      const i = (this.nextPick + k) % n;
      const proc = this.processes[i];
      if (proc.state === "exited") continue;
      const thread = proc.threads.find((t) => t.state === "runnable");
      if (thread) {
        this.nextPick = i + 1;
        return { proc, thread };
      }
    }
    return null;
  }

  /// One entry into the guest, run until it exits, asks the host, or jumps somewhere untranslated.
  async step(proc, thread) {
    this.switchTo(proc, thread);
    if (process.env.ARMJIT_TRACE_STEPS) {
      const v = new DataView(proc.memory.buffer);
      console.error(
        `step: ${proc.pid}/${thread.tid} entry=${thread.entry} pc=0x${v.getUint32(SHADOW_PC, true).toString(16)}` +
          ` resume=0x${v.getUint32(SHADOW_RESUME, true).toString(16)} x0=0x${v.getBigUint64(0, true).toString(16)}`,
      );
    }
    // A signal is taken before the guest runs again, which is the only moment its whole state is
    // in the shadow: the last return from a region put it there.
    const entry = proc.kernel.takeSignal();
    if (entry) {
      if (thread.pending) {
        // The call it was waiting on is interrupted rather than restarted: the handler runs first,
        // and the frame remembers the -EINTR the guest will find when it returns.
        thread.pending = null;
        thread.state = "runnable";
        thread.blockedOn = 0;
        thread.waitingFor = null;
        proc.mach.view.setBigInt64(0, BigInt(-EINTR), true);
      }
      this.deliver(proc, entry);
    }
    // A syscall that was waiting is answered here, not by running the guest's code again: the
    // function it was in pushed a frame before the svc, and a second entry would push another.
    if (thread.pending) {
      const request = thread.pending;
      thread.pending = null;
      return this.answer(proc, thread, request);
    }
    let status;
    try {
      if (thread.entry) {
        thread.entry = false;
        status = proc.instance.exports.run(proc.meta.entry, BigInt(proc.meta.sp), 0);
      } else {
        status = proc.instance.exports.run(0, 0n, 1);
      }
      while (status === 2) {
        const pc = proc.mach.view.getUint32(SHADOW_PC, true) >>> 0;
        if (pc === SIGTRAMP) return this.sigreturnAt(proc, thread);
        // A jump into a page the guest did not map executable is a fault rather than a request to
        // translate: running data is how a program finds out it has a wild function pointer.
        if ((proc.kernel.space.ptes[pc >>> 12] & (PTE.MAPPED | PTE.EXECUTABLE)) !== (PTE.MAPPED | PTE.EXECUTABLE)) {
          return this.faulted(proc, thread, {
            kind: 6,
            signal: 11,
            addr: pc,
            at: pc,
            what: "execution of a page that is not executable",
          });
        }
        if (!proc.kernel.space.imageOf(pc)) {
          console.error(`armjit: pid ${proc.pid} jumped to untranslated address 0x${pc.toString(16)}`);
          return 1;
        }
        status = await proc.mach.translateAndResume(pc);
      }
    } catch (e) {
      // A fault unwinds the wasm call it happened in, which is how the guest leaves the region it
      // was in: the process is over either way, and the address is the one a kernel would report.
      if (e && e.kind !== undefined && e.signal) return this.faulted(proc, thread, e);
      throw e;
    }
    if (status === 1) return this.serve(proc, thread);
    if (status === 0) return this.exitedBySyscall(proc, thread, proc.kernel.exited ?? 0);
    console.error(`armjit: pid ${proc.pid} stopped with status ${status}`);
    return 1;
  }

  /// A syscall gave up the wasm call: do what it asked, then answer it.
  serve(proc, thread) {
    const kernel = proc.kernel;
    if (kernel.parked) {
      kernel.parked = false;
      return this.resumeAt(proc, thread);
    }
    const request = kernel.pending;
    kernel.pending = null;
    if (kernel.exited !== null) return this.exitedBySyscall(proc, thread, kernel.exited);
    if (!request) {
      console.error(`armjit: pid ${proc.pid} returned from a syscall with no request`);
      return 1;
    }
    return this.answer(proc, thread, request);
  }

  /// The guest stopped itself: `exit` ends the thread that called it, and the process when it was
  /// the last one, while `exit_group` ends all of them. Either way the answers are the same.
  ///
  /// The request belongs to the thread that made it, so it is consumed here: a process where one
  /// thread has ended is a process that keeps running, and a flag left set on the kernel would end
  /// the next thread to make a call of its own.
  exitedBySyscall(proc, thread, code) {
    const group = proc.kernel.exitedGroup;
    proc.kernel.exited = null;
    proc.kernel.exitedGroup = false;
    if (group) return this.exit(proc, code);
    return this.exitThread(proc, thread, code);
  }

  answer(proc, thread, request) {
    switch (request.kind) {
      case "fork":
        return this.fork(proc, thread, request);
      case "clone":
        return this.clone(proc, thread, request);
      case "exec":
        return this.exec(proc, thread, request);
      case "wait":
        return this.wait(proc, thread, request);
      case "read":
        return this.read(proc, thread, request);
      case "recv":
        return this.recv(proc, thread, request);
      case "recvmsg":
        return this.recvMsg(proc, thread, request);
      case "recvmmsg":
        return this.recvMMsg(proc, thread, request);
      case "bind":
        return this.bind(proc, thread, request);
      case "connect":
        return this.connect(proc, thread, request);
      case "address":
        return this.address(proc, thread, request);
      case "accept":
        return this.accept(proc, thread, request);
      case "epoll":
        return this.epollWait(proc, thread, request);
      case "poll":
        return this.pollWait(proc, thread, request);
      case "select":
        return this.selectWait(proc, thread, request);
      case "futex":
        return this.futex(proc, thread, request);
      case "sleep":
        return this.sleepFor(proc, thread, request);
      case "deliver":
        return this.deliverRequest(proc, thread, request);
      case "sigreturn":
        return this.sigreturn(proc, thread, request);
      default:
        console.error(`armjit: pid ${proc.pid} asked for an unknown host action ${request.kind}`);
        return 1;
    }
  }

  /// An access the pages did not allow. It is synchronous, so it belongs to the instruction that
  /// made it, and the process ends the way a kernel ends one whose page fault it cannot answer:
  /// with the signal, which is what its parent's wait status reports.
  faulted(proc, thread, fault) {
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      const img = proc.kernel.space.imageOf(fault.at);
      const where = img
        ? `${img.host.split("/").pop()}+0x${(fault.at - img.base).toString(16)}`
        : "no image";
      console.error(
        `fault: ${proc.pid} ${fault.what} at 0x${fault.addr.toString(16)} from 0x${fault.at.toString(16)} (${where})`,
      );
    }
    proc.fault = { signal: fault.signal, addr: fault.addr, at: fault.at };
    return this.exit(proc, 0, fault.signal);
  }

  /// Where a handler returns to: the restorer its disposition named, or the trampoline.
  restorerFor(act) {
    const named = Number(BigInt.asUintN(64, act.restorer));
    if ((Number(act.flags) & SA_RESTORER) !== 0 && named !== 0) return named;
    return SIGTRAMP;
  }

  /// The `ret` a handler ends with, when it lands on the trampoline: the frame is on the stack the
  /// signal put it on, and `rt_sigreturn` is what the two instructions there asked for.
  sigreturnAt(proc, thread) {
    const at = Number(new DataView(proc.memory.buffer).getBigUint64(0xf8, true));
    // A frame that is not there is a process that does not survive the return, the way a real
    // kernel's `rt_sigreturn` kills one that hands it a stack it cannot read.
    if (!proc.kernel.inBounds(at, SIGFRAME.FPSIMD + 16 + 32 * 16)) return this.exit(proc, 0, 11);
    return this.sigreturn(proc, thread, { frame: at });
  }

  /// Hand the process the next signal it may take. The frame goes on the guest's stack, in the
  /// shape the kernel builds one, and the handler starts with the registers a call to it would
  /// have: the signal number, and the two pointers when the disposition asked for them.
  deliver(proc, entry) {
    const kernel = proc.kernel;
    const view = new DataView(proc.memory.buffer);
    const act = kernel.disposition(entry.sig);
    if (!act || act === "ignore" || act === "default") return false;
    const handler = Number(BigInt.asUintN(64, act.handler));
    if (handler === 0) return false;

    const sp = view.getBigUint64(0xf8, true);
    const alt = kernel.altstack;
    const onAlt = (Number(act.flags) & SA_ONSTACK) !== 0 && alt.flags !== SS_DISABLE;
    const top = onAlt ? BigInt.asUintN(64, alt.sp) + BigInt.asUintN(64, alt.size) : sp;
    const at = Number((top - BigInt(SIGFRAME.SIZE)) & ~15n);
    if (!kernel.inBounds(at, SIGFRAME.SIZE)) {
      // A signal whose frame cannot be built is one the process does not survive: that is what a
      // stack overflow does on a real kernel.
      return false;
    }

    const frame = Buffer.alloc(SIGFRAME.SIZE);
    frame.writeInt32LE(entry.sig, SIGFRAME.SI_SIGNO);
    frame.writeInt32LE(entry.code ?? SI_USER, SIGFRAME.SI_CODE);
    if (entry.addr !== undefined) {
      frame.writeBigUInt64LE(BigInt.asUintN(64, BigInt(entry.addr)), SIGFRAME.SI_ADDR);
      frame.writeBigUInt64LE(BigInt.asUintN(64, BigInt(entry.addr)), SIGFRAME.SC_FAULT);
    } else {
      frame.writeInt32LE(entry.pid ?? proc.pid, SIGFRAME.SI_PID);
      frame.writeInt32LE(entry.uid ?? 0, SIGFRAME.SI_UID);
    }
    // `ucontext`: what the machine was doing, so the restorer can put it back.
    frame.writeBigUInt64LE(BigInt.asUintN(64, alt.sp), SIGFRAME.UC_STACK);
    frame.writeInt32LE(alt.flags, SIGFRAME.UC_STACK + 8);
    frame.writeBigUInt64LE(BigInt.asUintN(64, alt.size), SIGFRAME.UC_STACK + 16);
    frame.writeBigUInt64LE(kernel.sigblock, SIGFRAME.UC_SIGMASK);
    for (let i = 0; i < 31; i++) {
      frame.writeBigUInt64LE(view.getBigUint64(i * 8, true), SIGFRAME.SC_REGS + i * 8);
    }
    frame.writeBigUInt64LE(sp, SIGFRAME.SC_SP);
    frame.writeUInt32LE(view.getUint32(0x118, true), SIGFRAME.SC_PC); // resume after the `svc`
    frame.writeUInt32LE(0, SIGFRAME.SC_PSTATE);
    // `struct fpsimd_context`: the magic the kernel writes there, its size, and the state.
    frame.writeUInt32LE(0x46508001, SIGFRAME.FPSIMD);
    frame.writeUInt32LE(16 + 32 * 16, SIGFRAME.FPSIMD + 4);
    frame.writeUInt32LE(Number(view.getBigUint64(0x128, true)), SIGFRAME.FPSIMD + 8);
    frame.writeUInt32LE(Number(view.getBigUint64(0x120, true)), SIGFRAME.FPSIMD + 12);
    for (let i = 0; i < 32; i++) {
      const from = 0x600 + i * 16;
      frame.set(new Uint8Array(proc.memory.buffer, from, 16), SIGFRAME.FPSIMD + 16 + i * 16);
    }
    kernel.put(at, frame);

    // The handler runs on that frame, with the mask the disposition asks for while it is there.
    view.setBigUint64(0xf8, BigInt(at), true);
    view.setBigUint64(0, BigInt(entry.sig), true);
    const info = Number(act.flags) & SA_SIGINFO ? BigInt(at) : 0n;
    view.setBigUint64(8, info, true);
    view.setBigUint64(16, info === 0n ? 0n : BigInt(at + SIGFRAME.UC), true);
    view.setBigUint64(30 * 8, BigInt(this.restorerFor(act)), true);
    view.setUint32(0x108, handler >>> 0, true);
    const bit = 1n << BigInt(entry.sig - 1);
    kernel.sigblock = BigInt.asUintN(64, kernel.sigblock | BigInt.asUintN(64, act.mask) | bit);
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(`signal: ${proc.pid} runs the handler for ${entry.sig} at 0x${handler.toString(16)}`);
    }
    return true;
  }

  /// The host's side of a backward branch whose counter ran out. Answering 1 gives the CPU back,
  /// which is how a pending signal is taken and how another thread gets a turn; answering 0 lets
  /// the loop go on.
  pollPoint(proc) {
    if (proc.state === "exited") return 0;
    this.poll();
    if (proc.kernel.deliverable()) {
      proc.kernel.parked = true;
      return 1;
    }
    // A deadline is a thing a spinning guest cannot see: a sleep that is due has to be answered by
    // the host, so the loop gives it the chance the same way.
    if (this.waiting()) {
      proc.kernel.parked = true;
      return 1;
    }
    const waiting = this.processes.some((p) =>
      p === proc
        ? p.threads.some((t) => t !== p.current && t.state === "runnable")
        : p.state !== "exited" && p.threads.some((t) => t.state === "runnable"),
    );
    if (waiting) proc.kernel.parked = true;
    return waiting ? 1 : 0;
  }

  /// Continue where a poll left off, which is the loop the guest was about to go round: nothing it
  /// had in a register has changed, so only the pc has to be put back.
  resumeAt(proc, thread) {
    const view = proc.mach.view;
    view.setUint32(SHADOW_PC, view.getUint32(SHADOW_RESUME, true), true);
    thread.state = "runnable";
    return 0;
  }

  /// Put the machine back the way the frame says it was, and continue where the signal interrupted.
  /// The registers are written here rather than in the syscall itself because the run's own exit
  /// path writes the shadow from the registers the restorer still holds, and would undo it.
  sigreturn(proc, thread, request) {
    const view = proc.mach.view;
    const at = Number(request.frame);
    for (let i = 0; i < 31; i++) {
      view.setBigUint64(i * 8, view.getBigUint64(at + SIGFRAME.SC_REGS + i * 8, true), true);
    }
    view.setBigUint64(0xf8, view.getBigUint64(at + SIGFRAME.SC_SP, true), true);
    proc.kernel.sigblock = view.getBigUint64(at + SIGFRAME.UC_SIGMASK, true);
    view.setBigUint64(0x128, BigInt(view.getUint32(at + SIGFRAME.FPSIMD + 8, true)), true);
    view.setBigUint64(0x120, BigInt(view.getUint32(at + SIGFRAME.FPSIMD + 12, true)), true);
    for (let i = 0; i < 32; i++) {
      const from = at + SIGFRAME.FPSIMD + 16 + i * 16;
      new Uint8Array(proc.memory.buffer, 0x600 + i * 16, 16).set(
        new Uint8Array(proc.memory.buffer, from, 16),
      );
    }
    view.setUint32(0x118, view.getUint32(at + SIGFRAME.SC_PC, true), true);
    return this.resume(proc, thread, view.getBigUint64(at + SIGFRAME.SC_REGS, true));
  }

  /// A signal this process raised on itself, taken before the syscall's answer reaches the guest:
  /// the handler runs first and the frame it returns through holds the state the call left, so the
  /// answer is the one the guest finds when the handler returns.
  deliverRequest(proc, thread, request) {
    this.resume(proc, thread, Number(request.answer ?? 0));
    const entry = proc.kernel.takeSignal();
    if (entry) this.deliver(proc, entry);
    return 0;
  }

  /// The console's interrupt and quit characters. A terminal turns them into signals to the
  /// foreground job, and the foreground job here is every process there is: one console, one
  /// process group, so a command that is running gets the signal and the shell that ignores it
  /// while it waits does not.
  interrupt(sig) {
    // A terminal signals the foreground job, and every process here shares one process group, so
    // the job is every process that has not said it ignores the signal: the shell and the command
    // it is waiting for both take it, and the command that catches it - a REPL's
    // `KeyboardInterrupt`, a `trap`, a package manager tidying up - gets to run its own code.
    for (const proc of this.processes) {
      if (proc.state === "exited") continue;
      if (proc.kernel.disposition(sig) === "ignore") continue;
      this.signal({ from: 0, pid: proc.pid, sig });
    }
  }

  /// A signal from one process to another. There is no handler to run, so what a signal does is
  /// what its default action says: a disposition that ignores it does nothing, a caught one is
  /// recorded and not run, and a default action that terminates ends the process and leaves its
  /// parent a wait status that says so.
  signal({ from, pid, sig, tid }) {
    const targets = [];
    if (tid) {
      for (const proc of this.processes) {
        const thread = proc.threads.find((t) => t.tid === tid);
        if (thread) targets.push({ proc, thread });
      }
    } else if (pid > 0) {
      const proc = this.processes.find((p) => p.pid === pid);
      if (proc) targets.push({ proc, thread: null });
    } else if (pid === 0) {
      const proc = this.processes.find((p) => p.pid === from);
      if (proc) targets.push({ proc, thread: null });
    } else if (pid === -1) {
      // Every process there is, which is the whole of one user's session.
      for (const proc of this.processes) if (proc.pid !== from) targets.push({ proc, thread: null });
    }
    // A process that has ended but not been reaped is still there to a signal: it answers and the
    // signal is thrown away, which is what a zombie does.
    const live = targets.filter(({ proc }) => proc.state !== "exited" || !proc.reaped);
    if (live.length === 0) return -ESRCH;
    if (sig === 0) return 0;
    for (const { proc, thread } of live) {
      if (proc.state === "exited") continue;
      // The disposition is the target's, and SIGKILL and SIGSTOP have none to consult.
      const how = sig === 9 || sig === 19 ? "default" : proc.kernel.disposition(sig);
      if (how === "ignore") continue;
      if (how !== "default") {
        proc.kernel.queueSignal(sig, { code: SI_USER, pid: from, uid: 0 });
        // A thread parked on a syscall has to wake up to see the signal, and the call it was in
        // answers EINTR: that is the whole point of a handler.
        const parked = thread ?? proc.threads.find((t) => t.state !== "exited");
        if (parked && parked.state === "blocked") {
          parked.state = "runnable";
          parked.blockedOn = 0;
          parked.waitingFor = null;
        }
        this.wake(proc);
        this.poll();
        continue;
      }
      if (!FATAL.has(sig)) continue;
      if (thread) this.exitThread(proc, thread, 0, sig);
      else this.exit(proc, 0, sig);
      // The caller may have just ended itself, and then there is no answer to give it.
      if (proc.pid === from) proc.kernel.exited = 0;
    }
    return 0;
  }

  /// x0 is the syscall's answer and the guest continues after the `svc`. The address to continue at
  /// is the one the syscall stored, not the block the run went out through, and it is a block start
  /// because a syscall ends the block it is in.
  resume(proc, thread, value) {
    const view = new DataView(proc.memory.buffer);
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(
        `resume: ${proc.pid} x0=${value} at 0x${view.getUint32(SHADOW_RESUME, true).toString(16)}`,
      );
    }
    view.setBigInt64(SHADOW, BigInt.asIntN(64, BigInt(value)), true);
    view.setUint32(SHADOW_PC, view.getUint32(SHADOW_RESUME, true), true);
    thread.state = "runnable";
    return 0;
  }

  fork(parent, parentThread, request) {
    const child = {
      pid: this.nextPid++,
      ppid: parent.pid,
      module: parent.module,
      meta: parent.meta,
      state: "runnable",
      code: null,
      threads: [],
      current: null,
    };
    this.instantiate(child);
    child.kernel.adopt(parent.kernel.forkState());
    this.copyMemory(parent, child);
    child.mach.adopt(parent.mach.lineage, parent.mach);

    // A child has one thread, and its memory already holds the parent's registers: a fork returns
    // zero in it, from the instruction after the svc.
    const childThread = this.newThread(child, child.pid);
    child.threads.push(childThread);
    child.current = childThread;
    const from = new DataView(parent.memory.buffer);
    const view = new DataView(child.memory.buffer);
    view.setBigInt64(SHADOW, 0n, true);
    view.setUint32(SHADOW_PC, view.getUint32(SHADOW_RESUME, true), true);
    childThread.regs.set(new Uint8Array(child.memory.buffer).subarray(0, THREAD_STATE));
    if (request.flags & CLONE_CHILD_SETTID && request.ctid) {
      view.setUint32(request.ctid, child.pid, true);
    }
    if (request.flags & CLONE_PARENT_SETTID && request.ptid) {
      from.setUint32(request.ptid, child.pid, true);
    }
    this.processes.push(child);
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(
        `fork: ${parent.pid} -> ${child.pid} at 0x${from.getUint32(SHADOW_RESUME, true).toString(16)}` +
          ` sp=0x${from.getBigUint64(0xf8, true).toString(16)}`,
      );
    }
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(`fork: ${parent.pid} keeps ${this.describeFds(parent)}`);
    }
    const verdict = this.resume(parent, parentThread, child.pid);
    // vfork suspends the parent until the child execs or exits, and the child runs on the stack the
    // parent is using, so it must not get a turn while it is still inside the fork.
    if (request.flags & CLONE_VFORK && !process.env.ARMJIT_NO_WAIT_VFORK) this.block(parentThread, child.pid);
    return verdict;
  }

  /// A second thread of the same process: the same memory, descriptor table and page table, with
  /// its own registers and its own stack. One linear memory cannot be two threads at once, so a
  /// thread is a coroutine: it runs until it asks the host for something, and the scheduler runs
  /// whichever of the process's threads is unimpeded next.
  clone(proc, thread, request) {
    if (proc.kernel.exited !== null) return this.exitedBySyscall(proc, thread, proc.kernel.exited);
    // A thread id and a process id come from the same space, so a `gettid` answer is unique and a
    // wait for a thread and a wait for a process cannot be confused.
    const tid = this.nextPid++;
    const child = this.newThread(proc, tid, {
      clearTid: request.flags & CLONE_CHILD_CLEARTID ? request.ctid : 0,
    });
    this.saveThread(proc, thread);
    child.regs.set(thread.regs);
    child.vecs.set(thread.vecs);
    // The new thread starts on the stack `clone` was given, at the instruction after the svc, with
    // zero as its answer: that is what the function `pthread_create` hands to it reads.
    const regs = new DataView(child.regs.buffer);
    regs.setBigInt64(0, 0n, true);
    regs.setBigUint64(0xf8, BigInt(request.stack), true);
    regs.setUint32(SHADOW_PC, regs.getUint32(SHADOW_RESUME, true), true);
    if (request.flags & CLONE_SETTLS) regs.setBigUint64(0x110, BigInt.asUintN(64, request.tls), true);
    proc.threads.push(child);
    const view = new DataView(proc.memory.buffer);
    if (request.flags & CLONE_PARENT_SETTID && request.ptid) view.setUint32(request.ptid, tid, true);
    if (request.flags & CLONE_CHILD_SETTID && request.ctid) view.setUint32(request.ctid, tid, true);
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      const at = (a) => (a ? view.getUint32(a, true) : "none");
      console.error(
        `clone: ${proc.pid} thread ${tid} on stack 0x${request.stack.toString(16)} flags=0x${request.flags.toString(16)}` +
          ` ptid=0x${request.ptid.toString(16)}(${at(request.ptid)}) ctid=0x${request.ctid.toString(16)}(${at(request.ctid)})`,
      );
    }
    return this.resume(proc, thread, tid);
  }

  /// A thread waiting for the host: it does not run again until something wakes it, and a request
  /// with a deadline is looked at again then even if nothing arrived. The timer keeps the deadline
  /// from depending on traffic: a `poll` on a socket nobody sends to still has to time out.
  park(thread, request, deadline, waitingFor = "socket") {
    this.block(thread, request.fd ?? 0, waitingFor);
    thread.pending = request;
    if (!deadline) return;
    const timer = setTimeout(() => {
      if (thread.pending === request) thread.state = "runnable";
    }, Math.max(0, deadline - Date.now()));
    timer.unref?.();
  }

  /// A request that has waited as long as its socket's timeout allows: the answer is EAGAIN, the
  /// same one a socket the guest set non-blocking gives.
  expired(request) {
    return request.deadline > 0 && Date.now() >= request.deadline;
  }

  /// A receive there was nothing for: answer it from what has arrived since, or keep waiting.
  recv(proc, thread, request) {
    const answer = proc.kernel.recvInto(request.fd, request.buf, request.len, request.flags, request.addr, request.lenp);
    if (answer && answer.host) {
      if (this.expired(request)) return this.resume(proc, thread, -EAGAIN);
      this.park(thread, request, request.deadline);
      return 0;
    }
    return this.resume(proc, thread, answer);
  }

  /// A receive into a message header there was nothing for.
  recvMsg(proc, thread, request) {
    const answer = proc.kernel.recvMsgInto(request.fd, request.msg, request.flags);
    if (answer && answer.host) {
      if (this.expired(request)) return this.resume(proc, thread, -EAGAIN);
      this.park(thread, request, request.deadline);
      return 0;
    }
    return this.resume(proc, thread, answer);
  }

  /// The same, for the array of headers a resolver reads its answers into.
  recvMMsg(proc, thread, request) {
    const answer = proc.kernel.recvMMsgInto(request.fd, request.vec, request.vlen, request.flags, request.deadline);
    if (answer && answer.host) {
      if (this.expired(request)) return this.resume(proc, thread, -EAGAIN);
      this.park(thread, request, request.deadline);
      return 0;
    }
    return this.resume(proc, thread, answer);
  }

  async bind(proc, thread, request) {
    const desc = proc.kernel.socketDesc(request.fd);
    if (typeof desc === "number") return this.resume(proc, thread, desc);
    const answer = await desc.bind(request.addr);
    return this.resume(proc, thread, answer);
  }

  async connect(proc, thread, request) {
    const desc = proc.kernel.socketDesc(request.fd);
    if (typeof desc === "number") return this.resume(proc, thread, desc);
    return this.resume(proc, thread, await desc.waitConnected());
  }

  /// An accept there was no connection for.
  accept(proc, thread, request) {
    const answer = proc.kernel.acceptInto(request.fd, request.addr, request.lenp, request.flags);
    if (answer && answer.host) {
      if (this.expired(request)) return this.resume(proc, thread, -EAGAIN);
      this.park(thread, request, request.deadline);
      return 0;
    }
    return this.resume(proc, thread, answer);
  }

  /// `getsockname` for a socket whose address the host has not chosen yet.
  async address(proc, thread, request) {
    const entry = proc.kernel.files.get(request.fd);
    if (!entry) return this.resume(proc, thread, -EBADF);
    const at = await entry.desc.ready();
    if (!proc.kernel.putAddr(request.addr, request.lenp, at)) return this.resume(proc, thread, -EFAULT);
    return this.resume(proc, thread, 0);
  }

  /// An `epoll_pwait` that found nothing ready, asked again: what arrived since, a timeout that has
  /// passed, or another wait. A wake with nothing to report is not an answer, so a wait with no
  /// deadline goes back to waiting.
  epollWait(proc, thread, request) {
    const ready = proc.kernel.epollReady(request.epfd, request.maxevents);
    if (ready === null) return this.resume(proc, thread, proc.kernel.files.get(request.epfd) ? -EINVAL : -EBADF);
    if (ready.length > 0) return this.resume(proc, thread, proc.kernel.epollDeliver(ready, request.events));
    if (this.expired(request)) return this.resume(proc, thread, 0);
    this.park(thread, request, request.deadline);
    return 0;
  }

  /// A `poll` that found nothing ready: ready now, out of time, or wait for the host.
  pollWait(proc, thread, request) {
    const ready = proc.kernel.pollOnce(request.fds, request.nfds);
    if (ready > 0) return this.resume(proc, thread, ready);
    if (request.deadline && Date.now() >= request.deadline) return this.resume(proc, thread, 0);
    this.park(thread, request, request.deadline);
    return 0;
  }

  selectWait(proc, thread, request) {
    const k = proc.kernel;
    const got = k.selectOnce(request.nfds, request.read, request.write, request.except);
    if (got.ready > 0) {
      k.putSelect(got.sets);
      return this.resume(proc, thread, got.ready);
    }
    if (request.deadline && Date.now() >= request.deadline) return this.resume(proc, thread, 0);
    this.park(thread, request, request.deadline);
    return 0;
  }

  /// `nanosleep`: the deadline is the whole of the wait, and success is already the answer by the
  /// time the timer that parks the thread has fired.
  sleepFor(proc, thread, request) {
    if (!request.deadline || Date.now() >= request.deadline) return this.resume(proc, thread, 0);
    this.park(thread, request, request.deadline, "sleep");
    return 0;
  }

  /// FUTEX_WAIT and FUTEX_WAKE, which is how one thread of a process waits for another.
  futex(proc, thread, request) {
    const view = new DataView(proc.memory.buffer);
    if (view.getInt32(request.addr, true) !== request.value) {
      return this.resume(proc, thread, -11); // EAGAIN: the value changed before the wait
    }
    thread.state = "blocked";
    thread.blockedOn = request.addr;
    thread.waitingFor = "futex";
    thread.pending = request;
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(`futex: ${proc.pid}/${thread.tid} waits on 0x${request.addr.toString(16)}`);
    }
    return 0;
  }

  /// The whole of the parent's memory that exists: the engine area, which holds the control block
  /// and the page table, and every page the page table says is mapped. Rest is zero in both.
  ///
  /// The engine area is copied first and by hand, because it is not mapped for the guest: the child
  /// resumes from the shadow the parent left, and a page the parent mapped at run time is one the
  /// child's own copy of the table has to say is there.
  copyMemory(from, to) {
    const src = new Uint8Array(from.memory.buffer);
    const dst = new Uint8Array(to.memory.buffer);
    const pteBase = from.meta.pte_base;
    dst.set(src.subarray(0, pteBase + (1 << 20)), 0);
    const ptes = new Uint8Array(from.memory.buffer, pteBase, 1 << 20);
    let i = 0;
    while (i < ptes.length) {
      if (ptes[i] === 0) {
        i++;
        continue;
      }
      const lo = i;
      while (i < ptes.length && ptes[i] !== 0) i++;
      // Not a shift: a page index times 4096 passes what a 32-bit shift can hold.
      const at = lo * 4096;
      // The page table covers 4 GiB and the memory is a few pages short of it.
      if (at >= dst.length) break;
      const len = Math.min((i - lo) * 4096, dst.length - at);
      dst.set(src.subarray(at, at + len), at);
    }
  }

  /// The interpreter a script names on its first line, and the one argument that line may carry.
  /// Linux stops at the newline, trims the whitespace around the name, and keeps the rest of the
  /// line whole rather than splitting it.
  shebang(host) {
    let head;
    try {
      const fd = fs.openSync(host, "r");
      try {
        const buf = Buffer.alloc(256);
        head = buf.subarray(0, fs.readSync(fd, buf, 0, buf.length, 0));
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      return null;
    }
    if (head.length < 2 || head[0] !== 0x23 || head[1] !== 0x21) return null;
    const nl = head.indexOf(0x0a);
    const line = head.subarray(2, nl === -1 ? head.length : nl).toString("latin1");
    const space = (c) => c === " " || c === "\t";
    let i = 0;
    while (i < line.length && space(line[i])) i++;
    let j = i;
    while (j < line.length && !space(line[j])) j++;
    const interp = line.slice(i, j);
    if (!interp) return null;
    let a = j;
    while (a < line.length && space(line[a])) a++;
    return { interp, arg: a < line.length ? line.slice(a) : null };
  }

  async exec(proc, thread, request) {
    const path = request.path.toString("latin1");
    let program = path;
    let argv = request.argv;
    let host = null;
    // A script's first line names the interpreter that runs it, so an exec of one runs that
    // instead, with the script's own path as the interpreter's first argument. `apt` starts
    // `apt-key` and `dpkg-preconfigure` this way, and they are shell scripts. Linux follows four
    // of these before it gives up on a loop.
    for (let depth = 0; host === null; depth++) {
      const at = proc.kernel.files.resolve(program);
      if (typeof at === "number") return this.resume(proc, thread, at);
      try {
        const st = fs.statSync(at);
        // A directory and a file without the execute bit are both EACCES, and a path that is not
        // there is ENOENT: `execvp` walks PATH on ENOENT and EACCES, and runs the file through a
        // shell on ENOEXEC, so answering the wrong one turns a missing program into a shell script.
        if (!st.isFile()) return this.resume(proc, thread, -EACCES);
        fs.accessSync(at, fs.constants.X_OK);
      } catch (e) {
        if (process.env.ARMJIT_TRACE_PROCESSES) console.error(`exec ${program}: ${e.code}`);
        return this.resume(proc, thread, -(e.code === "ENOENT" ? ENOENT : EACCES));
      }
      const script = this.shebang(at);
      if (!script) {
        host = at;
        break;
      }
      if (depth === 4) return this.resume(proc, thread, -ELOOP);
      argv = [
        Buffer.from(script.interp),
        ...(script.arg === null ? [] : [Buffer.from(script.arg)]),
        Buffer.from(program),
        ...argv.slice(1),
      ];
      program = script.interp;
    }
    const answer = await (async () => {
      try {
        return await this.translator.image(host, argv, request.envp);
      } catch (e) {
        if (process.env.ARMJIT_TRACE_PROCESSES) console.error(`exec ${program}: ${e.message}`);
        return { ok: false, error: e.message };
      }
    })();
    if (!answer.ok) {
      console.error(`armjit: cannot run ${program}: ${answer.error}`);
      return this.resume(proc, thread, -ENOEXEC);
    }
    const meta = answer.meta;
    // What survives an exec: the descriptor table (less close-on-exec entries) and the cwd. The
    // address space, the page tables and every translation in them do not.
    const files = proc.kernel.files;
    files.keepAcrossExec();
    proc.module = new WebAssembly.Module(answer.wasm);
    proc.meta = meta;
    // The ids are the process's, not the address space's: a program that dropped privileges stays
    // dropped when it execs.
    const ids = proc.kernel.ids;
    // A caught signal is back to its default after an exec, and an ignored one stays ignored.
    const ignored = new Map([...proc.kernel.signals].filter(([, how]) => how === "ignore"));
    this.instantiate(proc, files);
    proc.kernel.ids = ids;
    proc.kernel.signals = ignored;
    // An exec leaves one thread behind: the one that called it, with the others gone with the
    // address space they were in.
    proc.threads.forEach((t) => {
      t.state = "exited";
    });
    proc.threads = [thread];
    proc.current = thread;
    thread.entry = true;
    thread.state = "runnable";
    thread.regs.fill(0);
    thread.vecs.fill(0);
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(`exec: ${proc.pid} ${argv.map((a) => a.toString()).join(" ")} at 0x${meta.entry.toString(16)}`);
      for (const [fd, entry] of [...files.map].sort((a, b) => a[0] - b[0])) {
        const what = entry.kind === "pipe" ? `pipe ${entry.desc.id} ${entry.end}` : entry.host ?? entry.kind;
        console.error(`  pid ${proc.pid} fd ${fd} -> ${what}`);
      }
    }
    this.wake(proc);
    return 0;
  }

  wait(proc, thread, request) {
    const kids = this.processes.filter(
      (c) => c.ppid === proc.pid && (request.pid <= 0 || c.pid === request.pid),
    );
    if (kids.length === 0) return this.resume(proc, thread, -ECHILD);
    const done = kids.find((c) => c.state === "exited" && !c.reaped);
    if (done) {
      this.reap(proc, done, request);
      return this.resume(proc, thread, done.pid);
    }
    if (request.options & WNOHANG) return this.resume(proc, thread, 0);
    this.block(thread, request.pid);
    thread.pending = request;
    return 0;
  }

  block(thread, on, waitingFor = "child") {
    thread.state = "blocked";
    thread.blockedOn = on;
    thread.waitingFor = waitingFor;
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      const what = this.reason(thread);
      console.error(`block: thread ${thread.tid} waits for ${what}`);
    }
  }

  /// What a blocked thread is waiting for, in words a report can print.
  reason(thread) {
    if (thread.waitingFor === "pipe") return `a pipe (fd ${thread.pending?.fd ?? "?"})`;
    if (thread.waitingFor === "stdin") return "the console";
    if (thread.waitingFor === "futex") return `futex 0x${thread.blockedOn.toString(16)}`;
    if (thread.waitingFor === "epoll") return `an epoll (fd ${thread.blockedOn})`;
    if (thread.waitingFor === "sleep") return `a sleep (${thread.pending?.deadline ?? 0})`;
    if (thread.waitingFor === "socket") {
      const kind = thread.pending?.kind;
      if (kind === "poll" || kind === "select") return `a socket (${kind})`;
      return `socket ${thread.pending?.fd ?? thread.blockedOn}`;
    }
    return thread.blockedOn <= 0 ? "any child" : thread.blockedOn;
  }

  /// What a process's descriptor table holds, for a report.
  describeFds(proc) {
    return [...proc.kernel.files.map]
      .sort((a, b) => a[0] - b[0])
      .map(([fd, entry]) => {
        if (entry.kind === "pipe") return `${fd}=pipe${entry.desc.id}${entry.end === "read" ? "r" : "w"}`;
        if (entry.kind === "socket") return `${fd}=socket${entry.desc.id ?? ""}`;
        return `${fd}=${entry.kind}`;
      })
      .join(" ");
  }

  /// A pipe read that had nothing in it: answer it now, or keep waiting.
  read(proc, thread, request) {
    const got = proc.kernel.files.read(request.fd, request.len);
    if (got === WOULD_BLOCK) {
      const entry = proc.kernel.files.get(request.fd);
      this.block(thread, 0, entry && proc.kernel.files.consoleEntry(entry) ? "stdin" : "pipe");
      thread.pending = request;
      return 0;
    }
    if (typeof got === "number") return this.resume(proc, thread, got);
    proc.kernel.put(request.buf, got);
    return this.resume(proc, thread, got.length);
  }

  /// Something a thread may be waiting for happened, or a pipe has data in it. A socket waiter is
  /// woken by any event rather than the one it wants, because which of its descriptors is ready is
  /// the answer's business: it looks again, and parks again if the answer is still "nothing".
  poll() {
    for (const proc of this.processes) {
      for (const thread of proc.threads) {
        if (thread.state !== "blocked") continue;
        if (thread.waitingFor === "socket" || thread.waitingFor === "epoll") thread.state = "runnable";
        else if (thread.waitingFor === "pipe" && proc.kernel.files.readReady(thread.pending.fd)) {
          thread.state = "runnable";
        } else if (thread.waitingFor === "stdin" && proc.kernel.files.readReady(thread.pending.fd)) {
          thread.state = "runnable";
        } else if (thread.waitingFor === "sleep" && Date.now() >= thread.pending.deadline) {
          // A sleep cannot be a `setTimeout` alone: the host's event loop does not turn while a
          // guest is spinning, and a poll at a backward branch is the only thing that asks.
          thread.state = "runnable";
        }
      }
    }
  }

  /// Every thread waiting on a futex word, woken: that is how one thread of a process tells another
  /// that what it waited for has happened. A wake of -1 is every waiter.
  futexWake(proc, addr, n) {
    let woken = 0;
    for (const thread of proc.threads) {
      if (thread.state !== "blocked" || thread.waitingFor !== "futex") continue;
      if (thread.blockedOn !== addr) continue;
      if (n >= 0 && woken >= n) break;
      thread.state = "runnable";
      woken++;
    }
    if (woken && process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(`futex wake 0x${addr.toString(16)}: ${woken} thread(s)`);
    }
    return woken;
  }

  /// A parent waiting for this process, whether for its exit or for the exec that ends a vfork.
  wake(proc) {
    for (const q of this.processes) {
      for (const thread of q.threads) {
        if (thread.state !== "blocked" || thread.waitingFor !== "child" || proc.ppid !== q.pid) continue;
        if (thread.blockedOn <= 0 || thread.blockedOn === proc.pid) thread.state = "runnable";
      }
    }
  }

  /// The wait status a real kernel would give, and the rusage a program that asks for one reads.
  reap(parent, child, request) {
    const view = new DataView(parent.memory.buffer);
    // A process that a signal ended reports the signal, not an exit code: the low seven bits are the
    // one a `WIFSIGNALED` reader looks at.
    if (request.wstatus) {
      const status = child.signal ? child.signal & 0x7f : (child.code & 0xff) << 8;
      view.setInt32(request.wstatus, status, true);
    }
    if (request.rusage) new Uint8Array(parent.memory.buffer).fill(0, request.rusage, request.rusage + 144);
    child.reaped = true;
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(
        `reap: ${child.pid} code ${child.code}, status word at 0x${request.wstatus.toString(16)}` +
          ` = ${request.wstatus ? view.getInt32(request.wstatus, true) : "none"}`,
      );
    }
  }

  /// A thread that ended: the process goes with the last one, and `CLONE_CHILD_CLEARTID` is how a
  /// joining thread learns that it did.
  exitThread(proc, thread, code, signal = 0) {
    thread.state = "exited";
    thread.code = code & 0xff;
    thread.signal = signal;
    if (thread.clearTid) {
      new DataView(proc.memory.buffer).setUint32(thread.clearTid, 0, true);
      this.futexWake(proc, thread.clearTid, -1);
    }
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(
        `exit: thread ${thread.tid} of ${proc.pid} status ${thread.code} clearTid=0x${thread.clearTid.toString(16)}`,
      );
    }
    const live = proc.threads.filter((t) => t.state !== "exited");
    if (live.length === 0) return this.exit(proc, code, signal);
    thread.pending = null;
    return 0;
  }

  exit(proc, code, signal = 0) {
    if (proc.state === "exited") return 0;
    proc.state = "exited";
    proc.code = code & 0xff;
    proc.signal = signal & 0x7f;
    for (const t of proc.threads) t.state = "exited";
    proc.kernel.files.closeAll();
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(`exit: ${proc.pid} ${proc.signal ? `signal ${proc.signal}` : `status ${proc.code}`}`);
    }
    // A parent that was waiting for this one has something to see now, and a pipe this process
    // held the last writer of has reached its end.
    this.wake(proc);
    this.poll();
    return 0;
  }

  stuck() {
    const blocked = this.processes.flatMap((p) =>
      p.threads.filter((t) => t.state === "blocked").map((t) => ({ p, t })),
    );
    console.error(`armjit: nothing left to run but ${blocked.length} blocked thread(s)`);
    for (const { p, t } of blocked) {
      console.error(`  pid ${p.pid} thread ${t.tid} waits for ${this.reason(t)}`);
    }
    // The descriptors each process holds, because a deadlock between two of them is usually a pipe
    // whose two ends are not where the program thinks.
    for (const proc of this.processes) {
      if (proc.state === "exited") continue;
      console.error(`  pid ${proc.pid} fds ${this.describeFds(proc)}`);
    }
    return 1;
  }
}
