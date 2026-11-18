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
import { Kernel, ECHILD, EBADF, EFAULT } from "./syscall.mjs";
import { WOULD_BLOCK, ENOENT, EACCES } from "./files.mjs";
import { Net } from "./net.mjs";
import { Resolver } from "./dns.mjs";
import { Mach } from "./pages.mjs";

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

export class Session {
  constructor({ translator, rootfs, makeImports }) {
    this.translator = translator;
    this.rootfs = rootfs;
    this.makeImports = makeImports;
    this.processes = [];
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
      wake: () => this.poll(),
      futexWake: (addr, n) => this.futexWake(proc, addr, n),
    });
    for (const image of proc.meta.images ?? []) proc.kernel.space.images.push(image);
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
      if (this.root.state === "exited") return this.root.code;
      const pick = this.pick();
      if (!pick) {
        // Nothing can run, but a packet still can arrive: the host's event loop only turns while
        // this waits, and a guest blocked on a socket would otherwise never be woken.
        if (this.socketsWaiting()) {
          await this.net.next();
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

  /// Whether any thread is parked on the network.
  socketsWaiting() {
    return this.processes.some((p) => p.threads.some((t) => t.state === "blocked" && t.waitingFor === "socket"));
  }

  /// The next thread to run, and the process it belongs to. Threads are what a scheduler picks:
  /// a process whose threads are all waiting is waiting, and one with a runnable thread runs it.
  pick() {
    for (const proc of this.processes) {
      if (proc.state === "exited") continue;
      const thread = proc.threads.find((t) => t.state === "runnable");
      if (thread) return { proc, thread };
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
    // A syscall that was waiting is answered here, not by running the guest's code again: the
    // function it was in pushed a frame before the svc, and a second entry would push another.
    if (thread.pending) {
      const request = thread.pending;
      thread.pending = null;
      return this.answer(proc, thread, request);
    }
    let status;
    if (thread.entry) {
      thread.entry = false;
      status = proc.instance.exports.run(proc.meta.entry, BigInt(proc.meta.sp), 0);
    } else {
      status = proc.instance.exports.run(0, 0n, 1);
    }
    while (status === 2) {
      const pc = proc.mach.view.getUint32(SHADOW_PC, true) >>> 0;
      if (!proc.kernel.space.imageOf(pc)) {
        console.error(`armjit: pid ${proc.pid} jumped to untranslated address 0x${pc.toString(16)}`);
        return 1;
      }
      status = await proc.mach.translateAndResume(pc);
    }
    if (status === 1) return this.serve(proc, thread);
    if (status === 0) return this.exitedBySyscall(proc, thread, proc.kernel.exited ?? 0);
    console.error(`armjit: pid ${proc.pid} stopped with status ${status}`);
    return 1;
  }

  /// A syscall gave up the wasm call: do what it asked, then answer it.
  serve(proc, thread) {
    const kernel = proc.kernel;
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
      case "poll":
        return this.pollWait(proc, thread, request);
      case "select":
        return this.selectWait(proc, thread, request);
      case "futex":
        return this.futex(proc, thread, request);
      default:
        console.error(`armjit: pid ${proc.pid} asked for an unknown host action ${request.kind}`);
        return 1;
    }
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
  park(thread, request, deadline) {
    this.block(thread, request.fd ?? 0, "socket");
    thread.pending = request;
    if (!deadline) return;
    const timer = setTimeout(() => {
      if (thread.pending === request) thread.state = "runnable";
    }, Math.max(0, deadline - Date.now()));
    timer.unref?.();
  }

  /// A receive there was nothing for: answer it from what has arrived since, or keep waiting.
  recv(proc, thread, request) {
    const answer = proc.kernel.recvInto(request.fd, request.buf, request.len, request.flags, request.addr, request.lenp);
    if (answer && answer.host) {
      this.park(thread, request, request.deadline);
      return 0;
    }
    return this.resume(proc, thread, answer);
  }

  /// A receive into a message header there was nothing for.
  recvMsg(proc, thread, request) {
    const answer = proc.kernel.recvMsgInto(request.fd, request.msg, request.flags);
    if (answer && answer.host) {
      this.park(thread, request, request.deadline);
      return 0;
    }
    return this.resume(proc, thread, answer);
  }

  /// The same, for the array of headers a resolver reads its answers into.
  recvMMsg(proc, thread, request) {
    const answer = proc.kernel.recvMMsgInto(request.fd, request.vec, request.vlen, request.flags, request.deadline);
    if (answer && answer.host) {
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
    const answer = await desc.connect(request.addr);
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

  /// The whole of the parent's memory that exists: the engine area, which holds the page and
  /// dispatch tables, and every page the page table says is mapped. Rest is zero in both.
  copyMemory(from, to) {
    const src = new Uint8Array(from.memory.buffer);
    const dst = new Uint8Array(to.memory.buffer);
    const ptes = new Uint8Array(from.memory.buffer, from.meta.pte_base, 1 << 20);
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

  async exec(proc, thread, request) {
    const path = request.path.toString("latin1");
    const host = proc.kernel.files.resolve(path);
    if (typeof host === "number") return this.resume(proc, thread, host);
    let answer;
    try {
      const st = fs.statSync(host);
      // A directory and a file without the execute bit are both EACCES, and a path that is not
      // there is ENOENT: `execvp` walks PATH on ENOENT and EACCES, and runs the file through a
      // shell on ENOEXEC, so answering the wrong one turns a missing program into a shell script.
      if (!st.isFile()) return this.resume(proc, thread, -EACCES);
      fs.accessSync(host, fs.constants.X_OK);
    } catch (e) {
      if (process.env.ARMJIT_TRACE_PROCESSES) console.error(`exec ${path}: ${e.code}`);
      return this.resume(proc, thread, -(e.code === "ENOENT" ? ENOENT : EACCES));
    }
    try {
      answer = await this.translator.image(host, request.argv, request.envp);
    } catch (e) {
      if (process.env.ARMJIT_TRACE_PROCESSES) console.error(`exec ${path}: ${e.message}`);
      return this.resume(proc, thread, -ENOEXEC);
    }
    if (!answer.ok) {
      console.error(`armjit: cannot run ${path}: ${answer.error}`);
      return this.resume(proc, thread, -ENOEXEC);
    }
    const meta = answer.meta;
    // What survives an exec: the descriptor table (less close-on-exec entries) and the cwd. The
    // address space, the page tables and every translation in them do not.
    const files = proc.kernel.files;
    files.keepAcrossExec();
    proc.module = new WebAssembly.Module(Buffer.from(answer.wasm, "hex"));
    proc.meta = meta;
    this.instantiate(proc, files);
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
      console.error(`exec: ${proc.pid} ${path} at 0x${meta.entry.toString(16)}`);
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
    if (thread.waitingFor === "pipe") return "a pipe";
    if (thread.waitingFor === "futex") return `futex 0x${thread.blockedOn.toString(16)}`;
    if (thread.waitingFor === "socket") {
      const kind = thread.pending?.kind;
      if (kind === "poll" || kind === "select") return `a socket (${kind})`;
      return `socket ${thread.pending?.fd ?? thread.blockedOn}`;
    }
    return thread.blockedOn <= 0 ? "any child" : thread.blockedOn;
  }

  /// A pipe read that had nothing in it: answer it now, or keep waiting.
  read(proc, thread, request) {
    const got = proc.kernel.files.read(request.fd, request.len);
    if (got === WOULD_BLOCK) {
      this.block(thread, 0, "pipe");
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
        if (thread.waitingFor === "socket") thread.state = "runnable";
        else if (thread.waitingFor === "pipe" && proc.kernel.files.readReady(thread.pending.fd)) {
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
    if (request.wstatus) view.setInt32(request.wstatus, (child.code & 0xff) << 8, true);
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
  exitThread(proc, thread, code) {
    thread.state = "exited";
    thread.code = code & 0xff;
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
    if (live.length === 0) return this.exit(proc, code);
    thread.pending = null;
    return 0;
  }

  exit(proc, code) {
    proc.state = "exited";
    proc.code = code & 0xff;
    for (const t of proc.threads) t.state = "exited";
    proc.kernel.files.closeAll();
    if (process.env.ARMJIT_TRACE_PROCESSES) console.error(`exit: ${proc.pid} status ${proc.code}`);
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
    return 1;
  }
}
