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
import { Kernel, ECHILD } from "./syscall.mjs";
import { Mach } from "./pages.mjs";

const SHADOW = 0x0;
const SHADOW_PC = 0x108;

const CLONE_PARENT_SETTID = 0x00100000;
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
  }

  /// A process running an image from its entry point.
  spawn({ module, meta }, parent = null) {
    const proc = {
      pid: this.nextPid++,
      ppid: parent ? parent.pid : 0,
      module,
      meta,
      entry: true,
      state: "runnable",
      code: null,
      blockedOn: 0,
    };
    this.instantiate(proc);
    this.processes.push(proc);
    if (!parent) this.root = proc;
    return proc;
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
      const proc = this.processes.find((p) => p.state === "runnable");
      if (!proc) return this.stuck();
      if (after && Date.now() - startedAt > after) return 4;
      const verdict = await this.step(proc);
      if (verdict !== 0) return verdict;
    }
  }

  /// One entry into the guest, run until it exits, asks the host, or jumps somewhere untranslated.
  async step(proc) {
    let status;
    if (proc.entry) {
      proc.entry = false;
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
    if (status === 1) return this.serve(proc);
    if (status === 0) return this.exit(proc, proc.kernel.exited ?? 0);
    console.error(`armjit: pid ${proc.pid} stopped with status ${status}`);
    return 1;
  }

  /// A syscall gave up the wasm call: do what it asked, then answer it.
  serve(proc) {
    const kernel = proc.kernel;
    const request = kernel.pending;
    kernel.pending = null;
    if (kernel.exited !== null) return this.exit(proc, kernel.exited);
    if (!request) {
      console.error(`armjit: pid ${proc.pid} returned from a syscall with no request`);
      return 1;
    }
    switch (request.kind) {
      case "fork":
        return this.fork(proc, request);
      case "exec":
        return this.exec(proc, request);
      case "wait":
        return this.wait(proc, request);
      default:
        console.error(`armjit: pid ${proc.pid} asked for an unknown host action ${request.kind}`);
        return 1;
    }
  }

  /// x0 is the syscall's answer and the guest continues after the `svc`, whose address the shadow
  /// holds because the yield returned before the emitter stored x0.
  resume(proc, value) {
    const view = new DataView(proc.memory.buffer);
    view.setBigInt64(SHADOW, BigInt.asIntN(64, BigInt(value)), true);
    view.setUint32(SHADOW_PC, view.getUint32(SHADOW_PC, true) + 4, true);
    proc.state = "runnable";
    return 0;
  }

  fork(parent, request) {
    const child = {
      pid: this.nextPid++,
      ppid: parent.pid,
      module: parent.module,
      meta: parent.meta,
      entry: false,
      state: "runnable",
      code: null,
      blockedOn: 0,
    };
    this.instantiate(child);
    child.kernel.adopt(parent.kernel.forkState());
    this.copyMemory(parent, child);
    child.mach.adopt(parent.mach.lineage, parent.mach);

    // The child's fork returns zero, from the instruction after the svc.
    const from = new DataView(parent.memory.buffer);
    const view = new DataView(child.memory.buffer);
    const after = from.getUint32(SHADOW_PC, true) + 4;
    view.setBigInt64(SHADOW, 0n, true);
    view.setUint32(SHADOW_PC, after, true);
    if (request.flags & CLONE_CHILD_SETTID && request.ctid) {
      view.setUint32(request.ctid, child.pid, true);
    }
    if (request.flags & CLONE_PARENT_SETTID && request.ptid) {
      from.setUint32(request.ptid, child.pid, true);
    }
    this.processes.push(child);
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(`fork: ${parent.pid} -> ${child.pid}`);
    }
    return this.resume(parent, child.pid);
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
      const at = lo << 12;
      const len = (i - lo) << 12;
      dst.set(src.subarray(at, at + len), at);
    }
  }

  async exec(proc, request) {
    const path = request.path.toString("latin1");
    const host = proc.kernel.files.resolve(path);
    if (typeof host === "number") return this.resume(proc, host);
    let answer;
    try {
      fs.accessSync(host, fs.constants.R_OK);
      answer = await this.translator.image(host, request.argv, request.envp);
    } catch (e) {
      if (process.env.ARMJIT_TRACE_PROCESSES) console.error(`exec ${path}: ${e.message}`);
      return this.resume(proc, -ENOEXEC);
    }
    if (!answer.ok) {
      console.error(`armjit: cannot run ${path}: ${answer.error}`);
      return this.resume(proc, -ENOEXEC);
    }
    const meta = JSON.parse(answer.meta);
    // What survives an exec: the descriptor table (less close-on-exec entries) and the cwd. The
    // address space, the page tables and every translation in them do not.
    const files = proc.kernel.files;
    files.keepAcrossExec();
    proc.module = new WebAssembly.Module(Buffer.from(answer.wasm, "hex"));
    proc.meta = meta;
    this.instantiate(proc, files);
    proc.entry = true;
    proc.state = "runnable";
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(`exec: ${proc.pid} ${path} at 0x${meta.entry.toString(16)}`);
    }
    return 0;
  }

  wait(proc, request) {
    const kids = this.processes.filter(
      (c) => c.ppid === proc.pid && (request.pid <= 0 || c.pid === request.pid),
    );
    if (kids.length === 0) return this.resume(proc, -ECHILD);
    const done = kids.find((c) => c.state === "exited" && !c.reaped);
    if (done) {
      this.reap(proc, done, request);
      return this.resume(proc, done.pid);
    }
    if (request.options & WNOHANG) return this.resume(proc, 0);
    proc.state = "blocked";
    proc.blockedOn = request.pid;
    if (process.env.ARMJIT_TRACE_PROCESSES) {
      console.error(`wait: ${proc.pid} blocks on ${request.pid}`);
    }
    return 0;
  }

  /// The wait status a real kernel would give, and the rusage a program that asks for one reads.
  reap(parent, child, request) {
    const view = new DataView(parent.memory.buffer);
    if (request.wstatus) view.setInt32(request.wstatus, (child.code & 0xff) << 8, true);
    if (request.rusage) new Uint8Array(parent.memory.buffer).fill(0, request.rusage, request.rusage + 144);
    child.reaped = true;
  }

  exit(proc, code) {
    proc.state = "exited";
    proc.code = code & 0xff;
    if (process.env.ARMJIT_TRACE_PROCESSES) console.error(`exit: ${proc.pid} status ${proc.code}`);
    // A parent that was waiting for this one has something to see now.
    for (const q of this.processes) {
      if (q.state === "blocked" && proc.ppid === q.pid && (q.blockedOn <= 0 || q.blockedOn === proc.pid)) {
        q.state = "runnable";
      }
    }
    return 0;
  }

  stuck() {
    const blocked = this.processes.filter((p) => p.state === "blocked");
    console.error(`armjit: nothing left to run but ${blocked.length} blocked process(es)`);
    for (const p of blocked) {
      console.error(`  pid ${p.pid} waits for ${p.blockedOn <= 0 ? "any child" : p.blockedOn}`);
    }
    return 1;
  }
}
