// Host side of the armjit PoC: loads a translated module, provides the kernel the guest talks to,
// runs it. ARMJIT_ROOTFS names the directory the guest sees as /.
//
// The Linux ABI contract lives in host/syscall.mjs. Everything here is the process boundary: read
// the metadata the translator wrote next to the module, instantiate, run from the entry with the
// initial stack, and report how the run ended.

import fs from "node:fs";
import { Translator } from "./host/pages.mjs";
import { Session } from "./host/session.mjs";
import { terminal } from "./host/files.mjs";

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: node run.mjs <module.wasm>");
  process.exit(2);
}

const meta = JSON.parse(fs.readFileSync(`${wasmPath}.json`, "utf8"));
const bytes = fs.readFileSync(wasmPath);

let memory = null;
let kernel = null;

// Every report below reads the process the guest is in when it happens, so the hooks that make a
// process hand over the globals first.
function enter(proc) {
  memory = proc.memory;
  kernel = proc.kernel;
  ranges = kernel.space.images;
}

// The guest's state as the translator left it in the shadow: a run that stopped without a syscall
// says what it was doing here, and nothing else does.
function state() {
  const view = new DataView(memory.buffer);
  const regs = [];
  for (let i = 0; i < 31; i++) regs.push(view.getBigInt64(i * 8, true));
  return (
    `  pc=${where(view.getInt32(0x108, true) >>> 0)} sp=0x${view.getBigUint64(0xf8, true).toString(16)} ` +
    `nzcv=0x${view.getBigUint64(0x100, true).toString(16)} tp=0x${view.getBigUint64(0x110, true).toString(16)}\n` +
    `  ${regs.map((v, i) => `x${i}=0x${v.toString(16)}`).join(" ")}`
  );
}

// The last `n` dispatched pcs, which a module translated with --trace keeps in a ring.
function ring(n) {
  const view = new DataView(memory.buffer);
  const idx = view.getInt32(0x1fc, true);
  const pcs = [];
  for (let k = Math.max(0, idx - n); k < idx; k++) {
    pcs.push(view.getInt32(0x200 + (k & 255) * 4, true) >>> 0);
  }
  return pcs;
}

/// A guest access the pages did not allow, or an address that is not memory at all. It is a fault
/// and not a report: the process is the one the kernel would have killed, and the state it was in
/// is worth printing only when the runtime is asked for it.
class GuestFault {
  constructor(kind, addr, at) {
    this.kind = kind;
    this.addr = Number(BigInt.asUintN(64, addr));
    this.at = at >>> 0;
  }
}

/// The signal a fault raises, and what to call it in a report.
function faultOf(kind) {
  switch (kind) {
    case 1: return { signal: 11, what: "an address past the end of memory" };
    case 2: return { signal: 11, what: "a stack pointer outside its mapping" };
    case 4: return { signal: 11, what: "a load from a page that is not mapped" };
    case 5: return { signal: 11, what: "a store to a page that is not writable" };
    case 6: return { signal: 11, what: "execution of a page that is not executable" };
    default: return null;
  }
}

function trap(kind, addr, at) {
  // The address is a 64-bit guest address: a load whose base went wrong carries the high half, and
  // truncating it to 32 bits reports an address that is inside the image.
  const at64 = BigInt.asUintN(64, addr);
  throw new Error(
    `guest pc trail: ${ring(24).map(where).join(" -> ")}\n` +
      `guest trap ${Number(kind)} at address 0x${at64.toString(16)}` +
      (at64 < 1n << 32n ? ` (${where(Number(at64))})` : "") +
      ` from ${where(at >>> 0)}\n` +
      state() +
      "\n" + backtrace() +
      memory_dump(),
  );
}

// The instruction history a module translated with --trace leaves in the host: the ring in memory
// records dispatched blocks, and a wrong value needs the instructions that made it. A ring rather
// than a growing array, because removing the oldest entry of a million-element array copies it,
// and that costs a memmove per instruction.
const recent = new Int32Array(1 << 20);
const recentMask = recent.length - 1;
let recentLen = 0;
function recentAdd(pc) {
  recent[recentLen++ & recentMask] = pc;
}
/** The last `n` pcs, oldest first. */
function recentTail(n) {
  const count = Math.min(recentLen, recent.length, n);
  const out = new Array(count);
  for (let k = 0; k < count; k++) out[k] = recent[(recentLen - count + k) & recentMask];
  return out;
}
// ARMJIT_TRACE_PRINT prints the state *before* each instruction, which is what the translator wrote
// to the shadow: pc, packed NZCV and the registers named in ARMJIT_TRACE_REGS.
const traceRegs = (process.env.ARMJIT_TRACE_REGS || "8").split(",").map(Number);
// ARMJIT_WATCH_PC=0xADDR[:SKIP[:MAX]],... ARMJIT_WATCH_DUMP=0xADDR:LEN,... or xN+0xNN:LEN reads guest memory
// the time that instruction runs, once the first SKIP hits have gone by, MAX of them at most. Each hit
// also reports the call chain the frame pointers describe, because the caller is what says which call
// this is. An address is absolute, or `image+0xNN` for an offset inside the image whose path holds
// `image`, which is how a shared object's own code gets named before the load address of the run is
// known.
const watches = (process.env.ARMJIT_WATCH_PC || "")
  .split(",")
  .filter(Boolean)
  .map((s) => {
    const [at, skip, max] = s.split(":");
    const img = /^(.+)\+0x([0-9a-f]+)$/.exec(at);
    return {
      image: img ? img[1] : null,
      at: img ? parseInt(img[2], 16) : parseInt(at, 16),
      pc: img ? null : parseInt(at, 16),
      skip: skip ? parseInt(skip, 10) : 0,
      max: max ? parseInt(max, 10) : Infinity,
      hits: 0,
    };
  });
function watchAddress(w) {
  if (w.pc !== null) return w.pc;
  for (const m of ranges) if (m.host.includes(w.image)) return (w.pc = m.base + w.at);
  return NaN;
}
const watchVecRegs = (process.env.ARMJIT_WATCH_VREGS || "0,1").split(",").filter(Boolean).map(Number);
// A dump address is absolute, `sp+0xNN`, or a register plus an offset, because the frame a value
// lives in is only known once the run is there.
const watchRanges = (process.env.ARMJIT_WATCH_DUMP || "")
  .split(",")
  .filter(Boolean)
  .map((s) => {
    const [at, len] = s.split(":");
    const m = /^(sp|x(\d+))(?:(\+|-)(0x[0-9a-f]+))?$/.exec(at);
    const range = m
      ? { reg: m[1] === "sp" ? -1 : Number(m[2]), off: m[4] ? (m[3] === "-" ? -1 : 1) * parseInt(m[4], 16) : 0 }
      : { reg: null, at: parseInt(at, 16), off: 0 };
    return { ...range, len: parseInt(len, 16) };
  });

function dumpAddress({ reg, at, off }) {
  const view = new DataView(memory.buffer);
  if (reg === null) return at + off;
  return Number(view.getBigUint64((reg < 0 ? 0xf8 : reg * 8), true)) + off;
}
// ARMJIT_WATCH_MEM=0xADDR reports the instruction after which those eight bytes change, which is
// the only way to find what wrote to a guest address.
const watchMem = process.env.ARMJIT_WATCH_MEM ? parseInt(process.env.ARMJIT_WATCH_MEM, 16) : null;
let watchedValue = null;
function watchWrite(pc) {
  const bytes = kernel.read(watchMem, 8);
  if (bytes === null) return;
  const value = bytes.readBigUInt64LE(0);
  if (watchedValue === null) watchedValue = value;
  else if (value !== watchedValue) {
    console.error(
      `write 0x${watchMem.toString(16)}: 0x${watchedValue.toString(16)} -> 0x${value.toString(16)} at pc 0x${pc.toString(16)}`,
    );
    watchedValue = value;
  }
}
function watch(pc) {
  if (watchMem !== null) watchWrite(pc);
  for (const w of watches) {
    if (watchAddress(w) !== pc) continue;
    if (w.hits++ < w.skip) continue;
    if (w.hits > w.skip + w.max) continue;
    report(pc);
  }
}

// Which image a guest address is in, so a report names code instead of an address.
let ranges = [];
function where(pc) {
  for (const m of ranges) {
    if (pc >= m.lo && pc < m.hi) {
      return `${m.host.split("/").pop()}+0x${(pc - m.base).toString(16)}`;
    }
  }
  return `0x${pc.toString(16)}`;
}

// The frame-pointer chain the guest keeps: x29 holds the caller's x29, and the word above it the
// return address, which is how a wrapped `bl` can still be named.
function backtrace() {
  const view = new DataView(memory.buffer);
  const word = (at) => {
    const bytes = kernel.read(at, 8);
    return bytes === null ? 0 : Number(bytes.readBigUInt64LE(0));
  };
  const fps = [word(29 * 8)];
  let fp = fps[0];
  for (let depth = 1; depth < 32; depth++) {
    if (fp <= 0x1000) break;
    const next = word(fp);
    fps.push(next);
    if (next <= fp) break;
    fp = next;
  }
  const lines = [`  #0 at ${where(view.getInt32(0x108, true) >>> 0)} lr=${where(word(30 * 8))}`];
  for (let depth = 1; depth < fps.length; depth++) {
    const at = fps[depth - 1];
    if (at <= 0x1000) break;
    const ret = word(at + 8);
    lines.push(`  #${depth} from ${where(ret)}`);
    if (ret === 0) break;
  }
  return lines.join("\n");
}

// A guest string, when the word it starts at is plausibly one, so an argument that is a format
// string reads as text.
function cstr(at) {
  if (at < 0x1000) return null;
  const bytes = kernel.read(at, 200);
  if (bytes === null) return null;
  const end = bytes.indexOf(0);
  if (end < 0) return null;
  const text = bytes.subarray(0, end);
  const printable = text.every((b) => b === 9 || b === 10 || (b >= 32 && b < 127));
  return printable ? JSON.stringify(text.toString("latin1")) : null;
}

const ARM_RING = Number(process.env.ARMJIT_LAST || 24);
// Where the time went in the last `n` instructions, which is how a loop this large shows itself.
function hot(n) {
  const counts = new Map();
  for (const pc of recentTail(n)) counts.set(pc, (counts.get(pc) ?? 0) + 1);
  return [...counts]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([pc, c]) => `${where(pc)} x${c}`)
    .join(", ");
}

// The memory named by ARMJIT_WATCH_DUMP, for a report of any kind.
function memory_dump() {
  let out = "";
  for (const range of watchRanges) {
    const from = dumpAddress(range);
    const slice = kernel.read(from, range.len);
    if (slice === null) continue;
    out += `\n  mem 0x${from.toString(16)}: ${slice.toString("hex")} ${JSON.stringify(slice.toString("latin1"))}`;
  }
  return out;
}

function report(pc) {
  const view = new DataView(memory.buffer);
  const args = [];
  for (let i = 0; i < 8; i++) args.push(view.getBigUint64(i * 8, true));
  console.error(`watch at ${where(pc)} hit ${watches.find((w) => w.pc === pc).hits} sp=0x${view.getBigUint64(0xf8, true).toString(16)}`);
  console.error(`  ${args.map((v, i) => `x${i}=0x${v.toString(16)}`).join(" ")}`);
  for (let i = 0; i < 6; i++) {
    const text = cstr(Number(args[i]));
    if (text !== null) console.error(`  x${i} -> ${text}`);
  }
  for (const range of watchRanges) {
    const from = dumpAddress(range);
    const slice = kernel.read(from, range.len);
    if (slice === null) continue;
    console.error(`  mem 0x${from.toString(16)}: ${slice.toString("hex")} ${JSON.stringify(slice.toString("latin1"))}`);
  }
  console.error(state());
  // The FP argument and result of a conversion is what a report of the integer registers leaves out.
  const vecs = [];
  for (const r of watchVecRegs) {
    const off = 0x600 + r * 16;
    vecs.push(
      `v${r}=[${view.getFloat64(off, true)}, ${view.getFloat32(off, true)}f32]` +
        ` 0x${view.getBigUint64(off, true).toString(16)}:${view.getBigUint64(off + 8, true).toString(16)}`,
    );
  }
  console.error(`  ${vecs.join(" ")}`);
  console.error(backtrace());
  console.error(`  ring ${ring(40).map(where).join(" -> ")}`);
  console.error(`  last ${recentTail(ARM_RING).map(where).join(" -> ")}`);
}
// ARMJIT_HEARTBEAT=SECONDS reports where the guest is every so often, and ARMJIT_SPIN=N where one
// instruction has run N times in the last few thousand. Both exist because the wasm call does not
// return while a guest spins, so this hook is the only place the host sees it at all.
const spin = process.env.ARMJIT_SPIN ? Number(process.env.ARMJIT_SPIN) : 0;
const heartbeat = process.env.ARMJIT_HEARTBEAT ? Number(process.env.ARMJIT_HEARTBEAT) * 1000 : 0;
const startedAt = Date.now();
let beat = startedAt;
let ticks = 0;
const spins = new Map();
function trace2(pc, sp) {
  const at = pc >>> 0;
  recentAdd(at);
  if (spin) {
    spins.set(at, (spins.get(at) ?? 0) + 1);
    if (recentLen > 4096) {
      const old = recent[(recentLen - 4097) & recentMask];
      spins.set(old, spins.get(old) - 1);
    }
    const n = spins.get(at);
    if (n > spin) {
      const window = Math.min(recentLen, recent.length);
      throw new Error(
        `spin: ${where(at)} ran ${n} times in ${window} instructions\n` +
          state() +
          "\n" + backtrace() +
          memory_dump() +
          `\n  trail ${recentTail(32).map(where).join(" -> ")}`,
      );
    }
  }
  if (heartbeat && (++ticks & 0xfff) === 0 && Date.now() - beat > heartbeat) {
    beat = Date.now();
    console.error(
      `heartbeat ${((beat - startedAt) / 1000).toFixed(0)}s at ${where(at)} 0x${at.toString(16)}` +
        `\n  trail ${recentTail(16).map(where).join(" -> ")}` +
        "\n" + backtrace() +
        "\n" + state() +
        "\n  hot " + hot(4096),
    );
  }
  watch(at);
  if (!process.env.ARMJIT_TRACE_PRINT) return;
  const view = new DataView(memory.buffer);
  const regs = traceRegs.map((r) => `x${r}=0x${view.getBigUint64(r * 8, true).toString(16)}`);
  const nzcv = view.getBigUint64(0x100, true);
  console.log(`0x${(pc >>> 0).toString(16)} nzcv=0x${nzcv.toString(16)} sp=0x${BigInt.asUintN(64, sp).toString(16)} ${regs.join(" ")}`);
}

// The three calls the guest makes into the host, bound to one process: a fork has its own memory
// and its own kernel, and the same module bytes instantiated a second time.
function makeImports(proc) {
  return {
    syscall: (nr, a0, a1, a2, a3, a4, a5) => {
      enter(proc);
      if (process.env.ARMJIT_TRACE_WRITES && Number(nr) === 64) {
        const bytes = kernel.read(a1, Number(a2));
        const hex = bytes ? Buffer.from(bytes).toString("hex") : "?";
        const text = bytes ? JSON.stringify(Buffer.from(bytes).toString("latin1")) : "";
        console.error(`write fd=${a0} n=${a2} ${hex} ${text}`);
      }
      if (process.env.ARMJIT_TRACE_SYSCALLS) {
        const view = new DataView(memory.buffer);
        const pc = view.getUint32(0xf8 + 16, true) >>> 0;
        const args = [a0, a1, a2, a3, a4, a5].map((v) => `0x${BigInt(v).toString(16)}`).join(" ");
        console.error(`syscall ${nr} from ${where(pc)}: ${args}`);
      }
      const mark = proc.usage.mark();
      const answer = kernel.call(nr, a0, a1, a2, a3, a4, a5);
      // A syscall is the kernel's work on the guest's behalf, so the time inside it is its system
      // time. The run brackets it with the same clock and takes it back off the user time.
      proc.usage.charge(mark);
      if (Array.isArray(answer)) return [answer[0], answer[1]];
      // The host has to act, which it cannot do from inside this call: the run returns and the
      // scheduler resumes it with x0 holding the answer.
      kernel.pending = answer.host;
      return [0n, 1];
    },
    poll: () => {
      enter(proc);
      const mark = proc.usage.mark();
      const answer = session.pollPoint(proc);
      proc.usage.charge(mark);
      return answer;
    },
    trap: (kind, addr, at) => {
      enter(proc);
      const fault = faultOf(Number(kind));
      if (!fault) trap(kind, addr, at);
      const f = new GuestFault(Number(kind), addr, at);
      Object.assign(f, fault);
      throw f;
    },
    trace2: (pc, sp) => {
      enter(proc);
      trace2(pc, sp);
    },
  };
}

const module = new WebAssembly.Module(bytes);

const rootfs = process.env.ARMJIT_ROOTFS;
const translator = new Translator(process.env.ARMJIT_TRANSLATOR || "./target/release/armjit");
const configured = await translator.configure({
  bounds: meta.bounds === 1,
  trace: meta.trace === 1,
  traceLoops: meta.trace_loops === 1,
  memPages: meta.mem_pages,
  rootfs,
});
if (!configured.ok) {
  console.error(`armjit: translator did not start: ${configured.error}`);
  process.exit(1);
}

const session = new Session({ translator, rootfs, makeImports });
const root = session.spawn({ module, meta });
enter(root);
if (process.env.ARMJIT_DUMP_STACK) {
  const at = Number(BigInt(meta.sp));
  for (let i = 0; i < 16; i++) {
    const bytes = kernel.read(at + i * 8, 8);
    if (bytes === null) break;
    console.error(`sp+${i * 8}: 0x${bytes.readBigUInt64LE(0).toString(16)} ${JSON.stringify(bytes.toString("latin1"))}`);
  }
}

// The console: a guest that reads fd 0 waits on the host's own input, which node delivers while
// the scheduler waits for something. Off by default, because a test that runs a program which reads
// its input would otherwise wait for a line nobody is going to type.
if (process.env.ARMJIT_CONSOLE) {
  terminal.live = true;
  // The host's terminal is in raw mode for the whole session: this process is the one holding it, so
  // a cooked terminal would do the line discipline for a guest that asked to do it itself, and its
  // interrupt character would end this process instead of the command the guest is running.
  terminal.viaTty = Boolean(process.stdin.isTTY);
  if (process.stdin.isTTY) process.stdin.setRawMode(true);
  terminal.onSignal = (sig) => session.interrupt(sig);
  process.stdin.on("data", (chunk) => {
    terminal.feed(chunk);
    session.poll();
  });
  process.stdin.on("end", () => {
    terminal.closed = true;
    session.poll();
  });
  process.stdin.resume();
  // Leaving the terminal raw would follow the shell back to the prompt it was started from.
  process.on("exit", () => {
    if (process.stdin.isTTY) process.stdin.setRawMode(false);
  });
}

const started = process.hrtime.bigint();
const code = await session.run();
const elapsed = process.hrtime.bigint();
translator.stop();
if (code === 4) {
  console.error(`watchdog: still running after ${process.env.ARMJIT_WATCHDOG}s`);
  console.error(`  last pcs: ${ring(32).map(where).join(" -> ")}`);
  console.error(state());
  process.exit(4);
}
if (process.env.ARMJIT_TIME) {
  console.error(`guest run ${Number(elapsed - started) / 1e6} ms`);
}

process.exit(code);
