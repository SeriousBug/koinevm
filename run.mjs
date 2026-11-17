// Host side of the armjit PoC: loads a translated module, provides the kernel the guest talks to,
// runs it. ARMJIT_ROOTFS names the directory the guest sees as /.
//
// The Linux ABI contract lives in host/syscall.mjs. Everything here is the process boundary: read
// the metadata the translator wrote next to the module, instantiate, run from the entry with the
// initial stack, and report how the run ended.

import fs from "node:fs";
import { Kernel } from "./host/syscall.mjs";
import { Mach, Translator } from "./host/pages.mjs";

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: node run.mjs <module.wasm>");
  process.exit(2);
}

const meta = JSON.parse(fs.readFileSync(`${wasmPath}.json`, "utf8"));
const bytes = fs.readFileSync(wasmPath);

let memory = null;
let kernel = null;

// The guest's state as the translator left it in the shadow: a run that stopped without a syscall
// says what it was doing here, and nothing else does.
function state() {
  const view = new DataView(memory.buffer);
  const regs = [];
  for (let i = 0; i < 31; i++) regs.push(view.getBigInt64(i * 8, true));
  return (
    `  pc=${where(view.getInt32(0x108, true) >>> 0)} sp=0x${view.getBigUint64(0xf8, true).toString(16)} ` +
    `nzcv=0x${view.getBigUint64(0x100, true).toString(16)}\n` +
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

function trap(kind, addr, at) {
  throw new Error(
    `guest pc trail: ${ring(24).map(where).join(" -> ")}\n` +
      `guest trap ${Number(kind)} at address 0x${Number(addr).toString(16)} from 0x${(at >>> 0).toString(16)}\n` +
      state(),
  );
}

// The instruction history a module translated with --trace leaves in the host: the ring in memory
// records dispatched blocks, and a wrong value needs the instructions that made it.
const recent = [];
// ARMJIT_TRACE_PRINT prints the state *before* each instruction, which is what the translator wrote
// to the shadow: pc, packed NZCV and the registers named in ARMJIT_TRACE_REGS.
const traceRegs = (process.env.ARMJIT_TRACE_REGS || "8").split(",").map(Number);
// ARMJIT_WATCH_PC=0xADDR[:SKIP],... ARMJIT_WATCH_DUMP=0xADDR:LEN,... reads guest memory the time
// that instruction runs, once the first SKIP hits have gone by. Each hit also reports the call chain
// the frame pointers describe, because the caller is what says which call this is.
const watches = (process.env.ARMJIT_WATCH_PC || "")
  .split(",")
  .filter(Boolean)
  .map((s) => {
    const [at, skip] = s.split(":");
    return { pc: parseInt(at, 16), skip: skip ? parseInt(skip, 10) : 0, hits: 0 };
  });
const watchRanges = (process.env.ARMJIT_WATCH_DUMP || "")
  .split(",")
  .filter(Boolean)
  .map((s) => {
    const [at, len] = s.split(":");
    return [at.startsWith("sp+") ? -parseInt(at.slice(3), 16) : parseInt(at, 16), parseInt(len, 16)];
  });
// ARMJIT_WATCH_MEM=0xADDR reports the instruction after which those eight bytes change, which is
// the only way to find what wrote to a guest address.
const watchMem = process.env.ARMJIT_WATCH_MEM ? parseInt(process.env.ARMJIT_WATCH_MEM, 16) : null;
let watchedValue = null;
function watchWrite(pc) {
  const value = new DataView(memory.buffer).getBigUint64(watchMem, true);
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
    if (w.pc !== pc) continue;
    if (w.hits++ < w.skip) continue;
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
  const size = memory.buffer.byteLength;
  const fps = [Number(view.getBigUint64(29 * 8, true))];
  let fp = fps[0];
  for (let depth = 1; depth < 32; depth++) {
    if (fp <= 0x1000 || fp + 16 > size) break;
    const next = Number(view.getBigUint64(fp, true));
    fps.push(next);
    if (next <= fp) break;
    fp = next;
  }
  const lines = [`  #0 at ${where(view.getInt32(0x108, true) >>> 0)} lr=${where(Number(view.getBigUint64(30 * 8, true)))}`];
  for (let depth = 1; depth < fps.length; depth++) {
    const at = fps[depth - 1];
    if (at <= 0x1000 || at + 16 > size) break;
    const ret = Number(view.getBigUint64(at + 8, true));
    lines.push(`  #${depth} from ${where(ret)}`);
    if (ret === 0) break;
  }
  return lines.join("\n");
}

// A guest string, when the word it starts at is plausibly one, so an argument that is a format
// string reads as text.
function cstr(at) {
  if (at < 0x1000 || at + 1 > memory.buffer.byteLength) return null;
  const bytes = new Uint8Array(memory.buffer);
  let end = at;
  while (end < bytes.length && end - at < 200 && bytes[end] !== 0) end++;
  if (end === bytes.length) return null;
  const text = Buffer.from(bytes.subarray(at, end));
  const printable = text.every((b) => b === 9 || b === 10 || (b >= 32 && b < 127));
  return printable ? JSON.stringify(text.toString("latin1")) : null;
}

const ARM_RING = Number(process.env.ARMJIT_LAST || 24);
// Where the time went in the last `n` instructions, which is how a loop this large shows itself.
function hot(n) {
  const counts = new Map();
  for (const pc of recent.slice(-n)) counts.set(pc, (counts.get(pc) ?? 0) + 1);
  return [...counts]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([pc, c]) => `${where(pc)} x${c}`)
    .join(", ");
}

// The memory named by ARMJIT_WATCH_DUMP, for a report of any kind.
function memory_dump() {
  const view = new DataView(memory.buffer);
  const bytes = new Uint8Array(memory.buffer);
  let out = "";
  for (const [at, len] of watchRanges) {
    const from = at < 0 ? Number(view.getBigUint64(0xf8, true)) + -at : at;
    const slice = bytes.subarray(from, from + len);
    out += `\n  mem 0x${from.toString(16)}: ${Buffer.from(slice).toString("hex")} ${JSON.stringify(Buffer.from(slice).toString("latin1"))}`;
  }
  return out;
}

function report(pc) {
  const view = new DataView(memory.buffer);
  const bytes = new Uint8Array(memory.buffer);
  const args = [];
  for (let i = 0; i < 8; i++) args.push(view.getBigUint64(i * 8, true));
  console.error(`watch at ${where(pc)} hit ${watches.find((w) => w.pc === pc).hits} sp=0x${view.getBigUint64(0xf8, true).toString(16)}`);
  console.error(`  ${args.map((v, i) => `x${i}=0x${v.toString(16)}`).join(" ")}`);
  for (let i = 0; i < 6; i++) {
    const text = cstr(Number(args[i]));
    if (text !== null) console.error(`  x${i} -> ${text}`);
  }
  for (const [at, len] of watchRanges) {
    // `sp+0xNN:len` reads a frame slot, whose address is only known once the run is at it.
    const from = at < 0 ? Number(view.getBigUint64(0xf8, true)) + -at : at;
    const slice = bytes.subarray(from, from + len);
    const hex = Buffer.from(slice).toString("hex");
    const text = Buffer.from(slice).toString("latin1");
    console.error(`  mem 0x${from.toString(16)}: ${hex} ${JSON.stringify(text)}`);
  }
  console.error(state());
  console.error(backtrace());
  console.error(`  ring ${ring(40).map(where).join(" -> ")}`);
  console.error(`  last ${recent.slice(-ARM_RING).map(where).join(" -> ")}`);
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
  recent.push(at);
  if (recent.length > 1 << 20) recent.shift();
  if (spin) {
    spins.set(at, (spins.get(at) ?? 0) + 1);
    if (recent.length > 4096) {
      const old = recent[recent.length - 4097];
      spins.set(old, spins.get(old) - 1);
    }
    const n = spins.get(at);
    if (n > spin) {
      throw new Error(
        `spin: ${where(at)} ran ${n} times in ${recent.length} instructions\n` +
          state() +
          "\n" + backtrace() +
          memory_dump() +
          `\n  trail ${recent.slice(-32).map(where).join(" -> ")}`,
      );
    }
  }
  if (heartbeat && (++ticks & 0xfff) === 0 && Date.now() - beat > heartbeat) {
    beat = Date.now();
    console.error(
      `heartbeat ${((beat - startedAt) / 1000).toFixed(0)}s at ${where(at)}` +
        `\n  trail ${recent.slice(-16).map(where).join(" -> ")}` +
        "\n" + backtrace() +
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

function syscall(nr, a0, a1, a2, a3, a4, a5) {
  if (process.env.ARMJIT_TRACE_SYSCALLS) {
    const view = new DataView(memory.buffer);
    const pc = view.getInt32(0xf8 + 16, true) >>> 0;
    console.error(`from 0x${pc.toString(16)}`);
  }
  return kernel.call(nr, a0, a1, a2, a3, a4, a5);
}

const module = new WebAssembly.Module(bytes);
const instance = new WebAssembly.Instance(module, { env: { syscall, trap, trace2 } });
memory = instance.exports.mem;
kernel = new Kernel(memory, meta, { rootfs: process.env.ARMJIT_ROOTFS });
// The images the translator placed, before any mapping happened, so a jump into one that the scan
// did not predict can be translated on demand like a library page.
for (const image of meta.images ?? []) kernel.space.images.push(image);

if (process.env.ARMJIT_DUMP_STACK) {
  const view = new DataView(memory.buffer);
  const at = Number(BigInt(meta.sp));
  for (let i = 0; i < 16; i++) {
    const w = view.getBigUint64(at + i * 8, true);
    const ascii = Buffer.from(new Uint8Array(memory.buffer, at + i * 8, 8)).toString("latin1");
    console.error(`sp+${i * 8}: 0x${w.toString(16)} ${JSON.stringify(ascii)}`);
  }
}

const translator = new Translator(process.env.ARMJIT_TRANSLATOR || "./target/release/armjit");
const configured = await translator.configure({
  bounds: meta.bounds === 1,
  trace: meta.trace === 1,
  memPages: meta.mem_pages,
});
if (!configured.ok) {
  console.error(`armjit: translator did not start: ${configured.error}`);
  process.exit(1);
}

const mach = new Mach({ instance, memory, meta, kernel, translator, imports: { syscall, trap, trace2 } });
ranges = mach.kernel.space.images;
const started = process.hrtime.bigint();
const code = await mach.run();
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

process.exit(code === 0 ? (kernel.exited ?? 0) : code);
