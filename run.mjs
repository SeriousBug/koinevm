// Host side of the armjit PoC: loads a translated module, provides the kernel the guest talks to,
// runs it. ARMJIT_ROOTFS names the directory the guest sees as /.
//
// The Linux ABI contract lives in host/syscall.mjs. Everything here is the process boundary: read
// the metadata the translator wrote next to the module, instantiate, run from the entry with the
// initial stack, and report how the run ended.

import fs from "node:fs";
import { Kernel } from "./host/syscall.mjs";

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: node run.mjs <module.wasm>");
  process.exit(2);
}

const meta = JSON.parse(fs.readFileSync(`${wasmPath}.json`, "utf8"));
const bytes = fs.readFileSync(wasmPath);

let memory = null;
let kernel = null;

function trap(kind, addr, at) {
  if (recent.length) {
    console.error("last instructions (pc, sp):");
    for (const [pc, sp] of recent) console.error(`  0x${pc.toString(16)} sp=0x${sp.toString(16)}`);
  }
  const view = new DataView(memory.buffer);
  const pc = view.getInt32(0x108, true) >>> 0;
  const regs = [];
  for (let i = 0; i < 31; i++) regs.push(view.getBigInt64(i * 8, true).toString(16));
  const sp = view.getBigInt64(0xf8, true).toString(16);
  const nzcv = view.getBigInt64(0x100, true).toString(16);
  const idx = view.getInt32(0x1fc, true);
  const trail = [];
  for (let k = Math.max(0, idx - 24); k < idx; k++) {
    trail.push("0x" + (view.getInt32(0x200 + (k & 255) * 4, true) >>> 0).toString(16));
  }
  throw new Error(
    `guest pc trail: ${trail.join(" -> ")}\n` +
      `guest trap ${Number(kind)} at address 0x${Number(addr).toString(16)} from 0x${(at >>> 0).toString(16)}\n` +
      `  pc=0x${pc.toString(16)} sp=0x${sp} nzcv=0x${nzcv}\n` +
      `  ${regs.map((v, i) => `x${i}=0x${v}`).join(" ")}`,
  );
}

const recent = [];
// ARMJIT_TRACE_PRINT prints the state *before* each instruction, which is what the translator wrote
// to the shadow: pc, packed NZCV and the registers named in ARMJIT_TRACE_REGS.
const traceRegs = (process.env.ARMJIT_TRACE_REGS || "8").split(",").map(Number);
function trace2(pc, sp) {
  recent.push([pc >>> 0, BigInt.asUintN(64, sp)]);
  if (recent.length > 64) recent.shift();
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

if (process.env.ARMJIT_DUMP_STACK) {
  const view = new DataView(memory.buffer);
  const at = Number(BigInt(meta.sp));
  for (let i = 0; i < 16; i++) {
    const w = view.getBigUint64(at + i * 8, true);
    const ascii = Buffer.from(new Uint8Array(memory.buffer, at + i * 8, 8)).toString("latin1");
    console.error(`sp+${i * 8}: 0x${w.toString(16)} ${JSON.stringify(ascii)}`);
  }
}

const started = process.hrtime.bigint();
const status = instance.exports.run(meta.entry, BigInt(meta.sp));
const elapsed = process.hrtime.bigint();
if (process.env.ARMJIT_TIME) {
  console.error(`guest run ${Number(elapsed - started) / 1e6} ms`);
}

if (status !== 0) {
  const view = new DataView(memory.buffer);
  const pc = view.getInt32(0xf8 + 16, true);
  if (status === 2) {
    console.error(`armjit: guest jumped to untranslated address 0x${(pc >>> 0).toString(16)}`);
  } else {
    console.error(`armjit: stopped with status ${status}`);
  }
  process.exit(1);
}

process.exit(kernel.exited ?? 0);
