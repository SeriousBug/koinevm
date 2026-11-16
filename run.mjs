// Host side of the armjit PoC: loads a translated module, provides the syscall boundary, runs.
//
// The Linux ABI contract this file implements: the guest puts the syscall number in x8 and
// arguments in x0-x5, and gets a result (or -errno) in x0. Everything else about the guest state is
// the translator's business. Syscalls the PoC does not implement answer -ENOSYS, never a trap.

import fs from "node:fs";

const ENOSYS = 38n;
const EBADF = 9n;
const EFAULT = 14n;

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: node run.mjs <module.wasm>");
  process.exit(2);
}

const meta = JSON.parse(fs.readFileSync(`${wasmPath}.json`, "utf8"));
const bytes = fs.readFileSync(wasmPath);

let memory = null;
let exited = null;

function memRead(addr, len) {
  const a = Number(addr);
  if (a < 0 || a + len > memory.buffer.byteLength) return null;
  return new Uint8Array(memory.buffer, a, len).slice();
}

function memWrite(addr, src) {
  const a = Number(addr);
  if (a < 0 || a + src.length > memory.buffer.byteLength) return false;
  new Uint8Array(memory.buffer, a, src.length).set(src);
  return true;
}

// (result, stop) per syscall: stop tells the translated code the process is finished.
function syscall(nr, a0, a1, a2, a3, a4, a5) {
  switch (Number(nr)) {
    case 64: { // write
      const fd = Number(a0);
      if (fd !== 1 && fd !== 2) return [-EBADF, 0];
      const count = Math.min(Number(a2), 0x7ffff000);
      const buf = memRead(a1, count);
      if (buf === null) return [-EFAULT, 0];
      const stream = fd === 1 ? process.stdout : process.stderr;
      stream.write(buf);
      return [BigInt(buf.length), 0];
    }
    case 63: // read
      return [0n, 0]; // stdin is closed for now
    case 93: // exit
    case 94: // exit_group
      exited = Number(a0) & 0xff;
      return [0n, 1];
    default:
      return [-ENOSYS, 0];
  }
}

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
function trace2(pc, sp) {
  recent.push([pc >>> 0, BigInt.asUintN(64, sp)]);
  if (recent.length > 64) recent.shift();
}

const module = new WebAssembly.Module(bytes);
const instance = new WebAssembly.Instance(module, { env: { syscall, trap, trace2 } });
memory = instance.exports.mem;

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

process.exit(exited ?? 0);
