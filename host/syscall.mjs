// The Linux system-call surface, from the host's side.
//
// The guest puts the number in x8 and arguments in x0-x5, and gets a result or -errno in x0. A
// syscall that ends the process answers `stop = 1`; one this kernel does not implement answers
// -ENOSYS rather than trapping, so a run gets as far as it can and says what it was missing.

import { AddressSpace, EFAULT, ENOMEM, EINVAL } from "./addressspace.mjs";

export const ENOSYS = 38;
export const EBADF = 9;

const MAP_ANONYMOUS = 0x20;

export class Kernel {
  constructor(memory, meta) {
    this.memory = memory;
    this.meta = meta;
    this.space = new AddressSpace(memory, meta);
    this.exited = null;
    this.missing = new Set();
    this.table = new Map();
    this.register();
  }

  addr(x) {
    return Number(BigInt.asUintN(64, x));
  }

  inBounds(a, len) {
    return a >= 0 && a + len <= this.memory.buffer.byteLength;
  }

  read(x, len) {
    const a = this.addr(x);
    if (!this.inBounds(a, len)) return null;
    return new Uint8Array(this.memory.buffer, a, len).slice();
  }

  put(x, bytes) {
    const a = this.addr(x);
    if (!this.inBounds(a, bytes.length)) return false;
    new Uint8Array(this.memory.buffer, a, bytes.length).set(bytes);
    return true;
  }

  /// A NUL-terminated string at a guest address, read as the guest wrote it.
  str(x) {
    const a = this.addr(x);
    const view = new Uint8Array(this.memory.buffer);
    let end = a;
    while (end < view.length && view[end] !== 0) end++;
    return new TextDecoder().decode(view.subarray(a, end));
  }

  u32(x) {
    return new DataView(this.memory.buffer).getUint32(this.addr(x), true);
  }

  u64(x) {
    return new DataView(this.memory.buffer).getBigUint64(this.addr(x), true);
  }

  put32(x, v) {
    new DataView(this.memory.buffer).setUint32(this.addr(x), v >>> 0, true);
  }

  put64(x, v) {
    new DataView(this.memory.buffer).setBigUint64(this.addr(x), BigInt(v), true);
  }

  on(nr, fn) {
    this.table.set(nr, fn);
  }

  fail(no) {
    return [-BigInt(no), 0];
  }

  call(nr, a0, a1, a2, a3, a4, a5) {
    const fn = this.table.get(Number(nr));
    if (!fn) {
      const n = Number(nr);
      if (!this.missing.has(n)) {
        this.missing.add(n);
        if (process.env.ARMJIT_SYSCALLS) console.error(`unimplemented syscall ${n}`);
      }
      return this.fail(ENOSYS);
    }
    return fn(this, a0, a1, a2, a3, a4, a5);
  }

  register() {
    const exit = (k, code) => {
      k.exited = Number(code) & 0xff;
      return [0n, 1];
    };
    this.on(93, exit); // exit
    this.on(94, exit); // exit_group

    this.on(64, (k, fd, buf, count) => {
      const n = Number(fd);
      if (n !== 1 && n !== 2) return k.fail(EBADF);
      const bytes = k.read(buf, Math.min(Number(count), 0x7ffff000));
      if (bytes === null) return k.fail(EFAULT);
      (n === 1 ? process.stdout : process.stderr).write(bytes);
      return [BigInt(bytes.length), 0];
    });

    this.on(63, () => [0n, 0]); // read: stdin is closed until the fd table exists

    this.on(222, (k, addr, len, prot, flags, fd) => {
      if (Number(fd) >= 0 && !(Number(flags) & MAP_ANONYMOUS)) return k.fail(ENOSYS);
      const at = k.space.mmap({
        addr: k.addr(addr),
        len: Number(len),
        prot: Number(prot),
        flags: Number(flags),
      });
      return [BigInt(at), 0];
    });

    this.on(215, (k, addr, len) => [BigInt(k.space.munmap(k.addr(addr), Number(len))), 0]);

    this.on(226, (k, addr, len, prot) => [
      BigInt(k.space.mprotect(k.addr(addr), Number(len), Number(prot))),
      0,
    ]);

    this.on(214, (k, addr) => [BigInt(k.space.setBrk(k.addr(addr))), 0]);
  }
}

export { EFAULT, ENOMEM, EINVAL };
