// The Linux system-call surface, from the host's side.
//
// The guest puts the number in x8 and arguments in x0-x5, and gets a result or -errno in x0. A
// syscall that ends the process answers `stop = 1`; one this kernel does not implement answers
// -ENOSYS rather than trapping, so a run gets as far as it can and says what it was missing.

import fs from "node:fs";
import { AddressSpace, EFAULT, ENOMEM, EINVAL } from "./addressspace.mjs";
import { Files, AT_FDCWD, ENOENT, WOULD_BLOCK } from "./files.mjs";

export const ENOSYS = 38;
export const EBADF = 9;
export const ENOTTY = 25;
export const ECHILD = 10;
export const ENOEXEC = 8;

const MAP_ANONYMOUS = 0x20;
const CLONE_VM = 0x100;
const CLONE_VFORK = 0x4000;
const CLONE_THREAD = 0x10000;
const WNOHANG = 1;

export class Kernel {
  constructor(memory, meta, options = {}) {
    this.memory = memory;
    this.meta = meta;
    this.pid = options.pid ?? 1;
    this.ppid = options.ppid ?? 0;
    this.space = new AddressSpace(memory, meta);
    this.files = options.files ?? new Files(options.rootfs);
    this.exited = null;
    this.missing = new Set();
    this.table = new Map();
    this.random = 0;
    // What a syscall that cannot finish inside the guest's wasm call leaves for the host: the run
    // returns, this is served, and the process is resumed with x0 as the answer.
    this.pending = null;
    /// Called when something a process may be waiting for has happened.
    this.wake = options.wake ?? (() => {});
    this.register();
  }

  /// A syscall the host has to perform, which means giving up the wasm call until it can.
  ask(request) {
    return { host: request };
  }

  addr(x) {
    return Number(BigInt.asUintN(64, typeof x === "bigint" ? x : BigInt(x)));
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

  /// The bytes of a string the guest passes, without a character set in the way: `execve` hands
  /// over whatever it was given.
  strBytes(x) {
    const a = this.addr(x);
    const view = new Uint8Array(this.memory.buffer);
    let end = a;
    while (end < view.length && view[end] !== 0) end++;
    return view.subarray(a, end);
  }

  u64(x) {
    return new DataView(this.memory.buffer).getBigUint64(this.addr(x), true);
  }

  put32(x, v) {
    new DataView(this.memory.buffer).setUint32(this.addr(x), v >>> 0, true);
    return true;
  }

  put64(x, v) {
    new DataView(this.memory.buffer).setBigUint64(this.addr(x), BigInt(v), true);
    return true;
  }

  on(nr, fn) {
    this.table.set(nr, fn);
  }

  fail(no) {
    return [-BigInt(no), 0];
  }

  call(nr, a0, a1, a2, a3, a4, a5) {
    if (process.env.ARMJIT_TRACE_SYSCALLS) {
      const args = [a0, a1, a2, a3, a4, a5]
        .map((v) => "0x" + BigInt.asUintN(64, v).toString(16))
        .join(", ");
      console.error(`syscall ${Number(nr)}(${args})`);
    }
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

    this.on(222, (k, addr, len, prot, flags, fd, off) => {
      let contents = null;
      if (Number(fd) >= 0 && !(Number(flags) & MAP_ANONYMOUS)) {
        contents = k.files.contents(Number(fd), Number(off), Number(len));
        if (typeof contents === "number") return [BigInt(contents), 0];
      }
      const at = k.space.mmap({
        addr: k.addr(addr),
        len: Number(len),
        prot: Number(prot),
        flags: Number(flags),
        contents,
      });
      if (process.env.ARMJIT_TRACE_SYSCALLS)
        console.error(
          `  mmap at=0x${BigInt(at).toString(16)} len=0x${Number(len).toString(16)} prot=${Number(prot)} ` +
            `flags=0x${Number(flags).toString(16)} fd=${Number(fd)} off=0x${Number(off).toString(16)} ` +
            `bytes=${contents ? contents.length : 0}`,
        );
      if (contents && Number(at) > 0) {
        const entry = k.files.get(Number(fd));
        if (entry && entry.host) {
          k.space.noteImage(Number(at), Number(at) + Number(len), entry.host, Number(off));
        }
      }
      return [BigInt(at), 0];
    });

    this.on(215, (k, addr, len) => [BigInt(k.space.munmap(k.addr(addr), Number(len))), 0]);

    this.on(226, (k, addr, len, prot) => [
      BigInt(k.space.mprotect(k.addr(addr), Number(len), Number(prot))),
      0,
    ]);

    this.on(214, (k, addr) => [BigInt(k.space.setBrk(k.addr(addr))), 0]);

    this.registerFiles();
    this.registerStartup();
    this.registerProcess();
  }

  // ---- processes

  /// The kernel state a fork copies. The descriptor entries are shared by reference, because a
  /// fork shares its open file descriptions, so a read in one moves the position in the other; the
  /// tables that hold them are not shared, so closing in one leaves the other open.
  forkState() {
    return {
      brk: this.space.brk,
      free: this.space.free.map((s) => ({ ...s })),
      images: this.space.images.map((i) => ({ ...i })),
      fds: new Map([...this.files.map].map(([fd, entry]) => [fd, this.files.copyEntry(entry)])),
      nextFd: this.files.next,
      cwd: this.files.cwd,
      random: this.random,
    };
  }

  adopt(state) {
    this.space.brk = state.brk;
    this.space.free = state.free;
    this.space.images = state.images;
    this.files.map = state.fds;
    this.files.next = state.nextFd;
    this.files.cwd = state.cwd;
    this.random = state.random;
  }

  registerProcess() {
    this.on(220, (k, flags, stack, ptid, ctid, tls) => {
      const f = Number(flags);
      // A thread shares its memory with its creator, which one linear memory per process cannot
      // express. vfork also asks for shared memory, but on the one stack it already has, and it
      // promises not to touch anything but that stack before it execs, so a copy is enough.
      if (f & CLONE_THREAD) return k.fail(ENOSYS);
      // A new stack without shared memory is a coroutine, which has nowhere to run here.
      if (k.addr(stack) !== 0 && !(f & CLONE_VM)) return k.fail(ENOSYS);
      return k.ask({
        kind: "fork",
        flags: f,
        ptid: k.addr(ptid),
        ctid: k.addr(ctid),
        tls: Number(tls),
      });
    });

    // clone3, which is the same request as a struct: glibc's fork still uses clone, but
    // `posix_spawn` asks this one first.
    this.on(435, (k, args) => {
      const at = args;
      if (k.addr(at) === 0) return k.fail(EINVAL);
      const flags = Number(k.u64(at));
      const stack = k.addr(k.u64(at + 40n));
      if (flags & CLONE_THREAD) return k.fail(ENOSYS);
      if (stack !== 0 && !(flags & CLONE_VM)) return k.fail(ENOSYS);
      return k.ask({
        kind: "fork",
        flags,
        ptid: k.addr(k.u64(at + 24n)),
        ctid: k.addr(k.u64(at + 16n)),
        tls: Number(k.u64(at + 56n)),
      });
    });

    this.on(221, (k, path, argv, envp) =>
      k.ask({
        kind: "exec",
        path: Buffer.from(k.strBytes(path)),
        argv: stringVector(k, argv),
        envp: stringVector(k, envp),
      }),
    );

    this.on(260, (k, pid, wstatus, options, rusage) =>
      k.ask({
        kind: "wait",
        pid: Number(BigInt.asIntN(32, BigInt.asUintN(64, pid))),
        wstatus: k.addr(wstatus),
        options: Number(options),
        rusage: k.addr(rusage),
      }),
    );

    this.on(172, (k) => [BigInt(k.pid), 0]); // getpid
    this.on(173, (k) => [BigInt(k.ppid), 0]); // getppid
    this.on(178, (k) => [BigInt(k.pid), 0]); // gettid
    this.on(96, (k, uaddr) => {
      k.tidAddress = k.addr(uaddr);
      return [BigInt(k.pid), 0]; // set_tid_address
    });
  }

  // ---- files

  registerFiles() {
    this.on(56, (k, dirfd, path, flags, mode) => {
      if (process.env.ARMJIT_TRACE_SYSCALLS) console.error(`  openat ${k.str(path)}`);
      if (!isCwd(dirfd)) return k.fail(ENOSYS);
      return [BigInt(k.files.open(k.str(path), Number(flags), Number(mode))), 0];
    });

    this.on(57, (k, fd) => {
      const closed = k.files.close(Number(fd));
      k.wake();
      return [BigInt(closed), 0];
    });

    this.on(23, (k, fd) => [BigInt(k.files.dup(Number(fd), 0, false)), 0]); // dup

    this.on(24, (k, oldfd, newfd, flags) => [
      BigInt(k.files.dup3(Number(oldfd), Number(newfd), (Number(flags) & 0x80000) !== 0)),
      0,
    ]);

    this.on(25, (k, fd, cmd, arg) => {
      const entry = k.files.get(Number(fd));
      if (!entry) return k.fail(EBADF);
      switch (Number(cmd)) {
        case 0: // F_DUPFD
          return [BigInt(k.files.dup(Number(fd), Number(arg), false)), 0];
        case 1030: // F_DUPFD_CLOEXEC
          return [BigInt(k.files.dup(Number(fd), Number(arg), true)), 0];
        case 1: // F_GETFD
          return [BigInt(entry.cloexec ? 1 : 0), 0];
        case 2: // F_SETFD
          entry.cloexec = (Number(arg) & 1) !== 0;
          return [0n, 0];
        case 3: // F_GETFL
          return [BigInt(entry.desc?.append ? 0x400 : 0), 0];
        default:
          return [0n, 0];
      }
    });

    this.on(63, (k, fd, buf, count) => {
      const n = Math.min(Number(count), 0x7ffff000);
      if (process.env.ARMJIT_TRACE_SYSCALLS)
        console.error(`  read fd=${Number(fd)} at 0x${BigInt.asUintN(64, buf).toString(16)} n=${n}`);
      const got = k.files.read(Number(fd), n);
      // A pipe with writers and nothing in it yet: the host waits and answers this again.
      if (got === WOULD_BLOCK) return k.ask({ kind: "read", fd: Number(fd), buf: k.addr(buf), len: n });
      if (typeof got === "number") return [BigInt(got), 0];
      if (!k.put(buf, got)) return k.fail(EFAULT);
      return [BigInt(got.length), 0];
    });

    this.on(67, (k, fd, buf, count, off) => {
      const n = Math.min(Number(count), 0x7ffff000);
      const got = k.files.pread(Number(fd), n, k.addr(off));
      if (typeof got === "number") return [BigInt(got), 0];
      if (!k.put(buf, got)) return k.fail(EFAULT);
      return [BigInt(got.length), 0];
    });

    this.on(64, (k, fd, buf, count) => {
      const bytes = k.read(buf, Math.min(Number(count), 0x7ffff000));
      if (bytes === null) return k.fail(EFAULT);
      const wrote = k.files.write(Number(fd), Buffer.from(bytes));
      if (wrote > 0) k.wake();
      return [BigInt(wrote), 0];
    });

    this.on(66, (k, fd, iov, count) => {
      const n = Number(count);
      if (n > 1024) return k.fail(EINVAL);
      let total = 0;
      for (let i = 0; i < n; i++) {
        const base = k.u64(iov) + BigInt(i) * 16n;
        const len = Number(k.u64(base + 8n));
        const at = k.u64(base);
        const bytes = k.read(at, len);
        if (bytes === null) {
          if (process.env.ARMJIT_TRACE_SYSCALLS)
            console.error(`  writev fd=${Number(fd)} iov[${i}] at=0x${at.toString(16)} len=${len} unreachable`);
          return k.fail(EFAULT);
        }
        if (process.env.ARMJIT_TRACE_SYSCALLS)
          console.error(`  writev fd=${Number(fd)} ${JSON.stringify(Buffer.from(bytes).toString("latin1"))}`);
        const wrote = k.files.write(Number(fd), Buffer.from(bytes));
        if (typeof wrote === "number" && wrote < 0) return [BigInt(wrote), 0];
        total += wrote;
      }
      return [BigInt(total), 0];
    });

    this.on(62, (k, fd, off, whence) => {
      const r = k.files.seek(Number(fd), Number(BigInt.asIntN(64, off)), Number(whence));
      return [BigInt(r), 0];
    });

    this.on(80, (k, fd, buf) => {
      const st = k.files.statFd(Number(fd));
      if (typeof st === "number") return [BigInt(st), 0];
      k.fillStat(buf, st);
      return [0n, 0];
    });

    this.on(79, (k, dirfd, path, buf, flags) => {
      // glibc spells `fstat` as `newfstatat (fd, "", buf, AT_EMPTY_PATH)`.
      if (k.str(path) === "") {
        const st = k.files.statFd(Number(dirfd));
        if (typeof st === "number") return [BigInt(st), 0];
        k.fillStat(buf, st);
        return [0n, 0];
      }
      if (!isCwd(dirfd)) return k.fail(ENOSYS);
      const follow = (Number(flags) & 0x100) === 0; // AT_SYMLINK_NOFOLLOW is 0x100
      const st = follow ? k.files.statFile(k.str(path)) : k.files.statPath(k.str(path));
      if (typeof st === "number") return [BigInt(st), 0];
      k.fillStat(buf, st);
      return [0n, 0];
    });

    this.on(78, (k, dirfd, path, buf, size) => {
      if (!isCwd(dirfd)) return k.fail(ENOSYS);
      const target = k.files.readlink(k.str(path));
      if (typeof target === "number") return [BigInt(target), 0];
      const bytes = Buffer.from(target);
      if (bytes.length > Number(size)) return [BigInt(bytes.length), 0];
      if (!k.put(buf, bytes)) return k.fail(EFAULT);
      return [BigInt(bytes.length), 0];
    });

    this.on(48, (k, dirfd, path, mode) => {
      if (!isCwd(dirfd)) return k.fail(ENOSYS);
      const st = k.files.statFile(k.str(path));
      return [typeof st === "number" ? BigInt(st) : 0n, 0];
    });

    this.on(61, (k, fd, buf, len) => {
      const got = k.files.getdents(Number(fd), Number(len));
      if (typeof got === "number") return [BigInt(got), 0];
      if (!k.put(buf, got)) return k.fail(EFAULT);
      return [BigInt(got.length), 0];
    });

    this.on(59, (k, fds, flags) => {
      const cloexec = (Number(flags) & 0x80000) !== 0;
      const [read, write] = k.files.pipe(cloexec);
      const ok = k.put32(fds, read) && k.put32(k.addr(fds) + 4, write);
      if (process.env.ARMJIT_TRACE_SYSCALLS) console.error(`  pipe2 fds=${read},${write} ok=${ok}`);
      if (!ok) return k.fail(EFAULT);
      return [0n, 0];
    });

    this.on(43, (k, path, buf) => {
      const host = k.files.resolve(k.str(path));
      if (typeof host === "number") return [BigInt(host), 0];
      let st;
      try {
        st = fs.statfsSync(host);
      } catch {
        return [BigInt(-ENOENT), 0];
      }
      const put = (off, v) => k.put64(buf + BigInt(off), BigInt(v));
      put(0, st.type);
      put(8, st.bsize);
      put(16, st.blocks);
      put(24, st.bfree);
      put(32, st.bavail);
      put(40, st.files);
      put(48, st.ffree);
      put(56, 0);
      put(64, st.namelen);
      put(72, st.frsize ?? st.bsize);
      put(80, 0);
      for (let i = 0; i < 4; i++) put(88 + i * 8, 0);
      return [0n, 0];
    });

    this.on(17, (k, buf, size) => {
      const cwd = Buffer.from(k.files.cwd + "\0");
      if (cwd.length > Number(size)) return k.fail(EINVAL);
      if (!k.put(buf, cwd)) return k.fail(EFAULT);
      return [BigInt(cwd.length), 0];
    });

    this.on(29, (k, fd, request, arg) => {
      // There is no console, so the streams are pipes and `isatty` has to say so: a program that
      // believes it has a terminal formats for one, and its output stops matching a real run.
      const req = Number(request);
      if (req === 0x5401) return k.fail(ENOTTY); // TCGETS
      if (req === 0x5413) return k.fail(ENOTTY); // TIOCGWINSZ
      return [0n, 0];
    });
  }

  /// The 128 bytes newfstatat/fstat fill, in the order the ABI lays them out.
  fillStat(addr, st) {
    const time = (t) => (t ? BigInt(Math.floor(Number(t) / 1000)) : 0n);
    const nsec = (t) => (t ? BigInt((Number(t) % 1000) * 1000000) : 0n);
    this.put64(addr + 0n, st.dev ?? 0n);
    this.put64(addr + 8n, st.ino ?? 0n);
    this.put32(addr + 16n, Number(st.mode ?? 0n));
    this.put32(addr + 20n, Number(st.nlink ?? 0n));
    this.put32(addr + 24n, Number(st.uid ?? 0n));
    this.put32(addr + 28n, Number(st.gid ?? 0n));
    this.put64(addr + 32n, st.rdev ?? 0n);
    this.put64(addr + 40n, 0n);
    this.put64(addr + 48n, st.size ?? 0n);
    this.put32(addr + 56n, Number(st.blksize ?? 4096n));
    this.put32(addr + 60n, 0);
    this.put64(addr + 64n, st.blocks ?? 0n);
    this.put64(addr + 72n, time(st.atimeMs));
    this.put64(addr + 80n, 0n);
    this.put64(addr + 88n, time(st.mtimeMs));
    this.put64(addr + 96n, 0n);
    this.put64(addr + 104n, time(st.ctimeMs));
    this.put64(addr + 112n, 0n);
    this.put64(addr + 120n, 0n);
  }

  // ---- process start-up

  registerStartup() {
    this.on(96, () => [1n, 0]); // set_tid_address
    this.on(99, () => [0n, 0]); // set_robust_list
    this.on(172, () => [1n, 0]); // getpid
    this.on(173, () => [0n, 0]); // getppid
    this.on(174, () => [0n, 0]); // getuid
    this.on(175, () => [0n, 0]); // geteuid
    this.on(176, () => [0n, 0]); // getgid
    this.on(177, () => [0n, 0]); // getegid
    this.on(178, () => [1n, 0]); // gettid

    this.on(160, (k, buf) => {
      const field = (text) => {
        const b = Buffer.alloc(65);
        b.write(text);
        return b;
      };
      const uts = Buffer.concat([
        field("Linux"),
        field("armjit"),
        field("6.1.0-armjit"),
        field("#1"),
        field("aarch64"),
        field("(none)"),
      ]);
      if (!k.put(buf, uts)) return k.fail(EFAULT);
      return [0n, 0];
    });

    this.on(113, (k, clock, ts) => {
      // A clock that starts at a fixed point and advances with real time, so runs are comparable.
      const ns = 1_700_000_000_000_000_000n + BigInt(Math.round(performance.now() * 1e6));
      if (!k.put64(ts, ns / 1_000_000_000n) || !k.put64(ts + 8n, ns % 1_000_000_000n)) {
        return k.fail(EFAULT);
      }
      return [0n, 0];
    });

    this.on(278, (k, buf, len) => {
      // Deterministic, not random: the same run twice has to produce the same bytes.
      const n = Number(len);
      const bytes = Buffer.alloc(n);
      for (let i = 0; i < n; i++) {
        k.random = (k.random * 6364136223846793005 + 1442695040888963407) % 2 ** 32;
        bytes[i] = k.random & 0xff;
      }
      if (!k.put(buf, bytes)) return k.fail(EFAULT);
      return [BigInt(n), 0];
    });

    this.on(261, (k, pid, resource, newLimit, oldLimit) => {
      if (oldLimit !== 0n && Number(oldLimit) !== 0) {
        // RLIM_INFINITY for both, which is what a single-process runner can honour.
        k.put64(oldLimit, 0xffffffffffffffffn);
        k.put64(oldLimit + 8n, 0xffffffffffffffffn);
      }
      return [0n, 0];
    });

    this.on(123, (k, pid, size, mask) => {
      const n = Math.min(Number(size), 128);
      const bytes = Buffer.alloc(n);
      bytes[0] = 1; // one CPU
      if (!k.put(mask, bytes)) return k.fail(EFAULT);
      return [BigInt(n), 0];
    });

    this.on(134, () => [0n, 0]); // rt_sigaction: recorded nowhere yet
    this.on(135, (k, how, set, old) => {
      if (Number(old) !== 0) k.put64(old, 0n);
      return [0n, 0];
    });
    this.on(98, (k, uaddr, op) => {
      const cmd = Number(op) & 0x7f;
      if (cmd === 0) return k.fail(11); // FUTEX_WAIT with one thread: nothing to wait for
      return [0n, 0];
    });
    this.on(233, () => [0n, 0]); // madvise
    this.on(324, () => [0n, 0]); // membarrier: one thread, nothing to synchronise
    this.on(124, () => [0n, 0]); // sched_yield
  }
}

const isCwd = (x) => Number(BigInt.asIntN(64, x)) === AT_FDCWD;

export { EFAULT, ENOMEM, EINVAL };

/// A guest `char *const argv[]`: every string up to the null terminator.
function stringVector(k, vec) {
  if (k.addr(vec) === 0) return [];
  const out = [];
  for (let i = 0; i < 4096; i++) {
    const p = k.u64(vec + BigInt(i * 8));
    if (p === 0n) break;
    out.push(Buffer.from(k.strBytes(p)));
  }
  return out;
}
