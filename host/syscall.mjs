// The Linux system-call surface, from the host's side.
//
// The guest puts the number in x8 and arguments in x0-x5, and gets a result or -errno in x0. A
// syscall that ends the process answers `stop = 1`; one this kernel does not implement answers
// -ENOSYS rather than trapping, so a run gets as far as it can and says what it was missing.

import fs from "node:fs";
import { AddressSpace, EFAULT, ENOMEM, EINVAL } from "./addressspace.mjs";
import { Files, AT_FDCWD, ENOENT, WOULD_BLOCK } from "./files.mjs";
import {
  Net,
  decodeSockaddr,
  encodeSockaddr,
  EAGAIN,
  ENOTSOCK,
  ENOTCONN,
  EPROTONOSUPPORT,
  EAFNOSUPPORT,
  EDESTADDRREQ,
  EINPROGRESS,
} from "./net.mjs";

export const ENOSYS = 38;
export const ESRCH = 3;
export const EBADF = 9;
export const ENOTTY = 25;
export const ECHILD = 10;
export const ENOEXEC = 8;

const MAP_ANONYMOUS = 0x20;
/// `struct epoll_event` here is the mask, four bytes of padding, and the guest's own eight-byte value:
/// only x86-64 packs it, so this ABI does not.
const EPOLL_EVENT = 16;
const EPOLLIN = 0x001;
const EPOLLOUT = 0x004;
const EPOLLERR = 0x008;
const EPOLLHUP = 0x010;
const EPOLLONESHOT = 0x40000000;
const EEXIST = 17;
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
    this.files =
      options.files ??
      new Files(options.rootfs, { virtual: options.resolver?.files(options.rootfs), pid: this.pid });
    this.exited = null;
    /// `exit` ends one thread and `exit_group` ends them all, so the host has to know which.
    this.exitedGroup = false;
    this.missing = new Set();
    /// The ids this process runs as. There is one user in the tree and no permission is checked,
    /// but a program that drops privileges has to see the drop when it looks, which is what makes
    /// a package manager's own sandbox work rather than argue with it.
    this.ids = { uid: 0, euid: 0, gid: 0, egid: 0, groups: [0] };
    this.table = new Map();
    this.random = 0;
    // What a syscall that cannot finish inside the guest's wasm call leaves for the host: the run
    // returns, this is served, and the process is resumed with x0 as the answer.
    this.pending = null;
    /// Called when something a process may be waiting for has happened.
    this.wake = options.wake ?? (() => {});
    /// Signal dispositions this process installed: `catch` or `ignore`, and nothing at all for the
    /// default. A caught signal is recorded and not run, because there is nowhere to run it.
    this.signals = new Map();
    /// Called to deliver a signal to a process or a thread of the session, which is the host's job
    /// because the target may not be this process. Answers 0 or a negative errno.
    this.signal = options.signal ?? (() => -ESRCH);
    /// One map per epoll descriptor: the descriptors it watches, what each asked for, and the value
    /// it wants back with the event. The host's readiness is the same question `poll` asks.
    this.epolls = new Map();
    /// The sockets of the session. A fork shares them, because a socket description is shared by
    /// every descriptor on it, the same way an open file is.
    this.net = options.net ?? new Net({ wake: this.wake });
    /// Called to wake the threads asleep on a futex word; answers how many woke.
    this.futexWake = options.futexWake ?? (() => 0);
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

  /// The two `struct timespec` a `utimensat` caller passes, as seconds: a nanosecond field of
  /// UTIME_OMIT or UTIME_NOW is the marker that says the value is not a time at all.
  timespecPair(addr) {
    const at = BigInt(this.addr(addr));
    const one = (offset) => {
      const sec = Number(this.u64(at + BigInt(offset)));
      const nsec = Number(this.u64(at + BigInt(offset) + 8n));
      if (nsec === 0x3fffffff) return null;
      if (nsec === 0x3ffffffe) return Date.now() / 1000;
      return sec + nsec / 1e9;
    };
    return { atime: one(0), mtime: one(16) };
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
      console.error(`syscall ${Number(nr)}(${args}) pid ${this.pid}`);
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
    const answer = fn(this, a0, a1, a2, a3, a4, a5);
    if (!Array.isArray(answer)) return answer;
    // A read or a write would drown the trace, and its answer is the count it already reported.
    if (process.env.ARMJIT_TRACE_SYSCALLS && Number(nr) !== 63 && Number(nr) !== 64) {
      console.error(`  -> ${BigInt.asIntN(64, answer[0])}`);
    }
    return answer;
  }

  register() {
    const exit = (k, code) => {
      k.exited = Number(code) & 0xff;
      return [0n, 1];
    };
    this.on(93, exit); // exit: this thread, and the process when it was the last one
    this.on(94, (k, code) => {
      k.exitedGroup = true;
      return exit(k, code);
    }); // exit_group

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

    // A descriptor that is closed stops being watched, whichever way it was closed.
    this.files.onClose = (fd) => this.forgetFd(fd);
    this.registerFiles();
    this.registerSockets();
    this.registerEpoll();
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
      ids: { ...this.ids, groups: [...this.ids.groups] },
      signals: new Map(this.signals),
      epolls: new Map(
        [...this.epolls].map(([fd, interests]) => [fd, new Map([...interests].map(([f, i]) => [f, { ...i }]))]),
      ),
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
    this.ids = state.ids;
    this.signals = state.signals;
    this.epolls = state.epolls;
  }

  registerProcess() {
    // aarch64's clone takes the thread pointer before the child's tid word, which is where every
    // other 64-bit architecture puts them the other way round.
    this.on(220, (k, flags, stack, ptid, tls, ctid) => {
      const f = Number(flags);
      // A thread shares the memory of the process it is made in, which is the instance the process
      // runs: it is a coroutine with its own stack, not a second address space.
      if (f & CLONE_THREAD) {
        if (k.addr(stack) === 0) return k.fail(EINVAL);
        return k.ask({
          kind: "clone",
          flags: f,
          stack: k.addr(stack),
          ptid: k.addr(ptid),
          ctid: k.addr(ctid),
          tls,
        });
      }
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
      const fd = k.files.open(k.str(path), Number(flags), Number(mode), Number(dirfd));
      return [BigInt(fd), 0];
    });

    this.on(57, (k, fd) => {
      const closed = k.files.close(Number(fd));
      k.wake();
      return [BigInt(closed), 0];
    });

    this.on(23, (k, fd) => [BigInt(k.files.dup(Number(fd), 0, false)), 0]); // dup

    // ---- changing the tree, which is what unpacking a package is made of

    this.on(34, (k, dirfd, path, mode) => [BigInt(k.files.mkdir(k.str(path), Number(dirfd), Number(mode))), 0]);

    this.on(35, (k, dirfd, path, flags) => {
      const at = k.str(path);
      // AT_REMOVEDIR asks for a directory, and anything else for a file, exactly as on Linux.
      const removed = (Number(flags) & 0x200) !== 0
        ? k.files.rmdir(at, Number(dirfd))
        : k.files.unlink(at, Number(dirfd));
      return [BigInt(removed), 0];
    });

    this.on(36, (k, target, dirfd, path) => [BigInt(k.files.symlink(k.str(target), k.str(path), Number(dirfd))), 0]);

    this.on(37, (k, olddir, oldpath, newdir, newpath) => [
      BigInt(k.files.link(k.str(oldpath), Number(olddir), k.str(newpath), Number(newdir))),
      0,
    ]);

    this.on(38, (k, olddir, oldpath, newdir, newpath) => [
      BigInt(k.files.rename(k.str(oldpath), Number(olddir), k.str(newpath), Number(newdir))),
      0,
    ]);

    // renameat2 differs by the flags, which say whether to replace an existing target; the tree it
    // names is the same one, and the only flag `dpkg` uses is the default.
    this.on(276, (k, olddir, oldpath, newdir, newpath) => [
      BigInt(k.files.rename(k.str(oldpath), Number(olddir), k.str(newpath), Number(newdir))),
      0,
    ]);

    this.on(45, (k, path, len) => [BigInt(k.files.truncate(k.str(path), AT_FDCWD, Number(len))), 0]);

    this.on(46, (k, fd, len) => [BigInt(k.files.truncateFd(Number(fd), Number(len))), 0]);

    this.on(52, (k, fd, mode) => [BigInt(k.files.chmodFd(Number(fd), Number(mode))), 0]);

    this.on(53, (k, dirfd, path, mode, flags) => [
      BigInt(k.files.chmod(k.str(path), Number(dirfd), Number(mode), (Number(flags) & 0x100) === 0)),
      0,
    ]);

    this.on(54, () => [0n, 0]); // fchownat: one owner for the whole tree
    this.on(55, () => [0n, 0]); // fchown

    this.on(88, (k, dirfd, path, times, flags) => {
      const wanted = Number(times) === 0 ? null : k.timespecPair(times);
      // A null path is `futimens`: the descriptor is the file, not a name in a directory.
      if (k.addr(path) === 0) return [BigInt(k.files.utimensFd(Number(dirfd), wanted)), 0];
      const at = k.str(path);
      return [BigInt(k.files.utimens(at, Number(dirfd), wanted, (Number(flags) & 0x100) === 0)), 0];
    });

    this.on(49, (k, path) => [BigInt(k.files.chdir(k.str(path))), 0]); // chdir
    this.on(50, (k, fd) => [BigInt(k.files.chdirFd(Number(fd))), 0]); // fchdir
    this.on(166, (k, mask) => {
      const old = k.files.umask;
      k.files.umask = Number(mask) & 0o777;
      return [BigInt(old), 0];
    });

    // Every write is already on the host's disk when it returns, so there is nothing to flush: the
    // call is the confirmation the caller waits for.
    this.on(82, (k, fd) => (k.files.get(Number(fd)) ? [0n, 0] : k.fail(EBADF))); // fsync
    this.on(83, (k, fd) => (k.files.get(Number(fd)) ? [0n, 0] : k.fail(EBADF))); // fdatasync

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
          return [
            BigInt((entry.kind === "socket" ? 0x2 : entry.desc?.append ? 0x400 : 0) | (entry.desc?.nonblock ? 0x800 : 0)),
            0,
          ];
        case 4: // F_SETFL
          if (entry.desc) entry.desc.nonblock = (Number(arg) & 0x800) !== 0;
          return [0n, 0];
        // One process holds every lock it asks for, so a lock request succeeds and a query finds
        // nothing in the way. A query has to say so: `l_type` is `F_UNLCK`, or the caller reads
        // whatever it put there and reports that someone else holds the database.
        case 5: // F_GETLK
          if (!k.put(arg, Buffer.from([2, 0]))) return k.fail(EFAULT);
          return [0n, 0];
        case 6: // F_SETLK
        case 7: // F_SETLKW
          return [0n, 0];
        default:
          return [0n, 0];
      }
    });

    // flock is the other lock package managers take, on the same single-process model as fcntl.
    this.on(32, (k, fd) => (k.files.get(Number(fd)) ? [0n, 0] : k.fail(EBADF)));

    this.on(63, (k, fd, buf, count) => {
      const entry = k.files.get(Number(fd));
      if (entry && entry.kind === "socket") {
        return k.done(k.recvInto(Number(fd), k.addr(buf), Number(count), 0, 0, 0));
      }
      const n = Math.min(Number(count), 0x7ffff000);
      if (process.env.ARMJIT_TRACE_SYSCALLS)
        console.error(`  read fd=${Number(fd)} at 0x${BigInt.asUintN(64, buf).toString(16)} n=${n}`);
      const got = k.files.read(Number(fd), n);
      if (process.env.ARMJIT_TRACE_SYSCALLS) {
        console.error(`  read fd=${Number(fd)} n=${n} -> ${typeof got === "number" ? got : got.length}`);
      }
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
      const entry = k.files.get(Number(fd));
      if (entry && entry.kind === "socket") {
        return [BigInt(entry.desc.send(Buffer.from(bytes), null)), 0];
      }
      const wrote = k.files.write(Number(fd), Buffer.from(bytes));
      if (wrote > 0) k.wake();
      return [BigInt(wrote), 0];
    });

    this.on(66, (k, fd, iov, count) => {
      const n = Number(count);
      if (n > 1024) return k.fail(EINVAL);
      let total = 0;
      for (let i = 0; i < n; i++) {
        // A `struct iovec` is the address and then the length, and the array is at `iov`.
        const entry = k.addr(iov) + i * 16;
        const at = k.u64(entry);
        const len = Number(k.u64(entry + 8));
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
      const follow = (Number(flags) & 0x100) === 0; // AT_SYMLINK_NOFOLLOW is 0x100
      const st = follow
        ? k.files.statFile(k.str(path), Number(dirfd))
        : k.files.statPath(k.str(path), Number(dirfd));
      if (typeof st === "number") return [BigInt(st), 0];
      k.fillStat(buf, st);
      return [0n, 0];
    });

    this.on(78, (k, dirfd, path, buf, size) => {
      const target = k.files.readlink(k.str(path), Number(dirfd));
      if (typeof target === "number") return [BigInt(target), 0];
      const bytes = Buffer.from(target);
      if (bytes.length > Number(size)) return [BigInt(bytes.length), 0];
      if (!k.put(buf, bytes)) return k.fail(EFAULT);
      return [BigInt(bytes.length), 0];
    });

    this.on(48, (k, dirfd, path, mode) => {
      const st = k.files.statFile(k.str(path), Number(dirfd));
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
      const put = (off, v) => k.put64(buf + BigInt(off), BigInt(v ?? 0));
      // The filesystem type a Linux program expects to see, and the name limit it plans around;
      // the host's answer has neither under the same names.
      put(0, 0xef53); // EXT2_SUPER_MAGIC
      put(8, st.bsize);
      put(16, st.blocks);
      put(24, st.bfree);
      put(32, st.bavail);
      put(40, st.files);
      put(48, st.ffree);
      put(56, 0);
      put(64, 255);
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
      const req = Number(request);
      // FIONREAD: the bytes a receive would take now, which is how a resolver sizes the buffer it
      // reads an answer into. Without it the size is zero and the answer is read into nothing.
      if (req === 0x541b) {
        const entry = k.files.get(Number(fd));
        const waiting = entry?.kind === "socket" ? entry.desc.pending() : entry?.kind === "pipe" && entry.desc.data.length;
        if (!k.put32(arg, waiting || 0)) return k.fail(EFAULT);
        return [0n, 0];
      }
      // There is no console, so the streams are pipes and `isatty` has to say so: a program that
      // believes it has a terminal formats for one, and its output stops matching a real run.
      if (req === 0x5401) return k.fail(ENOTTY); // TCGETS
      if (req === 0x5413) return k.fail(ENOTTY); // TIOCGWINSZ
      return [0n, 0];
    });
  }

  // ---- sockets
  //
  // A socket is a descriptor in the file table, so everything that walks descriptors already sees
  // it, and the operations are the ones the ABI names. What cannot finish here (a bind that has to
  // reach the host, a receive with nothing queued) goes back through `ask`, and the host answers it
  // by calling the same helper again.

  // ---- epoll

  /// Drop every trace of a descriptor, from the epolls it was watching and from the epolls it was.
  forgetFd(fd) {
    this.epolls.delete(fd);
    for (const interests of this.epolls.values()) interests.delete(fd);
  }

  /// The registrations of an epoll that have something to report now, in the order they were added.
  /// A one-shot registration goes quiet after it has been reported, which is its whole point.
  epollReady(epfd, maxevents) {
    const interests = this.epolls.get(epfd);
    if (!interests) return null; // not an epoll descriptor, which the callers answer EINVAL for
    const out = [];
    for (const [fd, interest] of interests) {
      if (!interest.live) continue;
      const entry = this.files.get(fd);
      if (!entry) {
        interests.delete(fd);
        continue;
      }
      const state = this.pollState(entry, fd);
      let events = 0;
      if (state.read && (interest.events & EPOLLIN)) events |= EPOLLIN;
      if (state.write && (interest.events & EPOLLOUT)) events |= EPOLLOUT;
      // The two that are always reported, whatever the registration asked for.
      if (state.err) events |= EPOLLERR;
      if (state.hup) events |= EPOLLHUP;
      if (events === 0) continue;
      out.push({ fd, events, data: interest.data });
      if (interest.events & EPOLLONESHOT) interest.live = false;
      if (out.length >= maxevents) break;
    }
    return out;
  }

  /// The 12 bytes of an event, or null when the pointer is not readable.
  epollEvent(addr) {
    const at = this.addr(addr);
    if (!this.inBounds(at, EPOLL_EVENT)) return null;
    const view = new DataView(this.memory.buffer);
    return { events: view.getUint32(at, true), data: view.getBigUint64(at + 8, true) };
  }

  /// The events a caller asked for, written where it asked for them.
  epollDeliver(ready, at) {
    const view = new DataView(this.memory.buffer);
    ready.forEach((event, i) => {
      view.setUint32(at + i * EPOLL_EVENT, event.events, true);
      view.setBigUint64(at + i * EPOLL_EVENT + 8, event.data, true);
    });
    return ready.length;
  }

  /// epoll_pwait: what is ready, or a thread parked until something is.
  epollWait(epfd, at, maxevents, ms) {
    const ready = this.epollReady(epfd, maxevents);
    if (ready === null) return this.files.get(epfd) ? -EINVAL : -EBADF;
    if (ready.length > 0) return this.epollDeliver(ready, at);
    if (ms === 0) return 0;
    return this.ask({ kind: "epoll", epfd, events: at, maxevents, deadline: ms < 0 ? 0 : Date.now() + ms });
  }

  registerEpoll() {
    this.on(20, (k, flags) => {
      const fd = k.files.add({ kind: "epoll", cloexec: (Number(flags) & 0x80000) !== 0 });
      k.epolls.set(fd, new Map());
      return [BigInt(fd), 0];
    });

    this.on(21, (k, epfd, op, fd, event) => {
      const ep = Number(epfd);
      const target = Number(fd);
      const interests = k.epolls.get(ep);
      if (!interests) return k.fail(k.files.get(ep) ? EINVAL : EBADF);
      const how = Number(op);
      if (how === 2) {
        // EPOLL_CTL_DEL, which does not read the event the caller passed.
        if (!interests.has(target)) return k.fail(ENOENT);
        interests.delete(target);
        return [0n, 0];
      }
      if (how !== 1 && how !== 3) return k.fail(EINVAL);
      if (target === ep) return k.fail(EINVAL);
      if (how === 1 && interests.has(target)) return k.fail(EEXIST);
      if (how === 3 && !interests.has(target)) return k.fail(ENOENT);
      if (!k.files.get(target)) return k.fail(EBADF);
      const want = k.epollEvent(event);
      if (want === null) return k.fail(EFAULT);
      interests.set(target, { events: want.events, data: want.data, live: true });
      return [0n, 0];
    });

    this.on(22, (k, epfd, events, maxevents, timeout) => {
      const n = Number(maxevents);
      if (n <= 0) return k.fail(EINVAL);
      const at = k.addr(events);
      if (!k.inBounds(at, n * EPOLL_EVENT)) return k.fail(EFAULT);
      const ms = Number(BigInt.asIntN(32, BigInt.asUintN(64, timeout)));
      return k.done(k.epollWait(Number(epfd), at, n, ms));
    });
  }

  /// A signal from this process to another, or to one of its own threads. A signal of zero asks
  /// whether the target is there and does nothing else.
  kill(pid, sig, tid = 0) {
    if (sig < 0 || sig > 64) return -EINVAL;
    // What the signal does is the *target's* business, so the disposition is the host's to look up.
    return this.signal({ from: this.pid, pid, sig, tid });
  }

  /// The description behind a socket descriptor, or the negative errno the syscall answers with.
  socketDesc(fd) {
    const entry = this.files.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind !== "socket") return -ENOTSOCK;
    return entry.desc;
  }

  /// A helper's number is the syscall's answer; an ask is the host's, and goes back untouched.
  done(value) {
    return typeof value === "number" ? [BigInt(value), 0] : value;
  }

  /// A `struct sockaddr` the guest passed: `null` for an empty pointer, `undefined` for one that is
  /// not readable, which the caller answers as EFAULT.
  guestAddr(addr, len) {
    if (this.addr(addr) === 0) return null;
    const bytes = this.read(addr, Math.min(Math.max(Number(len), 0), 128));
    if (bytes === null) return undefined;
    return decodeSockaddr(bytes) ?? undefined;
  }

  /// Write an address back, and the length it really is: the caller's own limit bounds the copy,
  /// and a buffer that is too small still learns how much there was.
  putAddr(addr, lenp, value) {
    const bytes = encodeSockaddr(value);
    const at = this.addr(addr);
    if (at !== 0) {
      const limit =
        this.addr(lenp) === 0 ? bytes.length : new DataView(this.memory.buffer).getInt32(this.addr(lenp), true);
      if (limit < 0) return false;
      if (!this.put(at, bytes.subarray(0, Math.min(limit, bytes.length)))) return false;
    }
    if (this.addr(lenp) !== 0) new DataView(this.memory.buffer).setInt32(this.addr(lenp), bytes.length, true);
    return true;
  }

  /// A receive, and what `read` on a socket is: what is queued, or a thread parked until there is
  /// something. The host calls it again when the thread wakes, so it takes guest addresses rather
  /// than pointers into the buffer.
  recvInto(fd, buf, len, flags, addr, lenp) {
    const desc = this.socketDesc(fd);
    if (typeof desc === "number") return desc;
    const got = desc.recv(Math.min(Number(len), 0x7ffff000), (Number(flags) & 2) !== 0);
    if (got === WOULD_BLOCK) {
      if (desc.nonblock || (Number(flags) & 0x40) !== 0) return -EAGAIN;
      return this.ask({
        kind: "recv",
        fd,
        buf,
        len: Number(len),
        flags: Number(flags),
        addr,
        lenp,
        deadline: desc.timeout ? Date.now() + desc.timeout : 0,
      });
    }
    if (got.errno) return got.errno;
    if (!this.put(buf, got.data)) return -EFAULT;
    if (this.addr(addr) !== 0 && got.from && !this.putAddr(addr, lenp, got.from)) return -EFAULT;
    return (Number(flags) & 0x20) !== 0 ? got.full : got.data.length;
  }

  /// accept: the descriptor the new connection gets, the address it came from written back, or a
  /// thread parked until a connection arrives.
  acceptInto(fd, addr, lenp, flags) {
    const desc = this.socketDesc(fd);
    if (typeof desc === "number") return desc;
    const conn = desc.accept();
    if (conn === null) {
      if (desc.nonblock) return -EAGAIN;
      return this.ask({
        kind: "accept",
        fd,
        addr,
        lenp,
        flags,
        deadline: desc.timeout ? Date.now() + desc.timeout : 0,
      });
    }
    if (typeof conn === "number") return conn;
    if (this.addr(addr) !== 0 && conn.peer && !this.putAddr(addr, lenp, conn.peer)) return -EFAULT;
    conn.nonblock = (flags & 0x800) !== 0 || desc.nonblock;
    trace(`${desc.id} accepted ${conn.id} from ${conn.peer?.ip}:${conn.peer?.port}`);
    return this.files.add({ kind: "socket", desc: conn, cloexec: (flags & 0x80000) !== 0 });
  }

  /// The iovecs of a guest `struct msghdr`: where the bytes are, and how many.
  iovecs(msg) {
    const count = Number(this.u64(msg + 24));
    if (count < 0 || count > 1024) return null;
    const base = Number(this.u64(msg + 16));
    const list = [];
    for (let i = 0; i < count; i++) {
      list.push({ at: Number(this.u64(base + i * 16)), len: Number(this.u64(base + i * 16 + 8)) });
    }
    return list;
  }

  /// `struct msghdr` on this ABI: the address the guest names, the iovecs, the control buffer and
  /// the flags a receive answers with.
  static MSGHDR = 56;

  /// sendmsg: the bytes the iovecs name, to the address the header names or to the socket's peer.
  sendMsgInto(fd, msg, flags) {
    const desc = this.socketDesc(fd);
    if (typeof desc === "number") return desc;
    if (!this.inBounds(msg, Kernel.MSGHDR)) return -EFAULT;
    const name = Number(this.u64(msg));
    const namelen = new DataView(this.memory.buffer).getUint32(msg + 8, true);
    const to = this.guestAddr(name, namelen);
    if (to === undefined) return -EFAULT;
    const iovs = this.iovecs(msg);
    if (!iovs) return -EINVAL;
    const parts = [];
    for (const iov of iovs) {
      const bytes = this.read(iov.at, iov.len);
      if (bytes === null) return -EFAULT;
      parts.push(Buffer.from(bytes));
    }
    return desc.send(Buffer.concat(parts), to);
  }

  /// recvmsg: what is queued, scattered across the iovecs, or a thread parked until there is
  /// something. The host calls it again when the thread wakes, so it takes guest addresses.
  recvMsgInto(fd, msg, flags) {
    const desc = this.socketDesc(fd);
    if (typeof desc === "number") return desc;
    if (!this.inBounds(msg, Kernel.MSGHDR)) return -EFAULT;
    const iovs = this.iovecs(msg);
    if (!iovs) return -EINVAL;
    const total = iovs.reduce((n, iov) => n + iov.len, 0);
    const got = desc.recv(Math.min(total, 0x7ffff000), (Number(flags) & 2) !== 0);
    if (got === WOULD_BLOCK) {
      if (desc.nonblock || (Number(flags) & 0x40) !== 0) return -EAGAIN;
      return this.ask({ kind: "recvmsg", fd, msg, flags: Number(flags), deadline: desc.timeout ? Date.now() + desc.timeout : 0 });
    }
    if (got.errno) return got.errno;
    let done = 0;
    for (const iov of iovs) {
      if (done >= got.data.length) break;
      const take = got.data.subarray(done, done + Math.min(iov.len, got.data.length - done));
      if (!this.put(iov.at, take)) return -EFAULT;
      done += take.length;
    }
    const name = Number(this.u64(msg));
    if (name !== 0) {
      if (got.from) this.putAddr(name, msg + 8, got.from);
      else this.put32(msg + 8, 0);
    }
    // No control data is passed either way yet, and msg_flags says the datagram was cut short.
    this.put32(msg + 48, (Number(flags) & 0x20) !== 0 ? 0x20 : 0);
    this.put64(msg + 40, 0n);
    return (Number(flags) & 0x20) !== 0 ? got.full : got.data.length;
  }

  /// `struct mmsghdr` is the header and the length the call wrote.
  static MMSGHDR = 64;

  sendMMsgInto(fd, vec, vlen, flags) {
    if (vlen < 0 || vlen > 1024) return -EINVAL;
    if (!this.inBounds(vec, vlen * Kernel.MMSGHDR)) return -EFAULT;
    let sent = 0;
    for (let i = 0; i < vlen; i++) {
      const answer = this.sendMsgInto(fd, vec + i * Kernel.MMSGHDR, flags);
      if (answer < 0) return sent > 0 ? sent : answer;
      this.put32(vec + i * Kernel.MMSGHDR + Kernel.MSGHDR, answer);
      sent++;
    }
    return sent;
  }

  /// recvmmsg: only the first message waits, which is what MSG_WAITFORONE means; the rest are taken
  /// as far as they are there.
  recvMMsgInto(fd, vec, vlen, flags, deadline) {
    const desc = this.socketDesc(fd);
    if (typeof desc === "number") return desc;
    if (vlen < 0 || vlen > 1024) return -EINVAL;
    if (!this.inBounds(vec, vlen * Kernel.MMSGHDR)) return -EFAULT;
    let got = 0;
    for (let i = 0; i < vlen; i++) {
      const msg = vec + i * Kernel.MMSGHDR;
      const answer = this.recvMsgInto(fd, msg, flags);
      if (typeof answer !== "number") return i === 0 ? answer : got;
      if (answer === -EAGAIN) break;
      if (answer < 0) return got > 0 ? got : answer;
      this.put32(msg + Kernel.MSGHDR, answer);
      got++;
    }
    if (got === 0 && vlen > 0 && !desc.nonblock) {
      return this.ask({ kind: "recvmmsg", fd, vec, vlen, flags, deadline });
    }
    return got;
  }

  /// Milliseconds from a `struct timespec` a call may time out on: -1 means wait for ever, which
  /// is what a null pointer says, and null is a pointer that is not readable.
  timespecMs(addr) {
    if (this.addr(addr) === 0) return -1;
    const at = this.addr(addr);
    if (!this.inBounds(at, 16)) return null;
    const view = new DataView(this.memory.buffer);
    const sec = Number(view.getBigInt64(at, true));
    const nsec = Number(view.getBigInt64(at + 8, true));
    return Math.max(0, Math.ceil(sec * 1000 + nsec / 1e6));
  }

  /// Whether a descriptor would answer `poll` now, per direction.
  pollState(entry, fd) {
    if (entry.kind === "socket") return entry.desc.status();
    if (entry.kind === "epoll") {
      // An epoll descriptor is readable when one of the descriptors it watches is, which is how one
      // epoll can be waited on inside another.
      return { read: (this.epollReady(fd, 1) ?? []).length > 0, write: false, err: false, hup: false };
    }
    if (entry.kind === "pipe") {
      const read = entry.end === "read" && (entry.desc.data.length > 0 || entry.desc.writers === 0);
      return { read, write: entry.end === "write", err: false, hup: read && entry.desc.writers === 0 };
    }
    // A file, a device or a directory: the host never makes one wait.
    return { read: true, write: entry.kind !== "dir" && entry.desc?.writable !== false, err: false, hup: false };
  }

  /// One non-blocking pass of `poll` over the guest's own array of `struct pollfd`.
  pollOnce(fds, nfds) {
    const view = new DataView(this.memory.buffer);
    let ready = 0;
    for (let i = 0; i < nfds; i++) {
      const at = fds + i * 8;
      const fd = view.getInt32(at, true);
      const events = view.getUint16(at + 4, true);
      let revents = 0;
      if (fd < 0) {
        view.setUint16(at + 6, 0, true);
        continue;
      }
      const entry = this.files.get(fd);
      if (!entry) revents = 0x20; // POLLNVAL
      else {
        const state = this.pollState(entry, fd);
        if (state.read && (events & 0x41)) revents |= events & 0x41;
        if (state.write && (events & 0x04)) revents |= 0x04;
        if (state.err) revents |= 0x08;
        if (state.hup) revents |= 0x10;
      }
      view.setUint16(at + 6, revents, true);
      if (revents) ready++;
    }
    return ready;
  }

  /// One non-blocking pass of `select`, from the three bitmaps the guest passed: the sets are read
  /// as they are, so a pass that finds nothing leaves the call's arguments untouched.
  selectOnce(nfds, readp, writep, exceptp) {
    const size = Math.ceil(nfds / 8);
    const sets = [
      { kind: "read", at: readp, in: readp ? this.read(readp, size) : null },
      { kind: "write", at: writep, in: writep ? this.read(writep, size) : null },
      { kind: "except", at: exceptp, in: exceptp ? this.read(exceptp, size) : null },
    ].map((set) => ({ ...set, out: set.at ? Buffer.alloc(size) : null }));
    let ready = 0;
    for (let fd = 0; fd < nfds; fd++) {
      for (const set of sets) {
        if (!set.in || !(set.in[fd >> 3] & (1 << (fd & 7)))) continue;
        const entry = this.files.get(fd);
        const state = entry ? this.pollState(entry, fd) : null;
        const on = !state ? true : set.kind === "read" ? state.read : set.kind === "write" ? state.write : state.err;
        if (!on) continue;
        set.out[fd >> 3] |= 1 << (fd & 7);
        ready++;
      }
    }
    return { ready, sets };
  }

  putSelect(sets) {
    for (const set of sets) if (set.at) this.put(set.at, set.out);
  }

  registerSockets() {
    this.on(198, (k, domain, type, protocol) => {
      const desc = k.net.create(Number(domain), Number(type) & 0xf, Number(protocol));
      if (typeof desc === "number") return [BigInt(desc), 0];
      // SOCK_NONBLOCK and SOCK_CLOEXEC share their bits with O_NONBLOCK and O_CLOEXEC.
      desc.nonblock = (Number(type) & 0x800) !== 0;
      const entry = { kind: "socket", desc, cloexec: (Number(type) & 0x80000) !== 0 };
      return [BigInt(k.files.add(entry)), 0];
    });

    this.on(199, (k, domain, type, protocol, sv) => {
      const pair = k.net.pair(Number(domain), Number(type) & 0xf);
      if (typeof pair === "number") return [BigInt(pair), 0];
      const nonblock = (Number(type) & 0x800) !== 0;
      const cloexec = (Number(type) & 0x80000) !== 0;
      const fds = pair.map((desc) => {
        desc.nonblock = nonblock;
        return k.files.add({ kind: "socket", desc, cloexec });
      });
      if (!k.put32(sv, fds[0]) || !k.put32(k.addr(sv) + 4, fds[1])) return k.fail(EFAULT);
      return [0n, 0];
    });

    this.on(200, (k, fd, addr, len) => {
      const desc = k.socketDesc(Number(fd));
      if (typeof desc === "number") return [BigInt(desc), 0];
      const want = k.guestAddr(addr, len);
      if (want === undefined) return k.fail(EFAULT);
      if (want === null) return k.fail(EINVAL);
      return k.ask({ kind: "bind", fd: Number(fd), addr: want });
    });

    this.on(201, (k, fd, backlog) => {
      const desc = k.socketDesc(Number(fd));
      if (typeof desc === "number") return [BigInt(desc), 0];
      return [BigInt(desc.listen(Number(backlog))), 0];
    });

    // accept and accept4: the next connection as a descriptor of its own, or a thread parked until
    // one arrives.
    this.on(202, (k, fd, addr, lenp) => k.done(k.acceptInto(Number(fd), k.addr(addr), k.addr(lenp), 0)));
    this.on(242, (k, fd, addr, lenp, flags) =>
      k.done(k.acceptInto(Number(fd), k.addr(addr), k.addr(lenp), Number(flags))),
    );

    this.on(203, (k, fd, addr, len) => {
      const desc = k.socketDesc(Number(fd));
      if (typeof desc === "number") return [BigInt(desc), 0];
      const want = k.guestAddr(addr, len);
      if (want === undefined) return k.fail(EFAULT);
      if (want === null) return k.fail(EINVAL);
      // A datagram socket's connect records the peer and answers now. A connection has to reach the
      // host: a guest that asked not to wait gets EINPROGRESS and learns the outcome from `poll`
      // and SO_ERROR, which is the path every non-blocking client takes.
      const started = desc.connect(want);
      if (typeof started === "number") return [BigInt(started), 0];
      if (desc.nonblock) {
        started.catch(() => {});
        return k.fail(EINPROGRESS);
      }
      return k.ask({ kind: "connect", fd: Number(fd) });
    });

    this.on(210, (k, fd, how) => {
      const desc = k.socketDesc(Number(fd));
      if (typeof desc === "number") return [BigInt(desc), 0];
      return [BigInt(desc.shutdown(Number(how))), 0];
    });

    this.on(204, (k, fd, addr, lenp) => {
      const desc = k.socketDesc(Number(fd));
      if (typeof desc === "number") return [BigInt(desc), 0];
      // A socket that has sent but not been bound gets its port from the host a moment after the
      // send, so the answer waits for it rather than reporting a port of zero.
      if (desc.addressPending?.()) {
        return k.ask({ kind: "address", fd: Number(fd), addr: k.addr(addr), lenp: k.addr(lenp) });
      }
      if (!k.putAddr(addr, lenp, desc.address())) return k.fail(EFAULT);
      return [0n, 0];
    });

    this.on(205, (k, fd, addr, lenp) => {
      const desc = k.socketDesc(Number(fd));
      if (typeof desc === "number") return [BigInt(desc), 0];
      if (!desc.peer) return k.fail(ENOTCONN);
      if (!k.putAddr(addr, lenp, desc.peer)) return k.fail(EFAULT);
      return [0n, 0];
    });

    this.on(206, (k, fd, buf, len, flags, addr, addrlen) => {
      const desc = k.socketDesc(Number(fd));
      if (typeof desc === "number") return [BigInt(desc), 0];
      const to = k.guestAddr(addr, addrlen);
      if (to === undefined) return k.fail(EFAULT);
      const bytes = k.read(buf, Math.min(Number(len), 0x7ffff000));
      if (bytes === null) return k.fail(EFAULT);
      return [BigInt(desc.send(Buffer.from(bytes), to)), 0];
    });

    this.on(211, (k, fd, msg, flags) => k.done(k.sendMsgInto(Number(fd), k.addr(msg), Number(flags))));

    this.on(212, (k, fd, msg, flags) => k.done(k.recvMsgInto(Number(fd), k.addr(msg), Number(flags))));

    // sendmmsg and recvmmsg: the same two calls over an array of headers. glibc's resolver sends
    // the A and AAAA questions in one sendmmsg, and reads the answers in one recvmmsg, so a guest
    // that resolves a name needs both.
    this.on(269, (k, fd, vec, vlen, flags) => k.done(k.sendMMsgInto(Number(fd), k.addr(vec), Number(vlen), Number(flags))));

    this.on(243, (k, fd, vec, vlen, flags, tmo) => {
      const deadline = k.timespecMs(k.addr(tmo));
      if (deadline === null) return k.fail(EINVAL);
      return k.done(
        k.recvMMsgInto(Number(fd), k.addr(vec), Number(vlen), Number(flags), deadline < 0 ? 0 : Date.now() + deadline),
      );
    });

    this.on(207, (k, fd, buf, len, flags, addr, lenp) =>
      k.done(k.recvInto(Number(fd), k.addr(buf), Number(len), Number(flags), k.addr(addr), k.addr(lenp))),
    );

    this.on(208, (k, fd, level, name, val, len) => {
      const desc = k.socketDesc(Number(fd));
      if (typeof desc === "number") return [BigInt(desc), 0];
      const n = Math.min(Number(len), 128);
      const bytes = n > 0 ? k.read(val, n) : Buffer.alloc(0);
      if (bytes === null) return k.fail(EFAULT);
      return [BigInt(desc.option(Number(level), Number(name), bytes)), 0];
    });

    this.on(209, (k, fd, level, name, val, lenp) => {
      const desc = k.socketDesc(Number(fd));
      if (typeof desc === "number") return [BigInt(desc), 0];
      const answer = desc.get(Number(level), Number(name));
      if (answer === null) return [0n, 0];
      if (!k.put32(val, answer)) return k.fail(EFAULT);
      if (Number(lenp) !== 0) k.put32(lenp, 4);
      return [0n, 0];
    });

    // ppoll. aarch64 has no plain `poll`: glibc spells it with this one, timeout and all.
    this.on(73, (k, fds, nfds, tmo) => {
      const n = Number(nfds);
      const at = k.addr(fds);
      if (n < 0 || n > 4096 || !k.inBounds(at, n * 8)) return k.fail(EINVAL);
      const timeout = k.timespecMs(tmo);
      if (timeout === null) return k.fail(EINVAL);
      const ready = k.pollOnce(at, n);
      if (process.env.ARMJIT_TRACE_SOCKETS) {
        console.error(`sockets: poll n=${n} timeout=${timeout} ready=${ready}`);
      }
      if (ready > 0) return [BigInt(ready), 0];
      if (timeout === 0) return [0n, 0];
      return k.ask({ kind: "poll", fds: at, nfds: n, deadline: timeout < 0 ? 0 : Date.now() + timeout });
    });

    // pselect6, which is what glibc's `select` asks for.
    this.on(72, (k, nfds, readp, writep, exceptp, tmo) => {
      const n = Number(nfds);
      if (n < 0 || n > 4096) return k.fail(EINVAL);
      const timeout = k.timespecMs(k.addr(tmo));
      if (timeout === null) return k.fail(EINVAL);
      const sets = { read: k.addr(readp), write: k.addr(writep), except: k.addr(exceptp) };
      const got = k.selectOnce(n, sets.read, sets.write, sets.except);
      if (got.ready > 0) {
        k.putSelect(got.sets);
        return [BigInt(got.ready), 0];
      }
      if (timeout === 0) return [0n, 0];
      return k.ask({ kind: "select", ...sets, nfds: n, deadline: timeout < 0 ? 0 : Date.now() + timeout });
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
    // Every file belongs to the one user this machine has, which is the id `getuid` answers:
    // a stat that reported the host's ids would say the tree belongs to someone the guest is not.
    this.put32(addr + 24n, 0);
    this.put32(addr + 28n, 0);
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
    // One user, and it is root. The setters succeed because there is nobody to change to, which is
    // what a program that drops privileges before it talks to the network expects to hear; the
    // getters answer the one id everything in this tree belongs to.
    // The setters move the process to the ids they are given. Nothing is checked against them, so a
    // program that drops privileges before it talks to the network gets what it asked for and sees
    // it in the getters.
    const id = (v) => (v === -1n || v === 0xffffffffn ? null : Number(v));
    this.on(146, (k, uid) => { // setuid
      const u = Number(uid);
      k.ids = { ...k.ids, uid: u, euid: u };
      return [0n, 0];
    });
    this.on(144, (k, gid) => { // setgid
      const g = Number(gid);
      k.ids = { ...k.ids, gid: g, egid: g };
      return [0n, 0];
    });
    this.on(145, (k, ruid, euid) => { // setreuid
      const ids = { ...k.ids };
      if (id(ruid) !== null) ids.uid = id(ruid);
      if (id(euid) !== null) ids.euid = id(euid);
      k.ids = ids;
      return [0n, 0];
    });
    this.on(143, (k, rgid, egid) => { // setregid
      const ids = { ...k.ids };
      if (id(rgid) !== null) ids.gid = id(rgid);
      if (id(egid) !== null) ids.egid = id(egid);
      k.ids = ids;
      return [0n, 0];
    });
    this.on(147, (k, ruid, euid, suid) => { // setresuid
      const ids = { ...k.ids };
      if (id(ruid) !== null) ids.uid = id(ruid);
      if (id(euid) !== null) ids.euid = id(euid);
      if (id(suid) !== null) ids.uid = id(suid);
      k.ids = ids;
      return [0n, 0];
    });
    this.on(149, (k, rgid, egid, sgid) => { // setresgid
      const ids = { ...k.ids };
      if (id(rgid) !== null) ids.gid = id(rgid);
      if (id(egid) !== null) ids.egid = id(egid);
      if (id(sgid) !== null) ids.gid = id(sgid);
      k.ids = ids;
      return [0n, 0];
    });
    this.on(151, (k, uid) => { // setfsuid: the file system id, which is the effective one here
      k.ids = { ...k.ids, fsuid: Number(uid) };
      return [0n, 0];
    });
    this.on(152, (k, gid) => {
      k.ids = { ...k.ids, fsgid: Number(gid) };
      return [0n, 0];
    });
    this.on(148, (k, ruid, euid, suid) => {
      // getresuid: three ids, and a null pointer is a caller that does not want that one.
      if (Number(ruid) !== 0) k.put32(ruid, k.ids.uid);
      if (Number(euid) !== 0) k.put32(euid, k.ids.euid);
      if (Number(suid) !== 0) k.put32(suid, k.ids.uid);
      return [0n, 0];
    });
    this.on(150, (k, rgid, egid, sgid) => {
      if (Number(rgid) !== 0) k.put32(rgid, k.ids.gid);
      if (Number(egid) !== 0) k.put32(egid, k.ids.egid);
      if (Number(sgid) !== 0) k.put32(sgid, k.ids.gid);
      return [0n, 0];
    });
    // getgroups: the groups the process is in, and a zero-sized list is a question about how many.
    this.on(158, (k, size, list) => {
      const n = Number(size);
      if (n === 0) return [BigInt(k.ids.groups.length), 0];
      if (n < 0) return k.fail(EINVAL);
      const take = Math.min(n, k.ids.groups.length);
      const at = k.addr(list);
      for (let i = 0; i < take; i++) k.put32(at + i * 4, k.ids.groups[i]);
      return [BigInt(take), 0];
    });
    this.on(159, (k, size, list) => { // setgroups
      const n = Number(size);
      if (n < 0 || n > 65536) return k.fail(EINVAL);
      const groups = [];
      for (let i = 0; i < n; i++) {
        const gid = new DataView(k.memory.buffer).getUint32(k.addr(list) + i * 4, true);
        groups.push(gid);
      }
      k.ids = { ...k.ids, groups };
      return [0n, 0];
    });
    this.on(154, () => [0n, 0]); // setpgid
    this.on(155, (k, pid) => [pid === 0n ? BigInt(k.pid) : pid, 0]); // getpgid
    this.on(156, (k, pid) => [pid === 0n ? BigInt(k.pid) : pid, 0]); // getsid
    this.on(157, (k) => [BigInt(k.pid), 0]); // setsid: the process is its own session
    this.on(167, () => [0n, 0]); // prctl: nothing here to control

    this.on(174, (k) => [BigInt(k.ids.uid), 0]); // getuid
    this.on(175, (k) => [BigInt(k.ids.euid), 0]); // geteuid
    this.on(176, (k) => [BigInt(k.ids.gid), 0]); // getgid
    this.on(177, (k) => [BigInt(k.ids.egid), 0]); // getegid
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
      // RLIMIT_NOFILE is what `sysconf(_SC_OPEN_MAX)` reads, and a program that closes every
      // descriptor below it walks the whole number: apt's `ExecFork` does that before each child.
      // Infinite would mean two billion iterations, so the file limit is what a Debian container
      // reports. Everything else is unlimited, which one process can honour.
      const [soft, hard] =
        Number(resource) === 7 // RLIMIT_NOFILE
          ? [20480n, 1048576n]
          : [0xffffffffffffffffn, 0xffffffffffffffffn];
      if (oldLimit !== 0n && Number(oldLimit) !== 0) {
        k.put64(oldLimit, soft);
        k.put64(oldLimit + 8n, hard);
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

    // A signal number of zero asks whether a process is there, and a disposition of its own decides
    // what the rest do: an ignored signal is nothing, and a caught one is recorded here and never
    // run, because a handler is guest code this kernel has no way to enter.
    // A signal to the calling process itself is the way a program kills itself, so a call that ends
    // the caller has to end the wasm run too rather than answer and carry on.
    const stopped = (k, answer) => [BigInt(answer), k.exited !== null ? 1 : 0];
    this.on(129, (k, pid, sig) => stopped(k, k.kill(Number(BigInt.asIntN(32, pid)), Number(sig)))); // kill
    this.on(130, (k, tid, sig) => stopped(k, k.kill(0, Number(sig), Number(BigInt.asIntN(32, tid))))); // tkill
    this.on(131, (k, tgid, tid, sig) =>
      // tgkill: the thread id names the target, and the group is a check Linux makes that this
      // kernel has nothing to check it against.
      stopped(k, k.kill(0, Number(sig), Number(BigInt.asIntN(32, tid)))),
    );

    this.on(134, (k, sig, act, old) => {
      const n = Number(sig);
      if (n < 1 || n > 64) return k.fail(EINVAL);
      // SIGKILL and SIGSTOP have no disposition to set: asking about one is fine, and setting one
      // is EINVAL.
      if ((n === 9 || n === 19) && Number(act) !== 0) return k.fail(EINVAL);
      if (Number(old) !== 0) {
        // `struct sigaction` is the handler, the flags, the restorer and the mask.
        if (!k.put(Number(old), Buffer.alloc(32))) return k.fail(EFAULT);
      }
      if (Number(act) !== 0) {
        const handler = Number(k.u64(act));
        k.signals.set(n, handler === 1 ? "ignore" : "catch");
      } else {
        k.signals.delete(n);
      }
      return [0n, 0];
    });
    this.on(135, (k, how, set, old) => {
      if (Number(old) !== 0) k.put64(old, 0n);
      return [0n, 0];
    });
    this.on(98, (k, uaddr, op, val) => {
      // The private flag and the realtime clock are bits above the command, and the bitset forms
      // wait and wake on the same word as the plain ones do.
      const cmd = Number(op) & 0x7f;
      const at = k.addr(uaddr);
      if (cmd === 0 || cmd === 9) {
        // FUTEX_WAIT: the host checks the word and parks the thread, so that a wake that arrives
        // between the check and the sleep cannot be lost.
        return k.ask({ kind: "futex", addr: at, value: Number(BigInt.asIntN(32, BigInt.asUintN(32, val))) });
      }
      if (cmd === 1 || cmd === 10) {
        // FUTEX_WAKE
        const want = Number(BigInt.asIntN(32, BigInt.asUintN(32, val)));
        return [BigInt(k.futexWake(at, want < 0 ? -1 : want)), 0];
      }
      if (cmd === 2 || cmd === 3) return [0n, 0]; // FUTEX_FD / FUTEX_REQUEUE: nothing to do
      return k.fail(ENOSYS);
    });
    this.on(233, () => [0n, 0]); // madvise
    this.on(324, () => [0n, 0]); // membarrier: one thread, nothing to synchronise
    this.on(124, () => [0n, 0]); // sched_yield
  }
}


export { EFAULT, ENOMEM, EINVAL };

function trace(text) {
  if (process.env.ARMJIT_TRACE_SOCKETS) console.error(`sockets: ${text}`);
}

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
