// Open files, resolved against a root filesystem directory.
//
// The guest's paths are absolute and its root is the rootfs directory, so `openat` sees a normal
// tree: the host does the I/O, this class keeps the descriptor table and the guest's idea of them
// straight. Descriptors 0..2 are the process's own streams.

import fs from "node:fs";
import path from "node:path";

export const ENOENT = 2;
export const EBADF = 9;
export const EACCES = 13;
export const EFAULT = 14;
export const EINVAL = 22;
export const EISDIR = 21;
export const ENOTDIR = 20;
export const ESPIPE = 29;
export const ELOOP = 40;
export const ENAMETOOLONG = 36;
export const ENOSPC = 28;
export const EPIPE = 32;
export const EEXIST = 17;
export const EPERM = 1;
export const EAGAIN = 11;
export const ENOTEMPTY = 39;
export const EXDEV = 18;
export const ENOSYS = 38;
export const EROFS = 30;

/// What a read of a pipe with writers but no data answers: the process has to wait for one.
export const WOULD_BLOCK = Symbol("would block");

export const AT_FDCWD = -100;

const DT = { file: 8, dir: 4, link: 10, fifo: 1, sock: 12, chr: 2, blk: 6 };

/// The character devices a program expects to find: a rootfs unpacked by `apt` has an empty /dev,
/// so the kernel provides them by name rather than by node.
const DEVICES = new Map([
  ["/dev/null", { kind: "null", mode: 0o020666, rdev: 0x0103 }],
  ["/dev/zero", { kind: "zero", mode: 0o020666, rdev: 0x0105 }],
  ["/dev/full", { kind: "full", mode: 0o020666, rdev: 0x0107 }],
  ["/dev/random", { kind: "random", mode: 0o020666, rdev: 0x0108 }],
  ["/dev/urandom", { kind: "random", mode: 0o020666, rdev: 0x0109 }],
]);

const O_ACCMODE = 3;
export const O_WRONLY = 1;
export const O_RDWR = 2;
const O_CREAT = 0x40;
const O_EXCL = 0x80;
const O_TRUNC = 0x200;
const O_APPEND = 0x400;
const O_DIRECTORY = 0x4000;
const O_CLOEXEC = 0x80000;

export class Files {
  constructor(rootfs, options = {}) {
    this.rootfs = rootfs ? path.resolve(rootfs) : null;
    /// Whose table this is, so a trace of it names the process the descriptor belongs to.
    this.pid = options.pid ?? 0;
    /// Files this kernel has that the tree does not. A rootfs unpacked by `apt` has an empty
    /// `/etc/resolv.conf`, and a program that resolves a name still needs one to read.
    this.virtual = options.virtual ?? new Map();
    this.map = new Map();
    this.next = 3;
    this.seed = 1;
    /// The bytes `/dev/urandom` and `getrandom` hand out: one stream, so a run twice is a run twice.
    this.random = 1n;
    this.cwd = "/";
    this.umask = 0o022;
    this.map.set(0, { kind: "stdin" });
    this.map.set(1, { kind: "stdout" });
    this.map.set(2, { kind: "stderr" });
  }

  /// The path the guest named, as its own absolute path, with the components left as they are: a
  /// `..` that follows a symbolic link is that link's parent, not the parent of the name that
  /// reached it, and only a walk that reads the links can tell which.
  guestPath(name) {
    return name.startsWith("/") ? name : `${this.cwd}/${name}`;
  }

  /// Guest path to host path, following the tree's own symbolic links: an absolute target restarts
  /// at the guest's root and a relative one is joined to the directory its link sits in. The host's
  /// `read` would follow them with this machine's root, where the guest's `/etc/alternatives/awk`
  /// is a file that does not exist.
  resolve(guestPath, follow = true) {
    if (!this.rootfs) return -ENOENT;
    if (guestPath.includes("\0")) return -ENOENT;
    const queue = this.guestPath(guestPath).split("/").filter((p) => p !== "" && p !== ".");
    const done = [];
    let links = 0;
    while (queue.length) {
      const name = queue.shift();
      if (name === "..") {
        // `..` at the root is the root, the way a chroot's is.
        done.pop();
        continue;
      }
      // The form that does not follow its last component, which is the one that unlinks a link or
      // renames it, names the link itself.
      if (queue.length === 0 && !follow) {
        done.push(name);
        break;
      }
      const at = `/${[...done, name].join("/")}`;
      let st;
      try {
        st = fs.lstatSync(path.join(this.rootfs, at));
      } catch (e) {
        // A component that is not there is the caller's to report, and the last one is a file that
        // an open with O_CREAT is about to make.
        if (queue.length) return -ENOENT;
        done.push(name);
        break;
      }
      if (!st.isSymbolicLink()) {
        done.push(name);
        continue;
      }
      if (++links > 40) return -ELOOP;
      let target;
      try {
        target = fs.readlinkSync(path.join(this.rootfs, at));
      } catch (e) {
        return -EINVAL;
      }
      if (target.startsWith("/")) done.length = 0;
      queue.unshift(...target.split("/").filter((p) => p !== "" && p !== "."));
    }
    const host = path.join(this.rootfs, `/${done.join("/")}`);
    if (host !== this.rootfs && !host.startsWith(this.rootfs + path.sep)) return -EACCES;
    return host;
  }

  /// The guest path a host path inside the tree stands for.
  guestOf(host) {
    const rel = path.relative(this.rootfs, host).split(path.sep).join("/");
    return rel ? `/${rel}` : "/";
  }

  /// A `*at` call's path: an absolute one is the guest's root, a relative one is the directory
  /// descriptor it was given, which is either the process's own directory or an open one.
  resolveAt(name, dirfd, follow = true) {
    // A descriptor is a 32-bit int in the ABI, and AT_FDCWD arrives as -100 in whichever width the
    // caller used for it.
    const fd = Number(BigInt.asIntN(32, BigInt(dirfd)));
    let base = this.cwd;
    if (!name.startsWith("/") && fd !== AT_FDCWD) {
      const entry = this.map.get(fd);
      if (!entry) return -EBADF;
      if (entry.kind !== "dir") return -ENOTDIR;
      base = this.guestOf(entry.host);
    }
    return this.resolve(name.startsWith("/") ? name : `${base}/${name}`, follow);
  }

  /// The contents of a file this kernel provides rather than the tree, or null.
  virtualFile(guestPath) {
    return this.virtual.get(this.guestPath(guestPath)) ?? null;
  }

  /// The metadata of one, and the shape a program that `stat`s a config file expects.
  virtualStat(guestPath) {
    const bytes = this.virtualFile(guestPath);
    if (!bytes) return null;
    return { mode: 0o100644n, nlink: 1n, size: BigInt(bytes.length), ino: 3n, dev: 0n, rdev: 0n, blksize: 4096n };
  }

  add(entry) {
    const fd = this.next++;
    this.map.set(fd, entry);
    return fd;
  }

  get(fd) {
    return this.map.get(fd);
  }

  /// What the descriptor table did, for a run that has to explain a pipe that never closes.
  note(text, desc) {
    if (!process.env.ARMJIT_TRACE_FDS) return;
    const ends = desc && desc.readers !== undefined ? ` r=${desc.readers} w=${desc.writers}` : "";
    console.error(`fds: ${this.pid}: ${text}${ends}`);
  }

  /// A pipe: one description with a byte buffer, and one descriptor on each end.
  pipe(cloexec) {
    const desc = { id: (this.seed += 1), data: Buffer.alloc(0), readers: 1, writers: 1 };
    const read = this.add({ kind: "pipe", end: "read", desc, cloexec });
    const write = this.add({ kind: "pipe", end: "write", desc, cloexec });
    this.note(`pipe ${read},${write}`, desc);
    return [read, write];
  }

  /// A second descriptor on the same open file description, as a fork or a dup makes one.
  copyEntry(entry, cloexec = entry.cloexec) {
    const copy = { ...entry, cloexec };
    if (entry.kind === "pipe") {
      if (entry.end === "read") entry.desc.readers++;
      else entry.desc.writers++;
      this.note(`dup ${entry.end} end`, entry.desc);
    }
    // A socket description is the host socket: the last descriptor on it closes it, and a fork
    // shares it the way it shares an open file.
    if (entry.kind === "socket") entry.desc.refs++;
    if (entry.kind === "file") entry.desc.refs++;
    return copy;
  }

  /// Whether a read of this descriptor would return now instead of waiting.
  readReady(fd) {
    const entry = this.map.get(fd);
    if (!entry || entry.kind !== "pipe") return true;
    return entry.desc.data.length > 0 || entry.desc.writers === 0;
  }

  /// Bytes from a generator that starts from a fixed point, so a run reproduces.
  randomBytes(len) {
    // Deterministic, and 64 bits wide: the step's product does not fit in a double, and the low
    // bytes of a rounded one are always zero.
    const out = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      this.random = (this.random * 6364136223846793005n + 1442695040888963407n) & 0xffffffffffffffffn;
      out[i] = Number((this.random >> 33n) & 0xffn);
    }
    return out;
  }

  /// fcntl's F_DUPFD: another descriptor on the same open file description.
  dup(fd, from, cloexec) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    let n = Math.max(from, 0);
    while (this.map.has(n)) n++;
    this.map.set(n, this.copyEntry(entry, cloexec));
    return n;
  }

  /// dup3: make `newfd` another descriptor on the same open file description, closing it first.
  dup3(oldfd, newfd, cloexec) {
    const entry = this.map.get(oldfd);
    if (!entry) return -EBADF;
    if (oldfd === newfd) return -EINVAL;
    this.close(newfd);
    this.map.set(newfd, this.copyEntry(entry, cloexec));
    if (newfd >= this.next) this.next = newfd + 1;
    return newfd;
  }

  /// Every descriptor, for a process that exited: whoever was waiting on a pipe has to see the
  /// last writer go away.
  closeAll() {
    for (const fd of [...this.map.keys()]) this.close(fd);
  }

  /// What survives an exec: the descriptors whose entry was not opened close-on-exec. The others
  /// are closed, which matters for a pipe: the program that execs is no longer a reader of it.
  keepAcrossExec() {
    for (const [fd, entry] of this.map) {
      if (entry.cloexec) this.close(fd);
    }
  }

  open(guestPath, flags, mode, dirfd = AT_FDCWD) {
    const virtual = this.virtualFile(guestPath);
    if (virtual) {
      if ((flags & O_ACCMODE) !== 0 || (flags & O_TRUNC)) return -EROFS;
      return this.add({
        kind: "file",
        host: null,
        virtual,
        size: virtual.length,
        desc: { pos: 0, readable: true, writable: false },
        cloexec: (flags & O_CLOEXEC) !== 0,
      });
    }
    const device = DEVICES.get(this.guestPath(guestPath));
    if (device) return this.add({ ...device, desc: { pos: 0 }, cloexec: (flags & O_CLOEXEC) !== 0 });
    const host = this.resolveAt(guestPath, dirfd);
    if (host < 0) return host;
    const access = flags & O_ACCMODE;
    try {
      // The entry is one descriptor; `desc` is the open file description behind it, which a
      // duplicate shares, so a read through either one moves the position for both.
      const entry = {
        kind: "file",
        host,
        desc: {
          pos: 0,
          append: (flags & O_APPEND) !== 0,
          readable: access !== O_WRONLY,
          writable: access !== 0,
          /// How many descriptors hold this open file description, and the host's own descriptor
          /// once something has read or written through it.
          refs: 1,
          handle: null,
        },
        cloexec: (flags & O_CLOEXEC) !== 0,
      };
      if ((flags & O_CREAT) && (flags & O_EXCL) && fs.existsSync(host)) return -EEXIST;
      if ((flags & O_CREAT) && !fs.existsSync(host)) {
        fs.mkdirSync(path.dirname(host), { recursive: true });
        fs.writeFileSync(host, Buffer.alloc(0), { mode: this.mask(mode || 0o666) });
      }
      const st = fs.statSync(host);
      if ((flags & O_DIRECTORY) && !st.isDirectory()) return -ENOTDIR;
      if (st.isDirectory()) {
        if (entry.desc.writable) return -EISDIR;
        entry.kind = "dir";
        entry.size = st.size;
        return this.add(entry);
      }
      if ((flags & O_TRUNC) && entry.desc.writable) fs.writeFileSync(host, Buffer.alloc(0));
      entry.size = st.size;
      // The host's descriptor is opened here rather than on the first read, because the first read
      // can come after the guest has unlinked the name: that is how a program makes a temporary
      // file, and the bytes it then writes belong to the file it opened.
      entry.desc.handle = fs.openSync(
        host,
        entry.desc.readable && entry.desc.writable ? O_RDWR : entry.desc.writable ? O_WRONLY : 0,
      );
      return this.add(entry);
    } catch (e) {
      return fromErrno(e, -ENOENT);
    }
  }

  close(fd) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    this.map.delete(fd);
    // Whoever holds something about a descriptor - an epoll's registration - hears that it is gone,
    // whichever path closed it: a close, a dup3 that replaced it, or an exec that dropped it.
    this.onClose?.(fd);
    if (entry.kind === "socket") entry.desc.release();
    if (entry.kind === "pipe") {
      if (entry.end === "read") entry.desc.readers--;
      else entry.desc.writers--;
      this.note(`close fd ${fd} ${entry.end} end`, entry.desc);
    }
    if (entry.kind === "file" && entry.desc && --entry.desc.refs <= 0) this.closeHandle(entry.desc);
    return 0;
  }

  closeHandle(desc) {
    if (desc.handle === null) return;
    try {
      fs.closeSync(desc.handle);
    } catch {}
    desc.handle = null;
  }

  /// The host's own descriptor for an open file, opened the first time something needs it and kept
  /// until the last guest descriptor on it is closed. A program that makes a temporary file unlinks
  /// it and keeps reading and writing through the descriptor it opened, and the bytes have to stay
  /// reachable: a path goes away, an open file does not.
  handleOf(entry) {
    const desc = entry.desc;
    if (desc.handle !== null) return desc.handle;
    const flags = desc.readable && desc.writable ? O_RDWR : desc.writable ? O_WRONLY : 0;
    desc.handle = fs.openSync(entry.host, flags);
    return desc.handle;
  }

  bytes(entry, off, len) {
    if (entry.virtual) return entry.virtual.subarray(off, off + len);
    const buf = Buffer.alloc(len);
    const n = fs.readSync(this.handleOf(entry), buf, 0, len, off);
    return buf.subarray(0, n);
  }

  read(fd, len) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind === "dir") return -EISDIR;
    if (entry.kind === "stdin") return Buffer.alloc(0); // stdin is empty: no console yet
    if (entry.kind === "null") return Buffer.alloc(0);
    if (entry.kind === "zero" || entry.kind === "full") return Buffer.alloc(len);
    if (entry.kind === "random") return this.randomBytes(len);
    if (entry.kind === "pipe") {
      if (entry.end !== "read") return -EBADF;
      const desc = entry.desc;
      if (!desc.data.length) {
        this.note(`read fd ${fd} on pipe ${desc.id} with nothing (r=${desc.readers} w=${desc.writers})`, desc);
        if (desc.writers === 0) return Buffer.alloc(0);
        // A non-blocking pipe answers the guest's own question rather than parking its thread:
        // `apt` sets O_NONBLOCK on the pipes to its methods and then reads them in a loop that
        // expects EAGAIN.
        return desc.nonblock ? -EAGAIN : WOULD_BLOCK;
      }
      const out = desc.data.subarray(0, len);
      desc.data = desc.data.subarray(out.length);
      return Buffer.from(out);
    }
    const out = this.bytes(entry, entry.desc.pos, len);
    entry.desc.pos += out.length;
    return out;
  }

  pread(fd, len, off) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind !== "file") return -ESPIPE;
    return this.bytes(entry, off, len);
  }

  /// The entries of a directory descriptor, read once: a program reads them until it has seen every
  /// name, and the inode and type a listing shows come from the host's own metadata.
  dirEntries(entry) {
    if (entry.entries) return entry.entries;
    const out = [];
    const add = (name, host) => {
      let st = null;
      try {
        st = fs.lstatSync(host, { bigint: true });
      } catch {}
      const mode = st ? Number(st.mode) : 0;
      const type =
        mode === 0
          ? 0
          : (mode & 0o170000) === 0o040000
            ? DT.dir
            : (mode & 0o170000) === 0o100000
              ? DT.file
              : (mode & 0o170000) === 0o120000
                ? DT.link
                : (mode & 0o170000) === 0o010000
                  ? DT.fifo
                  : (mode & 0o170000) === 0o140000
                    ? DT.sock
                    : (mode & 0o170000) === 0o020000
                      ? DT.chr
                      : (mode & 0o170000) === 0o060000
                        ? DT.blk
                        : 0;
      out.push({ name, ino: st ? st.ino : 1n, type });
    };
    add(".", entry.host);
    add("..", path.join(entry.host, ".."));
    for (const d of fs.readdirSync(entry.host, { withFileTypes: true })) {
      add(d.name, path.join(entry.host, d.name));
    }
    entry.entries = out;
    return out;
  }

  /// getdents64: as many `linux_dirent64` records as fit in `len`, or an empty answer at the end.
  getdents(fd, len) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind !== "dir") return -ENOTDIR;
    const all = this.dirEntries(entry);
    entry.index ??= 0;
    const chunks = [];
    let used = 0;
    while (entry.index < all.length) {
      const e = all[entry.index];
      const name = Buffer.from(e.name, "utf8");
      const reclen = (19 + name.length + 1 + 7) & ~7;
      if (used + reclen > len) break;
      if (used === 0 && reclen > len) return -EINVAL;
      const rec = Buffer.alloc(reclen);
      rec.writeBigUInt64LE(e.ino, 0);
      rec.writeBigInt64LE(BigInt(entry.index + 1), 8);
      rec.writeUInt16LE(reclen, 16);
      rec.writeUInt8(e.type, 18);
      name.copy(rec, 19);
      chunks.push(rec);
      used += reclen;
      entry.index++;
    }
    return Buffer.concat(chunks);
  }

  write(fd, data) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind === "stdout" || entry.kind === "stderr") {
      (fd === 1 ? process.stdout : process.stderr).write(data);
      return data.length;
    }
    if (entry.kind === "pipe") {
      if (entry.end !== "write") return -EBADF;
      const desc = entry.desc;
      if (desc.readers === 0) return -EPIPE;
      desc.data = desc.data.length ? Buffer.concat([desc.data, data]) : Buffer.from(data);
      this.note(`write ${data.length} into pipe ${desc.id} (r=${desc.readers} w=${desc.writers})`, desc);
      if (process.env.ARMJIT_TRACE_PIPES) {
        const head = Buffer.from(data.subarray(0, 16)).toString("latin1");
        console.error(`  pipe ${desc.id}: +${data.length} bytes ${JSON.stringify(head)}`);
      }
      return data.length;
    }
    if (entry.kind === "null") return data.length;
    if (entry.kind === "zero") return data.length;
    if (entry.kind === "full") return -ENOSPC;
    if (!entry.desc.writable) return -EBADF;
    const handle = this.handleOf(entry);
    const at = entry.desc.append ? Number(fs.fstatSync(handle).size) : entry.desc.pos;
    fs.writeSync(handle, data, 0, data.length, at);
    entry.desc.pos = at + data.length;
    entry.size = Math.max(entry.size ?? 0, entry.desc.pos);
    return data.length;
  }

  seek(fd, off, whence) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind !== "file") return -ESPIPE;
    const base = whence === 0 ? 0 : whence === 1 ? entry.desc.pos : whence === 2 ? entry.size ?? 0 : -1;
    if (base < 0) return -EINVAL;
    entry.desc.pos = base + off;
    if (entry.desc.pos < 0) return -EINVAL;
    return entry.desc.pos;
  }

  /// The bytes a file-backed mapping gets, clipped to the mapping.
  contents(fd, off, len) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind !== "file") return -EINVAL;
    return this.bytes(entry, off, len);
  }

  statPath(guestPath, dirfd = AT_FDCWD) {
    const virtual = this.virtualStat(guestPath);
    if (virtual) return virtual;
    const host = this.resolveAt(guestPath, dirfd, false);
    if (host < 0) return host;
    try {
      return fs.lstatSync(host, { bigint: true });
    } catch (e) {
      return fromErrno(e, -ENOENT);
    }
  }

  statFile(guestPath, dirfd = AT_FDCWD) {
    const virtual = this.virtualStat(guestPath);
    if (virtual) return virtual;
    const host = this.resolveAt(guestPath, dirfd);
    if (host < 0) return host;
    try {
      return fs.statSync(host, { bigint: true });
    } catch (e) {
      return fromErrno(e, -ENOENT);
    }
  }

  statFd(fd) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind === "stdin" || entry.kind === "stdout" || entry.kind === "stderr") {
      return { mode: 0o020666n, nlink: 1n, size: 0n, ino: BigInt(fd + 1), dev: 0n, rdev: 0n };
    }
    if (entry.rdev) {
      return { mode: BigInt(entry.mode), nlink: 1n, size: 0n, ino: BigInt(fd + 1), dev: 0n, rdev: BigInt(entry.rdev) };
    }
    if (entry.kind === "pipe") {
      // A pipe is a FIFO of no size, and a program that stats one has to see that.
      return { mode: 0o010600n, nlink: 1n, size: 0n, ino: BigInt(fd + 1), dev: 0n, rdev: 0n, blksize: 4096n };
    }
    if (entry.kind === "socket") {
      return { mode: 0o140777n, nlink: 1n, size: 0n, ino: BigInt(fd + 1), dev: 0n, rdev: 0n, blksize: 4096n };
    }
    if (entry.kind === "epoll") {
      // An anon inode: a regular file to `fstat`, which is all a program reads it for.
      return { mode: 0o100600n, nlink: 1n, size: 0n, ino: BigInt(fd + 1), dev: 0n, rdev: 0n, blksize: 4096n };
    }
    if (entry.kind === "dir") {
      return { mode: 0o040755n, nlink: 2n, size: BigInt(entry.size ?? 0), ino: BigInt(fd + 1), dev: 0n, rdev: 0n };
    }
    if (entry.virtual) {
      return { mode: 0o100644n, nlink: 1n, size: BigInt(entry.virtual.length), ino: BigInt(fd + 1), dev: 0n, rdev: 0n };
    }
    try {
      // A file that is open answers for the file it opened, which is what survives an unlink.
      if (entry.desc && entry.desc.handle !== null) return fs.fstatSync(entry.desc.handle, { bigint: true });
      return fs.statSync(entry.host, { bigint: true });
    } catch (e) {
      return fromErrno(e, -ENOENT);
    }
  }

  readlink(guestPath, dirfd = AT_FDCWD) {
    const host = this.resolveAt(guestPath, dirfd, false);
    if (host < 0) return host;
    try {
      return fs.readlinkSync(host);
    } catch (e) {
      return fromErrno(e, -EINVAL);
    }
  }

  // ---- changing the tree. `dpkg` unpacks a package with these, so each one answers 0 or -errno
  // the way the syscall does, and the mode a new node gets is the mode with the umask taken out.

  mask(mode) {
    return (mode & 0o7777) & ~this.umask;
  }

  mkdir(name, dirfd, mode) {
    const host = this.resolveAt(name, dirfd, false);
    if (host < 0) return host;
    try {
      fs.mkdirSync(host, { mode: this.mask(mode) | 0o700 });
      return 0;
    } catch (e) {
      return fromErrno(e, -EEXIST);
    }
  }

  rmdir(name, dirfd) {
    const host = this.resolveAt(name, dirfd, false);
    if (host < 0) return host;
    try {
      fs.rmdirSync(host);
      return 0;
    } catch (e) {
      return fromErrno(e, -ENOTEMPTY);
    }
  }

  unlink(name, dirfd) {
    const host = this.resolveAt(name, dirfd, false);
    if (host < 0) return host;
    try {
      fs.unlinkSync(host);
      return 0;
    } catch (e) {
      return fromErrno(e, -ENOENT);
    }
  }

  rename(from, fromDir, to, toDir) {
    const a = this.resolveAt(from, fromDir, false);
    if (a < 0) return a;
    const b = this.resolveAt(to, toDir, false);
    if (b < 0) return b;
    try {
      fs.renameSync(a, b);
      return 0;
    } catch (e) {
      return fromErrno(e, -EXDEV);
    }
  }

  symlink(target, name, dirfd) {
    const host = this.resolveAt(name, dirfd, false);
    if (host < 0) return host;
    try {
      fs.symlinkSync(target, host);
      return 0;
    } catch (e) {
      return fromErrno(e, -EEXIST);
    }
  }

  link(from, fromDir, to, toDir) {
    const a = this.resolveAt(from, fromDir, false);
    if (a < 0) return a;
    const b = this.resolveAt(to, toDir, false);
    if (b < 0) return b;
    try {
      fs.linkSync(a, b);
      return 0;
    } catch (e) {
      return fromErrno(e, -EXDEV);
    }
  }

  chmod(name, dirfd, mode, follow) {
    const host = this.resolveAt(name, dirfd, follow);
    if (host < 0) return host;
    try {
      // Linux has no way to set a symbolic link's own mode, so the form that refuses to follow one
      // changes the file behind it and does nothing at all to the link.
      if (!follow && fs.lstatSync(host).isSymbolicLink()) return 0;
      fs.chmodSync(host, mode & 0o7777);
      return 0;
    } catch (e) {
      return fromErrno(e, -EPERM);
    }
  }

  chmodFd(fd, mode) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (!entry.host) return 0;
    try {
      fs.chmodSync(entry.host, mode & 0o7777);
      return 0;
    } catch (e) {
      return fromErrno(e, -EPERM);
    }
  }

  /// Ownership is one user's throughout: a rootfs unpacked on this machine has one owner, and the
  /// guest's ids are all zero, so the change is already true.
  chown() {
    return 0;
  }

  utimens(name, dirfd, times, follow) {
    const host = this.resolveAt(name, dirfd, follow);
    if (host < 0) return host;
    return this.utimensHost(host, times, follow);
  }

  utimensFd(fd, times) {
    const entry = this.map.get(fd);
    if (!entry || !entry.host) return -EBADF;
    return this.utimensHost(entry.host, times, true);
  }

  utimensHost(host, times, follow) {
    try {
      // A null field is `UTIME_OMIT`: that timestamp keeps the value it already has.
      if (times === null || times.atime === null || times.mtime === null) {
        const st = fs.lstatSync(host);
        const atime = times && times.atime !== null ? times.atime : st.atimeMs / 1000;
        const mtime = times && times.mtime !== null ? times.mtime : st.mtimeMs / 1000;
        (follow ? fs.utimesSync : fs.lutimesSync)(host, atime, mtime);
      } else {
        (follow ? fs.utimesSync : fs.lutimesSync)(host, times.atime, times.mtime);
      }
      return 0;
    } catch (e) {
      return fromErrno(e, -ENOENT);
    }
  }

  truncate(name, dirfd, len) {
    const host = this.resolveAt(name, dirfd);
    if (host < 0) return host;
    try {
      fs.truncateSync(host, len);
      return 0;
    } catch (e) {
      return fromErrno(e, -EINVAL);
    }
  }

  truncateFd(fd, len) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind !== "file") return -EINVAL;
    try {
      if (entry.desc && entry.desc.handle !== null) fs.ftruncateSync(entry.desc.handle, len);
      else fs.truncateSync(entry.host, len);
      if (entry.desc && entry.desc.pos > len) entry.desc.pos = len;
      return 0;
    } catch (e) {
      return fromErrno(e, -EINVAL);
    }
  }

  chdir(name) {
    const host = this.resolve(name);
    if (host < 0) return host;
    let st;
    try {
      st = fs.statSync(host);
    } catch (e) {
      return fromErrno(e, -ENOENT);
    }
    if (!st.isDirectory()) return -ENOTDIR;
    this.cwd = this.guestPath(name);
    return 0;
  }

  chdirFd(fd) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind !== "dir") return -ENOTDIR;
    this.cwd = this.guestOf(entry.host);
    return 0;
  }
}

function fromErrno(e, fallback) {
  switch (e && e.code) {
    case "ENOENT":
      return -ENOENT;
    case "EACCES":
    case "EPERM":
      return -EACCES;
    case "EISDIR":
      return -EISDIR;
    case "ENOTDIR":
      return -ENOTDIR;
    case "ELOOP":
      return -ELOOP;
    case "ENAMETOOLONG":
      return -ENAMETOOLONG;
    default:
      return fallback;
  }
}
