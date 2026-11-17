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

export const AT_FDCWD = -100;

const DT = { file: 8, dir: 4, link: 10, fifo: 1, sock: 12, chr: 2, blk: 6 };

const O_ACCMODE = 3;
const O_WRONLY = 1;
const O_RDWR = 2;
const O_CREAT = 0x40;
const O_EXCL = 0x80;
const O_TRUNC = 0x200;
const O_APPEND = 0x400;
const O_DIRECTORY = 0x4000;

export class Files {
  constructor(rootfs) {
    this.rootfs = rootfs ? path.resolve(rootfs) : null;
    this.map = new Map();
    this.next = 3;
    this.cwd = "/";
    this.map.set(0, { kind: "stdin" });
    this.map.set(1, { kind: "stdout" });
    this.map.set(2, { kind: "stderr" });
  }

  /// Guest path to host path, refusing anything that leaves the rootfs.
  resolve(guestPath) {
    if (!this.rootfs) return -ENOENT;
    const absolute = guestPath.startsWith("/") ? guestPath : path.posix.join(this.cwd, guestPath);
    const clean = path.posix.normalize(absolute);
    if (clean.includes("\0")) return -ENOENT;
    const host = path.join(this.rootfs, clean);
    if (host !== this.rootfs && !host.startsWith(this.rootfs + path.sep)) return -EACCES;
    return host;
  }

  add(entry) {
    const fd = this.next++;
    this.map.set(fd, entry);
    return fd;
  }

  get(fd) {
    return this.map.get(fd);
  }

  open(guestPath, flags, mode) {
    const host = this.resolve(guestPath);
    if (host < 0) return host;
    const access = flags & O_ACCMODE;
    try {
      const entry = {
        kind: "file",
        host,
        pos: 0,
        append: (flags & O_APPEND) !== 0,
        readable: access !== O_WRONLY,
        writable: access !== 0,
      };
      if ((flags & O_CREAT) && !fs.existsSync(host)) {
        fs.mkdirSync(path.dirname(host), { recursive: true });
        fs.writeFileSync(host, Buffer.alloc(0), { mode: mode || 0o644 });
      }
      const st = fs.statSync(host);
      if ((flags & O_DIRECTORY) && !st.isDirectory()) return -ENOTDIR;
      if (st.isDirectory()) {
        if (entry.writable) return -EISDIR;
        entry.kind = "dir";
        entry.size = st.size;
        return this.add(entry);
      }
      if ((flags & O_TRUNC) && entry.writable) fs.writeFileSync(host, Buffer.alloc(0));
      entry.size = st.size;
      return this.add(entry);
    } catch (e) {
      return fromErrno(e, -ENOENT);
    }
  }

  close(fd) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (fd > 2) this.map.delete(fd);
    return 0;
  }

  bytes(entry, off, len) {
    const buf = Buffer.alloc(len);
    const fd = fs.openSync(entry.host, "r");
    try {
      const n = fs.readSync(fd, buf, 0, len, off);
      return buf.subarray(0, n);
    } finally {
      fs.closeSync(fd);
    }
  }

  read(fd, len) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind === "dir") return -EISDIR;
    if (entry.kind === "stdin") return Buffer.alloc(0); // stdin is empty: no console yet
    const out = this.bytes(entry, entry.pos, len);
    entry.pos += out.length;
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
    const chunks = [];
    let used = 0;
    while (entry.pos < all.length) {
      const e = all[entry.pos];
      const name = Buffer.from(e.name, "utf8");
      const reclen = (19 + name.length + 1 + 7) & ~7;
      if (used + reclen > len) break;
      if (used === 0 && reclen > len) return -EINVAL;
      const rec = Buffer.alloc(reclen);
      rec.writeBigUInt64LE(e.ino, 0);
      rec.writeBigInt64LE(BigInt(entry.pos + 1), 8);
      rec.writeUInt16LE(reclen, 16);
      rec.writeUInt8(e.type, 18);
      name.copy(rec, 19);
      chunks.push(rec);
      used += reclen;
      entry.pos++;
    }
    return Buffer.concat(chunks);
  }

  write(fd, data) {    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind === "stdout" || entry.kind === "stderr") {
      (fd === 1 ? process.stdout : process.stderr).write(data);
      return data.length;
    }
    if (!entry.writable) return -EBADF;
    const at = entry.append ? Number(fs.statSync(entry.host).size) : entry.pos;
    const handle = fs.openSync(entry.host, "r+");
    try {
      fs.writeSync(handle, data, 0, data.length, at);
    } finally {
      fs.closeSync(handle);
    }
    entry.pos = at + data.length;
    entry.size = Math.max(entry.size ?? 0, entry.pos);
    return data.length;
  }

  seek(fd, off, whence) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind !== "file") return -ESPIPE;
    const base = whence === 0 ? 0 : whence === 1 ? entry.pos : whence === 2 ? entry.size ?? 0 : -1;
    if (base < 0) return -EINVAL;
    entry.pos = base + off;
    if (entry.pos < 0) return -EINVAL;
    return entry.pos;
  }

  /// The bytes a file-backed mapping gets, clipped to the mapping.
  contents(fd, off, len) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind !== "file") return -EINVAL;
    return this.bytes(entry, off, len);
  }

  statPath(guestPath) {
    const host = this.resolve(guestPath);
    if (host < 0) return host;
    try {
      return fs.lstatSync(host, { bigint: true });
    } catch (e) {
      return fromErrno(e, -ENOENT);
    }
  }

  statFile(guestPath) {
    const host = this.resolve(guestPath);
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
      return { mode: 0o020666n, nlink: 1n, size: 0n, ino: BigInt(fd + 1), dev: 0n };
    }
    try {
      return fs.statSync(entry.host, { bigint: true });
    } catch (e) {
      return fromErrno(e, -ENOENT);
    }
  }

  readlink(guestPath) {
    const host = this.resolve(guestPath);
    if (host < 0) return host;
    try {
      return fs.readlinkSync(host);
    } catch (e) {
      return fromErrno(e, -EINVAL);
    }
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
