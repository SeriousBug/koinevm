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

/// The prefix a name is stored under when the host directory already holds a name that differs only
/// in case: Debian's kernel headers hold both `xt_connmark.h` and `xt_CONNMARK.h`, and a volume that
/// does not tell them apart would let one overwrite the other. The guest name is the hex of its
/// bytes, which no name it can ask for collides with, and the walk decodes it back.
const CASE_ESCAPE = ".armjit.case.";

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

/// A path operation as it happened on this machine, when the trace names a part of the path: the
/// guest's name for a file is not the host's, and a package manager that fails one file at a time
/// says which of the two it meant.
function tracePath(op, text, result) {
  const want = process.env.ARMJIT_TRACE_PATHS;
  if (!want || !text.includes(want)) return;
  console.error(`${op} ${text} -> ${result}`);
}

const ISIG = 0x1;
const ICANON = 0x2;
/// Input translation: a carriage return from a terminal becomes a newline.
const ICRNL = 0x100;
const ECHO = 0x8;

/// A terminal: one device with an input side a program reads and an output side it writes, a line
/// discipline between them, and the flags that say what the discipline does. The console is the one
/// this run was started at; a pseudo-terminal is one a program made for a child that insists on
/// having a terminal of its own, and its two ends are as real as this one.
function makeTerminal({ viaTty = false, sink = (bytes) => process.stdout.write(bytes) } = {}) {
  return {
  data: Buffer.alloc(0),
  closed: false,
  live: false,
  /// Whether the input is a terminal rather than a pipe. A terminal echoes what is typed at it; a
  /// pipe's bytes are not typed at anything, and echoing them would print a script twice.
  viaTty: false,
  /// Whether the guest has turned off canonical input and echo, which is what a line editor does
  /// before it reads one keystroke at a time and draws them itself.
  raw: false,
  /// Whether the last thing typed was the end-of-file character on an empty line.
  eof: false,
  /// What the guest last said the console is. The flags are the ones a Linux tty starts with, so a
  /// program that only reads them sees a terminal rather than a row of zeros.
  termios: {
    iflag: 0x6400, // ICRNL IXON IUTF8
    oflag: 0x0005, // OPOST ONLCR
    cflag: 0x00bf, // B38400 CS8 CREAD
    lflag: 0xa85b, // ISIG ICANON ECHO ECHOE ECHOK ECHOCTL ECHOKE IEXTEN
    cc: [3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0],
  },
  setTermios(t) {
    this.termios = t;
    this.raw = (t.lflag & (ICANON | ECHO)) !== (ICANON | ECHO);
  },
  /// Called with the number of a signal the terminal raised, as its line discipline does for the
  /// interrupt and quit characters rather than passing them on as bytes.
  onSignal: null,
  /// The bytes node delivered, through the line discipline the guest asked for.
  ///
  /// The host's terminal stays in raw mode for the whole session, because the process holding it is
  /// this one: a cooked terminal would turn the interrupt character into a signal here, and the
  /// guest would never see it. So this is the discipline - the interrupt and quit characters become
  /// signals, a carriage return from a terminal that no longer translates it becomes a newline, the
  /// erase character edits the line, and in canonical mode the character that was typed is echoed
  /// back, which is what a terminal does and what a guest reading a line does not.
  feed(chunk) {
    for (const byte of chunk) {
      const l = this.termios.lflag;
      if (l & ISIG) {
        if (byte === this.termios.cc[0]) {
          this.onSignal?.(2);
          continue;
        }
        if (byte === this.termios.cc[1]) {
          this.onSignal?.(3);
          continue;
        }
      }
      if (this.raw) {
        this.data = Buffer.concat([this.data, Buffer.from([byte])]);
        continue;
      }
      const echo = (l & ECHO) !== 0 && this.viaTty;
      if (byte === 0x0d && (this.termios.iflag & ICRNL)) {
        this.data = Buffer.concat([this.data, Buffer.from([0x0a])]);
        if (echo) this.out("\r\n");
        continue;
      }
      if (byte === this.termios.cc[4]) {
        // End of file: a partial line is delivered as it stands, and an empty one ends the read.
        if (this.data.length && this.data[this.data.length - 1] !== 0x0a) {
          this.data = Buffer.concat([this.data, Buffer.from([0x0a])]);
          if (echo) this.out("\n");
        } else if (!this.data.length) {
          this.eof = true;
        }
        continue;
      }
      if (echo && (byte === this.termios.cc[2] || byte === 0x08)) {
        if (this.data.length && this.data[this.data.length - 1] !== 0x0a) {
          this.data = this.data.subarray(0, this.data.length - 1);
          this.out("\b \b");
        }
        continue;
      }
      if (echo && byte === this.termios.cc[3]) {
        while (this.data.length && this.data[this.data.length - 1] !== 0x0a) {
          this.data = this.data.subarray(0, this.data.length - 1);
          this.out("\b \b");
        }
        continue;
      }
      this.data = Buffer.concat([this.data, Buffer.from([byte])]);
      if (!echo) continue;
      // The terminal echoes what was typed, and the newline goes out as a carriage return and a
      // newline, because the guest's output side is not translating it any more either.
      if (byte === 0x0a) this.out("\r\n");
      else if (byte >= 0x20 || byte === 0x09) this.out(Buffer.from([byte]));
    }
  },
  /// Up to `len` bytes, or null when there are none to give.
  ///
  /// A console that the guest has not taken over hands over one line at a time, which is what makes
  /// a program that reads its input line by line behave as it does at a terminal; a partial line
  /// waits for its newline. In raw mode the bytes go over as they came, which is what a line editor
  /// reading one keystroke at a time needs.
  take(len) {
    if (!this.data.length) return null;
    let end = Math.min(len, this.data.length);
    if (!this.raw) {
      const nl = this.data.indexOf(0x0a);
      if (nl >= 0) end = Math.min(end, nl + 1);
      else if (!this.closed) return null;
    }
    const out = this.data.subarray(0, end);
    this.data = this.data.subarray(out.length);
    return Buffer.from(out);
  },
  /// Whether a read would hand bytes over now. A line discipline holds a partial line until its
  /// newline, so bytes that have arrived are not the same thing as a read that returns: a caller
  /// told yes that then gets nothing asks again at once, and a program in a poll loop spins.
  readable() {
    if (this.eof || this.closed) return true;
    if (!this.data.length) return false;
    return this.raw || this.data.includes(0x0a);
  },
  /// Bytes the device sends to whoever is looking at it: what the discipline echoes, and what a
  /// program writes to it. A console's go to the host's own output, and a pty's to its master.
  out(bytes) {
    this.sink(bytes);
  },
  };
}

/// The host's own terminal, shared by every process of a run: a fork inherits the terminal it was
/// started at, so there is one of these and not one per descriptor table. `live` is what a test
/// wants off, because a guest that reads a console nobody is typing at would wait forever.
export const terminal = makeTerminal();

/// The pseudo-terminals of the run, by number. A device belongs to the machine rather than to the
/// process that made it, so a program can hand its child the name of one and the child can open it.
const ptys = new Map();
let nextPty = 1;

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
    /// What each host directory holds, by the directory's own timestamp: the exact spelling of a
    /// name is only visible in a listing.
    this.names = new Map();
    // A description of their own, so that `O_NONBLOCK` sticks to them: `apt` empties the terminal
    // before it starts `dpkg`, by setting stdin non-blocking and reading until a read fails, and a
    // console that ignored the setting would hold that read until the next line was typed.
    /// Whether a `signalfd` has a signal waiting, which the kernel that owns this table answers:
    /// the queue is the process's, and the descriptor is only where the guest reads it.
    this.signalReady = () => false;
    this.map.set(0, { kind: "stdin", desc: { nonblock: false } });
    this.map.set(1, { kind: "stdout", desc: { nonblock: false } });
    this.map.set(2, { kind: "stderr", desc: { nonblock: false } });
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
      const at = this.hostName(done.length ? done[done.length - 1] : this.rootfs, name);
      // The form that does not follow its last component, which is the one that unlinks a link or
      // renames it, names the link itself.
      if (queue.length === 0 && !follow) {
        done.push(at);
        break;
      }
      let st;
      try {
        st = fs.lstatSync(at);
      } catch (e) {
        // A component that is not there is the caller's to report, and the last one is a file that
        // an open with O_CREAT is about to make.
        if (queue.length) return -ENOENT;
        done.push(at);
        break;
      }
      if (!st.isSymbolicLink()) {
        done.push(at);
        continue;
      }
      if (++links > 40) return -ELOOP;
      let target;
      try {
        target = fs.readlinkSync(at);
      } catch (e) {
        return -EINVAL;
      }
      if (target.startsWith("/")) done.length = 0;
      queue.unshift(...target.split("/").filter((p) => p !== "" && p !== "."));
    }
    const host = done.length ? done[done.length - 1] : this.rootfs;
    if (host !== this.rootfs && !host.startsWith(this.rootfs + path.sep)) return -EACCES;
    return host;
  }

  /// The host name a guest name is stored under in this host directory. A volume that folds case
  /// answers to a name it holds spelled another way, so a name the directory does not hold as asked
  /// is stored escaped where a name that differs only in case is in the way. Which of the two a name
  /// got is what the directory holds, not what its neighbours hold now: `dpkg` writes its temporary
  /// under the target's name and renames it later, by which time the sibling that forced the escape
  /// may be gone.
  hostName(dir, name) {
    const plain = path.join(dir, name);
    const names = this.namesOf(dir);
    if (!names) return plain;
    const escape = CASE_ESCAPE + Buffer.from(name, "utf8").toString("hex");
    if (names.includes(escape)) return path.join(dir, escape);
    if (names.includes(name)) return plain;
    const lower = name.toLowerCase();
    if (!names.some((n) => n.toLowerCase() === lower)) return plain;
    return path.join(dir, escape);
  }

  /// The names a host directory holds, spelled as it holds them: the only place the exact case of a
  /// name is visible. Cached against the directory's own timestamp, because every component of every
  /// path is looked up here.
  namesOf(dir) {
    let st;
    try {
      st = fs.statSync(dir, { bigint: true });
    } catch (e) {
      return null;
    }
    const stamp = `${st.mtimeNs}/${st.ino}`;
    const cached = this.names.get(dir);
    if (cached && cached.stamp === stamp) return cached.list;
    let list;
    try {
      list = fs.readdirSync(dir);
    } catch (e) {
      return null;
    }
    this.names.set(dir, { stamp, list });
    return list;
  }

  /// The guest name an entry of a host directory stands for.
  guestName(name) {
    if (!name.startsWith(CASE_ESCAPE)) return name;
    const hex = name.slice(CASE_ESCAPE.length);
    if (!/^([0-9a-f]{2})+$/.test(hex)) return name;
    return Buffer.from(hex, "hex").toString("utf8");
  }

  /// The guest path a host path inside the tree stands for.
  guestOf(host) {
    const rel = path.relative(this.rootfs, host).split(path.sep).filter((p) => p !== "");
    return rel.length ? `/${rel.map((p) => this.guestName(p)).join("/")}` : "/";
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
    if (entry.kind === "pty") {
      if (entry.end === "master") entry.desc.master++;
      else entry.desc.slave++;
    }
    return copy;
  }

  /// Whether a read of this descriptor would return now instead of waiting.
  readReady(fd) {
    const entry = this.map.get(fd);
    if (!entry) return true;
    if (entry.kind === "signalfd") return this.signalReady(entry.desc);
    if (entry.kind === "pty") {
      if (entry.end === "master") return entry.desc.output.length > 0 || entry.desc.slave === 0;
      return entry.desc.tty.readable() || entry.desc.master === 0;
    }
    if (this.consoleEntry(entry)) return !terminal.live || terminal.readable();
    if (entry.kind !== "pipe") return true;
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
    // A pseudo-terminal. `/dev/ptmx` makes a new one and hands back its master, and the name the
    // slave has is what `ptsname` asks for: a program that needs a child to have a terminal opens
    // the slave, and everything the child writes comes back out of the master.
    const name = this.guestPath(guestPath);
    if (name === "/dev/ptmx") {
      const pty = this.pty();
      pty.master++;
      return this.add({
        kind: "pty",
        end: "master",
        desc: pty,
        cloexec: (flags & O_CLOEXEC) !== 0,
      });
    }
    if (name.startsWith("/dev/pts/")) {
      const pty = ptys.get(Number(name.slice("/dev/pts/".length)));
      if (!pty) return -ENOENT;
      pty.slave++;
      return this.add({
        kind: "pty",
        end: "slave",
        desc: pty,
        cloexec: (flags & O_CLOEXEC) !== 0,
      });
    }
    const device = DEVICES.get(name);
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
      tracePath("open", host, 0);
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
    if (entry.kind === "pty") {
      if (entry.end === "master") entry.desc.master--;
      else entry.desc.slave--;
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

  /// The pseudo-terminal a number names, or null: `/dev/ptmx` hands out a new one, and everything
  /// written to its master is what its slave reads, through the discipline the slave's flags set.
  pty() {
    const id = nextPty++;
    const pty = {
      id,
      /// The bytes the master has not read yet: what the slave wrote, and what the discipline echoed.
      output: Buffer.alloc(0),
      size: { rows: 24, cols: 80 },
      /// The lock `unlockpt` takes off, and how many descriptors hold each end, which is what says
      /// when a read finds the far side gone rather than waiting for it.
      locked: true,
      master: 0,
      slave: 0,
    };
    pty.tty = makeTerminal({ viaTty: true, sink: (bytes) => pty.tty?.out(bytes) });
    // `sink` is where the discipline's echo goes, which on this device is the master's reader.
    pty.tty.sink = (bytes) => {
      pty.output = Buffer.concat([pty.output, Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes)]);
    };
    pty.tty.live = true;
    // An interrupt typed into a pty goes to the command reading it, the way the console's does:
    // one process group, one foreground job.
    pty.tty.onSignal = (sig) => terminal.onSignal?.(sig);
    ptys.set(id, pty);
    return pty;
  }

  /// The terminal a descriptor is on: the console's for the three standard ones, and the slave's or
  /// the master's for a pseudo-terminal, which are one terminal with two ends.
  terminalOf(entry) {
    return entry.kind === "pty" ? entry.desc.tty : terminal;
  }

  /// Whether this descriptor is the console. A terminal is one device, opened on all three standard
  /// descriptors, so each of them reads and writes the same one: `less` takes its keys from whichever
  /// it was handed, and here that is stderr, because there is no `/dev/tty` to open. A run with no
  /// console has a pipe or a file on those numbers instead, and reading one of them is not a read of
  /// the terminal.
  consoleEntry(entry) {
    if (entry.kind === "stdin") return true;
    return terminal.live && (entry.kind === "stdout" || entry.kind === "stderr");
  }

  read(fd, len) {
    const entry = this.map.get(fd);
    if (!entry) return -EBADF;
    if (entry.kind === "dir") return -EISDIR;
    if (entry.kind === "pty") {
      const pty = entry.desc;
      if (entry.end === "master") {
        if (!pty.output.length) {
          if (pty.slave === 0) return Buffer.alloc(0);
          return entry.desc.nonblock ? -EAGAIN : WOULD_BLOCK;
        }
        const out = pty.output.subarray(0, len);
        pty.output = pty.output.subarray(out.length);
        return Buffer.from(out);
      }
      const tty = pty.tty;
      if (!tty.data.length && pty.master === 0) return Buffer.alloc(0);
      const out = tty.take(len);
      if (out) return out;
      if (tty.eof) {
        tty.eof = false;
        return Buffer.alloc(0);
      }
      return entry.desc.nonblock ? -EAGAIN : WOULD_BLOCK;
    }
    if (this.consoleEntry(entry)) {
      // A console the host is not reading is an empty one: the guest sees end of file, which is
      // what a program run from a test expects of its input.
      if (!terminal.live) return Buffer.alloc(0);
      const out = terminal.take(len);
      if (out) return out;
      if (terminal.eof) {
        terminal.eof = false;
        return Buffer.alloc(0);
      }
      if (terminal.closed) return Buffer.alloc(0);
      if (entry.desc?.nonblock) return -EAGAIN;
      // The thread parks and the host's event loop turns: the bytes the terminal delivers answer
      // the read, the way a pipe's writer answers one.
      return WOULD_BLOCK;
    }
    // The host's own output, when there is no console: there is nothing here to read out of it.
    if (entry.kind === "stdout" || entry.kind === "stderr") return -EBADF;
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
      add(this.guestName(d.name), path.join(entry.host, d.name));
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
    // A pty is one terminal: what the master is given is what the slave reads, and what the slave
    // writes is what the master reads, with the output flags applied on the way.
    if (entry.kind === "pty") {
      const pty = entry.desc;
      if (entry.end === "master") {
        pty.tty.feed(data);
        return data.length;
      }
      let bytes = data;
      if ((pty.tty.termios.oflag & 0x4) !== 0) {
        // ONLCR: the newline a program wrote comes out as a carriage return and a newline, which is
        // what a terminal does with it and what the program reading the master expects.
        const out = Buffer.alloc(data.length * 2);
        let at = 0;
        for (const byte of data) {
          if (byte === 0x0a) out[at++] = 0x0d;
          out[at++] = byte;
        }
        bytes = out.subarray(0, at);
      }
      pty.output = Buffer.concat([pty.output, bytes]);
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
    if (entry.kind === "pty") {
      // A character device, which is what a program that fstats a terminal reads it for: a slave of
      // the UNIX98 range, `major 136`, whose minor is the number `/dev/pts` names it by. A libc
      // reads the name of a terminal out of that when it has no `/proc/self/fd` to ask.
      return {
        mode: 0o020620n,
        nlink: 1n,
        size: 0n,
        ino: BigInt(entry.desc.id + 1),
        dev: 0n,
        rdev: BigInt(entry.end === "slave" ? (136 << 8) + entry.desc.id : (5 << 8) + 2),
        blksize: 4096n,
      };
    }
    if (entry.kind === "epoll") {
      // An anon inode: a regular file to `fstat`, which is all a program reads it for.
      return { mode: 0o100600n, nlink: 1n, size: 0n, ino: BigInt(fd + 1), dev: 0n, rdev: 0n, blksize: 4096n };
    }
    if (entry.kind === "dir") {
      // A directory answers for itself rather than for an inode of its own making: a program that
      // opens one compares this stat with the stat of the name it came from, and `shutil.rmtree`
      // treats a directory whose two disagree as a symbolic link.
      try {
        return fs.statSync(entry.host, { bigint: true });
      } catch (e) {
        return { mode: 0o040755n, nlink: 2n, size: BigInt(entry.size ?? 0), ino: BigInt(fd + 1), dev: 0n, rdev: 0n };
      }
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
      tracePath("mkdir", host, "ok");
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
      tracePath("rmdir", host, "ok");
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
      tracePath("unlink", host, "ok");
      return 0;
    } catch (e) {
      tracePath("unlink", host, fromErrno(e, -ENOENT));
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
      tracePath("rename", `${a} -> ${b}`, "ok");
      return 0;
    } catch (e) {
      tracePath("rename", `${a} -> ${b}`, `${fromErrno(e, -EXDEV)} ${e.code}`);
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
