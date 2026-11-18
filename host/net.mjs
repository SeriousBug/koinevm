// The guest's sockets, on the host's network.
//
// A socket is a descriptor in the same table as the files, and the traffic is the host's: this
// layer keeps the host object behind each description and the queue of what arrived but has not
// been read, so a `recvfrom` with nothing queued parks its thread and the datagram that arrives
// later wakes it.
//
// Everything above the interface at the bottom of this file is the Linux side of it: the sockaddr
// layouts, the descriptor semantics, the errnos, and what a blocking call does. A host with no
// network of its own (a browser tab, an app's transport) replaces that interface, and the guest
// cannot tell.

import dgram from "node:dgram";
import { WOULD_BLOCK } from "./files.mjs";

export const AF_UNIX = 1;
export const AF_INET = 2;
export const AF_INET6 = 10;
export const SOCK_STREAM = 1;
export const SOCK_DGRAM = 2;

export const EPERM = 1;
export const ENOENT = 2;
export const EBADF = 9;
export const EAGAIN = 11;
export const EFAULT = 14;
export const EINVAL = 22;
export const EPIPE = 32;
export const ENOTSOCK = 88;
export const EDESTADDRREQ = 89;
export const EMSGSIZE = 90;
export const EPROTONOSUPPORT = 93;
export const EOPNOTSUPP = 95;
export const EAFNOSUPPORT = 97;
export const EADDRINUSE = 98;
export const EADDRNOTAVAIL = 99;
export const ENETDOWN = 100;
export const ENETUNREACH = 101;
export const ECONNRESET = 104;
export const EISCONN = 106;
export const ENOTCONN = 107;
export const ETIMEDOUT = 110;
export const ECONNREFUSED = 111;
export const EHOSTUNREACH = 113;
export const EINPROGRESS = 115;

/// A `struct sockaddr` as the guest wrote it. Anything this layer does not speak is null, which the
/// syscall turns into EAFNOSUPPORT rather than pretending the address was understood.
export function decodeSockaddr(bytes) {
  if (!bytes || bytes.length < 2) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const family = view.getUint16(0, true);
  if (family === AF_INET) {
    if (bytes.length < 16) return null;
    const port = view.getUint16(2, false);
    return { family, ip: `${bytes[4]}.${bytes[5]}.${bytes[6]}.${bytes[7]}`, port };
  }
  if (family === AF_INET6) {
    if (bytes.length < 28) return null;
    const port = view.getUint16(2, false);
    const groups = [];
    for (let i = 0; i < 8; i++) groups.push(view.getUint16(8 + i * 2, false));
    return { family, ip: formatV6(groups), port, scope: view.getUint32(24, true) };
  }
  if (family === AF_UNIX) {
    let end = 2;
    while (end < Math.min(bytes.length, 110) && bytes[end] !== 0) end++;
    return { family, path: bytes.toString("latin1", 2, end) };
  }
  return null;
}

/// The 16, 28 or 110 bytes a `getsockname`, a `getpeername` or the address a datagram came from
/// fills.
export function encodeSockaddr(value) {
  if (value.family === AF_UNIX) {
    // A socket with no name of its own is two bytes: the family, and nothing after it.
    const path = String(value.path ?? "");
    if (!path) return Buffer.from([AF_UNIX, 0]);
    const out = Buffer.alloc(110);
    out.writeUInt16LE(AF_UNIX, 0);
    out.write(path, 2, 108, "latin1");
    return out;
  }
  const v6 = value.family === AF_INET6;
  const out = Buffer.alloc(v6 ? 28 : 16);
  out.writeUInt16LE(value.family ?? (v6 ? AF_INET6 : AF_INET), 0);
  out.writeUInt16BE(value.port ?? 0, 2);
  if (v6) {
    for (const [i, group] of parseV6(value.ip).entries()) out.writeUInt16BE(group, 8 + i * 2);
    out.writeUInt32LE(value.scope ?? 0, 24);
  } else {
    const parts = String(value.ip ?? "0.0.0.0").split(".").map(Number);
    for (let i = 0; i < 4; i++) out[4 + i] = parts[i] ?? 0;
  }
  return out;
}

/// The text form of an address, with the longest run of zero groups written as `::` the way a
/// resolver and a human both expect to read one.
function formatV6(groups) {
  let best = { at: -1, len: 1 };
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > best.len) best = { at: i, len: j - i };
    i = j;
  }
  if (best.at < 0) return groups.map((g) => g.toString(16)).join(":");
  const head = groups.slice(0, best.at).map((g) => g.toString(16)).join(":");
  const tail = groups.slice(best.at + best.len).map((g) => g.toString(16)).join(":");
  return `${head}::${tail}`;
}

function parseV6(ip) {
  const text = String(ip ?? "::");
  const [head, tail] = text.split("::");
  const left = head ? head.split(":") : [];
  const right = tail === undefined ? [] : tail ? tail.split(":") : [];
  const fill = 8 - left.length - right.length;
  const all = [...left, ...Array(Math.max(fill, 0)).fill("0"), ...right];
  return all.slice(0, 8).map((g) => parseInt(g || "0", 16) & 0xffff);
}

/// What the host's own errno would be, from the error an operation on a host socket threw or
/// reported. A code this table does not name becomes EIO's neighbour EOPNOTSUPP, which is honest
/// about the operation having failed for a reason the guest's side has no name for.
export function errnoOf(error) {
  switch (error && error.code) {
    case "EACCES":
      return 13;
    case "EADDRINUSE":
      return EADDRINUSE;
    case "EADDRNOTAVAIL":
      return EADDRNOTAVAIL;
    case "EBADF":
      return EBADF;
    case "ECONNREFUSED":
      return ECONNREFUSED;
    case "ECONNRESET":
      return ECONNRESET;
    case "EHOSTUNREACH":
      return EHOSTUNREACH;
    case "EMSGSIZE":
      return EMSGSIZE;
    case "ENETDOWN":
      return ENETDOWN;
    case "ENETUNREACH":
      return ENETUNREACH;
    case "ENOENT":
      return ENOENT;
    case "ENOMEM":
      return 12;
    case "ENOTCONN":
      return ENOTCONN;
    case "EOPNOTSUPP":
    case "ENOTSUP":
      return EOPNOTSUPP;
    case "EPERM":
      return EPERM;
    case "EPIPE":
      return EPIPE;
    case "ETIMEDOUT":
      return ETIMEDOUT;
    case "ERR_SOCKET_DGRAM_NOT_RUNNING":
      return EBADF;
    default:
      return EINVAL;
  }
}

function trace(text) {
  if (process.env.ARMJIT_TRACE_SOCKETS) console.error(`sockets: ${text}`);
}

/// The sockets of one session: a fork shares this, because a socket description is shared between
/// the processes that hold a descriptor on it, the same way an open file is.
export class Net {
  constructor({ wake = () => {}, network = nodeNetwork } = {}) {
    this.wake = wake;
    this.network = network;
    this.waiters = [];
  }

  /// A socket description, or a negative errno. The descriptor that holds it is the caller's.
  create(domain, kind, protocol) {
    if (domain === AF_INET || domain === AF_INET6) {
      const any = protocol === 0;
      if (kind === SOCK_DGRAM && (any || protocol === 17)) return new Datagram(this, domain);
      if (kind === SOCK_STREAM && (any || protocol === 6)) return -EPROTONOSUPPORT;
      return -EAFNOSUPPORT;
    }
    // One AF_UNIX socket has nothing to talk to until something binds a name for it, and a name is
    // the host's filesystem here. `socketpair` is what a program actually uses, and it makes both
    // ends at once.
    if (domain === AF_UNIX) return -EAFNOSUPPORT;
    return -EAFNOSUPPORT;
  }

  /// The two ends of a `socketpair`: a queue each way, inside this process.
  pair(domain, kind) {
    if (domain !== AF_UNIX) return -EAFNOSUPPORT;
    if (kind !== SOCK_STREAM && kind !== SOCK_DGRAM) return -EAFNOSUPPORT;
    const a = new PairEnd(this, domain, kind);
    const b = new PairEnd(this, domain, kind);
    a.other = b;
    b.other = a;
    trace(`pair ${a.id} ${b.id} ${kind === SOCK_STREAM ? "stream" : "dgram"}`);
    return [a, b];
  }

  /// Something a guest may be waiting for happened: wake whoever is parked, and the scheduler when
  /// nothing at all is runnable.
  notify() {
    for (const w of this.waiters.splice(0)) w();
    this.wake();
  }

  /// No thread is runnable and one is waiting on the network. A packet cannot arrive while no
  /// guest code runs, so this is the only place the host's event loop gets to run at all. The
  /// timeout is what gives a `poll` with a deadline a chance to expire when no traffic comes.
  next(ms = 200) {
    return new Promise((resolve) => {
      const wake = () => resolve();
      this.waiters.push(wake);
      setTimeout(wake, ms);
    });
  }
}

/// A UDP socket. The host object is made on the first operation that needs it, so a `socket` call
/// nothing ever uses is not a port on the machine.
class Datagram {
  constructor(net, domain) {
    this.net = net;
    this.id = (Datagram.serial = (Datagram.serial ?? 0) + 1);
    this.domain = domain;
    this.type = SOCK_DGRAM;
    this.queue = [];
    this.error = 0;
    this.bound = null;
    this.peer = null;
    this.refs = 1;
    this.nonblock = false;
    this.timeout = 0;
    this.handle = null;
    this.binding = false;
    this.closed = false;
  }

  host() {
    if (this.handle) return this.handle;
    this.handle = this.net.network.datagram({
      ipv6: this.domain === AF_INET6,
      onMessage: (data, from) => {
        trace(`${this.id} <- ${data.length} from ${from.ip}:${from.port}`);
        this.queue.push({ data, from: { family: this.domain, ip: from.ip, port: from.port } });
        this.net.notify();
      },
      onError: (errno) => {
        // A failed bind is reported by bind's own promise; anything later is the error a POSIX
        // receive or send has to answer with.
        if (this.binding) return;
        trace(`${this.id} error ${errno}`);
        this.error = errno;
        this.net.notify();
      },
    });
    return this.handle;
  }

  address() {
    if (this.bound) return this.bound;
    const got = this.handle && this.handle.address();
    if (got) return { family: this.domain, ip: got.ip, port: got.port };
    return { family: this.domain, ip: this.domain === AF_INET6 ? "::" : "0.0.0.0", port: 0 };
  }

  async bind(addr) {
    if (this.bound) return -EINVAL;
    const host = this.host();
    this.binding = true;
    const errno = await host.bind(addr.ip, addr.port);
    this.binding = false;
    if (errno) {
      trace(`${this.id} bind ${addr.ip}:${addr.port} -> ${errno}`);
      return errno;
    }
    this.bound = { family: this.domain, ...host.address() };
    trace(`${this.id} bound ${this.bound.ip}:${this.bound.port}`);
    return 0;
  }

  /// A datagram socket's connect puts the peer on the description and sends nothing, which is what
  /// Linux does: a connected datagram socket only accepts traffic from that address.
  connect(addr) {
    this.peer = addr;
    trace(`${this.id} peer ${addr.ip}:${addr.port}`);
    return Promise.resolve(0);
  }

  send(bytes, addr) {
    const to = addr ?? this.peer;
    if (!to) return Promise.resolve(-EDESTADDRREQ);
    trace(`${this.id} -> ${bytes.length} to ${to.ip}:${to.port}`);
    return this.host().send(bytes, to.ip, to.port);
  }

  recv(max, peek = false) {
    if (this.queue.length) {
      const { data, from } = this.queue[0];
      if (!peek) this.queue.shift();
      return { data: data.subarray(0, max), from, full: data.length };
    }
    if (this.error) {
      const errno = this.error;
      if (!peek) this.error = 0;
      return { errno: -errno };
    }
    if (this.closed) return { errno: -EBADF };
    return WOULD_BLOCK;
  }

  status() {
    return { read: this.queue.length > 0 || this.error !== 0, write: true, err: this.error !== 0, hup: false };
  }

  option(level, name, value) {
    // SO_RCVTIMEO: a `struct timeval`, and a receive that waits longer than that answers EAGAIN
    // the way it would on a socket the guest itself had set non-blocking.
    if (level === 1 && name === 20) {
      if (!value || value.length < 16) return -EINVAL;
      const sec = Number(value.readBigInt64LE(0));
      const usec = Number(value.readBigInt64LE(8));
      this.timeout = Math.max(0, sec * 1000 + Math.round(usec / 1000));
      return 0;
    }
    if (level === 1) return 0;
    if (level !== 0 && level !== 41) return -EOPNOTSUPP;
    if (name === 35 || name === 36) {
      // IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP: `struct ip_mreq` is the group and the interface,
      // both `struct in_addr`, and an all-zero interface is "whichever one routes".
      if (!value || value.length < 8) return -EINVAL;
      const group = `${value[0]}.${value[1]}.${value[2]}.${value[3]}`;
      const iface = value[4] | value[5] | value[6] | value[7] ? `${value[4]}.${value[5]}.${value[6]}.${value[7]}` : undefined;
      return this.host().membership(group, iface, name === 35);
    }
    return 0;
  }

  /// What `getsockopt` answers with a four-byte value, or null for an option whose answer this
  /// layer has no number for.
  get(level, name) {
    switch (`${level}:${name}`) {
      case "1:3": // SO_TYPE
        return this.type;
      case "1:4": // SO_ERROR: reading it clears it, which is how a caller learns a send failed
        {
          const errno = this.error;
          this.error = 0;
          return errno;
        }
      case "1:7": // SO_SNDBUF
      case "1:8": // SO_RCVBUF
        return 212992;
      case "1:38": // SO_PROTOCOL
        return 17;
      case "1:39": // SO_DOMAIN
        return this.domain;
      default:
        return null;
    }
  }

  release() {
    if (--this.refs > 0) return;
    this.closed = true;
    trace(`${this.id} closed`);
    this.handle?.close();
    this.handle = null;
  }
}

/// One end of a `socketpair`. A stream keeps the rest of a short read for the next one, and a
/// datagram drops it, which is the one thing the two types do differently here.
class PairEnd {
  constructor(net, domain, kind) {
    this.net = net;
    this.id = (PairEnd.serial = (PairEnd.serial ?? 0) + 1);
    this.domain = domain;
    this.type = kind;
    this.queue = [];
    this.other = null;
    /// A pair is connected from the moment it exists, to a name that is only its own end.
    this.peer = { family: AF_UNIX, path: "" };
    this.peerClosed = false;
    this.refs = 1;
    this.nonblock = false;
    this.timeout = 0;
  }

  address() {
    return { family: AF_UNIX, path: "" };
  }

  bind() {
    return Promise.resolve(-EINVAL);
  }

  connect() {
    return Promise.resolve(-EOPNOTSUPP);
  }

  send(bytes) {
    if (!this.other || this.otherClosed) return Promise.resolve(-EPIPE);
    this.other.queue.push(Buffer.from(bytes));
    this.net.notify();
    return Promise.resolve(bytes.length);
  }

  recv(max, peek = false) {
    if (!this.queue.length) return this.peerClosed ? { data: Buffer.alloc(0), from: null, full: 0 } : WOULD_BLOCK;
    const first = this.queue[0];
    const data = first.subarray(0, max);
    if (!peek) {
      if (data.length === first.length || this.type === SOCK_DGRAM) this.queue.shift();
      else this.queue[0] = first.subarray(data.length);
    }
    return { data, from: null, full: first.length };
  }

  status() {
    return { read: this.queue.length > 0 || this.peerClosed, write: !this.peerClosed, err: false, hup: this.peerClosed };
  }

  option(level, name, value) {
    if (level === 1 && name === 20) {
      if (!value || value.length < 16) return -EINVAL;
      this.timeout = Math.max(0, Number(value.readBigInt64LE(0)) * 1000 + Math.round(Number(value.readBigInt64LE(8)) / 1000));
    }
    return 0;
  }

  get(level, name) {
    if (level !== 1) return null;
    if (name === 3) return this.type;
    if (name === 38) return this.type === SOCK_DGRAM ? 17 : 6;
    if (name === 39) return this.domain;
    if (name === 4) return 0;
    return null;
  }

  release() {
    if (--this.refs > 0) return;
    if (this.other) {
      this.other.peerClosed = true;
      this.other = null;
      this.net.notify();
    }
  }
}

/// The host's own networking, as the interface the layer above needs. Everything is a promise, or
/// a number for an errno, and `onMessage`/`onError` are how the host says something happened while
/// the guest was not running.
export const nodeNetwork = {
  datagram({ ipv6, onMessage, onError }) {
    const sock = dgram.createSocket({ type: ipv6 ? "udp6" : "udp4" });
    sock.on("message", (data, rinfo) => onMessage(data, { ip: rinfo.address, port: rinfo.port }));
    sock.on("error", (e) => onError(errnoOf(e)));
    let bound = false;
    return {
      bind(ip, port) {
        return new Promise((resolve) => {
          const settle = (errno) => {
            sock.off("listening", listening);
            sock.off("error", failed);
            bound = errno === 0;
            resolve(errno);
          };
          const listening = () => settle(0);
          const failed = (e) => settle(errnoOf(e));
          sock.on("listening", listening);
          sock.on("error", failed);
          try {
            sock.bind({ address: ip, port });
          } catch (e) {
            settle(errnoOf(e));
          }
        });
      },
      send(bytes, ip, port) {
        return new Promise((resolve) => {
          sock.send(bytes, port, ip, (e) => resolve(e ? errnoOf(e) : bytes.length));
        });
      },
      membership(group, iface, join) {
        try {
          if (join) sock.addMembership(group, iface);
          else sock.dropMembership(group, iface);
          return 0;
        } catch (e) {
          return errnoOf(e);
        }
      },
      // A socket that has sent is bound to a port without ever having been asked to be, and
      // `getsockname` has to report the one the host chose.
      address() {
        try {
          const got = sock.address();
          return { ip: got.address, port: got.port };
        } catch {
          return null;
        }
      },
      close() {
        try {
          sock.close();
        } catch {}
      },
    };
  },
};
