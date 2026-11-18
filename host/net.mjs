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
import net from "node:net";
import { WOULD_BLOCK } from "./files.mjs";

export const AF_UNSPEC = 0;
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
/// syscall turns into the errno for it. RFC 2553 made 24 bytes the length of a v6 address, so four
/// bytes less than the structure is still an address: the scope id is the only part missing.
export function decodeSockaddr(bytes) {
  if (!bytes || bytes.length < 2) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const family = view.getUint16(0, true);
  if (family === AF_UNSPEC) return { family };
  if (family === AF_INET) {
    if (bytes.length < 16) return null;
    const port = view.getUint16(2, false);
    return { family, ip: `${bytes[4]}.${bytes[5]}.${bytes[6]}.${bytes[7]}`, port };
  }
  if (family === AF_INET6) {
    if (bytes.length < 24) return null;
    const port = view.getUint16(2, false);
    const groups = [];
    for (let i = 0; i < 8; i++) groups.push(view.getUint16(8 + i * 2, false));
    const scope = bytes.length >= 28 ? view.getUint32(24, true) : 0;
    return { family, ip: formatV6(groups), port, scope };
  }
  if (family === AF_UNIX) {
    let end = 2;
    while (end < Math.min(bytes.length, 110) && bytes[end] !== 0) end++;
    return { family, path: bytes.toString("latin1", 2, end) };
  }
  return null;
}

/// An address as the socket it is given to holds it, or the errno a kernel answers with.
///
/// An AF_INET6 socket speaks both families, and a v4 address given to one is the v4-mapped form of
/// the same address: that is the address a real socket reports back from `getsockname`, and glibc
/// reads it looking for exactly that shape. Nothing maps the other way, and a `bind` maps nothing
/// in either direction, because it names a local address rather than a destination.
export function sockaddrFor(domain, addr, bind = false) {
  if (addr.family === domain || addr.family === AF_UNSPEC) return addr;
  if (domain === AF_INET6 && addr.family === AF_INET) return bind ? -EINVAL : mappedV4(addr);
  return -EAFNOSUPPORT;
}

/// The v4-mapped form of a v4 address, written the way the 16 bytes it becomes are written: the
/// first ten bytes zero, two bytes of ones, then the address.
function mappedV4(addr) {
  const [a, b, c, d] = String(addr.ip).split(".").map(Number);
  const hi = ((a << 8) | b).toString(16);
  const lo = ((c << 8) | d).toString(16);
  return { family: AF_INET6, ip: `::ffff:${hi}:${lo}`, port: addr.port, scope: 0 };
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
  const groups = (part) => (part ? part.split(":") : []).flatMap(splitV6Group);
  const left = groups(head);
  const right = groups(tail);
  const fill = 8 - left.length - right.length;
  const all = [...left, ...Array(Math.max(fill, 0)).fill(0), ...right];
  return all.slice(0, 8).map((g) => g & 0xffff);
}

/// One group of a v6 address, which the text may write as a dotted v4 pair at the end: the mapped
/// form of a v4 address reads `::ffff:127.0.0.1` as often as `::ffff:7f00:1`.
function splitV6Group(group) {
  if (!group.includes(".")) return [parseInt(group || "0", 16)];
  const [a, b, c, d] = group.split(".").map(Number);
  return [(a << 8) | b, (c << 8) | d];
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
  constructor({ wake = () => {}, network = nodeNetwork, resolver = null } = {}) {
    this.wake = wake;
    this.network = network;
    /// The host's name service, for the queries sent to the address it answers.
    this.resolver = resolver;
    this.waiters = [];
  }

  /// A socket description, or a negative errno. The descriptor that holds it is the caller's.
  create(domain, kind, protocol) {
    if (domain === AF_INET || domain === AF_INET6) {
      const any = protocol === 0;
      if (kind === SOCK_DGRAM && (any || protocol === 17)) return new Datagram(this, domain);
      if (kind === SOCK_STREAM && (any || protocol === 6)) return new Stream(this, domain);
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
    this.sent = false;
    this.connecting = null;
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

  /// A datagram socket's connect puts the peer on the description and sends no datagram, but it is
  /// still a connection: the host picks the local address and port the route gives it, and those
  /// are what `getsockname` reports to a caller that connects to learn which interface it would
  /// leave by.
  connect(addr) {
    const again = this.peer !== null;
    this.peer = addr;
    trace(`${this.id} peer ${addr.ip}:${addr.port}`);
    // The address the host's resolver answers is answered here, so nothing on the host's side ever
    // sees it, and asking the host to connect to an address it cannot route would only add an
    // error a guest could read.
    if (this.net.resolver?.handles(addr.ip)) return 0;
    this.connecting = (again ? this.replace() : Promise.resolve(0))
      .then(() => this.host().connect(addr.ip, addr.port))
      .then((errno) => {
        this.connecting = null;
        // The answer is the one the guest's `connect` returns: a program that sorts addresses
        // decides what it can reach by whether this call succeeded, not by what arrives later.
        if (errno) {
          this.error = -errno;
          this.peer = null;
        }
        this.net.notify();
        return errno;
      });
    return this.connecting;
  }

  waitConnected() {
    return this.connecting ?? Promise.resolve(0);
  }

  /// A second connect replaces the peer, and the host's socket is connected for good once it has
  /// been: the replacement is a new socket, on the local address the guest had chosen where it had
  /// chosen one, which is the part of the old socket a program can see.
  replace() {
    const bound = this.bound;
    this.handle?.close();
    this.handle = null;
    this.sent = false;
    this.bound = null;
    return bound ? this.host().bind(bound.ip, bound.port) : Promise.resolve(0);
  }

  /// A connect to no address at all, which is how a datagram socket forgets its peer.
  disconnect() {
    this.peer = null;
    try {
      this.handle?.disconnect();
    } catch {}
    return 0;
  }

  /// The bytes queued for sending, or a negative errno. Sending does not wait for the host: a
  /// datagram send answers the count on Linux, and a failure the network reports later is the one a
  /// receive or `SO_ERROR` answers with.
  send(bytes, addr) {
    const to = addr ?? this.peer;
    if (!to) return -EDESTADDRREQ;
    // A connected socket sends to the peer it was connected to, and a send anywhere else is the one
    // answer Linux gives rather than a datagram that ignores the description.
    if (this.peer && addr && (addr.ip !== this.peer.ip || addr.port !== this.peer.port)) return -EISCONN;
    // A query for the address the guest's resolver file names is answered by the host's own
    // resolver instead of reaching a network: the answer arrives on this socket, from that address,
    // which is what a resolver waiting for one expects.
    const resolver = this.net.resolver;
    if (resolver && to.port === 53 && resolver.handles(to.ip)) {
      trace(`${this.id} -> dns ${bytes.length} for ${to.ip}`);
      resolver
        .answer(bytes)
        .then((reply) => {
          trace(`${this.id} dns answered ${reply ? reply.length : "nothing"}`);
          if (!reply || this.closed) return;
          this.queue.push({ data: reply, from: { family: this.domain, ip: to.ip, port: to.port } });
          this.net.notify();
        })
        .catch((e) => trace(`${this.id} dns failed: ${e.message}`));
      return bytes.length;
    }
    trace(`${this.id} -> ${bytes.length} to ${to.ip}:${to.port}`);
    this.sent = true;
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

  /// The size of the datagram a receive would take now, which is what FIONREAD answers and what a
  /// resolver sizes its buffer from.
  pending() {
    return this.queue.length ? this.queue[0].data.length : 0;
  }

  /// Whether the address is one the host has yet to choose: a socket that has sent or connected
  /// without being bound gets its address from the route a moment later.
  addressPending() {
    return this.connecting !== null || (this.sent && this.bound === null);
  }

  /// The address once the host has chosen one, for a guest that asks in the same breath as the send
  /// or the connection that gave it one.
  async ready() {
    if (this.connecting) await this.connecting;
    if (!this.handle) return this.address();
    if (!this.sent && this.bound !== null) return this.address();
    const got = await this.handle.ready();
    if (got && !this.bound) this.bound = { family: this.domain, ...got };
    return this.address();
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

/// A TCP socket: a connection, or the listener that makes them. The host does the protocol, so what
/// is here is the shape the guest's calls expect - bytes in a queue, the end of the stream as a
/// zero-length read, a connecting socket that is writable only once it is connected - and the
/// backpressure that keeps a fast sender from filling memory with a slow reader's bytes.
class Stream {
  constructor(net, domain, sock = null) {
    this.net = net;
    this.id = (Stream.serial = (Stream.serial ?? 0) + 1);
    this.domain = domain;
    this.type = SOCK_STREAM;
    this.queue = [];
    /// Connections waiting for `accept`, each one a socket of its own.
    this.accepted = [];
    this.state = sock ? "connected" : "idle";
    this.error = 0;
    this.ended = false;
    this.readClosed = false;
    this.listening = false;
    this.bound = null;
    this.peer = sock ? { family: domain, ip: sock.remoteAddress, port: sock.remotePort } : null;
    this.refs = 1;
    this.nonblock = false;
    this.timeout = 0;
    this.noDelay = false;
    this.sock = sock;
    this.handle = null;
    this.listener = null;
    this.connecting = null;
    this.paused = false;
    // A connection the host accepted is already readable: its bytes are only queued once something
    // is listening for them, and that is this socket's host object.
    if (sock) this.host();
  }

  host() {
    if (this.handle) return this.handle;
    this.handle = this.net.network.connection({
      ipv6: this.domain === AF_INET6,
      sock: this.sock,
      noDelay: this.noDelay,
      onData: (bytes) => {
        this.queue.push(bytes);
        if (this.queued() > 256 * 1024 && !this.paused) {
          this.paused = true;
          this.handle.pause();
        }
        this.net.notify();
      },
      onEnd: () => {
        this.ended = true;
        this.net.notify();
      },
      onError: (errno) => {
        this.error = errno;
        this.net.notify();
      },
    });
    return this.handle;
  }

  queued() {
    return this.queue.reduce((n, chunk) => n + chunk.length, 0);
  }

  // ---- the listener

  async bind(addr) {
    if (this.bound || this.listener) return -EINVAL;
    const listener = this.net.network.listener({
      ipv6: this.domain === AF_INET6,
      onConnection: (sock) => {
        this.accepted.push(new Stream(this.net, this.domain, sock));
        this.net.notify();
      },
      onError: (errno) => {
        this.error = errno;
        this.net.notify();
      },
    });
    const errno = await listener.listen(addr.ip, addr.port);
    if (errno) {
      listener.close();
      return errno;
    }
    this.listener = listener;
    this.bound = { family: this.domain, ...listener.address() };
    trace(`${this.id} listening on ${this.bound.ip}:${this.bound.port}`);
    return 0;
  }

  listen() {
    if (!this.listener) return -EINVAL;
    this.listening = true;
    return 0;
  }

  /// The next connection, or null when there is none yet and an errno when this socket is not a
  /// listener to begin with.
  accept() {
    if (!this.listener) return -EINVAL;
    if (!this.listening) return -EINVAL;
    const conn = this.accepted.shift();
    return conn ?? null;
  }

  // ---- the connection

  connect(addr) {
    if (this.state === "connected") return -EISCONN;
    if (this.connecting) return this.connecting;
    this.peer = { family: addr.family, ip: addr.ip, port: addr.port };
    this.state = "connecting";
    trace(`${this.id} connecting to ${addr.ip}:${addr.port}`);
    this.connecting = this.host()
      .connect(addr.ip, addr.port)
      .then((errno) => {
        if (errno) {
          this.state = "failed";
          this.error = -errno;
          this.net.notify();
          return errno;
        }
        this.state = "connected";
        const got = this.handle.peer();
        if (got) this.peer = { family: this.domain, ...got };
        this.net.notify();
        return 0;
      });
    return this.connecting;
  }

  waitConnected() {
    return this.connecting ?? Promise.resolve(0);
  }

  /// A connection has nothing to forget: the request to connect to no address is the one answer
  /// Linux gives a stream socket, whatever state it was in.
  disconnect() {
    return -EAFNOSUPPORT;
  }

  send(bytes) {
    if (this.state !== "connected") return -ENOTCONN;
    return this.host().send(bytes);
  }

  recv(max, peek = false) {
    if (this.queue.length) {
      const first = this.queue[0];
      const data = first.subarray(0, max);
      if (!peek) {
        if (data.length === first.length) this.queue.shift();
        else this.queue[0] = first.subarray(data.length);
        if (this.paused && this.queued() < 64 * 1024) {
          this.paused = false;
          this.handle.resume();
        }
      }
      return { data, from: null, full: data.length };
    }
    if (this.error && this.state === "failed") {
      const errno = this.error;
      this.error = 0;
      return { errno };
    }
    // The peer is done sending: a read answers zero, which is the end of the stream.
    if (this.ended) return { data: Buffer.alloc(0), from: null, full: 0 };
    return WOULD_BLOCK;
  }

  status() {
    return {
      read: this.queue.length > 0 || this.ended,
      // A connecting socket is not writable yet, which is how a guest waiting on a non-blocking
      // connect learns that it finished.
      write: this.state === "connected",
      err: this.state === "failed",
      hup: this.ended,
    };
  }

  pending() {
    return this.queued();
  }

  addressPending() {
    return this.state === "connecting";
  }

  async ready() {
    if (this.state === "connecting") await this.connecting;
    return this.address();
  }

  address() {
    if (this.bound) return this.bound;
    if (this.listener) {
      const got = this.listener.address();
      if (got) return { family: this.domain, ...got };
    }
    if (this.handle) {
      const got = this.handle.address();
      if (got) return { family: this.domain, ...got };
    }
    return { family: this.domain, ip: this.domain === AF_INET6 ? "::" : "0.0.0.0", port: 0 };
  }

  shutdown(how) {
    // SHUT_RD, SHUT_WR or both. A half-close is the peer's end of stream, which is what a client
    // that has said everything it has to say does.
    if (how === 0 || how === 2) this.readClosed = true;
    if (how === 1 || how === 2) this.host().shutdownWrite();
    if (how === 2) this.ended = true;
    return 0;
  }

  option(level, name, value) {
    if (level === 1 && name === 20) {
      if (!value || value.length < 16) return -EINVAL;
      const sec = Number(value.readBigInt64LE(0));
      const usec = Number(value.readBigInt64LE(8));
      this.timeout = Math.max(0, sec * 1000 + Math.round(usec / 1000));
      return 0;
    }
    if (level === 6 && name === 1) {
      // TCP_NODELAY, which a program sets to stop the host waiting for a full segment.
      this.noDelay = !(value && value.length >= 4 && value.readInt32LE(0) === 0);
      if (this.handle) this.handle.setNoDelay(this.noDelay);
      return 0;
    }
    return 0;
  }

  get(level, name) {
    switch (`${level}:${name}`) {
      case "1:3":
        return this.type;
      case "1:4": {
        const errno = this.error;
        this.error = 0;
        return errno;
      }
      case "1:8":
      case "1:7":
        return 212992;
      case "1:30":
        return this.listening ? 1 : 0;
      case "1:38":
        return 6;
      case "1:39":
        return this.domain;
      default:
        return null;
    }
  }

  release() {
    if (--this.refs > 0) return;
    this.state = "closed";
    trace(`${this.id} closed`);
    for (const conn of this.accepted.splice(0)) conn.release();
    this.listener?.close();
    this.handle?.close();
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
    if (!this.other || this.otherClosed) return -EPIPE;
    this.other.queue.push(Buffer.from(bytes));
    this.net.notify();
    return bytes.length;
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

  pending() {
    return this.queue.reduce((n, chunk) => n + chunk.length, 0);
  }

  ready() {
    return Promise.resolve(this.address());
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
    // A socket is bound either by `bind` or by the host's own choice on the first send, and both
    // end with the same event.
    let bound = false;
    let peer = null;
    let announce;
    const listeningOnce = new Promise((resolve) => {
      announce = resolve;
    });
    sock.on("listening", () => {
      bound = true;
      announce();
    });
    // A socket that has sent is bound to a port without ever having been asked to be, and
    // `getsockname` has to report the one the host chose.
    const address = () => {
      try {
        const got = sock.address();
        return { ip: got.address, port: got.port };
      } catch {
        return null;
      }
    };
    return {
      bind(ip, port) {
        return new Promise((resolve) => {
          const settle = (errno) => {
            sock.off("listening", onListening);
            sock.off("error", failed);
            resolve(errno);
          };
          const onListening = () => settle(0);
          const failed = (e) => settle(errnoOf(e));
          sock.on("listening", onListening);
          sock.on("error", failed);
          try {
            sock.bind({ address: ip, port });
          } catch (e) {
            settle(errnoOf(e));
          }
        });
      },
      /// A connection, which for a datagram socket binds it: the local address and port are the
      /// route's answer, and the peer is the only address it will send to afterwards.
      connect(ip, port) {
        return new Promise((resolve) => {
          const settle = (errno) => {
            sock.off("connect", done);
            sock.off("error", failed);
            peer = errno ? null : { ip, port };
            resolve(errno);
          };
          const done = () => settle(0);
          const failed = (e) => settle(errnoOf(e));
          sock.on("connect", done);
          sock.on("error", failed);
          try {
            sock.connect(port, ip);
          } catch (e) {
            settle(errnoOf(e));
          }
        });
      },
      disconnect() {
        peer = null;
        try {
          sock.disconnect();
        } catch {}
      },
      send(bytes, ip, port) {
        // The callback is where the network reports a failure it found on the way out; the answer
        // is the count, which is what a sender gets. A connected socket already holds the address,
        // and the host's own call refuses one besides.
        try {
          if (peer && peer.ip === ip && peer.port === port) {
            sock.send(bytes, (e) => {
              if (e) onError(errnoOf(e));
            });
          } else {
            sock.send(bytes, port, ip, (e) => {
              if (e) onError(errnoOf(e));
            });
          }
        } catch (e) {
          return -errnoOf(e);
        }
        return bytes.length;
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
      address,
      /// The address, waiting for the host to choose it when it has not yet.
      ready() {
        const now = address();
        return now ? Promise.resolve(now) : listeningOnce.then(address);
      },
      close() {
        try {
          sock.close();
        } catch {}
      },
    };
  },

  /// A TCP connection, or the socket a connection will be made on. A socket the host accepted is
  /// handed over already connected, so this wraps it as it is.
  connection({ ipv6, sock = null, noDelay = false, onData, onError, onEnd }) {
    const socket = sock ?? new net.Socket();
    socket.on("data", (bytes) => onData(Buffer.from(bytes)));
    socket.on("end", () => onEnd());
    socket.on("close", () => onEnd());
    socket.on("error", (e) => onError(errnoOf(e)));
    if (noDelay) {
      try {
        socket.setNoDelay(true);
      } catch {}
    }
    // An accepted socket arrives paused, so the bytes stay in the kernel until there is somewhere
    // to put them; this is the where.
    socket.resume();
    return {
      connect(ip, port) {
        return new Promise((resolve) => {
          const finish = (errno) => {
            socket.off("connect", ready);
            socket.off("error", failed);
            resolve(errno);
          };
          const ready = () => finish(0);
          const failed = (e) => finish(errnoOf(e));
          socket.on("connect", ready);
          socket.on("error", failed);
          try {
            socket.connect({ host: ip, port });
          } catch (e) {
            finish(errnoOf(e));
          }
        });
      },
      send(bytes) {
        if (socket.destroyed || socket.writableEnded) return -EPIPE;
        socket.write(bytes);
        return bytes.length;
      },
      shutdownWrite() {
        try {
          socket.end();
        } catch {}
      },
      address() {
        try {
          const got = socket.address();
          return got && typeof got === "object" ? { ip: got.address, port: got.port } : null;
        } catch {
          return null;
        }
      },
      peer() {
        return socket.remoteAddress ? { ip: socket.remoteAddress, port: socket.remotePort } : null;
      },
      pause() {
        try {
          socket.pause();
        } catch {}
      },
      resume() {
        try {
          socket.resume();
        } catch {}
      },
      setNoDelay(on) {
        try {
          socket.setNoDelay(on);
        } catch {}
      },
      close() {
        try {
          socket.destroy();
        } catch {}
      },
    };
  },

  /// The listening side: every connection the host accepts is handed over as a socket, and the
  /// layer above wraps it into a descriptor of its own.
  listener({ onConnection, onError }) {
    // The connection is handed over paused: the layer above builds a descriptor out of it first,
    // and only then does anything read it.
    const server = net.createServer({ pauseOnConnect: true }, (sock) => onConnection(sock));
    server.on("error", (e) => onError(errnoOf(e)));
    let listening = false;
    let announce;
    const listeningOnce = new Promise((resolve) => {
      announce = resolve;
    });
    server.on("listening", () => {
      listening = true;
      announce();
    });
    const address = () => {
      try {
        const got = server.address();
        return got ? { ip: got.address, port: got.port } : null;
      } catch {
        return null;
      }
    };
    return {
      listen(ip, port) {
        return new Promise((resolve) => {
          const finish = (errno) => {
            server.off("listening", onListening);
            server.off("error", failed);
            resolve(errno);
          };
          const onListening = () => finish(0);
          const failed = (e) => finish(errnoOf(e));
          server.on("listening", onListening);
          server.on("error", failed);
          try {
            server.listen({ host: ip, port, backlog: 511 });
          } catch (e) {
            finish(errnoOf(e));
          }
        });
      },
      address,
      ready() {
        return listening ? Promise.resolve(address()) : listeningOnce.then(address);
      },
      close() {
        try {
          server.close();
        } catch {}
      },
    };
  },
};
