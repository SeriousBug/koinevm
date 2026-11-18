// The host's name service, as one address the guest's resolver file names.
//
// A guest that resolves a name writes a DNS query to whatever `/etc/resolv.conf` names. The file
// this kernel gives a guest with none of its own names 192.0.2.1, which is documentation space that
// no network routes, so a query sent there is a query for this kernel: it is answered from the
// host's own resolver. That is what makes `.local`, a VPN's split DNS, `.home.arpa` and the
// system's own DNS-over-HTTPS work, because the question asked is the one the machine would ask.
//
// Every other address in the file is a real UDP flow. A guest that points at its own server - a
// corporate one, a Pi-hole, `dig @8.8.8.8` - gets that server, because the address it asks is its
// own. The policy is per nameserver, not per query: the file decides, and a user who wants a
// different resolver edits it.

import dgram from "node:dgram";
import dns from "node:dns";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

/// RFC 5737's first documentation network. Nothing on the internet routes it, so nothing but this
/// kernel can answer a query sent to it.
export const HOST_RESOLVER = "192.0.2.1";

const RESOLV_CONF = Buffer.from(
  `# The host's own name service answers this address, so the names the machine can resolve
# - .local, a VPN's split DNS, .home.arpa - resolve the same way here. A server named
# instead of this one is asked directly.
nameserver ${HOST_RESOLVER}
`,
);

const A = 1;
const AAAA = 28;
const NXDOMAIN = 3;
const SERVFAIL = 2;

export class Resolver {
  /// `servers` is where the queries this cannot answer itself are forwarded; the default is the
  /// machine's own list.
  constructor({ servers = null } = {}) {
    this.servers = servers;
  }

  /// Whether this address is the one answered here rather than sent on.
  handles(ip) {
    return ip === HOST_RESOLVER;
  }

  /// The files the guest sees, given what its root filesystem already has: a rootfs that names no
  /// nameserver of its own is given the file above, and one that names its own keeps them.
  files(rootfs) {
    return new Map(hasNameserver(rootfs) ? [] : [["/etc/resolv.conf", RESOLV_CONF]]);
  }

  /// The answer to a query, or null when this is not a query whose answer this kernel can write.
  async answer(datagram) {
    const bytes = Buffer.from(datagram);
    const query = parse(bytes);
    if (!query) return null;
    if (query.type === A || query.type === AAAA) {
      const got = await lookup(query.name, query.type === A ? 4 : 6);
      if (got.nxdomain) return response(query, NXDOMAIN, []);
      const records = got.addresses.map((ip) => ({ type: query.type, bytes: addressBytes(ip) }));
      return response(query, 0, records);
    }
    // PTR, TXT, SRV and the rest: the guest's own bytes go to the machine's servers, because the
    // machine's resolver is the only thing that knows what they mean.
    return this.forward(bytes);
  }

  forward(bytes) {
    const target = (this.servers ?? dns.getServers())
      .map((server) => server.replace(/^\[(.*)\]$/, "$1").split("%")[0])
      .find((server) => net.isIP(server));
    if (!target) return servfail(bytes);
    return new Promise((resolve) => {
      const sock = dgram.createSocket(net.isIPv6(target) ? "udp6" : "udp4");
      const done = (reply) => {
        clearTimeout(timer);
        sock.close();
        resolve(reply);
      };
      const timer = setTimeout(() => done(servfail(bytes)), 2000);
      sock.on("message", (reply) => done(Buffer.from(reply)));
      sock.on("error", () => done(servfail(bytes)));
      sock.send(bytes, 53, target);
    });
  }
}

function hasNameserver(rootfs) {
  if (!rootfs) return false;
  try {
    const text = fs.readFileSync(path.join(rootfs, "etc/resolv.conf"), "latin1");
    return /^\s*nameserver\s+\S/m.test(text);
  } catch {
    return false;
  }
}

/// A stub resolver's question: one name, one type, and the offsets the answer has to echo.
function parse(bytes) {
  if (bytes.length < 12) return null;
  const flags = bytes.readUInt16BE(2);
  if (flags & 0x8000) return null; // a response, not a question
  if (bytes.readUInt16BE(4) !== 1) return null; // one question, which is what a stub sends
  const labels = [];
  let at = 12;
  for (;;) {
    if (at >= bytes.length) return null;
    const n = bytes[at];
    if (n === 0) {
      at += 1;
      break;
    }
    if (n > 63 || at + 1 + n > bytes.length) return null;
    labels.push(bytes.toString("latin1", at + 1, at + 1 + n));
    at += 1 + n;
  }
  if (at + 4 > bytes.length) return null;
  return {
    id: bytes.readUInt16BE(0),
    name: labels.join("."),
    type: bytes.readUInt16BE(at),
    end: at + 4,
    bytes,
  };
}

/// The answer a resolver writes: the question echoed, then one record per address, each owned by
/// the question's own name.
function response(query, rcode, records) {
  const head = Buffer.alloc(12);
  head.writeUInt16BE(query.id, 0);
  head.writeUInt16BE(0x8180 | rcode, 2); // a response, recursion asked for and available
  head.writeUInt16BE(1, 4);
  head.writeUInt16BE(records.length, 6);
  const body = [];
  for (const record of records) {
    const fixed = Buffer.alloc(12);
    fixed.writeUInt16BE(0xc00c, 0); // the name at offset 12, which is the question
    fixed.writeUInt16BE(record.type, 2);
    fixed.writeUInt16BE(1, 4); // class IN
    fixed.writeUInt32BE(60, 6); // a minute: long enough for a program's retries, short enough to forget
    fixed.writeUInt16BE(record.bytes.length, 10);
    body.push(fixed, record.bytes);
  }
  return Buffer.concat([head, query.bytes.subarray(12, query.end), ...body]);
}

function servfail(bytes) {
  const query = parse(bytes);
  if (!query) return null;
  return response(query, SERVFAIL, []);
}

/// What the host's own resolver says about a name, which is the same question `getaddrinfo` asks
/// on this machine: `/etc/hosts`, mDNS, a VPN's servers and the system's own transport all apply.
async function lookup(name, family) {
  try {
    const all = await dns.promises.lookup(name, { all: true });
    return { addresses: all.filter((answer) => answer.family === family).map((answer) => answer.address) };
  } catch (e) {
    return { addresses: [], nxdomain: e.code === "ENOTFOUND" };
  }
}

function addressBytes(ip) {
  if (net.isIPv4(ip)) return Buffer.from(ip.split(".").map(Number));
  const [head, tail] = ip.split("::");
  const left = head ? head.split(":") : [];
  const right = tail === undefined ? [] : tail ? tail.split(":") : [];
  const groups = left.map((group) => parseInt(group, 16));
  for (let i = 0; i < 8 - left.length - right.length; i++) groups.push(0);
  for (const group of right) groups.push(parseInt(group, 16));
  const out = Buffer.alloc(16);
  groups.slice(0, 8).forEach((group, i) => out.writeUInt16BE(group & 0xffff, i * 2));
  return out;
}
