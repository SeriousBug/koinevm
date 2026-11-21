# The network a guest gets

A guest socket is a descriptor in the file table, with the host's socket behind it. The guest sees
the Linux ABI: `sockaddr` layouts, `-errno` answers, `poll` readiness, and a receive that blocks
until a datagram arrives. A `dup` or a `fork` shares the description, so both hold one socket, the
same way both hold one open file.

What arrives while the guest is not running is the part that shapes this layer. A datagram cannot be
delivered from inside the guest's wasm call, so a receive with nothing queued parks its thread and
returns to the host; the packet that arrives later wakes it, and the call is answered then. Nothing
polls: the scheduler gives the host's event loop a turn only when no thread can run and one is
waiting on the network.

## What is implemented

| | |
|---|---|
| `socket` (198) | `AF_INET`/`AF_INET6`, `SOCK_DGRAM` or `SOCK_STREAM`; `SOCK_CLOEXEC` and `SOCK_NONBLOCK` |
| `socketpair` (199) | `AF_UNIX`, stream or dgram: two queues inside the process |
| `bind` (200) | awaits the host; port 0 reports the port the host chose |
| `connect` (203) | a datagram socket records the peer and sends nothing, as Linux does; a connection reaches the host, and one the guest asked not to wait on answers `EINPROGRESS` and completes through `poll` and `SO_ERROR` |
| `listen`, `accept`, `accept4` (201, 202, 242) | a backlog of connections, each accepted one a descriptor of its own |
| `shutdown` (210) | including the half-close a client that has said everything does |
| `getsockname`, `getpeername` (204, 205) | including the implicit bind a first send performs |
| `sendto`, `recvfrom` (206, 207) | `MSG_PEEK`, `MSG_DONTWAIT`, `MSG_TRUNC` |
| `sendmsg`, `recvmsg` (211, 212) | the iovecs gathered or scattered; no control data yet |
| `sendmmsg`, `recvmmsg` (269, 243) | glibc's resolver sends the A and AAAA questions in one and reads the answers in one |
| `setsockopt`, `getsockopt` (208, 209) | `IP_ADD_MEMBERSHIP`/`IP_DROP_MEMBERSHIP`, `SO_RCVTIMEO`, `SO_TYPE`, `SO_ERROR`, `SO_DOMAIN`, `SO_PROTOCOL`; buffer sizes are accepted and ignored, as hints |
| `read`, `write` (63, 64) | a receive and a send on a connected socket |
| `ppoll` (73), `pselect6` (72) | sockets, pipes and files; a timeout is a deadline the scheduler honours with no traffic at all |
| `fcntl` `F_GETFL`/`F_SETFL` | `O_NONBLOCK`, which is what `recvfrom` answers `EAGAIN` for |
| `ioctl` `FIONREAD` (29) | the size of the datagram a receive would take, which is what a resolver sizes its buffer from |

Not there yet: names for `AF_UNIX` sockets (`EAFNOSUPPORT`, so a `socket(AF_UNIX, ...)` fails while
`socketpair` works), control data (`SCM_RIGHTS`), `epoll`, `SO_RCVTIMEO` on a pair, and the address
`recvfrom` reports on a connection, which is the peer it is already talking to.

A send answers the count and does not wait for the host, so what a program writes faster than the
peer reads stays in the host's buffer. Bytes arriving for a guest that is not reading them stop in
the host instead, once a quarter of a megabyte has queued, which is the direction that can deadlock
a guest and so the direction that is bounded.

## Addresses

An address is held as the family the *socket* speaks, not as the family the address was written in.
A socket is the host's UDP or TCP socket underneath, so an `AF_INET6` socket has to see a `v4`
address as a `v6` one, which is the `::ffff:a.b.c.d` form Linux calls a mapped address; anything
else a guest tries to put on such a socket is `EAFNOSUPPORT` from `connect` and `EINVAL` from
`bind`. Resolution and the socket tables therefore agree: `getaddrinfo` sorts its answers so the
one whose family the socket has comes first, and a peer's address reported back from a receive is
in the shape the socket takes.

A `sockaddr` is decoded by its family, and the 28-byte `sockaddr_in6` is accepted at its own length
as well as the 16-byte `sockaddr_in`; family 0 is a valid "no address yet", which is what a
`connect` to a datagram socket that has not sent anything reports.

A datagram `connect` waits for the host to answer, because on a connected socket the peer's address
is one the host reports back, and until it has answered there is nothing to report. Connecting a
second time replaces the host's socket rather than disconnecting it, since the host's own
`disconnect` would leave the guest holding a socket it cannot send from.

`fcntl`'s `F_GETFL` reports the access mode as well as `O_NONBLOCK`: `fdopen` builds its `FILE` from
the mode the call answers, and a read-only descriptor that reports no mode at all makes glibc's own
stdio handle checks abort the program that asked.

## The interface a host implements

Everything above is the Linux side. The host side is one object, and replacing it is how a host
whose networking is not the process's own (a browser tab, an app's transport, a proxy on the far
side of a message port) runs guest sockets. It goes to `Session` as `network`:

```js
{
  datagram({ ipv6, onMessage, onError }) {
    return {
      // All of these answer a promise. An errno is a number, negative in the guest's answer:
      // resolve with 0 or with -errno.
      bind(ip, port),          // resolve when the port is bound, or with why it is not
      send(bytes, ip, port),   // resolve with the number of bytes queued, or -errno
      membership(group, iface, join), // resolve with 0 or -errno
      address(),               // { ip, port } once bound, else null
      close(),
    };
  },
}
```

`onMessage(data, { ip, port })` is how the host says a datagram arrived, and `onError(errno)` how it
says a later operation failed: both are called whenever they happen, and the layer wakes whatever
waits. `bind` is the only call that has to wait for the host before the guest can continue, because
`bind` to port 0 has to report the port that was chosen.

The default is `nodeNetwork` in `host/net.mjs`, over `node:dgram`. A host that cannot do UDP at
all implements `bind` and `send` with `-EACCES`, and every guest call gets a real errno, which is
what a program that reports "network unreachable" expects.

## Names

A guest that resolves a name writes a DNS query to whatever its `/etc/resolv.conf` names. The file
this kernel gives a guest whose root filesystem names no server of its own names `192.0.2.1`, an
address reserved for documentation that no network routes: a query sent there is a query for this
kernel, and it is answered from the host's own resolver. Names the machine can resolve resolve the
same way here, because the question asked is the one the machine would ask, which is what makes
`.local` (mDNS), a VPN's split DNS and `.home.arpa` work at all.

The policy is per nameserver, not per query. Any other address in the file is a real UDP flow, so a
guest that points at its own server - a corporate resolver, a Pi-hole, `dig @8.8.8.8` - gets that
server, and a rootfs that already names one keeps it. `KOINEVM_DNS=raw` leaves the file and the
servers alone entirely.

`A` and `AAAA` answers are built from what the host's resolver says. Everything else - `PTR`, `TXT`,
`SRV`, `MX` - is the guest's own query forwarded to the machine's servers, because the machine's
resolver is the only thing that knows what those mean.

## The limits of this shape

The guest's traffic is the host's traffic: the host's addresses, the host's routes, the host's name
service, and whatever the host's sandbox allows. A browser tab has no UDP at all, so a browser build
implements the interface over whatever the page can reach (a WebSocket to a relay, or nothing).

The address space is the guest's own: the host an address names is the host the *machine* is on.
`10.0.0.2` in the guest is `10.0.0.2` on the network, not an address inside the guest's machine.
That is what makes the network worth having, and it is also why the capability is the host's to
grant or refuse.
