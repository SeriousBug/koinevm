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
| `socket` (198) | `AF_INET`/`AF_INET6` `SOCK_DGRAM`; `SOCK_CLOEXEC` and `SOCK_NONBLOCK` |
| `socketpair` (199) | `AF_UNIX`, stream or dgram: two queues inside the process |
| `bind` (200) | awaits the host; port 0 reports the port the host chose |
| `connect` (203) | a datagram socket records the peer and sends nothing, as Linux does |
| `getsockname`, `getpeername` (204, 205) | including the implicit bind a first send performs |
| `sendto`, `recvfrom` (206, 207) | `MSG_PEEK`, `MSG_DONTWAIT`, `MSG_TRUNC` |
| `setsockopt`, `getsockopt` (208, 209) | `IP_ADD_MEMBERSHIP`/`IP_DROP_MEMBERSHIP`, `SO_RCVTIMEO`, `SO_TYPE`, `SO_ERROR`, `SO_DOMAIN`, `SO_PROTOCOL`; buffer sizes are accepted and ignored, as hints |
| `read`, `write` (63, 64) | a receive and a send on a connected socket |
| `ppoll` (73), `pselect6` (72) | sockets, pipes and files; a timeout is a deadline the scheduler honours with no traffic at all |
| `fcntl` `F_GETFL`/`F_SETFL` | `O_NONBLOCK`, which is what `recvfrom` answers `EAGAIN` for |

Not there yet: TCP (`EPROTONOSUPPORT`), names for `AF_UNIX` sockets (`EAFNOSUPPORT`, so a
`socket(AF_UNIX, ...)` fails while `socketpair` works), `sendmsg`/`recvmsg`, `shutdown`, `epoll`,
and `SO_RCVTIMEO` on a pair.

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

## The limits of this shape

The guest's traffic is the host's traffic: the host's addresses, the host's routes, the host's name
service, and whatever the host's sandbox allows. A browser tab has no UDP at all, so a browser build
implements the interface over whatever the page can reach (a WebSocket to a relay, or nothing).

The address space is the guest's own: the host an address names is the host the *machine* is on.
`10.0.0.2` in the guest is `10.0.0.2` on the network, not an address inside the guest's machine.
That is what makes the network worth having, and it is also why the capability is the host's to
grant or refuse.
