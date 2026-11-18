/* Guest that exercises the socket side of the ABI: the datagrams, the address a socket reports and
 * the wait a receive with nothing queued performs.
 *
 * It needs a host that answers, so tests/net.sh starts a UDP echo server and hands its port over as
 * argv[1]. Every check prints a line, and the run passes when none of them says FAIL. */

static inline long sc6(long nr, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
}

#define AF_UNIX 1
#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2

#define SOL_SOCKET 1
#define SO_TYPE 3

#define POLLIN 0x001
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK 0x800
#define EAGAIN 11

struct sockaddr_in {
    unsigned short family;
    unsigned short port;
    unsigned int addr;
    unsigned char zero[8];
};

struct sockaddr_un {
    unsigned short family;
    char path[108];
};

struct pollfd {
    int fd;
    short events;
    short revents;
};

struct timespec {
    long sec;
    long nsec;
};

static long socket_(long domain, long type, long protocol) { return sc6(198, domain, type, protocol, 0, 0, 0); }
static long socketpair_(long domain, long type, long protocol, int *sv) {
    return sc6(199, domain, type, protocol, (long)sv, 0, 0);
}
static long bind_(long fd, const void *addr, long len) { return sc6(200, fd, (long)addr, len, 0, 0, 0); }
static long getsockname_(long fd, void *addr, int *len) { return sc6(204, fd, (long)addr, (long)len, 0, 0, 0); }
static long getsockopt_(long fd, long level, long name, void *val, int *len) {
    return sc6(209, fd, level, name, (long)val, (long)len, 0);
}
static long sendto_(long fd, const void *buf, long len, const void *addr, long addrlen) {
    return sc6(206, fd, (long)buf, len, 0, (long)addr, addrlen);
}
static long recvfrom_(long fd, void *buf, long len, void *addr, int *addrlen) {
    return sc6(207, fd, (long)buf, len, 0, (long)addr, (long)addrlen);
}
static long fcntl_(long fd, long cmd, long arg) { return sc6(25, fd, cmd, arg, 0, 0, 0); }
static long ppoll_(struct pollfd *fds, long n, long ms) {
    struct timespec ts;
    ts.sec = ms / 1000;
    ts.nsec = (ms % 1000) * 1000000;
    return sc6(73, (long)fds, n, (long)&ts, 0, 0, 0);
}
static long write_(long fd, const void *buf, unsigned long n) { return sc6(64, fd, (long)buf, n, 0, 0, 0); }
static long read_(long fd, void *buf, unsigned long n) { return sc6(63, fd, (long)buf, n, 0, 0, 0); }
static long close_(long fd) { return sc6(57, fd, 0, 0, 0, 0, 0); }

static void guest_exit(long code) {
    register long x8 __asm__("x8") = 93;
    register long x0 __asm__("x0") = code;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0) : "memory");
    __builtin_unreachable();
}

static unsigned long str_len(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

static void put(const char *s) { write_(1, s, str_len(s)); }

static int failures;

static void check(int ok, const char *what) {
    put(ok ? "ok   " : "FAIL ");
    put(what);
    put("\n");
    if (!ok) failures++;
}

static int bytes_equal(const char *a, const char *b, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static void set_v4(struct sockaddr_in *sa, unsigned a, unsigned b, unsigned c, unsigned d, unsigned port) {
    unsigned char *raw = (unsigned char *)sa;
    for (unsigned long i = 0; i < sizeof(*sa); i++) raw[i] = 0;
    sa->family = AF_INET;
    raw[2] = (port >> 8) & 0xff;
    raw[3] = port & 0xff;
    raw[4] = a;
    raw[5] = b;
    raw[6] = c;
    raw[7] = d;
}

static unsigned port_of(const struct sockaddr_in *sa) {
    const unsigned char *raw = (const unsigned char *)sa;
    return (raw[2] << 8) | raw[3];
}

static int is_loopback(const struct sockaddr_in *sa) {
    const unsigned char *raw = (const unsigned char *)sa;
    return raw[4] == 127 && raw[5] == 0 && raw[6] == 0 && raw[7] == 1;
}

static unsigned long to_unsigned(const char *s) {
    unsigned long v = 0;
    for (unsigned long i = 0; s[i] >= '0' && s[i] <= '9'; i++) v = v * 10 + (unsigned long)(s[i] - '0');
    return v;
}

/// The stack the kernel handed over, taken before any frame is pushed onto it: the port of the echo
/// server is the guest's first argument, and it is the second word of the stack.
__attribute__((naked)) void _start(void) {
    __asm__ volatile("mov x0, sp\n\tb run");
}

void run(unsigned long *sp) {
    long argc = (long)sp[0];
    char **argv = (char **)(sp + 1);
    unsigned long echo_port = argc > 1 ? to_unsigned(argv[1]) : 0;
    char buf[64];
    struct sockaddr_in self, other, from, to;
    int len;

    // A fresh datagram socket, and what it says about itself before anything is bound to it.
    long a = socket_(AF_INET, SOCK_DGRAM, 0);
    check(a >= 0, "socket(AF_INET, SOCK_DGRAM) returns a descriptor");
    int type = 0;
    len = sizeof(type);
    check(getsockopt_(a, SOL_SOCKET, SO_TYPE, &type, &len) == 0 && type == SOCK_DGRAM,
          "getsockopt(SO_TYPE) says SOCK_DGRAM");

    len = sizeof(self);
    check(getsockname_(a, &self, &len) == 0, "getsockname of an unbound socket succeeds");
    check(len == 16 && self.family == AF_INET && port_of(&self) == 0,
          "an unbound socket has no port and no address");

    set_v4(&self, 127, 0, 0, 1, 0);
    check(bind_(a, &self, sizeof(self)) == 0, "bind to 127.0.0.1:0 succeeds");
    len = sizeof(self);
    check(getsockname_(a, &self, &len) == 0 && port_of(&self) != 0,
          "getsockname reports the port the host chose");
    check(is_loopback(&self), "getsockname reports the address it was bound to");

    // A second socket, which is bound by its first send, exactly as a real kernel does.
    long b = socket_(AF_INET, SOCK_DGRAM, 0);
    check(b >= 0 && b != a, "a second socket has a descriptor of its own");
    check(sendto_(b, "ping", 4, &self, sizeof(self)) == 4, "sendto reaches the bound socket");

    len = sizeof(other);
    check(getsockname_(b, &other, &len) == 0 && port_of(&other) != 0,
          "a socket that has sent is bound to a port");

    len = sizeof(from);
    long n = recvfrom_(a, buf, sizeof(buf), &from, &len);
    check(n == 4 && bytes_equal(buf, "ping", 4), "recvfrom answers what was sent");
    check(len == 16 && from.family == AF_INET && port_of(&from) == port_of(&other),
          "recvfrom says which port it came from");
    check(is_loopback(&from), "recvfrom says which address it came from");

    // Nothing left, on a socket the guest has asked not to wait.
    check(fcntl_(a, F_SETFL, O_NONBLOCK) == 0, "F_SETFL sets O_NONBLOCK");
    check((fcntl_(a, F_GETFL, 0) & O_NONBLOCK) != 0, "F_GETFL reports O_NONBLOCK");
    check(recvfrom_(a, buf, sizeof(buf), 0, 0) == -EAGAIN,
          "a non-blocking recvfrom with nothing queued says EAGAIN");

    // The one that has to wait: the answer comes from the host, while the thread is parked.
    set_v4(&to, 127, 0, 0, 1, (unsigned)echo_port);
    check(echo_port != 0, "the echo server's port is the guest's argument");
    check(sendto_(b, "echo-ping", 9, &to, sizeof(to)) == 9, "sendto reaches the host");
    n = recvfrom_(b, buf, sizeof(buf), 0, 0);
    check(n == 14 && bytes_equal(buf, "echo:echo-ping", 14), "a receive the host answers waits for it");

    // A timeout that expires with nothing to report, then one that does not.
    struct pollfd one;
    one.fd = (int)b;
    one.events = POLLIN;
    one.revents = 0;
    check(ppoll_(&one, 1, 100) == 0, "ppoll times out with nothing ready");

    check(sendto_(b, "poll", 4, &self, sizeof(self)) == 4, "sendto before polling");
    one.fd = (int)a;
    one.revents = 0;
    check(ppoll_(&one, 1, 5000) == 1 && (one.revents & POLLIN) != 0, "ppoll reports a queued datagram");
    len = sizeof(from);
    check(recvfrom_(a, buf, sizeof(buf), &from, &len) == 4 && bytes_equal(buf, "poll", 4),
          "the datagram ppoll reported is the one recvfrom returns");

    // A pair exists inside the process, and both ends behave like what they are.
    int sv[2] = {-1, -1};
    check(socketpair_(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair(AF_UNIX, SOCK_STREAM) succeeds");
    check(sv[0] >= 0 && sv[1] >= 0 && sv[0] != sv[1], "the pair has two descriptors");
    struct sockaddr_un none;
    len = sizeof(none);
    // An unnamed unix socket reports the family and nothing after it, which is two bytes.
    check(getsockname_(sv[0], &none, &len) == 0 && none.family == AF_UNIX && len == 2,
          "a pair end is an unnamed AF_UNIX address");
    check(write_(sv[0], "through the pair", 16) == 16, "write on one end");
    n = read_(sv[1], buf, sizeof(buf));
    check(n == 16 && bytes_equal(buf, "through the pair", 16), "read on the other end");
    one.fd = (int)sv[1];
    one.revents = 0;
    check(ppoll_(&one, 1, 0) == 0, "a pair with nothing left has nothing to report");

    check(close_(a) == 0 && close_(b) == 0, "close of a socket");
    check(recvfrom_(a, buf, sizeof(buf), 0, 0) == -9, "a closed socket is not a descriptor");

    put(failures ? "net: FAILURES\n" : "net: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}

