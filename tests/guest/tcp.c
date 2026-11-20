/* Guest that exercises the connection side of the ABI: a client against a host that answers, the
 * same client without blocking, and a listener of its own that a forked child connects to, then one
 * the same process connects to, whose bytes go out as two iovecs.
 *
 * tests/net.sh starts a TCP echo server and hands its port over as argv[1]. The checks are the same
 * on a real kernel, which is what the run compares against. */

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

#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2

#define SOL_SOCKET 1
#define SO_ERROR 4
#define SO_ACCEPTCONN 30

#define SHUT_WR 1

#define POLLIN 0x001
#define POLLOUT 0x004
#define F_SETFL 4
#define O_NONBLOCK 0x800
#define EAGAIN 11
#define EINPROGRESS 115
#define EINVAL 22

struct sockaddr_in {
    unsigned short family;
    unsigned short port;
    unsigned int addr;
    unsigned char zero[8];
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

struct iovec {
    void *base;
    unsigned long len;
};

static long socket_(long domain, long type, long protocol) { return sc6(198, domain, type, protocol, 0, 0, 0); }
static long bind_(long fd, const void *addr, long len) { return sc6(200, fd, (long)addr, len, 0, 0, 0); }
static long listen_(long fd, long backlog) { return sc6(201, fd, backlog, 0, 0, 0, 0); }
static long accept_(long fd, void *addr, int *len) { return sc6(202, fd, (long)addr, (long)len, 0, 0, 0); }
static long connect_(long fd, const void *addr, long len) { return sc6(203, fd, (long)addr, len, 0, 0, 0); }
static long getsockname_(long fd, void *addr, int *len) { return sc6(204, fd, (long)addr, (long)len, 0, 0, 0); }
static long getpeername_(long fd, void *addr, int *len) { return sc6(205, fd, (long)addr, (long)len, 0, 0, 0); }
static long getsockopt_(long fd, long level, long name, void *val, int *len) {
    return sc6(209, fd, level, name, (long)val, (long)len, 0);
}
static long shutdown_(long fd, long how) { return sc6(210, fd, how, 0, 0, 0, 0); }
static long fcntl_(long fd, long cmd, long arg) { return sc6(25, fd, cmd, arg, 0, 0, 0); }
static long ppoll_(struct pollfd *fds, long n, long ms) {
    struct timespec ts;
    ts.sec = ms / 1000;
    ts.nsec = (ms % 1000) * 1000000;
    return sc6(73, (long)fds, n, (long)&ts, 0, 0, 0);
}
static long write_(long fd, const void *buf, unsigned long n) { return sc6(64, fd, (long)buf, n, 0, 0, 0); }
static long read_(long fd, void *buf, unsigned long n) { return sc6(63, fd, (long)buf, n, 0, 0, 0); }
static long writev_(long fd, const struct iovec *iov, long n) { return sc6(66, fd, (long)iov, n, 0, 0, 0); }
static long close_(long fd) { return sc6(57, fd, 0, 0, 0, 0, 0); }
static long fork_(void) { return sc6(220, 17, 0, 0, 0, 0, 0); } /* SIGCHLD */
static long wait4_(long pid, int *status) { return sc6(260, pid, (long)status, 0, 0, 0, 0); }

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

static unsigned long to_unsigned(const char *s) {
    unsigned long v = 0;
    for (unsigned long i = 0; s[i] >= '0' && s[i] <= '9'; i++) v = v * 10 + (unsigned long)(s[i] - '0');
    return v;
}

/// Read until `want` bytes have arrived, or the peer is done.
static long read_fully(long fd, char *buf, long want) {
    long total = 0;
    while (total < want) {
        long n = read_(fd, buf + total, (unsigned long)(want - total));
        if (n <= 0) return total ? total : n;
        total += n;
    }
    return total;
}

/// The stack the kernel handed over, taken before any frame is pushed onto it.
__attribute__((naked)) void _start(void) {
    __asm__ volatile("mov x0, sp\n\tb run");
}

void run(unsigned long *sp) {
    long argc = (long)sp[0];
    char **argv = (char **)(sp + 1);
    unsigned long echo_port = argc > 1 ? to_unsigned(argv[1]) : 0;
    char buf[64];
    struct sockaddr_in to, from, self;
    int len;

    check(echo_port != 0, "the echo server's port is the guest's argument");
    set_v4(&to, 127, 0, 0, 1, (unsigned)echo_port);

    // A client that waits for the connection, which is what most programs do.
    long fd = socket_(AF_INET, SOCK_STREAM, 0);
    check(fd >= 0, "socket(AF_INET, SOCK_STREAM) returns a descriptor");
    check(connect_(fd, &to, sizeof(to)) == 0, "connect to the host succeeds");
    len = sizeof(self);
    check(getsockname_(fd, &self, &len) == 0 && port_of(&self) != 0,
          "a connected socket has a local port");
    len = sizeof(from);
    check(getpeername_(fd, &from, &len) == 0 && port_of(&from) == echo_port,
          "getpeername reports the address it connected to");
    check(write_(fd, "tcp-ping\n", 9) == 9, "write sends the bytes");
    long got = read_fully(fd, buf, 14);
    check(got == 14 && bytes_equal(buf, "echo:tcp-ping\n", 14), "read answers what was sent");
    check(shutdown_(fd, SHUT_WR) == 0, "shutdown(SHUT_WR) half-closes the writing end");
    check(read_(fd, buf, sizeof(buf)) == 0, "a read after the peer's end is end of stream");
    check(close_(fd) == 0, "close of a connection");

    // The same, without blocking: the connection reports EINPROGRESS and completes through poll.
    fd = socket_(AF_INET, SOCK_STREAM, 0);
    check(fcntl_(fd, F_SETFL, O_NONBLOCK) == 0, "the socket is set non-blocking");
    long started = connect_(fd, &to, sizeof(to));
    check(started == -EINPROGRESS, "a non-blocking connect answers EINPROGRESS");
    struct pollfd one;
    one.fd = (int)fd;
    one.events = POLLOUT;
    one.revents = 0;
    check(ppoll_(&one, 1, 5000) == 1 && (one.revents & POLLOUT) != 0,
          "poll reports the connection writable once it is made");
    int error = -1;
    len = sizeof(error);
    check(getsockopt_(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0,
          "SO_ERROR reports that the connection succeeded");
    one.fd = (int)fd;
    one.events = POLLIN;
    one.revents = 0;
    check(ppoll_(&one, 1, 0) == 0, "nothing is there to read yet");
    check(write_(fd, "nowait\n", 7) == 7, "write on a non-blocking connection");
    check(ppoll_(&one, 1, 5000) == 1 && (one.revents & POLLIN) != 0, "the answer makes it readable");
    got = read_fully(fd, buf, 12);
    check(got == 12 && bytes_equal(buf, "echo:nowait\n", 12), "the non-blocking client reads it");
    check(close_(fd) == 0, "close of the non-blocking connection");

    // A listener of the guest's own, and a child that connects to it.
    long server = socket_(AF_INET, SOCK_STREAM, 0);
    check(server >= 0, "a socket to listen on");
    set_v4(&self, 127, 0, 0, 1, 0);
    check(bind_(server, &self, sizeof(self)) == 0, "bind to a port of its own");
    len = sizeof(self);
    check(getsockname_(server, &self, &len) == 0 && port_of(&self) != 0,
          "the listener knows the port it was given");
    int accepting = -1;
    len = sizeof(accepting);
    check(getsockopt_(server, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &len) == 0 && accepting == 0,
          "a bound socket is not accepting yet");
    check(listen_(server, 4) == 0, "listen");
    accepting = -1;
    len = sizeof(accepting);
    check(getsockopt_(server, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &len) == 0 && accepting == 1,
          "a listening socket says it is accepting");
    one.fd = (int)server;
    one.events = POLLIN;
    one.revents = 0;
    check(ppoll_(&one, 1, 0) == 0, "a listener with no connection is not readable");

    long pid = fork_();
    check(pid >= 0, "fork");
    if (pid == 0) {
        long client = socket_(AF_INET, SOCK_STREAM, 0);
        if (client < 0) guest_exit(1);
        if (connect_(client, &self, sizeof(self)) != 0) guest_exit(2);
        if (write_(client, "from child\n", 11) != 11) guest_exit(3);
        close_(client);
        guest_exit(0);
    }

    len = sizeof(from);
    long conn = accept_(server, &from, &len);
    check(conn >= 0, "accept answers the child's connection");
    check(len == 16 && port_of(&from) != 0, "accept says where the connection came from");
    got = read_fully(conn, buf, 11);
    check(got == 11 && bytes_equal(buf, "from child\n", 11), "the accepted connection has the bytes");
    check(read_(conn, buf, sizeof(buf)) == 0, "and then the end of the child's stream");
    check(close_(conn) == 0, "close of an accepted connection");

    int status = -1;
    check(wait4_(pid, &status) == pid && status == 0, "the child exited with zero");

    // The same process on both ends, which is the shape every server has: the connection arrives
    // while nothing is waiting in `accept`, so the listener is what a program watches for it.
    long client = socket_(AF_INET, SOCK_STREAM, 0);
    check(client >= 0, "a socket to connect from");
    check(connect_(client, &self, sizeof(self)) == 0, "a connection to the guest's own listener");
    one.fd = (int)server;
    one.events = POLLIN;
    one.revents = 0;
    check(ppoll_(&one, 1, 5000) == 1 && (one.revents & POLLIN) != 0,
          "a listener with a connection waiting is readable");
    len = sizeof(from);
    conn = accept_(server, &from, &len);
    check(conn >= 0, "accept answers a connection nothing was waiting for");

    // A write of more than one piece, which is what a header and a body are: every iovec goes out,
    // and the peer reads one stream of them.
    struct iovec parts[2];
    parts[0].base = (void *)"part-one\n";
    parts[0].len = 9;
    parts[1].base = (void *)"part-two\n";
    parts[1].len = 9;
    check(writev_(client, parts, 2) == 18, "writev on a socket sends every iovec");
    got = read_fully(conn, buf, 18);
    check(got == 18 && bytes_equal(buf, "part-one\npart-two\n", 18),
          "the peer reads them as one stream");
    check(close_(conn) == 0, "close of that connection");
    check(close_(client) == 0, "close of the client end");

    check(close_(server) == 0, "close of the listener");

    // A socket that was never told to listen cannot accept.
    long idle = socket_(AF_INET, SOCK_STREAM, 0);
    check(accept_(idle, 0, 0) == -EINVAL, "accept without listen is EINVAL");
    check(close_(idle) == 0, "close of it");

    put(failures ? "tcp: FAILURES\n" : "tcp: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}
