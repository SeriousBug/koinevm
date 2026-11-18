/* Guest that watches descriptors through epoll: a pipe that becomes readable, one that is always
 * writable, a datagram that arrives while nothing else runs, and a watch that goes away when the
 * descriptor it names does.
 *
 * The checks are the same on a real kernel, which is what the run compares against. */

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
#define SOCK_DGRAM 2

#define EPOLLIN 0x001
#define EPOLLOUT 0x004
#define EPOLLHUP 0x010
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

#define EEXIST 17
#define ENOENT 2
#define EBADF 9
#define EINVAL 22

/// The mask, four bytes of padding, and the guest's own value: only x86-64 packs this structure.
struct epoll_event {
    unsigned int events;
    unsigned long data;
};

struct sockaddr_in {
    unsigned short family;
    unsigned short port;
    unsigned int addr;
    unsigned char zero[8];
};

static long epoll_create1_(long flags) { return sc6(20, flags, 0, 0, 0, 0, 0); }
static long epoll_ctl_(long epfd, long op, long fd, struct epoll_event *event) {
    return sc6(21, epfd, op, fd, (long)event, 0, 0);
}
static long epoll_pwait_(long epfd, struct epoll_event *events, long max, long ms) {
    return sc6(22, epfd, (long)events, max, ms, 0, 0);
}
static long pipe2_(int *fds) { return sc6(59, (long)fds, 0, 0, 0, 0, 0); }
static long write_(long fd, const void *buf, unsigned long n) { return sc6(64, fd, (long)buf, n, 0, 0, 0); }
static long read_(long fd, void *buf, unsigned long n) { return sc6(63, fd, (long)buf, n, 0, 0, 0); }
static long close_(long fd) { return sc6(57, fd, 0, 0, 0, 0, 0); }
static long socket_(long domain, long type, long protocol) { return sc6(198, domain, type, protocol, 0, 0, 0); }
static long bind_(long fd, const void *addr, long len) { return sc6(200, fd, (long)addr, len, 0, 0, 0); }
static long getsockname_(long fd, void *addr, int *len) { return sc6(204, fd, (long)addr, (long)len, 0, 0, 0); }
static long sendto_(long fd, const void *buf, long len, const void *addr, long addrlen) {
    return sc6(206, fd, (long)buf, len, 0, (long)addr, addrlen);
}

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

void run(unsigned long *sp) {
    (void)sp;
    struct epoll_event events[8];
    struct epoll_event interest;
    int fds[2];
    char byte;
    int len;

    long ep = epoll_create1_(0);
    check(ep >= 3, "epoll_create1 returns a descriptor");

    check(pipe2_(fds) == 0, "a pipe to watch");
    interest.events = EPOLLIN;
    interest.data = 0x1234;
    check(epoll_ctl_(ep, EPOLL_CTL_ADD, fds[0], &interest) == 0, "add the reading end for EPOLLIN");
    check(epoll_ctl_(ep, EPOLL_CTL_ADD, fds[0], &interest) == -EEXIST, "adding it twice is EEXIST");
    check(epoll_pwait_(ep, events, 8, 0) == 0, "nothing is ready before anything is written");

    check(write_(fds[1], "x", 1) == 1, "write into the pipe");
    long n = epoll_pwait_(ep, events, 8, 0);
    check(n == 1, "one descriptor is ready");
    check((events[0].events & EPOLLIN) != 0, "it says it is readable");
    check(events[0].data == 0x1234, "and carries back what the registration named");
    check(epoll_pwait_(ep, events, 8, 0) == 1, "a level-triggered watch reports it again");
    check(read_(fds[0], &byte, 1) == 1 && byte == 'x', "the byte is read");
    check(epoll_pwait_(ep, events, 8, 0) == 0, "and then there is nothing to report");

    interest.events = EPOLLOUT;
    interest.data = 0x5678;
    check(epoll_ctl_(ep, EPOLL_CTL_ADD, fds[1], &interest) == 0, "add the writing end for EPOLLOUT");
    n = epoll_pwait_(ep, events, 8, 0);
    check(n == 1 && (events[0].events & EPOLLOUT) != 0 && events[0].data == 0x5678,
          "a pipe with room is writable");
    check(epoll_ctl_(ep, EPOLL_CTL_DEL, fds[1], 0) == 0, "remove it");
    check(epoll_pwait_(ep, events, 8, 0) == 0, "and it is not watched any more");
    check(epoll_ctl_(ep, EPOLL_CTL_DEL, fds[1], 0) == -ENOENT, "removing it twice is ENOENT");
    check(epoll_ctl_(ep, EPOLL_CTL_MOD, fds[1], &interest) == -ENOENT, "changing what is gone is too");

    // A timeout is a deadline, not a guarantee: nothing is ready and the call comes back with none.
    check(epoll_pwait_(ep, events, 8, 100) == 0, "a wait with nothing to report times out");

    // A datagram that arrives from the host wakes the wait that was parked on it.
    long sock = socket_(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in self;
    unsigned char *raw = (unsigned char *)&self;
    for (unsigned long i = 0; i < sizeof(self); i++) raw[i] = 0;
    self.family = AF_INET;
    raw[4] = 127;
    raw[7] = 1;
    check(sock >= 0 && bind_(sock, &self, sizeof(self)) == 0, "a datagram socket to watch");
    len = sizeof(self);
    check(getsockname_(sock, &self, &len) == 0, "it has a port");
    interest.events = EPOLLIN;
    interest.data = 0x9abc;
    check(epoll_ctl_(ep, EPOLL_CTL_ADD, sock, &interest) == 0, "watch it for reading");
    check(sendto_(sock, "ep", 2, &self, sizeof(self)) == 2, "send to itself");
    n = epoll_pwait_(ep, events, 8, 5000);
    check(n == 1 && (events[0].events & EPOLLIN) != 0 && events[0].data == 0x9abc,
          "the datagram makes the socket ready");
    check(read_(sock, &byte, 1) == 1, "and it is read");

    // A watch goes away with the descriptor it names.
    check(epoll_ctl_(ep, EPOLL_CTL_DEL, sock, 0) == 0, "stop watching the socket");
    check(close_(sock) == 0, "close it");
    check(write_(fds[1], "y", 1) == 1, "write into the pipe again");
    check(epoll_pwait_(ep, events, 8, 0) == 1, "the pipe is still watched");
    check(close_(fds[0]) == 0, "close the watched end");
    check(epoll_pwait_(ep, events, 8, 0) == 0, "a closed descriptor is not reported");

    check(epoll_pwait_(fds[1], events, 8, 0) == -EINVAL, "a descriptor that is not an epoll is EINVAL");
    check(epoll_ctl_(ep, 9, fds[1], &interest) == -EINVAL, "an operation that is not one is EINVAL");

    check(close_(fds[1]) == 0, "close the writing end");
    check(close_(ep) == 0, "close the epoll");

    put(failures ? "epoll: FAILURES\n" : "epoll: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}

/// The stack the kernel handed over, taken before any frame is pushed onto it.
__attribute__((naked)) void _start(void) {
    __asm__ volatile("mov x0, sp\n\tb run");
}
