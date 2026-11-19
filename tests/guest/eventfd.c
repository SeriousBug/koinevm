/* Guest that counts wakeups through eventfd: the counter a read takes whole, the semaphore one that
 * takes a wakeup at a time, the two lengths that are errors, and a read that blocks until another
 * process adds to it.
 *
 * `libuv` starts the async handle of a loop with one of these, and a program whose descriptor was
 * never made - because the syscall was not there - finds out much later, on a thread, as a load
 * from a null pointer. The checks are the same on a real kernel. */

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

#define EFD_SEMAPHORE 1
#define EFD_NONBLOCK 0x800

#define EAGAIN 11
#define EINVAL 22

#define POLLIN 0x001

struct pollfd {
    int fd;
    short events;
    short revents;
};

struct timespec {
    long sec;
    long nsec;
};

static long eventfd2_(long initial, long flags) { return sc6(290, initial, flags, 0, 0, 0, 0); }
static long write_(long fd, const void *buf, unsigned long n) { return sc6(64, fd, (long)buf, n, 0, 0, 0); }
static long read_(long fd, void *buf, unsigned long n) { return sc6(63, fd, (long)buf, n, 0, 0, 0); }
static long close_(long fd) { return sc6(57, fd, 0, 0, 0, 0, 0); }
static long ppoll_(struct pollfd *fds, long n, long ms) {
    struct timespec ts;
    ts.sec = ms / 1000;
    ts.nsec = (ms % 1000) * 1000000;
    return sc6(73, (long)fds, n, (long)&ts, 0, 0, 0);
}
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

static void sleep_ms(long ms) {
    struct timespec ts;
    ts.sec = ms / 1000;
    ts.nsec = (ms % 1000) * 1000000;
    sc6(101, (long)&ts, 0, 0, 0, 0, 0);
}

void run(unsigned long *sp) {
    (void)sp;
    unsigned long count = 0;
    struct pollfd one;

    long fd = eventfd2_(0, EFD_NONBLOCK);
    check(fd >= 3, "eventfd2 makes a descriptor");
    check(read_(fd, &count, 8) == -EAGAIN, "an empty one has nothing to read");
    one.fd = (int)fd;
    one.events = POLLIN;
    one.revents = 0;
    check(ppoll_(&one, 1, 0) == 0, "and poll says so");

    unsigned long three = 3;
    check(write_(fd, &three, 8) == 8, "a write of eight bytes is a count");
    one.revents = 0;
    check(ppoll_(&one, 1, 0) == 1 && (one.revents & POLLIN) != 0, "poll sees the count");
    check(read_(fd, &count, 8) == 8 && count == 3, "a read takes the whole of it");
    count = 0;
    check(read_(fd, &count, 8) == -EAGAIN, "and clears it");

    long sem = eventfd2_(2, EFD_SEMAPHORE | EFD_NONBLOCK);
    check(sem >= 3, "a semaphore one");
    check(read_(sem, &count, 8) == 8 && count == 1, "takes one of its two");
    check(read_(sem, &count, 8) == 8 && count == 1, "takes the other");
    check(read_(sem, &count, 8) == -EAGAIN, "and then there is nothing left");

    check(write_(fd, &three, 4) == -EINVAL, "a write shorter than eight bytes is EINVAL");
    check(read_(fd, &count, 4) == -EINVAL, "a read of fewer than eight is too");

    // A read with nothing in the counter parks, and another process's write answers it.
    long blk = eventfd2_(0, 0);
    check(blk >= 3, "one without EFD_NONBLOCK");
    count = 3;
    long pid = fork_();
    check(pid >= 0, "fork");
    if (pid == 0) {
        sleep_ms(50);
        write_(blk, &three, 8);
        guest_exit(0);
    }
    long got = read_(blk, &count, 8);
    check(got == 8 && count == 3, "another process's write answers a blocking read");
    int status = -1;
    check(wait4_(pid, &status) == pid && status == 0, "the writer exited with zero");

    check(close_(fd) == 0 && close_(sem) == 0 && close_(blk) == 0, "close all three");
    put(failures ? "eventfd: FAILURES\n" : "eventfd: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}

/// The stack the kernel handed over, taken before any frame is pushed onto it.
__attribute__((naked)) void _start(void) {
    __asm__ volatile("mov x0, sp\n\tb run");
}
