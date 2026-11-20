/* Guest that asks what running has cost it: `getrusage` for the process, a thread, the children and
 * a reaped child, and `times` for the same accounting in ticks.
 *
 * No native oracle can be compared against this - a real kernel's counters are its own - so the
 * guest asserts what a kernel owes it: that the counters move when it works, that the split stays
 * inside the wall clock, and that a child's time reaches its parent when it is waited for.
 * tests/rusage.sh requires every check to pass. */

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

struct timeval {
    long tv_sec;
    long tv_usec;
};

struct rusage {
    struct timeval ru_utime;
    struct timeval ru_stime;
    long rest[14];
};

struct tms {
    long tms_utime;
    long tms_stime;
    long tms_cutime;
    long tms_cstime;
};

struct timespec {
    long tv_sec;
    long tv_nsec;
};

#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN (-1)
#define RUSAGE_THREAD 1
#define CLOCK_MONOTONIC 1
#define SIGCHLD 17
#define EFAULT 14
#define EINVAL 22

static long getrusage_(int who, struct rusage *ru) { return sc6(165, who, (long)ru, 0, 0, 0, 0); }
static long times_(struct tms *buf) { return sc6(153, (long)buf, 0, 0, 0, 0, 0); }
static long fork_(void) { return sc6(220, SIGCHLD, 0, 0, 0, 0, 0); }
static long wait4_(long pid, int *status, struct rusage *ru) {
    return sc6(260, pid, (long)status, 0, (long)ru, 0, 0);
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

static void put(const char *s) { sc6(64, 1, (long)s, (long)str_len(s), 0, 0, 0); }

static void put_hex(unsigned long v) {
    static const char digits[] = "0123456789abcdef";
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; i++) buf[2 + i] = digits[(v >> (60 - 4 * i)) & 0xf];
    buf[18] = 0;
    put(buf);
}

static unsigned long failures;

static void check(int cond, const char *what, unsigned long detail) {
    put(cond ? "ok   " : "FAIL ");
    put(what);
    put(" ");
    put_hex(detail);
    put("\n");
    if (!cond) failures++;
}

static unsigned long usec(const struct timeval *tv) {
    return (unsigned long)tv->tv_sec * 1000000UL + (unsigned long)tv->tv_usec;
}

static unsigned long now_us(void) {
    struct timespec ts;
    if (sc6(113, CLOCK_MONOTONIC, (long)&ts, 0, 0, 0, 0) != 0) return 0;
    return (unsigned long)ts.tv_sec * 1000000UL + (unsigned long)ts.tv_nsec / 1000;
}

/* Enough work that the counters move by several of the 10 ms ticks `times` reports, in a program
 * that is translated one instruction at a time. */
#define ROUNDS 40000000UL

static void burn(unsigned long rounds) {
    volatile unsigned long sink = 1;
    for (unsigned long i = 0; i < rounds; i++) sink = sink * 3 + (i ^ (sink >> 5));
}

static void report_self(void) {
    struct rusage before, after;
    struct tms t0, t1;
    // The wall clock covers everything the two readings are subtracted over, so a busy guest cannot
    // have spent more of it than has passed.
    unsigned long wall = now_us();
    check(getrusage_(RUSAGE_SELF, &before) == 0, "getrusage self", 0);
    long start = times_(&t0);
    check(start >= 0, "times returns a count", (unsigned long)start);
    check(times_(0) >= 0, "times takes no buffer", 0);

    burn(ROUNDS);

    check(getrusage_(RUSAGE_SELF, &after) == 0, "getrusage self after work", 0);
    wall = now_us() - wall;
    unsigned long user = usec(&after.ru_utime) - usec(&before.ru_utime);
    unsigned long sys = usec(&after.ru_stime) - usec(&before.ru_stime);
    check(user > 0, "self user time is not zero", user);
    check(user + sys <= wall + 1000, "user and sys are inside the wall clock", user + sys);

    long end = times_(&t1);
    check(end >= start, "the tick count only goes forward", (unsigned long)end);
    check(t1.tms_utime > t0.tms_utime, "times reports the user time in ticks",
          (unsigned long)(t1.tms_utime - t0.tms_utime));
    check(t1.tms_stime >= t0.tms_stime, "times reports the system time in ticks",
          (unsigned long)(t1.tms_stime - t0.tms_stime));
}

static void report_thread(void) {
    struct rusage thread, self;
    check(getrusage_(RUSAGE_THREAD, &thread) == 0, "getrusage thread", 0);
    check(getrusage_(RUSAGE_SELF, &self) == 0, "getrusage self for the thread comparison", 0);
    check(usec(&thread.ru_utime) > 0, "thread user time is not zero", usec(&thread.ru_utime));
    check(usec(&thread.ru_utime) <= usec(&self.ru_utime), "a thread is inside its process",
          usec(&thread.ru_utime));
}

static void report_children(void) {
    struct rusage before, after, waited;
    check(getrusage_(RUSAGE_CHILDREN, &before) == 0, "getrusage children", 0);

    long pid = fork_();
    if (pid == 0) {
        burn(ROUNDS / 2);
        guest_exit(0);
    }
    check(pid > 0, "fork", (unsigned long)pid);

    int status = 0;
    check(wait4_(pid, &status, &waited) == pid, "wait4", (unsigned long)pid);
    unsigned long child = usec(&waited.ru_utime);
    check(child > 0, "wait4 answers the child's own time", child);
    check(status == 0, "the child exited cleanly", (unsigned long)status);

    check(getrusage_(RUSAGE_CHILDREN, &after) == 0, "getrusage children after the wait", 0);
    unsigned long added = usec(&after.ru_utime) - usec(&before.ru_utime);
    check(added == child, "a reaped child's time is its parent's children time", added);
}

static void report_errors(void) {
    struct rusage ru;
    check(getrusage_(7, &ru) == -EINVAL, "an unknown resource is -EINVAL", 7);
    check(getrusage_(RUSAGE_SELF, 0) == -EFAULT, "a null rusage is -EFAULT", 0);
}

/* What the counters have added up to over the whole run, which the wall clock the guest reads has to
 * bound: a reading taken inside the work must not charge the same time twice. */
static void report_total(unsigned long started) {
    struct rusage self;
    check(getrusage_(RUSAGE_SELF, &self) == 0, "getrusage self at the end", 0);
    unsigned long wall = now_us() - started;
    unsigned long total = usec(&self.ru_utime) + usec(&self.ru_stime);
    check(total <= wall + 1000, "the totals stay inside the wall clock", total);
}

__attribute__((used)) void _start(void) {
    unsigned long started = now_us();
    report_self();
    report_thread();
    report_children();
    report_errors();
    report_total(started);
    put(failures ? "rusage: FAILURES\n" : "rusage: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}
