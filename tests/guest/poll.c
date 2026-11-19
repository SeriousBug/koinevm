/* Guest that stays inside a loop while the world moves: a signal that arrives while it spins, and a
 * child that spins for ever while its parent still gets a turn.
 *
 * Both need a preemption point, because the only other way out of a translated region is a syscall.
 * The same source on a real kernel is the oracle. */

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

#define SIGUSR1 10
#define SIGKILL 9
#define SA_SIGINFO 4

struct sigaction {
    unsigned long handler;
    unsigned long flags;
    unsigned long restorer;
    unsigned long mask;
};

static long getpid_(void) { return sc6(172, 0, 0, 0, 0, 0, 0); }
static long getppid_(void) { return sc6(173, 0, 0, 0, 0, 0, 0); }
static long kill_(long pid, long sig) { return sc6(129, pid, sig, 0, 0, 0, 0); }
static long fork_(void) { return sc6(220, 17, 0, 0, 0, 0, 0); }
static long wait4_(long pid, int *status) { return sc6(260, pid, (long)status, 0, 0, 0, 0); }
static long sigaction_(long sig, const struct sigaction *act) {
    return sc6(134, sig, (long)act, 0, 8, 0, 0);
}
static long nanosleep_(const long *req, long *rem) { return sc6(101, (long)req, (long)rem, 0, 0, 0, 0); }
static long write_(long fd, const void *buf, unsigned long n) { return sc6(64, fd, (long)buf, n, 0, 0, 0); }

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

static void restore(void) {
    register long x8 __asm__("x8") = 139;
    __asm__ volatile("svc #0" : : "r"(x8) : "memory");
    __builtin_unreachable();
}

static volatile int interrupted;

static void handler(int sig) {
    (void)sig;
    interrupted = 1;
}

/// Spin the way a program that waits on a flag does: no syscall, so nothing else can happen unless
/// the loop itself gives the machine back.
static void spin_until(int *flag) {
    while (!*flag) {
        for (volatile int i = 0; i < 1000; i++) {
        }
    }
}

void run(unsigned long *sp) {
    (void)sp;
    struct sigaction act;
    int status;

    act.handler = (unsigned long)handler;
    act.flags = 0;
    act.restorer = (unsigned long)restore;
    act.mask = 0;
    check(sigaction_(SIGUSR1, &act) == 0, "a handler for a signal that has to arrive mid-loop");

    // The child waits a moment and then sends the signal to its parent, which is inside the spin.
    long pid = fork_();
    check(pid >= 0, "fork");
    if (pid == 0) {
        long pause[2] = {0, 10000000}; // 10 ms
        nanosleep_(pause, 0);
        kill_(getppid_(), SIGUSR1);
        guest_exit(0);
    }
    long self = getpid_();
    while (!interrupted) {
        for (volatile int i = 0; i < 1000; i++) {
        }
    }
    check(interrupted == 1, "the handler ran while the guest was spinning");
    check(self == getpid_(), "and the loop went on afterwards");

    status = -1;
    check(wait4_(pid, &status) == pid, "the child is reaped");
    check((status & 0x7f) == 0 && ((status >> 8) & 0xff) == 0, "and exited with zero");

    // A child that spins for ever still has to give its parent a turn, or the parent never gets to
    // kill it.
    pid = fork_();
    check(pid >= 0, "fork");
    if (pid == 0) {
        for (;;) {
            for (volatile int i = 0; i < 1000; i++) {
            }
        }
    }
    long pause[2] = {0, 20000000}; // 20 ms, so the child holds the CPU when this returns
    nanosleep_(pause, 0);
    check(kill_(pid, SIGKILL) == 0, "the parent runs, so it can kill the spinner");
    status = -1;
    check(wait4_(pid, &status) == pid, "the spinner is reaped");
    check((status & 0x7f) == SIGKILL, "by the signal that ended it");

    put(failures ? "poll: FAILURES\n" : "poll: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}

/// The stack the kernel handed over, taken before any frame is pushed onto it.
__attribute__((naked)) void _start(void) {
    __asm__ volatile("mov x0, sp\n\tb run");
}
