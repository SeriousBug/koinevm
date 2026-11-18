/* Guest that sends signals to itself and to its children: what ends a process, what a parent's wait
 * status says about it, and what a disposition of the guest's own means.
 *
 * A handler cannot be run - there is no code to enter on the guest's behalf - so the dispositions
 * this checks are the two that need no handler: the default action, and an ignored signal. The
 * checks are the same on a real kernel, which is what the run compares against. */

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

#define SIGHUP 1
#define SIGINT 2
#define SIGKILL 9
#define SIGTERM 15
#define SIGIGNORE 1

#define EINVAL 22
#define ESRCH 3

static long getpid_(void) { return sc6(172, 0, 0, 0, 0, 0, 0); }
static long gettid_(void) { return sc6(178, 0, 0, 0, 0, 0, 0); }
static long kill_(long pid, long sig) { return sc6(129, pid, sig, 0, 0, 0, 0); }
static long tkill_(long tid, long sig) { return sc6(130, tid, sig, 0, 0, 0, 0); }
static long tgkill_(long tgid, long tid, long sig) { return sc6(131, tgid, tid, sig, 0, 0, 0); }
static long sigaction_(long sig, const void *act) { return sc6(134, sig, (long)act, 0, 8, 0, 0); }
static long fork_(void) { return sc6(220, 17, 0, 0, 0, 0, 0); } /* SIGCHLD */
static long wait4_(long pid, int *status) { return sc6(260, pid, (long)status, 0, 0, 0, 0); }
static long pipe2_(int *fds) { return sc6(59, (long)fds, 0, 0, 0, 0, 0); }
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

#define WIFEXITED(s) (((s) & 0x7f) == 0)
#define WEXITSTATUS(s) (((s) >> 8) & 0xff)
#define WIFSIGNALED(s) ((((s) & 0x7f) + 1) >> 1 > 0)
#define WTERMSIG(s) ((s) & 0x7f)

/// The kernel's `struct sigaction`: the handler, the flags, the restorer and the mask.
struct sigaction {
    unsigned long handler;
    unsigned long flags;
    unsigned long restorer;
    unsigned long mask;
};

static void ignore_(long sig) {
    struct sigaction act;
    act.handler = SIGIGNORE;
    act.flags = 0;
    act.restorer = 0;
    act.mask = 0;
    if (sigaction_(sig, &act) != 0) guest_exit(3);
}

/// A child that says it is up on `ready`, then waits on `go` for its parent, and exits 7. Two pipes,
/// because a child that read back the byte it wrote would never be waiting at all.
static long child_waiting(int *ready, int *go, int ignore_term) {
    char up = 'R';
    if (write_(ready[1], &up, 1) != 1) guest_exit(5);
    if (ignore_term) ignore_(SIGTERM);
    char byte;
    if (read_(go[0], &byte, 1) != 1) guest_exit(4);
    return 7;
}

void run(unsigned long *sp) {
    (void)sp;
    int status = -1;
    int ready[2];
    int go[2];
    char buf[8];

    check(kill_(getpid_(), 0) == 0, "a signal of zero to itself asks and answers");
    check(tkill_(gettid_(), 0) == 0, "and the same through the thread id");
    check(tgkill_(getpid_(), gettid_(), 0) == 0, "and through the thread group");
    check(kill_(999999, SIGTERM) == -ESRCH, "a process that is not there is ESRCH");
    check(sigaction_(9, 0) == 0, "SIGKILL can be asked about");
    {
        struct sigaction kill_act;
        kill_act.handler = SIGIGNORE;
        kill_act.flags = 0;
        kill_act.restorer = 0;
        kill_act.mask = 0;
        check(sigaction_(9, &kill_act) == -EINVAL, "and has no disposition to set");
    }

    // The default action of SIGTERM ends the process, and the parent sees which signal it was.
    check(pipe2_(ready) == 0 && pipe2_(go) == 0, "pipes to order the two processes");
    long pid = fork_();
    check(pid >= 0, "fork");
    if (pid == 0) guest_exit(child_waiting(ready, go, 0));
    check(read_(ready[0], buf, 1) == 1 && buf[0] == 'R', "the child says it is up");
    check(kill_(pid, SIGTERM) == 0, "SIGTERM to the child");
    check(wait4_(pid, &status) == pid, "its parent reaps it");
    check(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM, "the status says a signal ended it");

    // The same signal to a child that ignores it is nothing at all.
    pid = fork_();
    check(pid >= 0, "fork");
    if (pid == 0) guest_exit(child_waiting(ready, go, 1));
    check(read_(ready[0], buf, 1) == 1 && buf[0] == 'R', "the child installs its disposition and is up");
    check(kill_(pid, SIGTERM) == 0, "SIGTERM to the child that ignores it");
    check(kill_(pid, 0) == 0, "the ignored signal left it there");
    check(write_(go[1], "x", 1) == 1, "the parent lets it go on");
    status = -1;
    check(wait4_(pid, &status) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 7,
          "it ran to its own exit status");

    // SIGKILL ends a process that is waiting, which is the signal nothing can refuse.
    pid = fork_();
    check(pid >= 0, "fork");
    if (pid == 0) {
        ignore_(SIGTERM);
        guest_exit(child_waiting(ready, go, 1));
    }
    check(read_(ready[0], buf, 1) == 1, "the child is up");
    check(kill_(pid, SIGKILL) == 0, "SIGKILL to a child that ignores SIGTERM");
    // A signal to a process that has ended but not been reaped is still not a miss.
    check(kill_(pid, SIGTERM) == 0, "a zombie is there to a signal");
    status = -1;
    check(wait4_(pid, &status) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
          "SIGKILL ends it whatever it asked for");

    check(close_(ready[0]) == 0 && close_(ready[1]) == 0, "the pipes close");
    check(close_(go[0]) == 0 && close_(go[1]) == 0, "both of them");

    put(failures ? "signals: FAILURES\n" : "signals: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}

/// The stack the kernel handed over, taken before any frame is pushed onto it.
__attribute__((naked)) void _start(void) {
    __asm__ volatile("mov x0, sp\n\tb run");
}
