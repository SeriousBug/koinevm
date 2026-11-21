/* Guest whose signal handler is its own code: a plain handler and an `SA_SIGINFO` one, a signal
 * that is blocked and taken when it is unblocked, and the mask a handler runs under.
 *
 * A handler is entered by the kernel writing a frame on the guest's stack and starting the guest at
 * the handler, and it returns through the restorer that frame names, which calls `rt_sigreturn`.
 * Both sides are this machine's, so the same source on a real kernel is the oracle. */

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
#define SIGUSR2 12
#define SA_SIGINFO 4

#define SIG_BLOCK 0
#define SIG_UNBLOCK 1

/// The kernel's `struct sigaction`: the handler, the flags, the restorer and the mask.
struct sigaction {
    unsigned long handler;
    unsigned long flags;
    unsigned long restorer;
    unsigned long mask;
};

/// The first words of `siginfo`, which is what an `SA_SIGINFO` handler is given.
struct siginfo {
    int signo;
    int errno_;
    int code;
    int pad;
    long from;
};

static long getpid_(void) { return sc6(172, 0, 0, 0, 0, 0, 0); }
static long kill_(long pid, long sig) { return sc6(129, pid, sig, 0, 0, 0, 0); }
static long sigaction_(long sig, const struct sigaction *act, struct sigaction *old) {
    return sc6(134, sig, (long)act, (long)old, 8, 0, 0);
}
static long sigprocmask_(long how, const unsigned long *set, unsigned long *old) {
    return sc6(135, how, (long)set, (long)old, 8, 0, 0);
}
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

/// What a handler returns into, which is the `rt_sigreturn` a libc's `__restore_rt` performs:
/// without one, the handler's own `ret` has nowhere to go.
static void restore(void) {
    register long x8 __asm__("x8") = 139;
    __asm__ volatile("svc #0" : : "r"(x8) : "memory");
    __builtin_unreachable();
}

static volatile int ran;
static volatile int got_signo;
static volatile int got_code;
static volatile long got_from;

static void handler(int sig) {
    ran++;
    got_signo = sig;
}

static void info_handler(int sig, struct siginfo *info, void *ucontext) {
    (void)ucontext;
    ran++;
    got_signo = sig;
    got_code = info->code;
    got_from = info->from;
}

/// The mask a signal would find in force, which is what a handler's own mask has to combine with.
static unsigned long current_mask(void) {
    unsigned long mask = 0;
    if (sigprocmask_(SIG_BLOCK, 0, &mask) != 0) guest_exit(3);
    return mask;
}

/// The bit of a signal in a `sigset_t`.
static unsigned long bit_of(long sig) { return 1ul << (sig - 1); }

#define SIG_SETMASK 2

#define CLONE_VM 0x00000100
#define CLONE_FS 0x00000200
#define CLONE_FILES 0x00000400
#define CLONE_SIGHAND 0x00000800
#define CLONE_THREAD 0x00010000
#define CLONE_SYSVSEM 0x00040000

/// A second thread of this process, started on a stack of its own at `fn`. The child comes back
/// from the `svc` with zero in x0 and the one that made the call with the new thread's id, so the
/// branch after it is what tells the two apart.
static long clone_thread(void (*fn)(void)) {
    static unsigned char stack[16384] __attribute__((aligned(16)));
    register long x8 __asm__("x8") = 220;
    register long x0 __asm__("x0") =
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
    register long x1 __asm__("x1") = (long)(stack + sizeof stack);
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = 0;
    register long x9 __asm__("x9") = (long)fn;
    __asm__ volatile("svc #0\n\tcbnz x0, 1f\n\tblr x9\n1:"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x9)
                     : "memory");
    return x0;
}

static volatile unsigned long child_mask;
static volatile int child_done;

static void blocks_everything(void) {
    unsigned long all = ~0ul;
    sigprocmask_(SIG_SETMASK, &all, 0);
    child_mask = current_mask();
    child_done = 1;
    guest_exit(0);
}

/// The guest gives the CPU back at a poll, so spinning here is how one thread waits for another.
static void join_child(void) {
    while (!child_done) {
    }
}

void run(unsigned long *sp) {
    (void)sp;
    struct sigaction act;
    struct sigaction old;

    // A handler is guest code, and the signal that reaches it is the one a `kill` sent.
    act.handler = (unsigned long)handler;
    act.flags = 0;
    act.restorer = (unsigned long)restore;
    act.mask = 0;
    check(sigaction_(SIGUSR1, &act, &old) == 0, "a handler is installed");
    check(sigaction_(SIGUSR1, 0, &old) == 0 && old.handler == (unsigned long)handler,
          "and reads back as the same one");

    ran = 0;
    check(kill_(getpid_(), SIGUSR1) == 0, "a signal sent to itself is taken");
    check(ran == 1, "the handler ran");
    check(got_signo == SIGUSR1, "with the signal number in the first argument");

    // The handler returns and the guest goes on where it was, so a call after it still returns
    // what it should: the frame is the stack, not a copy of the machine.
    ran = 0;
    check(kill_(getpid_(), SIGUSR1) == 0 && ran == 1, "and again on the next one");

    // A blocked signal waits instead of running, and runs when the block is lifted.
    unsigned long set = bit_of(SIGUSR1);
    unsigned long before = current_mask();
    check(sigprocmask_(SIG_BLOCK, &set, 0) == 0, "a signal can be blocked");
    ran = 0;
    check(kill_(getpid_(), SIGUSR1) == 0, "a blocked signal is accepted");
    check(ran == 0, "and does not run while it is blocked");
    check((current_mask() & set) != 0, "the block is in the mask");
    check(sigprocmask_(SIG_UNBLOCK, &set, 0) == 0, "unblocking it");
    check(ran == 1, "runs it, at the first moment the guest is at a signal's mercy");
    check((current_mask() & set) == 0, "and leaves the mask as it was apart from the block");
    check((before & set) == 0, "which was clear to begin with");

    // `SA_SIGINFO` hands the handler the reason for the signal, which for a `kill` is who sent it.
    act.handler = (unsigned long)info_handler;
    act.flags = SA_SIGINFO;
    act.restorer = (unsigned long)restore;
    act.mask = 0;
    check(sigaction_(SIGUSR2, &act, 0) == 0, "a three-argument handler is installed");
    ran = 0;
    got_code = -1;
    got_from = -1;
    check(kill_(getpid_(), SIGUSR2) == 0, "a signal reaches it");
    check(ran == 1, "the three-argument handler ran");
    check(got_signo == SIGUSR2, "with the signal number");
    check(got_from == getpid_(), "and the sender it came from");

    // A mask belongs to the thread that set it, which is what `pthread_sigmask` is for. A library
    // blocks every signal around a `clone` and unblocks in the thread that made the call, so a
    // thread that blocks them all for itself must not leave the process deaf to them.
    unsigned long mine = current_mask();
    check(clone_thread(blocks_everything) > 0, "a second thread is started");
    join_child();
    check((child_mask & bit_of(SIGUSR1)) != 0, "which has the signal blocked for itself");
    check(current_mask() == mine, "and this thread's mask is as it was");
    ran = 0;
    check(kill_(getpid_(), SIGUSR1) == 0, "the signal still reaches this thread");
    check(ran == 1, "and the handler runs");

    put(failures ? "sighandler: FAILURES\n" : "sighandler: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}

/// The stack the kernel handed over, taken before any frame is pushed onto it.
__attribute__((naked)) void _start(void) {
    __asm__ volatile("mov x0, sp\n\tb run");
}
