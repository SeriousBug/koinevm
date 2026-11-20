/* Guest that exercises the futex ABI: a wait that times out in each of the shapes its timeout
 * comes in, the value check that answers before any wait, a wake that ends one, and the requeue
 * that moves waiters onto another word instead of waking them.
 *
 * A wait that ignores its deadline hangs, and hang is the worst failure to debug: glibc's
 * condition variables, `sem_timedwait`, and the worker pools that wait on a job all ask for one.
 * The answer a wake gives is the other half - a waiter that heard a wake reports the wait ending,
 * and only a caller whose word was already wrong hears EAGAIN.
 *
 * No native oracle can run this: the answers are the host's. So the guest asserts the properties a
 * kernel has to provide and reports each one, and tests/futex.sh requires every check to pass. */

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

struct timespec {
    long sec;
    long nsec;
};

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAIT_BITSET 9
#define FUTEX_CLOCK_REALTIME 0x100
#define FUTEX_PRIVATE 0x80
#define FUTEX_BITSET_MATCH_ANY 0xffffffffL

#define CLONE_VM 0x100
#define CLONE_FS 0x200
#define CLONE_FILES 0x400
#define CLONE_SIGHAND 0x800
#define CLONE_THREAD 0x10000

#define EAGAIN 11
#define EINVAL 22
#define ETIMEDOUT 110

#define CLOCK_MONOTONIC 1
#define CLOCK_REALTIME 0

#define STACK 16384

static long futex_wait(int *addr, long op, long want, struct timespec *timeout) {
    return sc6(98, (long)addr, op, want, (long)timeout, 0, 0);
}

static long futex_wait_bitset(int *addr, long op, long want, struct timespec *timeout) {
    return sc6(98, (long)addr, op, want, (long)timeout, 0, FUTEX_BITSET_MATCH_ANY);
}

static long futex_wake(int *addr, long n) { return sc6(98, (long)addr, FUTEX_WAKE, n, 0, 0, 0); }

/// The fourth argument of the requeue forms is a count to move, not a timespec: it is the same
/// register a plain wait's timeout arrives in.
static long futex_requeue(int *addr, int *addr2, long wake, long move) {
    return sc6(98, (long)addr, FUTEX_REQUEUE, wake, move, (long)addr2, 0);
}

static long futex_cmp_requeue(int *addr, int *addr2, long wake, long move, long expect) {
    return sc6(98, (long)addr, FUTEX_CMP_REQUEUE, wake, move, (long)addr2, expect);
}

static long now_ms(void) {
    struct timespec ts;
    if (sc6(113, CLOCK_MONOTONIC, (long)&ts, 0, 0, 0, 0) < 0) return -1;
    return ts.sec * 1000 + ts.nsec / 1000000;
}

static long clock_ms(long clock) {
    struct timespec ts;
    if (sc6(113, clock, (long)&ts, 0, 0, 0, 0) < 0) return -1;
    return ts.sec * 1000 + ts.nsec / 1000000;
}

static void sleep_ms(long ms) {
    struct timespec ts;
    ts.sec = ms / 1000;
    ts.nsec = (ms % 1000) * 1000000;
    sc6(115, (long)&ts, 0, 0, 0, 0, 0);
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

static void put_dec(long v) {
    char buf[24];
    int i = 23;
    unsigned long n = v < 0 ? (unsigned long)-v : (unsigned long)v;
    buf[i] = 0;
    do {
        buf[--i] = (char)('0' + n % 10);
        n /= 10;
    } while (n);
    if (v < 0) buf[--i] = '-';
    put(buf + i);
}

static unsigned long failures;

static void check(int cond, const char *what, long detail) {
    put(cond ? "ok   " : "FAIL ");
    put(what);
    put(" ");
    put_dec(detail);
    put("\n");
    if (!cond) failures++;
}

/// A thread of the same process. A kernel makes one out of `clone` with a stack of its own; the
/// child comes back from the same instruction with zero, which is what the function it then calls
/// is reached through.
static void clone_thread(void (*fn)(void), void *stacktop) {
    register long x0 __asm__("x0") =
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
    register long x1 __asm__("x1") = (long)stacktop;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = 0;
    register long x8 __asm__("x8") = 220;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory");
    if (x0 == 0) {
        fn();
        guest_exit(0);
    }
}

static unsigned char stack_a[STACK] __attribute__((aligned(16)));
static unsigned char stack_b[STACK] __attribute__((aligned(16)));

static volatile int word;
static volatile int word2;
static volatile int word3;
static volatile int ready;
static volatile int done_a;
static volatile int done_b;
static volatile long answer_a;
static volatile long answer_b;

/// Waiters, one per shape the test needs: a plain wait, and two that a requeue moves.
static void wait_plain(void) {
    ready++;
    answer_a = futex_wait((int *)&word, FUTEX_WAIT, 0, 0);
    done_a = 1;
}

static void wait_timed(void) {
    struct timespec ts;
    ts.sec = 10; // long enough that a wake, not the deadline, has to be the answer
    ts.nsec = 0;
    ready++;
    answer_a = futex_wait((int *)&word, FUTEX_WAIT, 0, &ts);
    done_a = 1;
}

static void wait_first(void) {
    ready++;
    answer_a = futex_wait((int *)&word2, FUTEX_WAIT, 0, 0);
    done_a = 1;
}

static void wait_second(void) {
    ready++;
    answer_b = futex_wait((int *)&word2, FUTEX_WAIT, 0, 0);
    done_b = 1;
}

static void reset(void) {
    ready = 0;
    done_a = 0;
    done_b = 0;
    answer_a = 0;
    answer_b = 0;
}

/// Wait for something the other threads do. A spin is not a busy loop here: a backward branch is
/// where a guest gives the CPU back, so another thread runs and the flag is seen.
static void run_threads(void) {
    while (!(done_a && done_b)) {
    }
}

static void spin_on(volatile int *flag, int want) {
    while (*flag < want) {
    }
}

__attribute__((used)) void _start(void) {
    long started;
    long elapsed;
    long answer;

    // A relative timeout, the shape FUTEX_WAIT takes: a wait nobody wakes ends by itself.
    {
        struct timespec ts;
        ts.sec = 0;
        ts.nsec = 120 * 1000 * 1000;
        started = now_ms();
        answer = futex_wait((int *)&word, FUTEX_WAIT, 0, &ts);
        elapsed = now_ms() - started;
        check(answer == -ETIMEDOUT, "a relative wait times out", answer);
        check(elapsed >= 100 && elapsed < 1000, "and waits about that long", elapsed);
    }

    // A timeout of zero is the shortest wait there is, and it is still a wait that ends.
    {
        struct timespec ts;
        ts.sec = 0;
        ts.nsec = 0;
        started = now_ms();
        answer = futex_wait((int *)&word, FUTEX_WAIT, 0, &ts);
        elapsed = now_ms() - started;
        check(answer == -ETIMEDOUT, "a timeout of zero ends at once", answer);
        check(elapsed < 100, "without waiting", elapsed);
    }

    // FUTEX_WAIT_BITSET takes a point on CLOCK_MONOTONIC rather than a length.
    {
        struct timespec ts;
        long target = clock_ms(CLOCK_MONOTONIC) + 120;
        ts.sec = target / 1000;
        ts.nsec = (target % 1000) * 1000000;
        started = now_ms();
        answer = futex_wait_bitset((int *)&word, FUTEX_WAIT_BITSET | FUTEX_PRIVATE, 0, &ts);
        elapsed = now_ms() - started;
        check(answer == -ETIMEDOUT, "a monotonic bitset wait times out", answer);
        check(elapsed >= 100 && elapsed < 1000, "against its own clock", elapsed);
    }

    // The same call on CLOCK_REALTIME, which is the one glibc's timed waits hand it.
    {
        struct timespec ts;
        long target = clock_ms(CLOCK_REALTIME) + 120;
        ts.sec = target / 1000;
        ts.nsec = (target % 1000) * 1000000;
        started = now_ms();
        answer = futex_wait_bitset((int *)&word,
                                   FUTEX_WAIT_BITSET | FUTEX_PRIVATE | FUTEX_CLOCK_REALTIME, 0, &ts);
        elapsed = now_ms() - started;
        check(answer == -ETIMEDOUT, "a realtime bitset wait times out", answer);
        check(elapsed >= 100 && elapsed < 1000, "against the wall clock", elapsed);
    }

    // A word that is not the value the caller expects is answered before any wait.
    {
        word = 1;
        started = now_ms();
        answer = futex_wait((int *)&word, FUTEX_WAIT, 0, 0);
        elapsed = now_ms() - started;
        check(answer == -EAGAIN, "a changed word is EAGAIN", answer);
        check(elapsed < 100, "and does not wait", elapsed);
        word = 0;
    }

    // A wait with no deadline is ended by a wake, and hears that as the wait ending.
    {
        reset();
        clone_thread(wait_plain, stack_a + STACK);
        spin_on(&ready, 1);
        word = 1;
        answer = futex_wake((int *)&word, 1);
        check(answer == 1, "a wake counts the waiter it found", answer);
        spin_on(&done_a, 1);
        check(answer_a == 0, "a woken wait answers 0, not EAGAIN", answer_a);
        word = 0;
    }

    // A wake beats a deadline that is still far off.
    {
        reset();
        clone_thread(wait_timed, stack_a + STACK);
        spin_on(&ready, 1);
        started = now_ms();
        word = 1;
        answer = futex_wake((int *)&word, 1);
        spin_on(&done_a, 1);
        elapsed = now_ms() - started;
        check(answer == 1 && answer_a == 0, "a wake ends a timed wait early", answer_a);
        check(elapsed < 1000, "long before its deadline", elapsed);
        word = 0;
    }

    // A wake with nothing waiting wakes nobody.
    answer = futex_wake((int *)&word3, 1);
    check(answer == 0, "a wake with no waiter wakes nobody", answer);

    // Requeue moves waiters onto the second word instead of waking them, and the next wake there
    // finds them.
    {
        reset();
        clone_thread(wait_first, stack_a + STACK);
        clone_thread(wait_second, stack_b + STACK);
        spin_on(&ready, 2);
        answer = futex_requeue((int *)&word2, (int *)&word3, 0, 2);
        check(answer == 2, "a requeue counts the waiters it moved", answer);
        sleep_ms(30);
        check(!done_a && !done_b, "a requeued waiter is not woken by the move", done_a + done_b);
        word3 = 1;
        answer = futex_wake((int *)&word3, 2);
        check(answer == 2, "the wake on the second word finds them", answer);
        run_threads();
        check(answer_a == 0 && answer_b == 0, "both requeued waits answer 0", answer_a + answer_b);
        word3 = 0;
    }

    // The compare form refuses to move anything when the word is not what the caller thinks.
    {
        word2 = 5;
        answer = futex_cmp_requeue((int *)&word2, (int *)&word3, 0, 1, 4);
        check(answer == -EAGAIN, "a compare requeue checks the word", answer);
        word2 = 0;
    }

    put(failures ? "futex: FAILURES\n" : "futex: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}
