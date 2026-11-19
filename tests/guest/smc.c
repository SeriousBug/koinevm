/* Guest that writes an instruction into its own text and runs it: the page is made writable, the
 * words of a function are replaced, and the call has to run the new code rather than the
 * translation of the old one.
 *
 * The instruction cache is coherent on the machines this runs on, so there is no `dc`/`ic` sequence
 * here; a kernel on hardware that is not coherent would need one, and this machine has no
 * instruction for a guest to flush with either. */

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

#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define PAGE 4096

static long mprotect_(void *addr, unsigned long len, long prot) {
    return sc6(226, (long)addr, (long)len, prot, 0, 0, 0);
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

/// The cache maintenance a guest does after writing code: data out, barrier, instruction in, barrier.
static void flush(void *start, unsigned long len) {
    unsigned long ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    unsigned long dline = 4ul << ((ctr >> 16) & 0xf);
    unsigned long iline = 4ul << (ctr & 0xf);
    for (unsigned long p = (unsigned long)start; p < (unsigned long)start + len; p += dline) {
        __asm__ volatile("dc cvau, %0" ::"r"(p) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    for (unsigned long p = (unsigned long)start; p < (unsigned long)start + len; p += iline) {
        __asm__ volatile("ic ivau, %0" ::"r"(p) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    __asm__ volatile("isb" ::: "memory");
}

static int failures;

static void check(int ok, const char *what) {
    put(ok ? "ok   " : "FAIL ");
    put(what);
    put("\n");
    if (!ok) failures++;
}

static volatile int seed = 1;

/// Long enough to be a translation of its own, short enough to overwrite in one page, and reading
/// something the compiler cannot fold away, so the call is a real one.
__attribute__((noinline)) int patchme(void) {
    return seed;
}

void run(unsigned long *sp) {
    (void)sp;
    unsigned int *code = (unsigned int *)(unsigned long)patchme;
    unsigned long page = (unsigned long)patchme & ~(unsigned long)(PAGE - 1);

    check(patchme() == 1, "the function as compiled");

    // Make its page writable, which is what tells this machine the translation of it is stale.
    check(mprotect_((void *)page, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC) == 0, "the page is made writable");

    // `mov w0, #42` then `ret`, over the first two instructions of the function.
    code[0] = 0x52800540;
    code[1] = 0xd65f03c0;
    __asm__ volatile("" ::: "memory");
    flush(code, 8);

    check(patchme() == 42, "the patched function is what runs");
    check(patchme() == 42, "and keeps running");

    // The page is put back the way the loader left it, which must not resurrect the old code.
    check(mprotect_((void *)page, PAGE, PROT_READ | PROT_EXEC) == 0, "and the page goes back to read only");
    check(patchme() == 42, "the patched code is still what runs");

    put(failures ? "smc: FAILURES\n" : "smc: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}

/// The stack the kernel handed over, taken before any frame is pushed onto it.
__attribute__((naked)) void _start(void) {
    __asm__ volatile("mov x0, sp\n\tb run");
}
