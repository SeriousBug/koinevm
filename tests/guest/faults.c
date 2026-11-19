/* Guest that breaks its own memory on purpose: a store to a page it made read-only, a load from one
 * it unmapped, a call into a page that is not executable, a store to the null page, and one to the
 * page table the machine keeps at 0x1000.
 *
 * Each case runs in a child, because the point of a fault is that the process does not come back.
 * The parent is what checks that the wait status says a signal ended it, which is the same answer a
 * real kernel gives the same source, so this fixture has an oracle: `tests/faults.sh` compares the
 * two. */

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

#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define PAGE 4096

#define SIGSEGV 11

static void *mmap_(void *addr, unsigned long len, long prot) {
    return (void *)sc6(222, (long)addr, (long)len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
static long munmap_(void *addr, unsigned long len) { return sc6(215, (long)addr, (long)len, 0, 0, 0, 0); }
static long mprotect_(void *addr, unsigned long len, long prot) {
    return sc6(226, (long)addr, (long)len, prot, 0, 0, 0);
}
static long fork_(void) { return sc6(220, 17, 0, 0, 0, 0, 0); }
static long wait4_(long pid, int *status) { return sc6(260, pid, (long)status, 0, 0, 0, 0); }
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

#define WIFSIGNALED(s) ((((s) & 0x7f) + 1) >> 1 > 0)
#define WIFEXITED(s) (((s) & 0x7f) == 0)
#define WEXITSTATUS(s) (((s) >> 8) & 0xff)
#define WTERMSIG(s) ((s) & 0x7f)

static unsigned char *page;
static unsigned char *gone;
static unsigned char *pair;

static void store_to_readonly(void) { *(volatile unsigned char *)page = 0xa5; }
static void load_from_unmapped(void) { (void)*(volatile unsigned char *)gone; }
static void call_into_data(void) {
    // `ret`, in a page that is mapped and writable and has no business being run.
    page[0] = 0xc0;
    page[1] = 0x03;
    page[2] = 0x5f;
    page[3] = 0xd6;
    ((void (*)(void))page)();
}
static void store_to_nothing(void) { *(volatile unsigned long *)0 = 1; }
static void store_to_page_table(void) { *(volatile unsigned long *)0x1000 = 1; }
static void store_to_no_access(void) { *(volatile unsigned char *)(pair + PAGE) = 1; }

/// The wait status of a child that runs `body`, which is a fault unless the body returns.
static int status_of(void (*body)(void)) {
    long pid = fork_();
    if (pid == 0) {
        body();
        guest_exit(0);
    }
    if (pid < 0) return -1;
    int status = -1;
    if (wait4_(pid, &status) != pid) return -1;
    return status;
}

static void expects_fault(const char *what, void (*body)(void)) {
    int status = status_of(body);
    check(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV, what);
}

void run(unsigned long *sp) {
    (void)sp;

    page = (unsigned char *)mmap_(0, PAGE, PROT_READ | PROT_WRITE);
    gone = (unsigned char *)mmap_(0, PAGE, PROT_READ | PROT_WRITE);
    pair = (unsigned char *)mmap_(0, 2 * PAGE, PROT_READ | PROT_WRITE);
    if (page == (void *)-1 || gone == (void *)-1 || pair == (void *)-1) {
        put("FAIL mmap\n");
        guest_exit(1);
    }

    // What the same page does when it is allowed: the checks below are about the permission, not
    // about the mapping.
    page[0] = 0x5a;
    check(page[0] == 0x5a, "a writable page takes a store");

    gone = (unsigned char *)munmap_(gone, PAGE) ? (unsigned char *)-1 : gone;
    mprotect_(page, PAGE, PROT_READ);
    check(page[0] == 0x5a, "a read-only page still loads");
    mprotect_(pair + PAGE, PAGE, PROT_NONE);

    expects_fault("a store to a read-only page faults", store_to_readonly);
    expects_fault("a load from an unmapped page faults", load_from_unmapped);
    expects_fault("a call into a page that is not executable faults", call_into_data);
    expects_fault("a store to the null page faults", store_to_nothing);
    expects_fault("a store to the page table faults", store_to_page_table);
    expects_fault("a store to a PROT_NONE page faults", store_to_no_access);

    // `mprotect` back to writable makes the page usable again, which is the other half of a
    // permission: it is the pages that say so, and they can say something else.
    mprotect_(page, PAGE, PROT_READ | PROT_WRITE);
    check(status_of(store_to_readonly) != -1, "a page put back to writable takes the store again");

    put(failures ? "faults: FAILURES\n" : "faults: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}

/// The stack the kernel handed over, taken before any frame is pushed onto it.
__attribute__((naked)) void _start(void) {
    __asm__ volatile("mov x0, sp\n\tb run");
}
