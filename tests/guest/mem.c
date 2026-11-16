/* Guest that exercises the memory side of the ABI: mmap, munmap, mprotect and brk.
 *
 * No native oracle can run this: the syscall numbers and the initial map are Linux's, and the host
 * supplies them. So the guest asserts the properties a kernel has to provide and reports each one,
 * and tests/mem.sh requires every check to pass. */

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

static long brk(void *addr) { return sc6(214, (long)addr, 0, 0, 0, 0, 0); }

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define PAGE 4096

static void *mmap(void *addr, unsigned long len) {
    return (void *)sc6(222, (long)addr, (long)len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static long munmap(void *addr, unsigned long len) { return sc6(215, (long)addr, (long)len, 0, 0, 0, 0); }

static long mprotect(void *addr, unsigned long len, long prot) {
    return sc6(226, (long)addr, (long)len, prot, 0, 0, 0);
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

static void fill(unsigned char *p, unsigned long n, unsigned long seed) {
    for (unsigned long i = 0; i < n; i++) p[i] = (unsigned char)(seed + i * 7);
}

static int same(unsigned char *p, unsigned long n, unsigned long seed) {
    for (unsigned long i = 0; i < n; i++) {
        if (p[i] != (unsigned char)(seed + i * 7)) return 0;
    }
    return 1;
}

__attribute__((used)) void _start(void) {
    // brk: the break is a byte address and moving it has to make the memory usable.
    unsigned long base = (unsigned long)brk(0);
    check(base != 0 && base % 8 == 0, "brk base", base);
    unsigned long grown = (unsigned long)brk((void *)(base + 4 * PAGE));
    check(grown == base + 4 * PAGE, "brk grows", grown);
    fill((unsigned char *)base, 4 * PAGE, 3);
    check(same((unsigned char *)base, 4 * PAGE, 3), "brk memory round trip", base);

    // mmap: page aligned, zeroed, usable, and distinct from the heap.
    unsigned char *p = mmap(0, 2 * PAGE);
    check((unsigned long)p % PAGE == 0, "mmap aligned", (unsigned long)p);
    check((unsigned long)p >= grown, "mmap above the break", (unsigned long)p);
    int zero = 1;
    for (unsigned long i = 0; i < 2 * PAGE; i++) zero &= p[i] == 0;
    check(zero, "mmap is zeroed", (unsigned long)p);
    fill(p, 2 * PAGE, 11);
    check(same(p, 2 * PAGE, 11), "mmap round trip", (unsigned long)p);

    unsigned char *q = mmap(0, PAGE);
    check((unsigned long)q % PAGE == 0, "second mmap aligned", (unsigned long)q);
    check((unsigned long)q + PAGE <= (unsigned long)p || (unsigned long)q >= (unsigned long)p + 2 * PAGE,
          "mappings do not overlap", (unsigned long)q);

    // mprotect: succeeds on mapped pages, refuses a range that is not mapped.
    check(mprotect(p, 2 * PAGE, PROT_READ) == 0, "mprotect", (unsigned long)p);
    unsigned char *unmapped = (unsigned char *)((unsigned long)q + 64 * PAGE);
    check(mprotect(unmapped, PAGE, PROT_READ) == -12, "mprotect unmapped is -ENOMEM",
          (unsigned long)unmapped);

    // munmap: the range goes back, and mapping over it again gives zeroed memory.
    check(munmap(p, 2 * PAGE) == 0, "munmap", (unsigned long)p);
    unsigned char *again = mmap(0, 2 * PAGE);
    check((unsigned long)again % PAGE == 0, "mmap after munmap", (unsigned long)again);
    check((unsigned long)again + 2 * PAGE <= (unsigned long)q || (unsigned long)again >= (unsigned long)q + PAGE,
          "remap does not overlap a live mapping", (unsigned long)again);
    int clean = 1;
    for (unsigned long i = 0; i < 2 * PAGE; i++) clean &= again[i] == 0;
    check(clean, "remapped memory is zeroed", (unsigned long)again);

    // An explicit address must be honoured, as a loader relies on.
    unsigned char *hint = mmap((void *)((unsigned long)again + 8 * PAGE), PAGE);
    check(hint == again + 8 * PAGE, "mmap honours an address", (unsigned long)hint);
    unsigned char *fixed = (void *)sc6(222, (long)((unsigned long)again + 16 * PAGE), PAGE,
                                      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | 0x10, -1, 0);
    check(fixed == again + 16 * PAGE, "mmap MAP_FIXED", (unsigned long)fixed);

    put(failures ? "mem: FAILURES\n" : "mem: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}
