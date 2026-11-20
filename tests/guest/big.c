/* Guest that lives in more than one wasm memory: the address space past the first 4 GiB is a
 * second memory, so an address there is a different instruction sequence than one below it.
 *
 * Every access width goes through that boundary here - the byte, half, word and doubleword forms
 * and one 128-bit load and store - along with the mapping that put them there: the address the
 * guest asked for is the address it gets, a page given back reads as zeros, and what `sysinfo`
 * reports is the whole of the space, not the first memory of it.
 *
 * There is no native oracle: the answer is the host's. So the guest asserts the properties and
 * tests/big.sh requires every check to pass, translating with an address space of 8 GiB. */

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
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MADV_DONTNEED 4
#define PAGE 4096

/// The first byte of the second memory: the smallest address that is not in the first one.
#define CHUNK 0x100000000UL
#define HINT (CHUNK + 0x100000UL)

static void *mmap(void *addr, unsigned long len) {
    return (void *)sc6(222, (long)addr, (long)len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static long munmap(void *addr, unsigned long len) { return sc6(215, (long)addr, (long)len, 0, 0, 0, 0); }

static long madvise(void *addr, unsigned long len, long advice) {
    return sc6(233, (long)addr, (long)len, advice, 0, 0, 0);
}

static long sysinfo(void *buf) { return sc6(179, (long)buf, 0, 0, 0, 0, 0); }


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

static unsigned long field64(const unsigned char *buf, int off) {
    unsigned long v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | buf[off + i];
    return v;
}

#define CLOCK_MONOTONIC 1

static void clock_gettime(long clock, void *ts) { sc6(113, clock, (long)ts, 0, 0, 0, 0); }

/// Nanoseconds since the clock's origin, from the `struct timespec` the call fills in.
static unsigned long now_ns(void) {
    unsigned char ts[16];
    clock_gettime(CLOCK_MONOTONIC, ts);
    return field64(ts, 0) * 1000000000UL + field64(ts, 8);
}

__attribute__((used)) void _start(void) {
    // A mapping asked for above the first memory gets the address it named, which is what a runtime
    // that reserves a region of its own depends on.
    unsigned char *p = mmap((void *)HINT, 2 * PAGE);
    check(p == (unsigned char *)HINT, "mmap above 4 GiB honours the address", (unsigned long)p);
    check((unsigned long)p >= CHUNK, "and the address is in the second memory", (unsigned long)p);

    // Every width, at an address the inline path cannot serve.
    *(volatile unsigned char *)(p + 1) = 0x5a;
    *(volatile unsigned short *)(p + 2) = 0x1234;
    *(volatile unsigned int *)(p + 8) = 0xdeadbeef;
    *(volatile unsigned long *)(p + 16) = 0x0123456789abcdefUL;
    check(*(volatile unsigned char *)(p + 1) == 0x5a, "byte round trip above 4 GiB", p[1]);
    check(*(volatile unsigned short *)(p + 2) == 0x1234, "half round trip", *(unsigned short *)(p + 2));
    check(*(volatile unsigned int *)(p + 8) == 0xdeadbeef, "word round trip", *(unsigned int *)(p + 8));
    check(*(volatile unsigned long *)(p + 16) == 0x0123456789abcdefUL, "doubleword round trip",
          *(unsigned long *)(p + 16));

    // The 128-bit forms are the widest access the translator has, and they are their own helpers.
    unsigned long *q = (unsigned long *)(p + 64);
    unsigned long *r = (unsigned long *)(p + PAGE);
    *(unsigned long *)(p + 64) = 0x1111111111111111UL;
    *(unsigned long *)(p + 72) = 0x2222222222222222UL;
    __asm__ volatile("ldr q1, [%0]\n\tstr q1, [%1]" : : "r"(q), "r"(r) : "v1", "memory");
    check(*(unsigned long *)(p + PAGE) == 0x1111111111111111UL, "vector store above 4 GiB",
          *(unsigned long *)(p + PAGE));
    check(*(unsigned long *)(p + PAGE + 8) == 0x2222222222222222UL, "and its second half",
          *(unsigned long *)(p + PAGE + 8));

    // The mapping below the boundary is still the first memory, and both are the same address space
    // to a program: a copy between them is an ordinary load and store.
    unsigned char *low = mmap((void *)0x50000000UL, PAGE);
    check((unsigned long)low == 0x50000000UL, "mmap below 4 GiB honours the address",
          (unsigned long)low);
    for (int i = 0; i < PAGE; i++) low[i] = (unsigned char)(i * 7);
    for (int i = 0; i < PAGE; i++) *(volatile unsigned char *)(p + PAGE * 2 - PAGE + i) = low[i];
    int same = 1;
    for (int i = 0; i < PAGE; i++) same &= *(volatile unsigned char *)(p + PAGE + i) == low[i];
    check(same, "a copy across the boundary is a copy", (unsigned long)low);

    // A page given back reads as a fresh mapping of the same thing, whichever memory it is in.
    check(madvise(p, 2 * PAGE, MADV_DONTNEED) == 0, "madvise above 4 GiB", (unsigned long)p);
    int zero = 1;
    for (unsigned long i = 0; i < 2 * PAGE; i++) zero &= p[i] == 0;
    check(zero, "a discarded page above 4 GiB reads as zeros", (unsigned long)p);

    // The whole space comes back, not the first memory of it: an address space of 8 GiB is more
    // than a program that reads the machine can be told less of.
    unsigned char info[112];
    check(sysinfo(info) == 0, "sysinfo", (unsigned long)info);
    unsigned long total = field64(info, 32);
    check(total > CHUNK, "sysinfo counts every memory", total);
    check(field64(info, 40) <= total, "and the free part is inside it", field64(info, 40));

    // A mapping bigger than one memory: the address space is a sequence of them, and a run of
    // addresses that crosses from one into the next is one mapping to the program that asked for
    // it. Every access at the seam has to work, including one that starts in one memory and ends
    // in the other - 16 bytes at 8 GiB - 8, an 8-byte load at 8 GiB - 4, and a copy across it.
    unsigned long wide_len = CHUNK + CHUNK / 4;
    unsigned char *wide = mmap((void *)(2 * CHUNK), wide_len);
    check(wide == (unsigned char *)(2 * CHUNK), "a mapping bigger than one memory", (unsigned long)wide);
    unsigned long base = (unsigned long)wide;
    check(base / CHUNK != (base + wide_len - 1) / CHUNK, "and it covers a seam",
          (base + wide_len - 1) / CHUNK - base / CHUNK);
    unsigned long seam = (base / CHUNK + 1) * CHUNK;
    *(volatile unsigned long *)(seam - 4) = 0x1122334455667788UL;
    check(*(volatile unsigned long *)(seam - 4) == 0x1122334455667788UL,
          "a store that starts in one memory and ends in the next", *(unsigned long *)(seam - 4));
    __asm__ volatile("movi v2.2d, #0\n\t"
                     "mov v2.d[0], %1\n\t"
                     "mov v2.d[1], %2\n\t"
                     "str q2, [%0]\n\t"
                     "ldr q3, [%0]"
                     : : "r"(seam - 8), "r"(0x0011223344556677UL), "r"(0x8899aabbccddeeffUL)
                     : "v2", "v3", "memory");
    check(*(volatile unsigned long *)(seam - 8) == 0x0011223344556677UL &&
              *(volatile unsigned long *)seam == 0x8899aabbccddeeffUL,
          "a 128-bit store across the seam", *(unsigned long *)(seam - 8));
    for (int i = 0; i < 32; i++) *(volatile unsigned char *)(seam + 16 + i) = (unsigned char)(0x40 + i);
    for (int i = 0; i < 32; i++) *(volatile unsigned char *)(seam - 16 + i) =
        *(volatile unsigned char *)(seam + 16 + i);
    int copied = 1;
    for (int i = 0; i < 32; i++)
        copied &= *(volatile unsigned char *)(seam - 16 + i) == (unsigned char)(0x40 + i);
    check(copied, "a copy that crosses the seam", seam);
    check(*(volatile unsigned long *)(base + wide_len - 8) == 0,
          "and the far end of the mapping is there and zero", *(unsigned long *)(base + wide_len - 8));
    // Freeing it is work per page that holds a translation, not per word the range covers: a range
    // of gigabytes that is walked word by word takes longer than the program that freed it lives.
    unsigned long freed_at = now_ns();
    check(munmap(wide, wide_len) == 0, "munmap of a range that crosses a boundary", base);
    unsigned long freed_in = now_ns() - freed_at;
    check(freed_in < 5000000000UL, "and freeing it is not a walk over every word (us)", freed_in / 1000);

    // Unmapping and mapping again above the boundary works the same way.
    check(munmap(p, 2 * PAGE) == 0, "munmap above 4 GiB", (unsigned long)p);
    unsigned char *again = mmap((void *)HINT, 2 * PAGE);
    check(again == (unsigned char *)HINT, "the range comes back where it was", (unsigned long)again);

    put(failures ? "big: FAILURES\n" : "big: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}
