/* Scalar bit manipulation, the instructions string code is built from, against a native oracle.
 *
 * `rbit`/`clz` pairs are how glibc finds the first match in a 16-byte block, so a wrong bit
 * reversal shows up as a wrong byte offset rather than as a crash, which is exactly the kind of
 * bug the other fixtures miss. Every case is inline assembly over a table of bit patterns. */

#ifdef __APPLE__
extern long write(int, const void *, unsigned long);
extern void exit(int);
#define GUEST_WRITE(fd, buf, n) write((fd), (buf), (unsigned long)(n))
#define GUEST_EXIT(code) exit((int)(code))
#define GUEST_ENTRY bits_main
#else
static inline long guest_syscall3(long nr, long a, long b, long c) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
static void guest_exit(long code) {
    register long x8 __asm__("x8") = 93;
    register long x0 __asm__("x0") = code;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0) : "memory");
    __builtin_unreachable();
}
#define GUEST_WRITE(fd, buf, n) guest_syscall3(64, (fd), (long)(buf), (long)(n))
#define GUEST_EXIT(code) guest_exit(code)
#define GUEST_ENTRY _start
#endif

static char out[65536];
static int out_n;

static void put(char c) { out[out_n++] = c; }

static void put_hex(unsigned long v) {
    static const char digits[] = "0123456789abcdef";
    put('0');
    put('x');
    for (int i = 0; i < 16; i++) put(digits[(v >> (60 - 4 * i)) & 0xf]);
    put('\n');
}

static const unsigned long pat[] = {
    0x0000000000000000ul, 0xfffffffffffffffful, 0x8000000000000000ul, 0x0000000000000001ul,
    0x0123456789abcdeful, 0xfedcba9876543210ul, 0x0f0f0f0f0f0f0f0ful, 0xf0f0f0f0f0f0f0f0ul,
    0x0000000000000ff0ul, 0x0000000000008000ul, 0x0003000000000000ul, 0x00000000000000fful,
};

#define CASES(X)                                                                              \
    X(rbit, "rbit", "rbit %0, %1")                                                            \
    X(clz, "clz", "clz %0, %1")                                                               \
    X(cls, "cls", "cls %0, %1")                                                               \
    X(rev, "rev", "rev %0, %1")                                                               \
    X(rev32, "rev32", "rev32 %0, %1")                                                         \
    X(rev16, "rev16", "rev16 %0, %1")                                                         \
    X(rbit_clz, "rbit; clz", "rbit %0, %1\n clz %0, %0")                                      \
    X(rbit_clz_pair, "rbit; clz; lsr #2", "rbit %0, %1\n clz %0, %0\n lsr %0, %0, #2")

#define DEF(name, tag, body)                                                                  \
    __attribute__((noinline)) static unsigned long b_##name(unsigned long v) {                \
        unsigned long r;                                                                      \
        __asm__ volatile(body : "=r"(r) : "r"(v) : "cc");                                     \
        return r;                                                                             \
    }

#define ENTRY(name, tag, body) {b_##name, tag},

CASES(DEF)

struct case_ {
    unsigned long (*fn)(unsigned long);
    const char *name;
};

static const struct case_ cases[] = {CASES(ENTRY)};

/* Every byte boundary, so a reversal that mixes up two of them shows up. */
static unsigned long pattern(int i) {
    if (i < (int)(sizeof pat / sizeof pat[0])) return pat[i];
    return 1ul << i;
}

__attribute__((used)) void GUEST_ENTRY(void) {
    for (unsigned long c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        for (int i = 0; i < 76; i++) {
            char tag = (char)cases[c].name[0];
            put(tag);
            put(' ');
            put_hex(pattern(i));
            put_hex(cases[c].fn(pattern(i)));
        }
    }
    GUEST_WRITE(1, out, out_n);
    GUEST_EXIT(0);
}
