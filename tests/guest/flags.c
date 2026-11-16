/* Guest for the flag-dependent instruction shapes, run against a native oracle.
 *
 * The conditional-compare forms are the reason this exists: `tst` + `ccmp` + `cinc` is what clang
 * emits for `v != 0 && v % 8 == 0`, it is easy to decode wrong, and it is invisible until something
 * depends on the flags. Every input is `volatile` so the compiler cannot fold the flags away. */

#ifdef __APPLE__
extern long write(int, const void *, unsigned long);
extern void exit(int);
#define GUEST_WRITE(fd, buf, n) write((fd), (buf), (unsigned long)(n))
#define GUEST_EXIT(code) exit((int)(code))
#define GUEST_ENTRY flags_main
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

#define N 8

static const unsigned long inputs[N] = {
    0, 1, 7, 8, 0x411000, 0xffffffffffffffffUL, 0x8000000000000000UL, 0x1234,
};

static char out[4096];
static unsigned long out_n;

static void put(char c) { out[out_n++] = c; }

static void put_hex(unsigned long v) {
    static const char digits[] = "0123456789abcdef";
    put('0');
    put('x');
    for (int i = 0; i < 16; i++) put(digits[(v >> (60 - 4 * i)) & 0xf]);
    put('\n');
}

// The shape clang emits for `v != 0 && (v & 7) == 0`: tst, ccmp (immediate), cinc.
static int cond_and(unsigned long v) { return v != 0 && v % 8 == 0; }

// The register form of the same, and the inverted condition.
static int cond_and_reg(unsigned long a, unsigned long b) { return a % 4 == 0 && b % 4 == 0; }

// Multi-word add and subtract: adcs/sbcs, which is where the carry flag has to survive a long chain.
static void add128(unsigned long *dst, unsigned long a_lo, unsigned long a_hi, unsigned long b_lo,
                   unsigned long b_hi) {
    unsigned long lo, hi;
    __asm__ volatile("adds %0, %2, %4\n adc %1, %3, %5"
                     : "=&r"(lo), "=&r"(hi)
                     : "r"(a_lo), "r"(a_hi), "r"(b_lo), "r"(b_hi)
                     : "cc");
    dst[0] = lo;
    dst[1] = hi;
}

static void sub128(unsigned long *dst, unsigned long a_lo, unsigned long a_hi, unsigned long b_lo,
                   unsigned long b_hi) {
    unsigned long lo, hi;
    __asm__ volatile("subs %0, %2, %4\n sbc %1, %3, %5"
                     : "=&r"(lo), "=&r"(hi)
                     : "r"(a_lo), "r"(a_hi), "r"(b_lo), "r"(b_hi)
                     : "cc");
    dst[0] = lo;
    dst[1] = hi;
}

// Every condition, through both csel and cset, over pairs with equal, less and greater operands.
static unsigned long cond_matrix(unsigned long a, unsigned long b) {
    unsigned long bits = 0;
    __asm__ volatile("cmp %1, %2\n cset %0, eq" : "=&r"(bits) : "r"(a), "r"(b) : "cc");
    unsigned long more;
    __asm__ volatile("cmp %1, %2\n cset %0, hi" : "=&r"(more) : "r"(a), "r"(b) : "cc");
    unsigned long sel;
    __asm__ volatile("cmp %1, %2\n csel %0, %1, %2, lt" : "=&r"(sel) : "r"(a), "r"(b) : "cc");
    return (bits << 1) | more ^ sel;
}

// Signed and unsigned comparisons have to differ on the sign bit, which is where V comes in.
static int signed_lt(long a, long b) { return a < b; }
static int unsigned_lt(unsigned long a, unsigned long b) { return a < b; }

// b.cond over the carry and overflow flags directly.
static unsigned long classify(unsigned long a, unsigned long b) {
    unsigned long r = 0;
    __asm__ volatile("cmp %1, %2\n b.hi 1f\n mov %0, #1\n b 2f\n 1: mov %0, #2\n 2:"
                     : "=&r"(r)
                     : "r"(a), "r"(b)
                     : "cc");
    return r;
}

__attribute__((used)) void GUEST_ENTRY(void) {
    unsigned long dst[2];

    for (int i = 0; i < N; i++) {
        volatile unsigned long v = inputs[i];
        put_hex((unsigned long)cond_and(v));
        put_hex((unsigned long)cond_and_reg(v, ~v));
        put_hex((unsigned long)classify(v, inputs[(i + 1) % N]));
        put_hex((unsigned long)signed_lt((long)v, (long)inputs[(i + 1) % N]));
        put_hex((unsigned long)unsigned_lt(v, inputs[(i + 1) % N]));
        put_hex(cond_matrix(v, inputs[(i + 1) % N]));

        volatile unsigned long a_lo = v;
        volatile unsigned long b_lo = inputs[(i + 3) % N];
        add128(dst, a_lo, 0x0123456789abcdefUL, b_lo, 0xfedcba9876543210UL);
        put_hex(dst[0]);
        put_hex(dst[1]);
        sub128(dst, a_lo, 0xfedcba9876543210UL, b_lo, 0x0123456789abcdefUL);
        put_hex(dst[0]);
        put_hex(dst[1]);
        put('-');
        put('\n');
    }

    GUEST_WRITE(1, out, out_n);
    GUEST_EXIT(0);
}
