/* The SHA-3 group: `eor3`, `bcax`, `xar` and `rax1`, the four instructions Keccak's round is
 * written with and an ARMv8.2 kernel offers only on hardware that has them.
 *
 * There is no native oracle: a Mac has no FEAT_SHA3, so the same instructions here would be an
 * illegal instruction on the host that builds the expected output. The reference is computed in
 * scalar C from the definitions instead, and tests/sha3.sh requires every check to pass. */

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

static void put_dec(unsigned long v) {
    char buf[24];
    int i = 23;
    buf[i] = 0;
    if (v == 0) buf[--i] = '0';
    while (v) {
        buf[--i] = (char)('0' + v % 10);
        v /= 10;
    }
    put(&buf[i]);
}

static unsigned long failures;

static void check(int cond, const char *what, unsigned long detail) {
    put(cond ? "ok   " : "FAIL ");
    put(what);
    put(" ");
    put_dec(detail);
    put("\n");
    if (!cond) failures++;
}

typedef struct {
    unsigned char b[16];
} vec;

/* ---- the instructions, one noinline function each, so the emitter sees them where they are ---- */

__attribute__((noinline)) static vec do_eor3(vec a, vec b, vec c) {
    __asm__ volatile("ldr q0, %[a]\n\t"
                     "ldr q1, %[b]\n\t"
                     "ldr q2, %[c]\n\t"
                     "eor3 v0.16b, v0.16b, v1.16b, v2.16b\n\t"
                     "str q0, %[out]\n\t"
                     : [out] "=m"(a)
                     : [a] "m"(a), [b] "m"(b), [c] "m"(c)
                     : "v0", "v1", "v2", "memory");
    return a;
}

__attribute__((noinline)) static vec do_bcax(vec a, vec b, vec c) {
    __asm__ volatile("ldr q0, %[a]\n\t"
                     "ldr q1, %[b]\n\t"
                     "ldr q2, %[c]\n\t"
                     "bcax v0.16b, v0.16b, v1.16b, v2.16b\n\t"
                     "str q0, %[out]\n\t"
                     : [out] "=m"(a)
                     : [a] "m"(a), [b] "m"(b), [c] "m"(c)
                     : "v0", "v1", "v2", "memory");
    return a;
}

__attribute__((noinline)) static vec do_xar(vec a, vec b, int n) {
    switch (n) {
        case 0:
            __asm__ volatile("ldr q0, %[a]\n\t"
                             "ldr q1, %[b]\n\t"
                             "xar v0.2d, v0.2d, v1.2d, #0\n\t"
                             "str q0, %[out]\n\t"
                             : [out] "=m"(a)
                             : [a] "m"(a), [b] "m"(b)
                             : "v0", "v1", "memory");
            break;
        case 1:
            __asm__ volatile("ldr q0, %[a]\n\t"
                             "ldr q1, %[b]\n\t"
                             "xar v0.2d, v0.2d, v1.2d, #1\n\t"
                             "str q0, %[out]\n\t"
                             : [out] "=m"(a)
                             : [a] "m"(a), [b] "m"(b)
                             : "v0", "v1", "memory");
            break;
        case 27:
            __asm__ volatile("ldr q0, %[a]\n\t"
                             "ldr q1, %[b]\n\t"
                             "xar v0.2d, v0.2d, v1.2d, #27\n\t"
                             "str q0, %[out]\n\t"
                             : [out] "=m"(a)
                             : [a] "m"(a), [b] "m"(b)
                             : "v0", "v1", "memory");
            break;
        case 63:
            __asm__ volatile("ldr q0, %[a]\n\t"
                             "ldr q1, %[b]\n\t"
                             "xar v0.2d, v0.2d, v1.2d, #63\n\t"
                             "str q0, %[out]\n\t"
                             : [out] "=m"(a)
                             : [a] "m"(a), [b] "m"(b)
                             : "v0", "v1", "memory");
            break;
        default:
            a = b;
            break;
    }
    return a;
}

__attribute__((noinline)) static vec do_rax1(vec a, vec b) {
    __asm__ volatile("ldr q0, %[a]\n\t"
                     "ldr q1, %[b]\n\t"
                     "rax1 v0.2d, v0.2d, v1.2d\n\t"
                     "str q0, %[out]\n\t"
                     : [out] "=m"(a)
                     : [a] "m"(a), [b] "m"(b)
                     : "v0", "v1", "memory");
    return a;
}

/* ---- the reference, in scalar C ---- */

static void fill(vec *v, unsigned long seed) {
    for (int i = 0; i < 16; i++) v->b[i] = (unsigned char)(seed * 31 + i * 7 + (seed >> 3));
}

static unsigned long lane64(const vec *v, int lane) {
    unsigned long w = 0;
    for (int i = 7; i >= 0; i--) w = (w << 8) | v->b[lane * 8 + i];
    return w;
}

static void put_lane64(vec *v, int lane, unsigned long w) {
    for (int i = 0; i < 8; i++) v->b[lane * 8 + i] = (unsigned char)(w >> (8 * i));
}

static vec ref_eor3(vec a, vec b, vec c) {
    vec r;
    for (int i = 0; i < 16; i++) r.b[i] = (unsigned char)(a.b[i] ^ b.b[i] ^ c.b[i]);
    return r;
}

static vec ref_bcax(vec a, vec b, vec c) {
    vec r;
    for (int i = 0; i < 16; i++) r.b[i] = (unsigned char)(a.b[i] ^ (b.b[i] & (unsigned char)~c.b[i]));
    return r;
}

static unsigned long ror64(unsigned long w, int n) {
    if (n == 0) return w;
    return (w >> n) | (w << (64 - n));
}

static vec ref_xar(vec a, vec b, int n) {
    // The rotate comes after the exclusive or, and it is of each 64-bit lane.
    vec r;
    for (int l = 0; l < 2; l++) put_lane64(&r, l, ror64(lane64(&a, l) ^ lane64(&b, l), n));
    return r;
}

static vec ref_rax1(vec a, vec b) {
    vec r;
    for (int l = 0; l < 2; l++) put_lane64(&r, l, lane64(&a, l) ^ ror64(lane64(&b, l), 63));
    return r;
}

static int same(const vec *x, const vec *y) {
    for (int i = 0; i < 16; i++) {
        if (x->b[i] != y->b[i]) return 0;
    }
    return 1;
}

static unsigned long seed_of(const vec *v) {
    // Enough of the operand to name the case in a report.
    unsigned long s = 0;
    for (int i = 0; i < 8; i++) s = (s << 8) | v->b[i];
    return s;
}

__attribute__((used)) void _start(void) {
    const int rotations[] = {0, 1, 27, 63};

    for (unsigned long seed = 0; seed < 6; seed++) {
        vec a, b, c, got, want;
        fill(&a, seed);
        fill(&b, seed + 101);
        fill(&c, seed + 211);

        got = do_eor3(a, b, c);
        want = ref_eor3(a, b, c);
        check(same(&got, &want), "eor3", seed_of(&c));

        got = do_bcax(a, b, c);
        want = ref_bcax(a, b, c);
        check(same(&got, &want), "bcax", seed_of(&c));

        for (unsigned long r = 0; r < sizeof rotations / sizeof rotations[0]; r++) {
            got = do_xar(a, b, rotations[r]);
            want = ref_xar(a, b, rotations[r]);
            check(same(&got, &want), "xar rotation", (unsigned long)rotations[r]);
        }

        got = do_rax1(a, b);
        want = ref_rax1(a, b);
        check(same(&got, &want), "rax1", seed_of(&b));
    }

    // The operands of a Keccak round are all over the register file, and the forms that share a
    // destination with a source must read the source before they write it.
    {
        vec a, b, c, got, want;
        fill(&a, 7);
        fill(&b, 8);
        fill(&c, 9);
        got = do_eor3(a, a, b);
        want = ref_eor3(a, a, b);
        check(same(&got, &want), "eor3 with the destination as a source", seed_of(&a));
        got = do_bcax(c, c, b);
        want = ref_bcax(c, c, b);
        check(same(&got, &want), "bcax with the destination as a source", seed_of(&c));
    }

    put(failures ? "sha3: FAILURES\n" : "sha3: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}
