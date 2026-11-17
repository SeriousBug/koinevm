/* Scalar floating point, every instruction shape, over the values that separate IEEE from anything
 * that looks like it: the two zeros, the infinities, a quiet and a signalling NaN, a denormal, and
 * values that only differ in their low bit. The native build is the oracle.
 *
 * The last section asks what a scalar write leaves in the rest of the register, which is the one
 * part of this the instruction manual and the engine disagree about. */

#ifdef __APPLE__
extern long write(int, const void *, unsigned long);
extern void exit(int);
#define GUEST_WRITE(fd, buf, n) write((fd), (buf), (unsigned long)(n))
#define GUEST_EXIT(code) exit((int)(code))
#define GUEST_ENTRY fp_main
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

static char out[1 << 18];
static unsigned long out_n;

static void put(char c) { out[out_n++] = c; }

static void put_str(const char *s) {
    while (*s) put(*s++);
}

static void put_bits(unsigned long v) {
    static const char digits[] = "0123456789abcdef";
    put('0');
    put('x');
    for (int i = 0; i < 16; i++) put(digits[(v >> (60 - 4 * i)) & 0xf]);
    put('\n');
}

static void put_bits32(unsigned int v) {
    static const char digits[] = "0123456789abcdef";
    put('0');
    put('x');
    for (int i = 0; i < 8; i++) put(digits[(v >> (28 - 4 * i)) & 0xf]);
    put('\n');
}

static void put_name(const char *s) {
    put_str(s);
    put('\n');
}

/* The bit pattern goes across in a register rather than through memory: a union would compare
 * whatever the bytes beside the value happen to hold, and what that is changes with -O. */
static double d_of(unsigned long u) {
    double d;
    __asm__ volatile("fmov %d0, %1" : "=w"(d) : "r"(u));
    return d;
}

static unsigned long u_of_d(double d) {
    unsigned long u;
    __asm__ volatile("fmov %0, %d1" : "=r"(u) : "w"(d));
    return u;
}

static float f_of(unsigned int w) {
    float f;
    __asm__ volatile("fmov %s0, %w1" : "=w"(f) : "r"(w));
    return f;
}

static unsigned int u_of_f(float f) {
    unsigned int w;
    __asm__ volatile("fmov %w0, %s1" : "=r"(w) : "w"(f));
    return w;
}

#define TWO_DOUBLE(name, insn)                                                                \
    static double name(double a, double b) {                                                  \
        double r;                                                                             \
        __asm__ volatile(insn " %d0, %d1, %d2" : "=w"(r) : "w"(a), "w"(b));                   \
        return r;                                                                             \
    }
#define ONE_DOUBLE(name, insn)                                                                \
    static double name(double a) {                                                            \
        double r;                                                                             \
        __asm__ volatile(insn " %d0, %d1" : "=w"(r) : "w"(a));                                \
        return r;                                                                             \
    }
#define TWO_SINGLE(name, insn)                                                                \
    static float name(float a, float b) {                                                     \
        float r;                                                                              \
        __asm__ volatile(insn " %s0, %s1, %s2" : "=w"(r) : "w"(a), "w"(b));                   \
        return r;                                                                             \
    }
#define ONE_SINGLE(name, insn)                                                                \
    static float name(float a) {                                                              \
        float r;                                                                              \
        __asm__ volatile(insn " %s0, %s1" : "=w"(r) : "w"(a));                                \
        return r;                                                                             \
    }

TWO_DOUBLE(d_fadd, "fadd")
TWO_DOUBLE(d_fsub, "fsub")
TWO_DOUBLE(d_fmul, "fmul")
TWO_DOUBLE(d_fdiv, "fdiv")
TWO_DOUBLE(d_fmax, "fmax")
TWO_DOUBLE(d_fmin, "fmin")
TWO_DOUBLE(d_fmaxnm, "fmaxnm")
TWO_DOUBLE(d_fminnm, "fminnm")
TWO_DOUBLE(d_fnmul, "fnmul")
ONE_DOUBLE(d_fabs, "fabs")
ONE_DOUBLE(d_fneg, "fneg")
ONE_DOUBLE(d_fsqrt, "fsqrt")
ONE_DOUBLE(d_frintn, "frintn")
ONE_DOUBLE(d_frintp, "frintp")
ONE_DOUBLE(d_frintm, "frintm")
ONE_DOUBLE(d_frintz, "frintz")
ONE_DOUBLE(d_frinta, "frinta")
ONE_DOUBLE(d_frintx, "frintx")
ONE_DOUBLE(d_frinti, "frinti")

TWO_SINGLE(s_fadd, "fadd")
TWO_SINGLE(s_fsub, "fsub")
TWO_SINGLE(s_fmul, "fmul")
TWO_SINGLE(s_fdiv, "fdiv")
TWO_SINGLE(s_fmax, "fmax")
TWO_SINGLE(s_fmin, "fmin")
TWO_SINGLE(s_fmaxnm, "fmaxnm")
TWO_SINGLE(s_fminnm, "fminnm")
TWO_SINGLE(s_fnmul, "fnmul")
ONE_SINGLE(s_fabs, "fabs")
ONE_SINGLE(s_fneg, "fneg")
ONE_SINGLE(s_fsqrt, "fsqrt")
ONE_SINGLE(s_frintn, "frintn")
ONE_SINGLE(s_frinta, "frinta")
ONE_SINGLE(s_frintz, "frintz")

static unsigned long d_fcmp(double a, double b) {
    unsigned long nzcv;
    __asm__ volatile("fcmp %d1, %d2\n mrs %0, nzcv" : "=r"(nzcv) : "w"(a), "w"(b) : "cc");
    return nzcv >> 28;
}

static unsigned long d_fcmpe(double a, double b) {
    unsigned long nzcv;
    __asm__ volatile("fcmpe %d1, %d2\n mrs %0, nzcv" : "=r"(nzcv) : "w"(a), "w"(b) : "cc");
    return nzcv >> 28;
}

static unsigned long d_fcmp_zero(double a) {
    unsigned long nzcv;
    __asm__ volatile("fcmp %d1, #0.0\n mrs %0, nzcv" : "=r"(nzcv) : "w"(a) : "cc");
    return nzcv >> 28;
}

static unsigned long s_fcmp(float a, float b) {
    unsigned long nzcv;
    __asm__ volatile("fcmp %s1, %s2\n mrs %0, nzcv" : "=r"(nzcv) : "w"(a), "w"(b) : "cc");
    return nzcv >> 28;
}

static unsigned long s_fcmp_zero(float a) {
    unsigned long nzcv;
    __asm__ volatile("fcmp %s1, #0.0\n mrs %0, nzcv" : "=r"(nzcv) : "w"(a) : "cc");
    return nzcv >> 28;
}

/* The condition codes, so a wrong one cannot hide behind a pair of equal operands. */
#define SEL(name, cond)                                                                       \
    static double name(double a, double b) {                                                  \
        double r;                                                                             \
        __asm__ volatile("fcmp %d3, %d3\n fcsel %d0, %d1, %d2, " cond : "=w"(r)               \
                         : "w"(a), "w"(b), "w"(a));                                           \
        return r;                                                                             \
    }
SEL(d_eq, "eq")
SEL(d_ne, "ne")
SEL(d_hs, "hs")
SEL(d_lo, "lo")
SEL(d_mi, "mi")
SEL(d_pl, "pl")
SEL(d_vs, "vs")
SEL(d_vc, "vc")
SEL(d_hi, "hi")
SEL(d_ls, "ls")
SEL(d_ge, "ge")
SEL(d_lt, "lt")
SEL(d_gt, "gt")
SEL(d_le, "le")
SEL(d_al, "al")
SEL(d_nv, "nv")

static double d_fcvt_from_single(float a) {
    double r;
    __asm__ volatile("fcvt %d0, %s1" : "=w"(r) : "w"(a));
    return r;
}

static float s_fcvt_from_double(double a) {
    float r;
    __asm__ volatile("fcvt %s0, %d1" : "=w"(r) : "w"(a));
    return r;
}

/* The eight-bit immediate, which is the one place the encoding of a constant is not the bit
 * pattern of anything. */
#define IMM(name, imm)                                                                        \
    static unsigned long name(void) {                                                         \
        double r;                                                                             \
        __asm__ volatile("fmov %d0, #" imm : "=w"(r));                                        \
        return u_of_d(r);                                                                     \
    }
IMM(d_imm_1, "1.0")
IMM(d_imm_neg1, "-1.0")
IMM(d_imm_half, "0.5")
IMM(d_imm_quarter, "0.25")
IMM(d_imm_two, "2.0")
IMM(d_imm_neg25, "-2.5")
IMM(d_imm_tiny, "0.15625")

#define IMM_S(name, imm)                                                                      \
    static unsigned long name(void) {                                                         \
        float r;                                                                              \
        __asm__ volatile("fmov %s0, #" imm : "=w"(r));                                        \
        return u_of_f(r);                                                                     \
    }
IMM_S(s_imm_1, "1.0")
IMM_S(s_imm_neg1, "-1.0")
IMM_S(s_imm_neg25, "-2.5")
IMM_S(s_imm_tiny, "0.15625")

/* What a scalar write leaves above the value, with the register full of garbage first. */
static void upper_lanes(void) {
    unsigned char buf[32];
    static const char digits[] = "0123456789abcdef";

    __asm__ volatile("movi v0.16b, #0xff\n"
                     "fmov s1, #1.0\n"
                     "fmov s2, #3.0\n"
                     "fadd s0, s1, s2\n"
                     "str q0, [%0]"
                     :
                     : "r"(buf)
                     : "v0", "v1", "v2", "memory");
    for (int i = 0; i < 16; i++) {
        put(digits[buf[i] >> 4]);
        put(digits[buf[i] & 0xf]);
    }
    put('\n');

    __asm__ volatile("movi v0.16b, #0xff\n"
                     "fmov d1, #1.0\n"
                     "fmov d2, #3.0\n"
                     "fdiv d0, d1, d2\n"
                     "str q0, [%0]"
                     :
                     : "r"(buf)
                     : "v0", "v1", "v2", "memory");
    for (int i = 0; i < 16; i++) {
        put(digits[buf[i] >> 4]);
        put(digits[buf[i] & 0xf]);
    }
    put('\n');

    __asm__ volatile("movi v0.16b, #0xff\n"
                     "fmov s1, #-2.0\n"
                     "fmov s0, s1\n"
                     "str q0, [%0]"
                     :
                     : "r"(buf)
                     : "v0", "v1", "memory");
    for (int i = 0; i < 16; i++) {
        put(digits[buf[i] >> 4]);
        put(digits[buf[i] & 0xf]);
    }
    put('\n');
}

static const unsigned long dvals[] = {
    0x0000000000000000UL, /* +0 */
    0x8000000000000000UL, /* -0 */
    0x3ff0000000000000UL, /* 1 */
    0xbff0000000000000UL, /* -1 */
    0x4008000000000000UL, /* 3 */
    0x3fe0000000000000UL, /* 0.5 */
    0x7ff0000000000000UL, /* +inf */
    0xfff0000000000000UL, /* -inf */
    0x7ff8000000000000UL, /* quiet NaN */
    0x7ff0000000000001UL, /* signalling NaN */
    0x0000000000000001UL, /* smallest denormal */
    0x4330000080000000UL, /* large, not integral */
};

static const unsigned int fvals[] = {
    0x00000000u, /* +0 */
    0x80000000u, /* -0 */
    0x3f800000u, /* 1 */
    0xbf800000u, /* -1 */
    0x40400000u, /* 3 */
    0x3f000000u, /* 0.5 */
    0x7f800000u, /* +inf */
    0xff800000u, /* -inf */
    0x7fc00000u, /* quiet NaN */
    0x7f800001u, /* signalling NaN */
    0x00000001u, /* smallest denormal */
};

#define ND (sizeof dvals / sizeof dvals[0])
#define NF (sizeof fvals / sizeof fvals[0])

static void two_double(const char *name, double (*fn)(double, double)) {
    put_name(name);
    for (unsigned long i = 0; i < ND; i++)
        for (unsigned long j = 0; j < ND; j++) put_bits(u_of_d(fn(d_of(dvals[i]), d_of(dvals[j]))));
}

static void two_single(const char *name, float (*fn)(float, float)) {
    put_name(name);
    for (unsigned long i = 0; i < NF; i++)
        for (unsigned long j = 0; j < NF; j++)
            put_bits32(u_of_f(fn(f_of(fvals[i]), f_of(fvals[j]))));
}

static void one_double(const char *name, double (*fn)(double)) {
    put_name(name);
    for (unsigned long i = 0; i < ND; i++) put_bits(u_of_d(fn(d_of(dvals[i]))));
}

static void one_single(const char *name, float (*fn)(float)) {
    put_name(name);
    for (unsigned long i = 0; i < NF; i++) put_bits32(u_of_f(fn(f_of(fvals[i]))));
}

static void cmp_double(const char *name, unsigned long (*fn)(double, double)) {
    put_name(name);
    for (unsigned long i = 0; i < ND; i++)
        for (unsigned long j = 0; j < ND; j++) put_bits(fn(d_of(dvals[i]), d_of(dvals[j])));
}

__attribute__((used)) void GUEST_ENTRY(void) {
    two_double("fadd", d_fadd);
    two_double("fsub", d_fsub);
    two_double("fmul", d_fmul);
    two_double("fdiv", d_fdiv);
    two_double("fmax", d_fmax);
    two_double("fmin", d_fmin);
    two_double("fmaxnm", d_fmaxnm);
    two_double("fminnm", d_fminnm);
    two_double("fnmul", d_fnmul);

    two_single("fadd s", s_fadd);
    two_single("fsub s", s_fsub);
    two_single("fmul s", s_fmul);
    two_single("fdiv s", s_fdiv);
    two_single("fmax s", s_fmax);
    two_single("fmin s", s_fmin);
    two_single("fmaxnm s", s_fmaxnm);
    two_single("fminnm s", s_fminnm);
    two_single("fnmul s", s_fnmul);

    one_double("fabs", d_fabs);
    one_double("fneg", d_fneg);
    one_double("fsqrt", d_fsqrt);
    one_double("frintn", d_frintn);
    one_double("frintp", d_frintp);
    one_double("frintm", d_frintm);
    one_double("frintz", d_frintz);
    one_double("frinta", d_frinta);
    one_double("frintx", d_frintx);
    one_double("frinti", d_frinti);

    one_single("fabs s", s_fabs);
    one_single("fneg s", s_fneg);
    one_single("fsqrt s", s_fsqrt);
    one_single("frintn s", s_frintn);
    one_single("frinta s", s_frinta);
    one_single("frintz s", s_frintz);

    cmp_double("fcmp", d_fcmp);
    cmp_double("fcmpe", d_fcmpe);
    put_name("fcmp #0");
    for (unsigned long i = 0; i < ND; i++) put_bits(d_fcmp_zero(d_of(dvals[i])));
    put_name("fcmp s");
    for (unsigned long i = 0; i < NF; i++)
        for (unsigned long j = 0; j < NF; j++)
            put_bits(s_fcmp(f_of(fvals[i]), f_of(fvals[j])));
    put_name("fcmp s #0");
    for (unsigned long i = 0; i < NF; i++) put_bits(s_fcmp_zero(f_of(fvals[i])));

    two_double("fcsel eq", d_eq);
    two_double("fcsel ne", d_ne);
    two_double("fcsel hs", d_hs);
    two_double("fcsel lo", d_lo);
    two_double("fcsel mi", d_mi);
    two_double("fcsel pl", d_pl);
    two_double("fcsel vs", d_vs);
    two_double("fcsel vc", d_vc);
    two_double("fcsel hi", d_hi);
    two_double("fcsel ls", d_ls);
    two_double("fcsel ge", d_ge);
    two_double("fcsel lt", d_lt);
    two_double("fcsel gt", d_gt);
    two_double("fcsel le", d_le);
    two_double("fcsel al", d_al);
    two_double("fcsel nv", d_nv);

    put_name("fcvt d<-s");
    for (unsigned long i = 0; i < NF; i++) put_bits(u_of_d(d_fcvt_from_single(f_of(fvals[i]))));
    put_name("fcvt s<-d");
    for (unsigned long i = 0; i < ND; i++)
        put_bits32(u_of_f(s_fcvt_from_double(d_of(dvals[i]))));

    put_name("fmov imm");
    put_bits(d_imm_1());
    put_bits(d_imm_neg1());
    put_bits(d_imm_half());
    put_bits(d_imm_quarter());
    put_bits(d_imm_two());
    put_bits(d_imm_neg25());
    put_bits(d_imm_tiny());
    put_bits32(s_imm_1());
    put_bits32(s_imm_neg1());
    put_bits32(s_imm_neg25());
    put_bits32(s_imm_tiny());

    put_name("upper lanes");
    upper_lanes();

    GUEST_WRITE(1, out, out_n);
    GUEST_EXIT(0);
}
