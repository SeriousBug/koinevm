/* SIMD/NEON and scalar FP guest, run against a native macOS oracle.
 *
 * Every case is an explicit instruction sequence in a noinline function, applied to a table of bit
 * patterns, so the translated guest and the oracle run literally the same instructions over the
 * same operands and the results compare as raw bit patterns. Nothing is left to the C compiler:
 * inputs arrive through volatile stores, results leave through memory or a general register, and no
 * arithmetic happens outside the asm blocks.
 *
 * The moves and conversions get NaN, infinities and denormals as input: their result is defined for
 * every bit pattern, so feeding them in compares instruction semantics rather than the host's
 * choice of NaN payload. Arithmetic that produces a NaN is not in this guest, because scalar
 * floating point arithmetic is not translated yet. */

#ifdef __APPLE__
extern long write(int, const void *, unsigned long);
extern void exit(int);
#define GUEST_WRITE(fd, buf, n) write((fd), (buf), (unsigned long)(n))
#define GUEST_EXIT(code) exit((int)(code))
#define GUEST_ENTRY simd_main
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

/* ---- output: hex words, one per line, no stdio ---- */

#define OUT_CHUNK 4096
static char out[OUT_CHUNK];
static unsigned long out_n;

static void flush(void) {
    if (out_n) {
        GUEST_WRITE(1, out, out_n);
        out_n = 0;
    }
}

static void put(char c) {
    if (out_n == OUT_CHUNK) flush();
    out[out_n++] = c;
}

static void put_str(const char *s) {
    while (*s) put(*s++);
}

static void put_dec(unsigned long v) {
    char b[8];
    int n = 0;
    if (v == 0) {
        put('0');
        return;
    }
    while (v) {
        b[n++] = (char)('0' + v % 10);
        v /= 10;
    }
    while (n) put(b[--n]);
}

static void put_hex(unsigned long v) {
    static const char digits[] = "0123456789abcdef";
    put('0');
    put('x');
    for (int i = 0; i < 16; i++) put(digits[(v >> (60 - 4 * i)) & 0xf]);
    put('\n');
}

/* ---- inputs ---- */

#define NPAT 5
#define PAT_BYTES (NPAT * 32)

/* Four words per pattern: 32 bytes, so ldp/stp and the two-vector forms have room. */
static const unsigned long pat[NPAT][4] = {
    {0x0000000000000000ul, 0x0000000000000000ul, 0x0000000000000000ul, 0x0000000000000000ul},
    {0xfffffffffffffffful, 0xfffffffffffffffful, 0xfffffffffffffffful, 0xfffffffffffffffful},
    {0x8000000000000000ul, 0x8000000000000000ul, 0x8000000000000000ul, 0x8000000000000000ul},
    {0x0123456789abcdeful, 0xfedcba9876543210ul, 0x0f0f0f0f0f0f0f0ful, 0xf0f0f0f0f0f0f0f0ul},
    {0x7f0180ff01377f80ul, 0xff007f018000fe7ful, 0x7fff800000010001ul, 0x80007ffffffe0001ul},
};

#define ARENA 4096
static unsigned char arena[ARENA] __attribute__((aligned(16)));
static unsigned char *patr; /* NPAT * 32 bytes of patterns, the inputs */
static unsigned char *pbuf; /* 32 bytes of results */
static unsigned char *pscr; /* 64 bytes of scratch the asm blocks store to */

static unsigned char *pa, *pb;

static void zero_results(void) {
    volatile unsigned long *w = (volatile unsigned long *)pbuf;
    for (int i = 0; i < 4; i++) w[i] = 0;
}

/* Two words is the whole destination register; the cases that move two vectors through memory
 * print four. */
static void put_results(int words) {
    const volatile unsigned long *w = (const volatile unsigned long *)pbuf;
    for (int i = 0; i < words; i++) put_hex(w[i]);
}

static void put_tag(const char *name, int i, int j) {
    put_str(name);
    put(' ');
    put_dec((unsigned long)i);
    if (j >= 0) {
        put(',');
        put_dec((unsigned long)j);
    }
    put('\n');
}

static void setup(void) {
    unsigned char *base = (unsigned char *)(((unsigned long)arena + 15ul) & ~15ul);
    patr = base;
    pbuf = base + PAT_BYTES;
    pscr = pbuf + 32;
    for (int i = 0; i < NPAT; i++) {
        volatile unsigned long *w = (volatile unsigned long *)(patr + 32 * i);
        for (int k = 0; k < 4; k++) w[k] = pat[i][k];
    }
}

/* ---- case shapes ---- */

/* Live across every case: q0 and q3 are the first input pattern's two vectors, q1 and q4 the
 * second's, and x9 points at the scratch area, so a body can do its own loads, stores and
 * post-index without needing another operand. */
#define VCLOB "v0", "v1", "v2", "v3", "v4", "v5", "x9", "x10", "memory"

#define DEF_U(fn, body)                                                       \
    __attribute__((noinline)) static void fn(void) {                          \
        __asm__ volatile("ldr q0, [%0]\n mov x9, %2\n" body "\n str q2, [%1]" \
                         :                                                    \
                         : "r"(pa), "r"(pbuf), "r"(pscr)                      \
                         : VCLOB);                                            \
    }

#define DEF_B(fn, body)                                                        \
    __attribute__((noinline)) static void fn(void) {                           \
        __asm__ volatile("ldr q0, [%0]\n ldr q1, [%1]\n ldr q3, [%0, #16]\n"  \
                         " ldr q4, [%1, #16]\n mov x9, %3\n" body "\n str q2, [%2]" \
                         :                                                     \
                         : "r"(pa), "r"(pb), "r"(pbuf), "r"(pscr)              \
                         : VCLOB);                                             \
    }

/* The body leaves a general-register result in %0. */
#define DEF_X(fn, body)                                     \
    __attribute__((noinline)) static unsigned long fn(void) { \
        register unsigned long r __asm__("x0") = 0;         \
        __asm__ volatile("ldr q0, [%1]\n mov x9, %2\n" body \
                         : "+r"(r)                          \
                         : "r"(pa), "r"(pscr)               \
                         : VCLOB);                         \
        return r;                                           \
    }

/* Two 32-bit and two 64-bit inputs, all raw bit patterns, one 64-bit result. */
#define DEF_F(fn, body)                                                                        \
    __attribute__((noinline)) static unsigned long fn(unsigned int a, unsigned int b,          \
                                                     unsigned long da, unsigned long db) {     \
        unsigned long r;                                                                       \
        __asm__ volatile("fmov s0, %w1\n fmov s1, %w2\n fmov d0, %3\n fmov d1, %4\n" body       \
                         : "=r"(r)                                                             \
                         : "r"(a), "r"(b), "r"(da), "r"(db)                                    \
                         : "v0", "v1", "v2", "v3", "x9", "cc");                                \
        return r;                                                                              \
    }

/* A 32-bit FP result goes out through w9 so its bits land in the low half of %0 with zeros above;
 * x9 is clobbered by every DEF_F, so the compiler cannot have put %0 there. */
#define S2W "fmov w9, s2\n mov %0, x9"
#define D2X "fmov %0, d2"

/* The memory cases move two vectors in and out, so they print both. */
#define L_CASES(X)                                                                              \
    X(ldr_str_q, "ldr/str q", "str q0, [x9, #16]\n ldr q2, [x9, #16]")                          \
    X(stur_ldur_q, "stur/ldur q", "add x9, x9, #32\n stur q0, [x9, #-16]\n ldur q2, [x9, #-16]") \
    X(ldp_stp_q, "ldp/stp q", "stp q0, q1, [x9]\n ldp q2, q3, [x9]\n str q3, [%2, #16]")        \
    X(ld1_st1_pst, "ld1/st1 16b post-index",                                                     \
      "st1 {v0.16b}, [x9], #16\n st1 {v1.16b}, [x9], #16\n sub x9, x9, #32\n"                    \
      " ld1 {v2.16b}, [x9], #16\n ld1 {v3.16b}, [x9], #16\n str q3, [%2, #16]")                  \
    X(ld1_st1_16b, "ld1/st1 16b", "ld1 {v2.16b}, [%0]\n st1 {v2.16b}, [x9]\n ldr q2, [x9]")     \
    /* The interleaved structures: two, three and four registers, in an element width each. */   \
    X(st2_16b, "st2 16b",                                                                        \
      "st2 {v0.16b, v1.16b}, [x9]\n ldr q2, [x9]\n str q2, [%2]\n ldr q2, [x9, #16]\n"          \
      " str q2, [%2, #16]")                                                                      \
    X(ld2_16b, "ld2 16b",                                                                        \
      "str q0, [x9]\n str q1, [x9, #16]\n ld2 {v2.16b, v3.16b}, [x9]\n str q2, [%2]\n"          \
      " str q3, [%2, #16]")                                                                      \
    X(st2_8h, "st2 8h",                                                                          \
      "st2 {v0.8h, v1.8h}, [x9]\n ldr q2, [x9]\n str q2, [%2]\n ldr q2, [x9, #16]\n"           \
      " str q2, [%2, #16]")                                                                      \
    X(ld2_8h, "ld2 8h",                                                                          \
      "str q0, [x9]\n str q1, [x9, #16]\n ld2 {v2.8h, v3.8h}, [x9]\n str q2, [%2]\n"           \
      " str q3, [%2, #16]")                                                                      \
    X(st2_2d, "st2 2d",                                                                          \
      "st2 {v0.2d, v1.2d}, [x9]\n ldr q2, [x9]\n str q2, [%2]\n ldr q2, [x9, #16]\n"           \
      " str q2, [%2, #16]")                                                                      \
    X(ld2_2d, "ld2 2d",                                                                          \
      "str q0, [x9]\n str q1, [x9, #16]\n ld2 {v2.2d, v3.2d}, [x9]\n str q2, [%2]\n"           \
      " str q3, [%2, #16]")                                                                      \
    X(ld2_pst_16b, "ld2 16b post-index",                                                         \
      "str q0, [x9]\n str q1, [x9, #16]\n mov x10, x9\n ld2 {v2.16b, v3.16b}, [x9], #32\n"     \
      " sub x9, x9, x10\n str x9, [%2]\n str q2, [%2, #8]")                                     \
    X(st3_8b, "st3 8b",                                                                          \
      "ldr q2, [%0]\n ldr q3, [%0, #16]\n ldr q4, [%1]\n st3 {v2.8b, v3.8b, v4.8b}, [x9]\n"    \
      " ldr q2, [x9]\n str q2, [%2]\n ldr d2, [x9, #16]\n str d2, [%2, #16]")                  \
    X(ld3_8b, "ld3 8b",                                                                          \
      "str q0, [x9]\n str q1, [x9, #16]\n ld3 {v2.8b, v3.8b, v4.8b}, [x9]\n str d2, [%2]\n"    \
      " str d3, [%2, #8]\n str d4, [%2, #16]")                                                  \
    X(st3_4h, "st3 4h",                                                                          \
      "ldr q2, [%0]\n ldr q3, [%0, #16]\n ldr q4, [%1]\n st3 {v2.4h, v3.4h, v4.4h}, [x9]\n"    \
      " ldr q2, [x9]\n str q2, [%2]\n ldr d2, [x9, #16]\n str d2, [%2, #16]")                  \
    X(ld3_4h, "ld3 4h",                                                                          \
      "str q0, [x9]\n str q1, [x9, #16]\n ld3 {v2.4h, v3.4h, v4.4h}, [x9]\n str d2, [%2]\n"    \
      " str d3, [%2, #8]\n str d4, [%2, #16]")                                                  \
    X(st4_8b, "st4 8b",                                                                          \
      "ldr q2, [%0]\n ldr q3, [%0, #16]\n ldr q4, [%1]\n ldr q5, [%1, #16]\n"                  \
      " st4 {v2.8b, v3.8b, v4.8b, v5.8b}, [x9]\n ldr q2, [x9]\n str q2, [%2]\n"                 \
      " ldr q2, [x9, #16]\n str q2, [%2, #16]")                                                 \
    X(ld4_8b, "ld4 8b",                                                                          \
      "str q0, [x9]\n str q1, [x9, #16]\n ld4 {v2.8b, v3.8b, v4.8b, v5.8b}, [x9]\n"            \
      " str d2, [%2]\n str d3, [%2, #8]\n str d4, [%2, #16]\n str d5, [%2, #24]")              \
    X(st4_4h, "st4 4h",                                                                          \
      "ldr q2, [%0]\n ldr q3, [%0, #16]\n ldr q4, [%1]\n ldr q5, [%1, #16]\n"                  \
      " st4 {v2.4h, v3.4h, v4.4h, v5.4h}, [x9]\n ldr q2, [x9]\n str q2, [%2]\n"                 \
      " ldr q2, [x9, #16]\n str q2, [%2, #16]")                                                 \
    X(ld4_4h, "ld4 4h",                                                                          \
      "str q0, [x9]\n str q1, [x9, #16]\n ld4 {v2.4h, v3.4h, v4.4h, v5.4h}, [x9]\n"            \
      " str d2, [%2]\n str d3, [%2, #8]\n str d4, [%2, #16]\n str d5, [%2, #24]")              \
    /* The scalar `dup`: one lane of a register, and everything above it zero. */                 \
    X(mov_d_d1, "mov d2, v0.d[1]", "mov d2, v0.d[1]")                                            \
    X(mov_s_s3, "mov s2, v0.s[3]", "mov s2, v0.s[3]")                                            \
    X(mov_h_h7, "mov h2, v0.h[7]", "mov h2, v0.h[7]")                                            \
    X(mov_b_b13, "mov b2, v0.b[13]", "mov b2, v0.b[13]")                                         \
    /* The scalar shifts, which is how a compiler writes a 64-bit value into a vector one byte at
     * a time, and the lane insert it then uses. A digest's length field is written exactly so. */ \
    X(ushr_d_8, "ushr d #8", "ushr d2, d0, #8")                                                  \
    X(ushr_d_56, "ushr d #56", "ushr d2, d0, #56")                                               \
    X(ushr_d_1, "ushr d #1", "ushr d2, d0, #1")                                                  \
    X(sshr_d_8, "sshr d #8", "sshr d2, d0, #8")                                                  \
    X(shl_d_4, "shl d #4", "shl d2, d0, #4")                                                     \
    X(ins_b14, "ins v2.b[14], v1.b[0]", "mov v2.16b, v0.16b\n mov v2.b[14], v1.b[0]")         \
    X(ins_b15, "ins v2.b[15], v1.b[0]", "mov v2.16b, v0.16b\n mov v2.b[15], v1.b[0]")         \
    X(ins_b0, "ins v2.b[0], v1.b[0]", "mov v2.16b, v0.16b\n mov v2.b[0], v1.b[0]")            \
    X(ins_h7, "ins v2.h[7], v1.h[1]", "mov v2.16b, v0.16b\n mov v2.h[7], v1.h[1]")            \
    X(ushr_d_then_ins, "ushr d #8 then ins",                                                     \
      "ushr d2, d0, #8\n mov v3.16b, v0.16b\n mov v3.b[14], v2.b[0]\n mov v2.16b, v3.16b")  \
    X(dup_d0, "dup d2, v0.d[0]", "dup d2, v0.d[0]")                                            \
    /* The conversions between floating point and fixed point: two lanes of a register, and the */\
    /* scalar form of one, which is the shape a runtime scales by a power of two with. */      \
    X(ucvtf_2s_20, "ucvtf 2s #20", "ucvtf v2.2s, v0.2s, #20")                                 \
    X(scvtf_2s_20, "scvtf 2s #20", "scvtf v2.2s, v0.2s, #20")                                 \
    X(ucvtf_2s_32, "ucvtf 2s #32", "ucvtf v2.2s, v0.2s, #32")                                 \
    X(scvtf_2s_1, "scvtf 2s #1", "scvtf v2.2s, v0.2s, #1")                                    \
    X(ucvtf_2d_20, "ucvtf 2d #20", "ucvtf v2.2d, v0.2d, #20")                                 \
    X(scvtf_2d_20, "scvtf 2d #20", "scvtf v2.2d, v0.2d, #20")                                 \
    X(ucvtf_2d_64, "ucvtf 2d #64", "ucvtf v2.2d, v0.2d, #64")                                 \
    X(fcvtzs_2d_20, "fcvtzs 2d #20", "fcvtzs v2.2d, v0.2d, #20")                              \
    X(fcvtzu_2d_20, "fcvtzu 2d #20", "fcvtzu v2.2d, v0.2d, #20")                              \
    X(fcvtzs_2s_7, "fcvtzs 2s #7", "fcvtzs v2.2s, v0.2s, #7")                                 \
    X(fcvtzu_2s_20, "fcvtzu 2s #20", "fcvtzu v2.2s, v0.2s, #20")                              \
    X(ucvtf_d_20, "ucvtf d #20", "ucvtf d2, d0, #20")                                        \
    X(scvtf_d_20, "scvtf d #20", "scvtf d2, d0, #20")                                         \
    X(ucvtf_s_20, "ucvtf s #20", "ucvtf s2, s0, #20")                                         \
    X(fcvtzs_d_20, "fcvtzs d #20", "fcvtzs d2, d0, #20")                                      \
    X(fcvtzu_d_20, "fcvtzu d #20", "fcvtzu d2, d0, #20")

#define U_CASES(X)                                                                              \
    /* three-same integer */                                                                    \
    X(not_16b, "not 16b", "not v2.16b, v0.16b")                                                 \
    X(addv_16b, "addv b, 16b", "addv b2, v0.16b")                                              \
    X(addv_8h, "addv h, 8h", "addv h2, v0.8h")                                                  \
    X(addv_4s, "addv s, 4s", "addv s2, v0.4s")                                                  \
    X(umaxv_16b, "umaxv b, 16b", "umaxv b2, v0.16b")                                           \
    X(smaxv_8h, "smaxv h, 8h", "smaxv h2, v0.8h")                                               \
    X(smaxv_4s, "smaxv s, 4s", "smaxv s2, v0.4s")                                               \
    X(uminv_4s, "uminv s, 4s", "uminv s2, v0.4s")                                               \
    X(addp_d, "addp d, 2d", "addp d2, v0.2d")                                                   \
    /* narrows, widens, shifts */                                                               \
    X(xtn_8b, "xtn 8b", "xtn v2.8b, v0.8h")                                                     \
    X(xtn_4h, "xtn 4h", "xtn v2.4h, v0.4s")                                                     \
    X(xtn_2s, "xtn 2s", "xtn v2.2s, v0.2d")                                                     \
    X(fcvtn_2s, "fcvtn 2s", "fcvtn v2.2s, v0.2d")                                               \
    X(fcvtl_2d, "fcvtl 2d", "fcvtl v2.2d, v0.2s")                                              \
    X(shrn_8b, "shrn 8b #3", "shrn v2.8b, v0.8h, #3")                                           \
    X(shrn_4h, "shrn 4h #7", "shrn v2.4h, v0.4s, #7")                                           \
    X(shrn_2s, "shrn 2s #13", "shrn v2.2s, v0.2d, #13")                                         \
    X(rshrn_8b, "rshrn 8b #3", "rshrn v2.8b, v0.8h, #3")                                        \
    X(rshrn_4h, "rshrn 4h #7", "rshrn v2.4h, v0.4s, #7")                                        \
    X(rshrn_2s, "rshrn 2s #13", "rshrn v2.2s, v0.2d, #13")                                      \
    X(sshll_8h, "sshll 8h #0", "sshll v2.8h, v0.8b, #0")                                        \
    X(sshll_4s, "sshll 4s #4", "sshll v2.4s, v0.4h, #4")                                        \
    X(sshll_2d, "sshll 2d #2", "sshll v2.2d, v0.2s, #2")                                        \
    X(ushll_8h, "ushll 8h #0", "ushll v2.8h, v0.8b, #0")                                        \
    X(ushll_4s, "ushll 4s #4", "ushll v2.4s, v0.4h, #4")                                        \
    X(ushll_2d, "ushll 2d #2", "ushll v2.2d, v0.2s, #2")                                        \
    X(sxtl_8h, "sxtl 8h", "sxtl v2.8h, v0.8b")                                                  \
    X(sxtl_2d, "sxtl 2d", "sxtl v2.2d, v0.2s")                                                  \
    X(uxtl_8h, "uxtl 8h", "uxtl v2.8h, v0.8b")                                                  \
    X(uxtl_4s, "uxtl 4s", "uxtl v2.4s, v0.4h")                                                  \
    X(ushr_16b, "ushr 16b #3", "ushr v2.16b, v0.16b, #3")                                       \
    X(ushr_4s, "ushr 4s #7", "ushr v2.4s, v0.4s, #7")                                           \
    X(sshr_16b, "sshr 16b #3", "sshr v2.16b, v0.16b, #3")                                       \
    X(sshr_4s, "sshr 4s #7", "sshr v2.4s, v0.4s, #7")                                           \
    X(sshr_2d, "sshr 2d #13", "sshr v2.2d, v0.2d, #13")                                         \
    X(shl_16b, "shl 16b #3", "shl v2.16b, v0.16b, #3")                                          \
    X(shl_4s, "shl 4s #5", "shl v2.4s, v0.4s, #5")                                              \
    /* copy, move, immediate */                                                                 \
    X(dup_16b_gpr, "dup 16b, w9", "ldr x9, [%0]\n dup v2.16b, w9")                              \
    X(dup_8h_gpr, "dup 8h, w10", "ldr w10, [%0, #8]\n dup v2.8h, w10")                          \
    X(dup_4s_gpr, "dup 4s, w9", "ldr x9, [%0]\n dup v2.4s, w9")                                 \
    X(dup_2d_gpr, "dup 2d, x9", "ldr x9, [%0]\n dup v2.2d, x9")                                 \
    X(dup_16b_el, "dup 16b, b[5]", "dup v2.16b, v0.b[5]")                                       \
    X(dup_8h_el, "dup 8h, h[3]", "dup v2.8h, v0.h[3]")                                          \
    X(dup_4s_el, "dup 4s, s[2]", "dup v2.4s, v0.s[2]")                                          \
    X(dup_2d_el, "dup 2d, d[1]", "dup v2.2d, v0.d[1]")                                          \
    X(movi_16b, "movi 16b #0x5a", "movi v2.16b, #0x5a")                                         \
    X(movi_8h, "movi 8h #0x5a", "movi v2.8h, #0x5a")                                            \
    X(movi_8h_lsl, "movi 8h #0x5a, lsl 8", "movi v2.8h, #0x5a, lsl #8")                         \
    X(movi_4s, "movi 4s #0x12", "movi v2.4s, #0x12")                                            \
    X(movi_4s_lsl, "movi 4s #0xff, lsl 16", "movi v2.4s, #0xff, lsl #16")                       \
    X(movi_d, "movi d #ff00ff00ff00ff00", "movi d2, #0xff00ff00ff00ff00")                       \
    X(movi_d_alt, "movi d #00ff00ff00ff00ff", "movi d2, #0x00ff00ff00ff00ff")                   \
    X(mvni_8h, "mvni 8h #0x5a", "mvni v2.8h, #0x5a")                                            \
    X(mvni_4s, "mvni 4s #0x0f", "mvni v2.4s, #0x0f")                                            \
    X(mvni_4s_lsl, "mvni 4s #0x0f, lsl 8", "mvni v2.4s, #0x0f, lsl #8")                         \
    X(movi_4s_msl, "movi 4s #0x0f, msl 8", "movi v2.4s, #0x0f, msl #8")                         \
    X(mvni_4s_msl, "mvni 4s #0x0f, msl 8", "mvni v2.4s, #0x0f, msl #8")                         \
    X(mvni_4s_msl16, "mvni 4s #0x0f, msl 16", "mvni v2.4s, #0x0f, msl #16")                     \
    X(movi_2s, "movi 2s #0x12", "movi v2.2s, #0x12")                                            \
    X(mvni_2s, "mvni 2s #0x12", "mvni v2.2s, #0x12")                                            \
    X(movi_2d, "movi 2d #ff00ff00ff00ff00", "movi v2.2d, #0xff00ff00ff00ff00")                  \
    X(bic_2s, "bic 2s #0x0f", "mov v2.16b, v3.16b\n bic v2.2s, #0x0f")                         \
    X(orr_4s, "orr 4s #0x0f", "mov v2.16b, v3.16b\n orr v2.4s, #0x0f")                         \
    X(rev16_16b, "rev16 16b", "rev16 v2.16b, v0.16b")                                           \
    X(rev32_16b, "rev32 16b", "rev32 v2.16b, v0.16b")                                           \
    X(rev32_8h, "rev32 8h", "rev32 v2.8h, v0.8h")                                               \
    X(rev64_16b, "rev64 16b", "rev64 v2.16b, v0.16b")                                           \
    X(rev64_4s, "rev64 4s", "rev64 v2.4s, v0.4s")                                               \
    /* The scalar forms work on the one 64-bit lane a `d` register names and leave the other half
     * alone, which is what makes them usable for integer arithmetic on 128-bit halves. */        \
    X(neg_d, "neg d", "mov v2.16b, v0.16b\n neg d2, d0")                                        \
    X(abs_d, "abs d", "mov v2.16b, v0.16b\n abs d2, d0")                                        \
    X(cmeq_d_z, "cmeq d #0", "cmeq d2, d0, #0")                                                 \
    X(cmge_d_z, "cmge d #0", "cmge d2, d0, #0")                                                 \
    X(cmgt_d_z, "cmgt d #0", "cmgt d2, d0, #0")                                                 \
    X(cnt_16b, "cnt 16b", "cnt v2.16b, v0.16b")                                                 \
    X(fabs_4s, "fabs 4s", "fabs v2.4s, v0.4s")                                                  \
    X(fabs_2d, "fabs 2d", "fabs v2.2d, v0.2d")                                                  \
    X(fneg_4s, "fneg 4s", "fneg v2.4s, v0.4s")                                                  \
    X(fneg_2d, "fneg 2d", "fneg v2.2d, v0.2d")                                                  \
    X(fsqrt_2s, "fsqrt 2s", "fsqrt v2.2s, v0.2s")                                               \
    X(fsqrt_2d, "fsqrt 2d", "fsqrt v2.2d, v0.2d")                                               \
    X(shll_8h, "shll 8h", "shll v2.8h, v0.8b, #8")                                              \
    X(shll_4s, "shll 4s", "shll v2.4s, v0.4h, #16")                                             \
    X(shll2_2d, "shll2 2d", "shll2 v2.2d, v0.4s, #32")                                          \
    /* A float compared with zero, and the vector conversions to integers: the roundings ARM     \
     * gives them all, at both widths, with the patterns above feeding in NaN, the infinities and \
     * denormals as well as numbers. */                                                          \
    X(fcmeqz_4s, "fcmeq 4s #0.0", "fcmeq v2.4s, v0.4s, #0.0")                                   \
    X(fcmeqz_2s, "fcmeq 2s #0.0", "fcmeq v2.2s, v0.2s, #0.0")                                   \
    X(fcmeqz_2d, "fcmeq 2d #0.0", "fcmeq v2.2d, v0.2d, #0.0")                                   \
    X(fcmgtz_4s, "fcmgt 4s #0.0", "fcmgt v2.4s, v0.4s, #0.0")                                   \
    X(fcmgez_2d, "fcmge 2d #0.0", "fcmge v2.2d, v0.2d, #0.0")                                   \
    X(fcmlez_2d, "fcmle 2d #0.0", "fcmle v2.2d, v0.2d, #0.0")                                   \
    X(fcmltz_4s, "fcmlt 4s #0.0", "fcmlt v2.4s, v0.4s, #0.0")                                   \
    X(fcvtzs_4s, "fcvtzs 4s", "fcvtzs v2.4s, v0.4s")                                            \
    X(fcvtzs_2s, "fcvtzs 2s", "fcvtzs v2.2s, v0.2s")                                            \
    X(fcvtzs_2d, "fcvtzs 2d", "fcvtzs v2.2d, v0.2d")                                            \
    X(fcvtzu_4s, "fcvtzu 4s", "fcvtzu v2.4s, v0.4s")                                            \
    X(fcvtzu_2d, "fcvtzu 2d", "fcvtzu v2.2d, v0.2d")                                            \
    X(fcvtns_4s, "fcvtns 4s", "fcvtns v2.4s, v0.4s")                                            \
    X(fcvtns_2d, "fcvtns 2d", "fcvtns v2.2d, v0.2d")                                            \
    X(fcvtnu_4s, "fcvtnu 4s", "fcvtnu v2.4s, v0.4s")                                            \
    X(fcvtms_4s, "fcvtms 4s", "fcvtms v2.4s, v0.4s")                                            \
    X(fcvtms_2d, "fcvtms 2d", "fcvtms v2.2d, v0.2d")                                            \
    X(fcvtmu_4s, "fcvtmu 4s", "fcvtmu v2.4s, v0.4s")                                            \
    X(fcvtps_4s, "fcvtps 4s", "fcvtps v2.4s, v0.4s")                                            \
    X(fcvtps_2d, "fcvtps 2d", "fcvtps v2.2d, v0.2d")                                            \
    X(fcvtpu_4s, "fcvtpu 4s", "fcvtpu v2.4s, v0.4s")                                            \
    /* The integer comparisons against zero, including the pair of U forms nothing had. */       \
    X(cmeqz_16b, "cmeq 16b #0", "cmeq v2.16b, v0.16b, #0")                                      \
    X(cmgtz_16b, "cmgt 16b #0", "cmgt v2.16b, v0.16b, #0")                                      \
    X(cmgez_16b, "cmge 16b #0", "cmge v2.16b, v0.16b, #0")                                      \
    X(cmlez_16b, "cmle 16b #0", "cmle v2.16b, v0.16b, #0")                                      \
    X(cmltz_16b, "cmlt 16b #0", "cmlt v2.16b, v0.16b, #0")                                      \
    X(cmgez_2d, "cmge 2d #0", "cmge v2.2d, v0.2d, #0")                                          \
    X(cmlez_2d, "cmle 2d #0", "cmle v2.2d, v0.2d, #0")                                          \
    X(cmltz_2d, "cmlt 2d #0", "cmlt v2.2d, v0.2d, #0")                                          \
    X(cmlez_8h, "cmle 8h #0", "cmle v2.8h, v0.8h, #0")

#define X_CASES(X)                                                                              \
    X(umov_b3, "umov %w0, b[3]", "umov %w0, v0.b[3]")                                           \
    X(umov_h1, "umov %w0, h[1]", "umov %w0, v0.h[1]")                                           \
    X(umov_s2, "umov %w0, s[2]", "umov %w0, v0.s[2]")                                           \
    X(umov_d1, "umov %0, d[1]", "umov %0, v0.d[1]")                                             \
    X(smov_b5, "smov %w0, b[5]", "smov %w0, v0.b[5]")                                           \
    X(smov_h2, "smov %w0, h[2]", "smov %w0, v0.h[2]")                                           \
    X(smov_s1, "smov %0, s[1]", "smov %0, v0.s[1]")                                            \
    /* The pair forms write the base register back, which is the half of them a load does not read. */ \
    X(ldp_q_pre_wb, "ldp q pre-index writeback",                                                \
      "mov %0, x9\n ldr q2, [x9]\n stp q2, q2, [x9, #16]\n ldp q0, q1, [x9, #16]!\n"          \
      " sub %0, x9, %0")                                                                        \
    X(ldp_q_pre_neg_wb, "ldp q pre-index writeback back",                                       \
      "mov %0, x9\n add x9, x9, #32\n ldp q0, q1, [x9, #-16]!\n sub %0, x9, %0")               \
    X(stp_q_post_wb, "stp q post-index writeback",                                              \
      "mov %0, x9\n ldr q2, [x9]\n stp q2, q2, [x9], #32\n sub %0, x9, %0")

#define B_CASES(X)                                                                              \
    /* three-same integer */                                                                    \
    X(add_16b, "add 16b", "add v2.16b, v0.16b, v1.16b")                                         \
    X(add_8h, "add 8h", "add v2.8h, v0.8h, v1.8h")                                              \
    X(add_4s, "add 4s", "add v2.4s, v0.4s, v1.4s")                                              \
    X(add_2d, "add 2d", "add v2.2d, v0.2d, v1.2d")                                              \
    X(sub_16b, "sub 16b", "sub v2.16b, v0.16b, v1.16b")                                         \
    X(sub_8h, "sub 8h", "sub v2.8h, v0.8h, v1.8h")                                              \
    X(sub_4s, "sub 4s", "sub v2.4s, v0.4s, v1.4s")                                              \
    X(sub_2d, "sub 2d", "sub v2.2d, v0.2d, v1.2d")                                              \
    /* The scalar integer forms move 128-bit halves through the register file. */                \
    X(add_d, "add d", "add d2, d0, d1")                                    \
    X(sub_d, "sub d", "sub d2, d0, d1")                                    \
    X(mul_16b, "mul 16b", "mul v2.16b, v0.16b, v1.16b")                                         \
    X(mul_8h, "mul 8h", "mul v2.8h, v0.8h, v1.8h")                                              \
    X(mul_4s, "mul 4s", "mul v2.4s, v0.4s, v1.4s")                                              \
    X(and_16b, "and 16b", "and v2.16b, v0.16b, v1.16b")                                         \
    X(orr_16b, "orr 16b", "orr v2.16b, v0.16b, v1.16b")                                         \
    X(eor_16b, "eor 16b", "eor v2.16b, v0.16b, v1.16b")                                         \
    X(bic_16b, "bic 16b", "bic v2.16b, v0.16b, v1.16b")                                         \
    X(orn_16b, "orn 16b", "orn v2.16b, v0.16b, v1.16b")                                         \
    X(bsl_16b, "bsl 16b", "mov v2.16b, v0.16b\n bsl v2.16b, v1.16b, v3.16b")                     \
    X(bit_16b, "bit 16b", "mov v2.16b, v0.16b\n bit v2.16b, v1.16b, v3.16b")                     \
    X(bif_16b, "bif 16b", "mov v2.16b, v0.16b\n bif v2.16b, v1.16b, v3.16b")                     \
    X(mla_16b, "mla 16b", "mov v2.16b, v3.16b\n mla v2.16b, v0.16b, v1.16b")                     \
    X(mla_4s, "mla 4s", "mov v2.16b, v3.16b\n mla v2.4s, v0.4s, v1.4s")                          \
    X(mls_16b, "mls 16b", "mov v2.16b, v3.16b\n mls v2.16b, v0.16b, v1.16b")                     \
    X(mls_4s, "mls 4s", "mov v2.16b, v3.16b\n mls v2.4s, v0.4s, v1.4s")                          \
    X(smax_16b, "smax 16b", "smax v2.16b, v0.16b, v1.16b")                                      \
    X(smax_8h, "smax 8h", "smax v2.8h, v0.8h, v1.8h")                                           \
    X(smax_4s, "smax 4s", "smax v2.4s, v0.4s, v1.4s")                                           \
    X(smin_16b, "smin 16b", "smin v2.16b, v0.16b, v1.16b")                                      \
    X(smin_8h, "smin 8h", "smin v2.8h, v0.8h, v1.8h")                                           \
    X(smin_4s, "smin 4s", "smin v2.4s, v0.4s, v1.4s")                                           \
    X(umax_16b, "umax 16b", "umax v2.16b, v0.16b, v1.16b")                                      \
    X(umax_8h, "umax 8h", "umax v2.8h, v0.8h, v1.8h")                                           \
    X(umax_4s, "umax 4s", "umax v2.4s, v0.4s, v1.4s")                                           \
    X(umin_16b, "umin 16b", "umin v2.16b, v0.16b, v1.16b")                                      \
    X(umin_8h, "umin 8h", "umin v2.8h, v0.8h, v1.8h")                                           \
    X(umin_4s, "umin 4s", "umin v2.4s, v0.4s, v1.4s")                                           \
    X(cmgt_16b, "cmgt 16b", "cmgt v2.16b, v0.16b, v1.16b")                                      \
    X(cmgt_4s, "cmgt 4s", "cmgt v2.4s, v0.4s, v1.4s")                                           \
    X(cmgt_2d, "cmgt 2d", "cmgt v2.2d, v0.2d, v1.2d")                                           \
    X(cmge_16b, "cmge 16b", "cmge v2.16b, v0.16b, v1.16b")                                      \
    X(cmge_4s, "cmge 4s", "cmge v2.4s, v0.4s, v1.4s")                                           \
    X(cmeq_16b, "cmeq 16b", "cmeq v2.16b, v0.16b, v1.16b")                                      \
    X(cmeq_8b, "cmeq 8b", "cmeq v2.8b, v0.8b, v1.8b")                                           \
    X(cmeq_4h, "cmeq 4h", "cmeq v2.4h, v0.4h, v1.4h")                                           \
    X(cmeqz_16b, "cmeq 16b #0", "cmeq v2.16b, v0.16b, #0")                                      \
    X(cmeqz_8b, "cmeq 8b #0", "cmeq v2.8b, v0.8b, #0")                                          \
    X(cmeq_4s, "cmeq 4s", "cmeq v2.4s, v0.4s, v1.4s")                                           \
    X(cmeq_2d, "cmeq 2d", "cmeq v2.2d, v0.2d, v1.2d")                                           \
    /* The FP comparisons of the same group, which answer a mask of lanes rather than a value. */ \
    X(fcmeq_4s, "fcmeq 4s", "fcmeq v2.4s, v0.4s, v1.4s")                                        \
    X(fcmeq_2s, "fcmeq 2s", "fcmeq v2.2s, v0.2s, v1.2s")                                        \
    X(fcmeq_2d, "fcmeq 2d", "fcmeq v2.2d, v0.2d, v1.2d")                                        \
    X(fcmge_4s, "fcmge 4s", "fcmge v2.4s, v0.4s, v1.4s")                                        \
    X(fcmge_2d, "fcmge 2d", "fcmge v2.2d, v0.2d, v1.2d")                                        \
    X(fcmgt_4s, "fcmgt 4s", "fcmgt v2.4s, v0.4s, v1.4s")                                        \
    X(fcmgt_2d, "fcmgt 2d", "fcmgt v2.2d, v0.2d, v1.2d")                                        \
    X(facge_4s, "facge 4s", "facge v2.4s, v0.4s, v1.4s")                                        \
    X(facge_2d, "facge 2d", "facge v2.2d, v0.2d, v1.2d")                                        \
    X(facgt_4s, "facgt 4s", "facgt v2.4s, v0.4s, v1.4s")                                        \
    X(facgt_2d, "facgt 2d", "facgt v2.2d, v0.2d, v1.2d")                                        \
    X(cmhs_16b, "cmhs 16b", "cmhs v2.16b, v0.16b, v1.16b")                                      \
    X(cmhs_4s, "cmhs 4s", "cmhs v2.4s, v0.4s, v1.4s")                                           \
    X(cmhs_2d, "cmhs 2d", "cmhs v2.2d, v0.2d, v1.2d")                                           \
    X(cmhi_16b, "cmhi 16b", "cmhi v2.16b, v0.16b, v1.16b")                                      \
    X(cmhi_4s, "cmhi 4s", "cmhi v2.4s, v0.4s, v1.4s")                                           \
    /* The widening multiplies: a product is twice the width of its factors, so the pairs and the
     * halves matter more than in any other form. */                                              \
    X(umull_2d, "umull 2d", "umull v2.2d, v0.2s, v1.2s")                                         \
    X(umull2_2d, "umull2 2d", "umull2 v2.2d, v0.4s, v1.4s")                                      \
    X(smull_2d, "smull 2d", "smull v2.2d, v0.2s, v1.2s")                                         \
    X(smull2_2d, "smull2 2d", "smull2 v2.2d, v0.4s, v1.4s")                                      \
    X(umull_4s, "umull 4s", "umull v2.4s, v0.4h, v1.4h")                                         \
    X(smull_4s, "smull 4s", "smull v2.4s, v0.4h, v1.4h")                                         \
    X(umlal_2d, "umlal 2d", "mov v2.16b, v3.16b\n umlal v2.2d, v0.2s, v1.2s")                    \
    X(umlsl_2d, "umlsl 2d", "mov v2.16b, v3.16b\n umlsl v2.2d, v0.2s, v1.2s")                    \
    X(umaxp_16b, "umaxp 16b", "umaxp v2.16b, v0.16b, v1.16b")                                   \
    X(umaxp_4s, "umaxp 4s", "umaxp v2.4s, v0.4s, v1.4s")                                        \
    X(smaxp_16b, "smaxp 16b", "smaxp v2.16b, v0.16b, v1.16b")                                   \
    X(smaxp_4s, "smaxp 4s", "smaxp v2.4s, v0.4s, v1.4s")                                        \
    X(uminp_16b, "uminp 16b", "uminp v2.16b, v0.16b, v1.16b")                                   \
    X(uminp_8h, "uminp 8h", "uminp v2.8h, v0.8h, v1.8h")                                        \
    X(uminp_4s, "uminp 4s", "uminp v2.4s, v0.4s, v1.4s")                                        \
    X(addp_16b, "addp 16b", "addp v2.16b, v0.16b, v1.16b")                                      \
    X(addp_4s, "addp 4s", "addp v2.4s, v0.4s, v1.4s")                                           \
    X(addp_2d, "addp 2d, v", "addp v2.2d, v0.2d, v1.2d")                                        \
    /* narrows, widens, shifts */                                                               \
    X(xtn2_16b, "xtn2 16b", "mov v2.16b, v3.16b\n xtn2 v2.16b, v0.8h")                          \
    X(xtn2_8h, "xtn2 8h", "mov v2.16b, v3.16b\n xtn2 v2.8h, v0.4s")                             \
    X(xtn2_4s, "xtn2 4s", "mov v2.16b, v3.16b\n xtn2 v2.4s, v0.2d")                             \
    X(fcvtn2_4s, "fcvtn2 4s", "mov v2.16b, v3.16b\n fcvtn2 v2.4s, v0.2d")                       \
    X(fcvtl2_2d, "fcvtl2 2d", "fcvtl2 v2.2d, v0.4s")                                           \
    X(addhn_8b, "addhn 8b", "addhn v2.8b, v0.8h, v1.8h")                                        \
    X(addhn_4h, "addhn 4h", "addhn v2.4h, v0.4s, v1.4s")                                        \
    X(addhn_2s, "addhn 2s", "addhn v2.2s, v0.2d, v1.2d")                                        \
    X(sli_16b, "sli 16b #3", "mov v2.16b, v3.16b\n sli v2.16b, v0.16b, #3")                     \
    X(sri_4s, "sri 4s #7", "mov v2.16b, v3.16b\n sri v2.4s, v0.4s, #7")                         \
    X(usra_16b, "usra 16b #3", "mov v2.16b, v3.16b\n usra v2.16b, v0.16b, #3")                  \
    X(usra_4s, "usra 4s #7", "mov v2.16b, v3.16b\n usra v2.4s, v0.4s, #7")                      \
    X(ssra_2d, "ssra 2d #13", "mov v2.16b, v3.16b\n ssra v2.2d, v0.2d, #13")                    \
    X(ushl_4s, "ushl 4s", "ushl v2.4s, v0.4s, v1.4s")                                           \
    X(ushl_2s, "ushl 2s", "ushl v2.2s, v0.2s, v1.2s")                                           \
    X(ushl_8h, "ushl 8h", "ushl v2.8h, v0.8h, v1.8h")                                           \
    X(and_8b, "and 8b", "and v2.8b, v0.8b, v1.8b")                                              \
    X(add_2s, "add 2s", "add v2.2s, v0.2s, v1.2s")                                              \
    X(mul_2s, "mul 2s", "mul v2.2s, v0.2s, v1.2s")                                              \
    X(mls_2s, "mls 2s", "mov v2.16b, v3.16b\n mls v2.2s, v0.2s, v1.2s")                          \
    X(mls_8h, "mls 8h", "mov v2.16b, v3.16b\n mls v2.8h, v0.8h, v1.8h")                          \
    X(orr_8b, "orr 8b", "orr v2.8b, v0.8b, v1.8b")                                              \
    X(ins_b_lane3, "ins v2.b[3], w9", "ldr w9, [%0]\n mov v2.16b, v0.16b\n mov v2.b[3], w9")    \
    X(ins_h_lane3, "ins v2.h[3], w9", "ldr w9, [%0]\n mov v2.16b, v0.16b\n mov v2.h[3], w9")    \
    X(ins_s_lane3, "ins v2.s[3], w9", "ldr w9, [%0]\n mov v2.16b, v0.16b\n mov v2.s[3], w9")    \
    X(ins_d_lane1, "ins v2.d[1], x9", "ldr x9, [%0]\n mov v2.16b, v0.16b\n mov v2.d[1], x9")    \
    X(movi_8b, "movi 8b #0x30", "movi v2.8b, #0x30")                                            \
    X(sshl_16b, "sshl 16b", "sshl v2.16b, v0.16b, v1.16b")                                      \
    /* copy, move, immediate */                                                                 \
    X(ins_s_el, "ins s[1], s[3]", "mov v2.16b, v0.16b\n ins v2.s[1], v0.s[3]")                  \
    X(ins_d_el, "ins d[1], d[0]", "mov v2.16b, v3.16b\n ins v2.d[1], v0.d[0]")                  \
    X(ins_b_el, "ins b[6], b[1]", "mov v2.16b, v0.16b\n ins v2.b[6], v3.b[1]")                  \
    X(ins_s_gpr, "ins s[1], w9", "mov v2.16b, v0.16b\n ldr w9, [%1]\n ins v2.s[1], w9")         \
    X(ins_b_gpr, "ins b[2], w9", "mov v2.16b, v0.16b\n ldr w9, [%1, #4]\n ins v2.b[2], w9")     \
    X(ext_5, "ext 16b #5", "ext v2.16b, v0.16b, v1.16b, #5")                                    \
    X(ext_11, "ext 16b #11", "ext v2.16b, v0.16b, v1.16b, #11")                                 \
    X(zip1_16b, "zip1 16b", "zip1 v2.16b, v0.16b, v1.16b")                                      \
    X(zip2_16b, "zip2 16b", "zip2 v2.16b, v0.16b, v1.16b")                                      \
    X(zip1_4s, "zip1 4s", "zip1 v2.4s, v0.4s, v1.4s")                                           \
    X(zip2_4s, "zip2 4s", "zip2 v2.4s, v0.4s, v1.4s")                                           \
    X(uzp1_16b, "uzp1 16b", "uzp1 v2.16b, v0.16b, v1.16b")                                      \
    X(uzp2_16b, "uzp2 16b", "uzp2 v2.16b, v0.16b, v1.16b")                                      \
    X(uzp1_4s, "uzp1 4s", "uzp1 v2.4s, v0.4s, v1.4s")                                           \
    X(uzp2_4s, "uzp2 4s", "uzp2 v2.4s, v0.4s, v1.4s")                                           \
    X(trn1_16b, "trn1 16b", "trn1 v2.16b, v0.16b, v1.16b")                                      \
    X(trn2_16b, "trn2 16b", "trn2 v2.16b, v0.16b, v1.16b")                                      \
    X(trn1_4s, "trn1 4s", "trn1 v2.4s, v0.4s, v1.4s")                                           \
    X(trn2_4s, "trn2 4s", "trn2 v2.4s, v0.4s, v1.4s")                                           \
    X(tbl_1reg, "tbl 16b, 1 table", "tbl v2.16b, {v0.16b}, v1.16b")                             \
    X(tbl_2reg, "tbl 16b, 2 tables", "tbl v2.16b, {v0.16b, v1.16b}, v4.16b")                    \
    X(tbx_1reg, "tbx 16b, 1 table", "mov v2.16b, v3.16b\n tbx v2.16b, {v0.16b}, v1.16b")        \
    /* Floating point on vectors: the four arithmetic operations at both widths, the absolute
     * difference, and the multiply-accumulate pair. */                                           \
    X(fadd_4s, "fadd 4s", "fadd v2.4s, v0.4s, v1.4s")                                           \
    X(fadd_2s, "fadd 2s", "fadd v2.2s, v0.2s, v1.2s")                                           \
    X(fadd_2d, "fadd 2d", "fadd v2.2d, v0.2d, v1.2d")                                           \
    X(fsub_4s, "fsub 4s", "fsub v2.4s, v0.4s, v1.4s")                                           \
    X(fsub_2d, "fsub 2d", "fsub v2.2d, v0.2d, v1.2d")                                           \
    X(fmul_4s, "fmul 4s", "fmul v2.4s, v0.4s, v1.4s")                                           \
    X(fmul_2d, "fmul 2d", "fmul v2.2d, v0.2d, v1.2d")                                           \
    X(fdiv_4s, "fdiv 4s", "fdiv v2.4s, v0.4s, v1.4s")                                           \
    X(fdiv_2d, "fdiv 2d", "fdiv v2.2d, v0.2d, v1.2d")                                           \
    X(fabd_4s, "fabd 4s", "fabd v2.4s, v0.4s, v1.4s")                                           \
    X(fabd_2d, "fabd 2d", "fabd v2.2d, v0.2d, v1.2d")                                           \
    X(fmulx_4s, "fmulx 4s", "fmulx v2.4s, v0.4s, v1.4s")                                        \
    X(fmla_2d, "fmla 2d", "mov v2.16b, v3.16b\n fmla v2.2d, v0.2d, v1.2d")                      \
    X(fmls_4s, "fmls 4s", "mov v2.16b, v3.16b\n fmls v2.4s, v0.4s, v1.4s")

/* The by-element forms: the operations above with one lane of the second operand broadcast, and a
 * lane written out for every shape whose lane count allows it, so the three bits that name the lane
 * are checked at both ends of their range. */
#define BE_CASES(X)                                                                             \
    X(be_mul_8h, "mul 8h, h[4]", "mul v2.8h, v0.8h, v1.h[4]")                                   \
    X(be_mul_4s, "mul 4s, s[1]", "mul v2.4s, v0.4s, v1.s[1]")                                   \
    X(be_mul_4s3, "mul 4s, s[3]", "mul v2.4s, v0.4s, v1.s[3]")                                  \
    X(be_mla_8h, "mla 8h, h[1]", "mov v2.16b, v3.16b\n mla v2.8h, v0.8h, v1.h[1]")              \
    X(be_mla_4s, "mla 4s, s[2]", "mov v2.16b, v3.16b\n mla v2.4s, v0.4s, v1.s[2]")              \
    X(be_mls_8h, "mls 8h, h[3]", "mov v2.16b, v3.16b\n mls v2.8h, v0.8h, v1.h[3]")              \
    X(be_mls_4s, "mls 4s, s[3]", "mov v2.16b, v3.16b\n mls v2.4s, v0.4s, v1.s[3]")              \
    X(be_smull_4s, "smull 4s, h[1]", "smull v2.4s, v0.4h, v1.h[1]")                             \
    X(be_smull2_4s, "smull2 4s, h[2]", "smull2 v2.4s, v0.8h, v1.h[2]")                          \
    X(be_umull_4s, "umull 4s, h[3]", "umull v2.4s, v0.4h, v1.h[3]")                             \
    X(be_smlal_4s, "smlal 4s, h[0]", "mov v2.16b, v3.16b\n smlal v2.4s, v0.4h, v1.h[0]")        \
    X(be_umlal_4s, "umlal 4s, h[1]", "mov v2.16b, v3.16b\n umlal v2.4s, v0.4h, v1.h[1]")        \
    X(be_umlal2_4s, "umlal2 4s, h[2]", "mov v2.16b, v3.16b\n umlal2 v2.4s, v0.8h, v1.h[2]")     \
    X(be_smull_2d, "smull 2d, s[1]", "smull v2.2d, v0.2s, v1.s[1]")                             \
    X(be_smlal_2d, "smlal 2d, s[0]", "mov v2.16b, v3.16b\n smlal v2.2d, v0.2s, v1.s[0]")

/* The FP by-element forms, which are arithmetic on values: every input comes from a pattern row
 * that holds no NaN, because a NaN result is the one thing a native kernel and a wasm engine are
 * allowed to disagree on. */
#define BE_FP_CASES(X)                                                                          \
    X(befp_mul_4s, "fmul 4s, s[3]", "fmul v2.4s, v0.4s, v1.s[3]")                               \
    X(befp_mul_2s, "fmul 2s, s[1]", "fmul v2.2s, v0.2s, v1.s[1]")                               \
    X(befp_mul_2d, "fmul 2d, d[1]", "fmul v2.2d, v0.2d, v1.d[1]")                               \
    X(befp_mulx_4s, "fmulx 4s, s[2]", "fmulx v2.4s, v0.4s, v1.s[2]")                            \
    X(befp_mla_4s, "fmla 4s, s[1]", "mov v2.16b, v3.16b\n fmla v2.4s, v0.4s, v1.s[1]")          \
    X(befp_mla_2d, "fmla 2d, d[1]", "mov v2.16b, v3.16b\n fmla v2.2d, v0.2d, v1.d[1]")          \
    X(befp_mls_4s, "fmls 4s, s[3]", "mov v2.16b, v3.16b\n fmls v2.4s, v0.4s, v1.s[3]")          \
    X(befp_mls_2s, "fmls 2s, s[0]", "mov v2.16b, v3.16b\n fmls v2.2s, v0.2s, v1.s[0]")

/* Scalar floating point: moves between the GPR and FP register files, the integer conversions, and
 * the forms that work on the bit patterns rather than on the values. Arithmetic on the values
 * (fadd, fcvt, ...) is not translated yet, so it is not here. */
#define FP_CASES(X)                                                                        \
    X(fmov_w_s, "fmov %w0, s0", "fmov %w0, s0")                                            \
    X(fmov_x_d, "fmov %0, d0", "fmov %0, d0")                                              \
    X(fmov_s_w, "fmov s2, w0-in", "fmov s2, %w1\n" S2W)                                    \
    X(fmov_d_x, "fmov d2, x0-in", "fmov d2, %3\n" D2X)                                     \
    X(scvtf_s_w, "scvtf s, w0-in", "scvtf s2, %w1\n" S2W)                                  \
    X(ucvtf_s_w, "ucvtf s, w0-in", "ucvtf s2, %w1\n" S2W)                                  \
    X(scvtf_d_x, "scvtf d, x0-in", "scvtf d2, %3\n" D2X)                                   \
    X(ucvtf_d_x, "ucvtf d, x0-in", "ucvtf d2, %3\n" D2X)                                   \
    X(fcvtzs_w_s, "fcvtzs w, s", "fcvtzs w9, s0\n mov %0, x9")                             \
    X(fcvtzu_w_s, "fcvtzu w, s", "fcvtzu w9, s0\n mov %0, x9")                             \
    X(fcvtzs_x_d, "fcvtzs x, d", "fcvtzs %0, d0")                                          \
    X(fcvtzu_x_d, "fcvtzu x, d", "fcvtzu %0, d0")                                          \
    /* The scalar three-same group, which is the vector operation on the one lane a `d` register
     * names: integer add and subtract of the bit patterns, high half left alone. */             \
    X(add_d_d, "add d, d, d", "add d2, d0, d1\n" D2X)                                        \
    X(sub_d_d, "sub d, d, d", "sub d2, d0, d1\n" D2X)                                        \
    /* The high half of a vector register, which is where a 128-bit value's second word goes. */ \
    X(fmov_x_d1, "fmov %0, v2.d[1]", "fmov d2, %3\n fmov v2.d[1], %4\n fmov %0, v2.d[1]")     \
    X(fmov_d1_keeps_low, "fmov v2.d[1], x keeps d2", "fmov d2, %3\n fmov v2.d[1], %4\n fmov %0, d2") \
    /* fccmp compares only when its condition holds, and takes the flags it was given otherwise. */ \
    X(fccmp_taken, "fccmp, condition holds", "fcmp d0, d1\n fccmp d0, d1, #0x0, eq\n cset %0, ne") \
    X(fccmp_skipped, "fccmp, condition does not hold", "fcmp d0, d1\n fccmp d1, d0, #0x6, eq\n cset %0, ne") \
    X(fabd_d, "fabd d", "fmov d0, %3\n fmov d1, %4\n fabd d2, d0, d1\n" D2X)                  \
    X(fabd_s, "fabd s", "fmov s0, %w1\n fmov s1, %w2\n fabd s2, s0, s1\n" S2W)                  \
    X(fmulx_d, "fmulx d", "fmov d0, %3\n fmov d1, %4\n fmulx d2, d0, d1\n" D2X)                \
    X(fmulx_s, "fmulx s", "fmov s0, %w1\n fmov s1, %w2\n fmulx s2, s0, s1\n" S2W)              \
    /* The four fused forms: bit 15 negates the product and bit 21 the accumulator, so the
     * accumulator is the minuend and `fmsub` is `Va - Vn*Vm`, not the other way round. */       \
    X(fmadd_d, "fmadd d", "fmov d2, %4\n fmadd d3, d0, d1, d2\n fmov %0, d3")                   \
    X(fmsub_d, "fmsub d", "fmov d2, %4\n fmsub d3, d0, d1, d2\n fmov %0, d3")                   \
    X(fnmadd_d, "fnmadd d", "fmov d2, %4\n fnmadd d3, d0, d1, d2\n fmov %0, d3")                \
    X(fnmsub_d, "fnmsub d", "fmov d2, %4\n fnmsub d3, d0, d1, d2\n fmov %0, d3")                \
    X(fmsub_s, "fmsub s", "fmov s2, %w2\n fmsub s3, s0, s1, s2\n fmov w9, s3\n mov %0, x9")      \
    X(fnmsub_s, "fnmsub s", "fmov s2, %w2\n fnmsub s3, s0, s1, s2\n fmov w9, s3\n mov %0, x9")   \
    /* The scalar single-source group. `fsqrt` and `fabs` carry the marker bits that a wide
     * match on the conversions takes, so this is what tells the two groups apart. */           \
    X(fsqrt_d_s, "fsqrt d", "fsqrt d2, d0\n fmov %0, d2")                                      \
    X(fsqrt_s_s, "fsqrt s", "fsqrt s2, s0\n fmov w9, s2\n mov %0, x9")                          \
    X(fabs_d_s, "fabs d", "fabs d2, d0\n fmov %0, d2")                                          \
    X(fneg_d_s, "fneg d", "fneg d2, d0\n fmov %0, d2")                                          \
    X(frintn_d_s, "frintn d", "frintn d2, d0\n fmov %0, d2")                                    \
    X(frinta_d_s, "frinta d", "frinta d2, d0\n fmov %0, d2")                                    \
    X(frintz_d_s, "frintz d", "frintz d2, d0\n fmov %0, d2")                                    \
    /* A conversion with a fraction-bit count, which scales the integer before it becomes a
     * float: the form a compiler uses for a value held as a fixed-point fraction. */              \
    X(scvtf_d_w_f24, "scvtf d, w, #24", "scvtf d2, %w1, #0x18\n" D2X)                           \
    X(scvtf_d_w_f8, "scvtf d, w, #8", "scvtf d2, %w1, #0x8\n" D2X)                              \
    X(ucvtf_d_w_f30, "ucvtf d, w, #30", "ucvtf d2, %w1, #0x1e\n" D2X)                           \
    X(scvtf_s_w_f3, "scvtf s, w, #3", "scvtf s2, %w1, #0x3\n" S2W)                              \
    X(ucvtf_s_w_f20, "ucvtf s, w, #20", "ucvtf s2, %w1, #0x14\n" S2W)                           \
    X(scvtf_d_x_f10, "scvtf d, x, #10", "scvtf d2, %3, #0xa\n" D2X)                             \
    X(ucvtf_d_x_f32, "ucvtf d, x, #32", "ucvtf d2, %3, #0x20\n" D2X)                            \
    /* The conversions between a float and an integer in the same register, every rounding. */ \
    X(fcvtzu_d, "fcvtzu d", "fmov d0, %3\n fcvtzu d2, d0\n fmov %0, d2") \
    X(fcvtzu_s, "fcvtzu s", "fmov s0, %w1\n fcvtzu s2, s0\n fmov w9, s2\n mov %0, x9") \
    X(fcvtns_d, "fcvtns d", "fmov d0, %3\n fcvtns d2, d0\n fmov %0, d2") \
    X(fcvtns_s, "fcvtns s", "fmov s0, %w1\n fcvtns s2, s0\n fmov w9, s2\n mov %0, x9") \
    X(fcvtms_d, "fcvtms d", "fmov d0, %3\n fcvtms d2, d0\n fmov %0, d2") \
    X(fcvtms_s, "fcvtms s", "fmov s0, %w1\n fcvtms s2, s0\n fmov w9, s2\n mov %0, x9") \
    X(fcvtps_d, "fcvtps d", "fmov d0, %3\n fcvtps d2, d0\n fmov %0, d2") \
    X(fcvtps_s, "fcvtps s", "fmov s0, %w1\n fcvtps s2, s0\n fmov w9, s2\n mov %0, x9") \
    X(fcvtas_d, "fcvtas d", "fmov d0, %3\n fcvtas d2, d0\n fmov %0, d2") \
    X(fcvtas_s, "fcvtas s", "fmov s0, %w1\n fcvtas s2, s0\n fmov w9, s2\n mov %0, x9") \
    X(fcvtmu_d, "fcvtmu d", "fmov d0, %3\n fcvtmu d2, d0\n fmov %0, d2") \
    X(fcvtmu_s, "fcvtmu s", "fmov s0, %w1\n fcvtmu s2, s0\n fmov w9, s2\n mov %0, x9") \
    X(fcvtnu_d, "fcvtnu d", "fmov d0, %3\n fcvtnu d2, d0\n fmov %0, d2") \
    X(fcvtnu_s, "fcvtnu s", "fmov s0, %w1\n fcvtnu s2, s0\n fmov w9, s2\n mov %0, x9") \
    X(fcvtpu_d, "fcvtpu d", "fmov d0, %3\n fcvtpu d2, d0\n fmov %0, d2") \
    X(fcvtpu_s, "fcvtpu s", "fmov s0, %w1\n fcvtpu s2, s0\n fmov w9, s2\n mov %0, x9") \
    X(fcvtau_d, "fcvtau d", "fmov d0, %3\n fcvtau d2, d0\n fmov %0, d2") \
    X(fcvtau_s, "fcvtau s", "fmov s0, %w1\n fcvtau s2, s0\n fmov w9, s2\n mov %0, x9") \
    X(scvtf_d_self, "scvtf d, d", "fmov d0, %3\n scvtf d2, d0\n fmov %0, d2") \
    X(ucvtf_d_self, "ucvtf d, d", "fmov d0, %3\n ucvtf d2, d0\n fmov %0, d2") \
    X(scvtf_s_self, "scvtf s, s", "fmov s0, %w1\n scvtf s2, s0\n fmov w9, s2\n mov %0, x9") \
    X(ucvtf_s_self, "ucvtf s, s", "fmov s0, %w1\n ucvtf s2, s0\n fmov w9, s2\n mov %0, x9") \
    X(scvtf_s_x_f40, "scvtf s, x, #40", "scvtf s2, %3, #0x28\n" S2W)

struct vcase {
    void (*fn)(void);
    const char *name;
};

struct xcase {
    unsigned long (*fn)(void);
    const char *name;
};

struct fcase {
    unsigned long (*fn)(unsigned int, unsigned int, unsigned long, unsigned long);
    const char *name;
};

#define U_DEF(name, tag, body) DEF_U(u_##name, body)
#define B_DEF(name, tag, body) DEF_B(b_##name, body)
#define X_DEF(name, tag, body) DEF_X(x_##name, body)
#define F_DEF(name, tag, body) DEF_F(f_##name, body)
#define U_ENTRY(name, tag, body) {u_##name, tag},
#define B_ENTRY(name, tag, body) {b_##name, tag},
#define X_ENTRY(name, tag, body) {x_##name, tag},
#define F_ENTRY(name, tag, body) {f_##name, tag},

L_CASES(B_DEF)
U_CASES(U_DEF)
X_CASES(X_DEF)
B_CASES(B_DEF)
BE_CASES(B_DEF)
BE_FP_CASES(B_DEF)
FP_CASES(F_DEF)

static const struct vcase wide_cases[] = {L_CASES(B_ENTRY)};
static const struct vcase unary_cases[] = {U_CASES(U_ENTRY)};
static const struct vcase binary_cases[] = {B_CASES(B_ENTRY)};
static const struct vcase by_element_cases[] = {BE_CASES(B_ENTRY)};
static const struct vcase by_element_fp_cases[] = {BE_FP_CASES(B_ENTRY)};
static const struct xcase gpr_cases[] = {X_CASES(X_ENTRY)};
static const struct fcase fp_cases[] = {FP_CASES(F_ENTRY)};

static const unsigned char pairs[][2] = {{0, 1}, {2, 3}, {4, 0}, {4, 3}};

/* The rows a value can come from without being a NaN: 0, -0 and the denormal patterns. */
static const unsigned char value_pairs[][2] = {{0, 2}, {2, 3}, {3, 0}, {0, 3}, {3, 2}, {2, 0}};

struct fp_in {
    unsigned int f;
    unsigned long d;
};

static const struct fp_in fp_in[] = {
    {0x00000000u, 0x0000000000000000ul}, /* +0.0 */
    {0x80000000u, 0x8000000000000000ul}, /* -0.0 */
    {0x3f800000u, 0x3ff0000000000000ul}, /* 1.0 */
    {0xc0200000u, 0xc00c000000000000ul}, /* -2.5 / -3.5 */
    {0x7149f2cau, 0x47e0c37937e08000ul}, /* 1e30 */
    {0x7f800000u, 0x7ff0000000000000ul}, /* +inf */
    {0xff800000u, 0xfff0000000000000ul}, /* -inf */
    {0x3f400000u, 0x3fe8000000000000ul}, /* 0.75 */
    {0x4f000000u, 0x4330000000000000ul}, /* 2^31, 2^52 */
    {0xcf000000u, 0xc330000000000000ul}, /* -2^31, -2^52 */
    {0x7fc00000u, 0x7ff8000000000000ul}, /* quiet NaN */
    {0x7f7fffffu, 0x7feffffffffffffful}, /* float max, double max */
    {0x3fc00000u, 0x3ff8000000000000ul}, /* 1.5 */
};

static const unsigned char fp_pairs[][2] = {
    {0, 2}, {2, 3}, {3, 12}, {4, 2}, {5, 6}, {8, 3}, {9, 3}, {6, 5}, {10, 2}, {2, 10},
};

__attribute__((used)) void GUEST_ENTRY(void) {
    unsigned long n, p;

    setup();

    for (n = 0; n < sizeof wide_cases / sizeof wide_cases[0]; n++) {
        for (p = 0; p < sizeof pairs / sizeof pairs[0]; p++) {
            pa = patr + 32 * pairs[p][0];
            pb = patr + 32 * pairs[p][1];
            zero_results();
            wide_cases[n].fn();
            put_tag(wide_cases[n].name, pairs[p][0], pairs[p][1]);
            put_results(4);
        }
    }

    for (n = 0; n < sizeof unary_cases / sizeof unary_cases[0]; n++) {
        for (int i = 0; i < NPAT; i++) {
            pa = patr + 32 * i;
            pb = patr + 32 * ((i + 1) % NPAT);
            zero_results();
            unary_cases[n].fn();
            put_tag(unary_cases[n].name, i, -1);
            put_results(2);
        }
    }

    for (n = 0; n < sizeof binary_cases / sizeof binary_cases[0]; n++) {
        for (p = 0; p < sizeof pairs / sizeof pairs[0]; p++) {
            pa = patr + 32 * pairs[p][0];
            pb = patr + 32 * pairs[p][1];
            zero_results();
            binary_cases[n].fn();
            put_tag(binary_cases[n].name, pairs[p][0], pairs[p][1]);
            put_results(2);
        }
    }

    for (n = 0; n < sizeof by_element_cases / sizeof by_element_cases[0]; n++) {
        for (p = 0; p < sizeof pairs / sizeof pairs[0]; p++) {
            pa = patr + 32 * pairs[p][0];
            pb = patr + 32 * pairs[p][1];
            zero_results();
            by_element_cases[n].fn();
            put_tag(by_element_cases[n].name, pairs[p][0], pairs[p][1]);
            put_results(2);
        }
    }

    for (n = 0; n < sizeof by_element_fp_cases / sizeof by_element_fp_cases[0]; n++) {
        for (p = 0; p < sizeof value_pairs / sizeof value_pairs[0]; p++) {
            pa = patr + 32 * value_pairs[p][0];
            pb = patr + 32 * value_pairs[p][1];
            zero_results();
            by_element_fp_cases[n].fn();
            put_tag(by_element_fp_cases[n].name, value_pairs[p][0], value_pairs[p][1]);
            put_results(2);
        }
    }

    for (n = 0; n < sizeof gpr_cases / sizeof gpr_cases[0]; n++) {
        for (int i = 0; i < NPAT; i++) {
            pa = patr + 32 * i;
            put_tag(gpr_cases[n].name, i, -1);
            put_hex(gpr_cases[n].fn());
        }
    }

    for (n = 0; n < sizeof fp_cases / sizeof fp_cases[0]; n++) {
        for (p = 0; p < sizeof fp_pairs / sizeof fp_pairs[0]; p++) {
            put_tag(fp_cases[n].name, fp_pairs[p][0], fp_pairs[p][1]);
            put_hex(fp_cases[n].fn(fp_in[fp_pairs[p][0]].f, fp_in[fp_pairs[p][1]].f,
                                   fp_in[fp_pairs[p][0]].d, fp_in[fp_pairs[p][1]].d));
        }
    }

    flush();
    GUEST_EXIT(0);
}
