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

static char out[1 << 20];
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
    X(rbit_clz_pair, "rbit; clz; lsr #2", "rbit %0, %1\n clz %0, %0\n lsr %0, %0, #2")      \
    /* Bitfield moves, including the ones whose field wraps past the top of the register: those
     * are the forms a compiler emits for a shifted field and they are easy to mask wrongly. */    \
    X(ubfx_2_5, "ubfx #2 #5", "ubfx %0, %1, #2, #5")                                          \
    X(ubfx_0_1, "ubfx #0 #1", "ubfx %0, %1, #0, #1")                                          \
    X(ubfx_31_1, "ubfx #31 #1", "ubfx %0, %1, #31, #1")                                       \
    X(ubfx_60_4, "ubfx #60 #4", "ubfx %0, %1, #60, #4")                                       \
    X(sbfx_3_7, "sbfx #3 #7", "sbfx %0, %1, #3, #7")                                          \
    X(sbfx_62_2, "sbfx #62 #2", "sbfx %0, %1, #62, #2")                                       \
    X(ubfiz_2_1, "ubfiz #2 #1", "ubfiz %0, %1, #2, #1")                                       \
    X(ubfiz_4_8, "ubfiz #4 #8", "ubfiz %0, %1, #4, #8")                                       \
    X(ubfiz_60_4, "ubfiz #60 #4", "ubfiz %0, %1, #60, #4")                                    \
    X(sbfiz_5_6, "sbfiz #5 #6", "sbfiz %0, %1, #5, #6")                                       \
    X(sbfiz_1_1, "sbfiz #1 #1", "sbfiz %0, %1, #1, #1")                                       \
    X(sbfiz_61_3, "sbfiz #61 #3", "sbfiz %0, %1, #61, #3")                                    \
    X(bfi_2_1, "bfi #2 #1", "mov %0, %1\n bfi %0, %1, #2, #1")                                \
    X(bfi_8_4, "bfi #8 #4", "mov %0, %1\n bfi %0, %1, #8, #4")                                \
    X(bfxil_4_6, "bfxil #4 #6", "mov %0, %1\n bfxil %0, %1, #4, #6")                          \
    X(bfc_3_2, "bfc #3 #2", "mov %0, %1\n bfc %0, #3, #2")                                    \
    X(bfc_50_5, "bfc #50 #5", "mov %0, %1\n bfc %0, #50, #5")                                 \
    /* The 32-bit register forms: a compiler emits `sxtb w` for every `(signed char)` cast, and a
     * sign extension that only reaches 32 bits has to fill the top half of the result with it. */ \
    X(sxtb_w, "sxtb w", "sxtb %w0, %w1")                                                      \
    X(sxth_w, "sxth w", "sxth %w0, %w1")                                                      \
    X(uxtb_w, "uxtb w", "uxtb %w0, %w1")                                                      \
    X(uxth_w, "uxth w", "uxth %w0, %w1")                                                      \
    X(sbfx_w_3_7, "sbfx w #3 #7", "sbfx %w0, %w1, #3, #7")                                    \
    X(ubfx_w_0_8, "ubfx w #0 #8", "ubfx %w0, %w1, #0, #8")                                    \
    X(sbfiz_w_5_6, "sbfiz w #5 #6", "sbfiz %w0, %w1, #5, #6")                                 \
    X(bfi_w_8_4, "bfi w #8 #4", "mov %w0, %w1\n bfi %w0, %w1, #8, #4")                           \
    /* A rotate by immediate is `extr` with the same register twice, and the 32-bit form is where
     * the bits that leave one end have to come back at the other end of 32 bits rather than of 64:
     * every 32-bit rotate in a hash, a CRC or a PRNG is this instruction. */                     \
    X(ror_w_7, "ror w #7", "ror %w0, %w1, #7")                                                 \
    X(ror_w_1, "ror w #1", "ror %w0, %w1, #1")                                                 \
    X(ror_w_31, "ror w #31", "ror %w0, %w1, #31")                                              \
    X(ror_x_13, "ror x #13", "ror %0, %1, #13")                                                \
    X(ror_x_63, "ror x #63", "ror %0, %1, #63")                                                \
    X(extr_w_5, "extr w #5 of two", "lsl %w0, %w1, #3\n extr %w0, %w1, %w0, #5")           \
    X(extr_x_9, "extr x #9 of two", "lsl %0, %1, #3\n extr %0, %1, %0, #9")                \
    /* The high half of a product, which bignum code is built from: `mul` alone answers the low. */ \
    X(umulh_self, "umulh x", "umulh %0, %1, %1")                                                \
    X(smulh_self, "smulh x", "smulh %0, %1, %1")                                                \
    /* The carry forms, which is how bignum code adds a limb: the first instruction makes the
     * carry and the second one spends it, so a second operand that is stored instead of the sum
     * shows up as the wrong limb rather than as a wrong flag. */                                 \
    X(adcs_after_adds, "adcs after adds", "adds %0, %1, %1\n adcs %0, %0, %1")                   \
    X(sbcs_after_subs, "sbcs after subs", "subs %0, %1, %1\n sbcs %0, %1, %0")                   \
    X(adcs_w, "adcs w", "adds %w0, %w1, %w1\n adcs %w0, %w0, %w1")                               \
    X(sbcs_w, "sbcs w", "subs %w0, %w1, %w1\n sbcs %w0, %w1, %w0")                             \
    /* The logical forms take a shifted or rotated second operand, which is the shape every hash
     * round has: `eor x16,x16,x25,ror#18` is three of SHA-512's sigma functions. */              \
    X(eor_x_ror18, "eor x ror#18", "eor %0, %1, %1, ror #18")                                  \
    X(eor_x_ror41, "eor x ror#41", "eor %0, %1, %1, ror #41")                                   \
    X(eor_x_lsr7, "eor x lsr#7", "eor %0, %1, %1, lsr #7")                                      \
    X(eor_x_lsr6, "eor x lsr#6", "eor %0, %1, %1, lsr #6")                                      \
    X(eor_x_lsl9, "eor x lsl#9", "eor %0, %1, %1, lsl #9")                                      \
    X(eor_x_asr3, "eor x asr#3", "eor %0, %1, %1, asr #3")                                      \
    X(orr_x_ror13, "orr x ror#13", "orr %0, %1, %1, ror #13")                                   \
    X(and_x_lsr11, "and x lsr#11", "and %0, %1, %1, lsr #11")                                   \
    X(bic_x_asr5, "bic x asr#5", "bic %0, %1, %1, asr #5")                                      \
    X(orn_x_lsl7, "orn x lsl#7", "orn %0, %1, %1, lsl #7")                                      \
    X(eor_w_ror13, "eor w ror#13", "eor %w0, %w1, %w1, ror #13")                                \
    X(eor_w_lsr3, "eor w lsr#3", "eor %w0, %w1, %w1, lsr #3")                                   \
    X(and_w_asr2, "and w asr#2", "and %w0, %w1, %w1, asr #2")                                   \
    X(bic_w_lsl1, "bic w lsl#1", "bic %w0, %w1, %w1, lsl #1")                                   \
    /* Adds and subs whose second operand is shifted or extended: the shape a length or an offset
     * is computed in, and the one a hash uses to find the end of its input. */                   \
    X(add_x_lsl4, "add x lsl#4", "add %0, %1, %1, lsl #4")                                      \
    X(add_x_lsr3, "add x lsr#3", "add %0, %1, %1, lsr #3")                                      \
    X(add_x_asr2, "add x asr#2", "add %0, %1, %1, asr #2")                                      \
    X(sub_x_lsl2, "sub x lsl#2", "sub %0, %1, %1, lsl #2")                                      \
    X(add_w_lsl4, "add w lsl#4", "add %w0, %w1, %w1, lsl #4")                                   \
    X(sub_w_asr3, "sub w asr#3", "sub %w0, %w1, %w1, asr #3")                                   \
    X(add_x_uxtb, "add x uxtb", "add %0, %1, %w1, uxtb")                                        \
    X(add_x_sxtb_2, "add x sxtb lsl#2", "add %0, %1, %w1, sxtb #2")                             \
    X(add_x_uxth_1, "add x uxth lsl#1", "add %0, %1, %w1, uxth #1")                             \
    X(sub_x_sxth_3, "sub x sxth lsl#3", "sub %0, %1, %w1, sxth #3")                             \
    X(add_w_uxtb, "add w uxtb", "add %w0, %w1, %w1, uxtb")                                      \
    X(add_x_uxtw_2, "add x uxtw lsl#2", "add %0, %1, %w1, uxtw #2")

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
            for (const char *p = cases[c].name; *p; p++) put(*p);
            put(' ');
            put_hex(pattern(i));
            put_hex(cases[c].fn(pattern(i)));
        }
    }
    GUEST_WRITE(1, out, out_n);
    GUEST_EXIT(0);
}
