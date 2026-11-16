/* Stack frames whose size is decided at run time.
 *
 * `sub sp, sp, xN` is how a caller sizes a frame for a buffer whose length it only learns while
 * running, which is what the loader does before it calls into the image it just mapped. In
 * add/sub the register fields that hold SP are 31, so an emitter that treats 31 as XZR drops the
 * write and leaves the buffer sitting on the frame's saved x29/x30. Nothing looks wrong until the
 * function returns, so these cases read SP back after each form instead of trusting it. */

#ifdef __APPLE__
extern long write(int, const void *, unsigned long);
extern void exit(int);
#define GUEST_WRITE(fd, buf, n) write((fd), (buf), (unsigned long)(n))
#define GUEST_EXIT(code) exit((int)(code))
#define GUEST_ENTRY stack_main
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

static void put_name(const char *s) {
    while (*s) put(*s++);
    put(' ');
}

/* Each probe moves SP, reads it back and restores it inside one asm block: a block that leaves SP
 * moved cannot return its results, because at -O0 the compiler spills them through SP itself. */
__attribute__((noinline)) static void probe_reg(unsigned long delta, unsigned long *r) {
    __asm__ volatile(
        "mov x9, sp\n\t"
        "sub sp, sp, %0\n\t"
        "mov x10, sp\n\t"
        "add sp, sp, %1, lsl #4\n\t"
        "mov x11, sp\n\t"
        "sub sp, sp, %1, lsl #4\n\t"
        "add sp, sp, %0\n\t"
        "mov x12, sp\n\t"
        "sub x13, x9, x10\n\t"
        "sub x11, x11, x10\n\t"
        "sub x12, x12, x9\n\t"
        "str x13, [%2]\n\t"
        "str x11, [%2, #8]\n\t"
        "str x12, [%2, #16]\n\t"
        :
        : "r"(delta), "r"(4ul), "r"(r)
        : "x9", "x10", "x11", "x12", "x13", "cc", "memory");
}

/* The extended-register forms, which is what the assembler picks for `sub sp, sp, xN`. */
__attribute__((noinline)) static void probe_ext(unsigned long delta, unsigned long *r) {
    __asm__ volatile(
        "mov x9, sp\n\t"
        "sub sp, sp, %0, uxtx\n\t"
        "mov x10, sp\n\t"
        "add sp, sp, %0, uxtx\n\t"
        "mov x11, sp\n\t"
        "sub x12, x9, x10\n\t"
        "sub x11, x11, x9\n\t"
        "str x12, [%1]\n\t"
        "str x11, [%1, #8]\n\t"
        :
        : "r"(delta), "r"(r)
        : "x9", "x10", "x11", "x12", "cc", "memory");
}

/* `and sp, xn, #-16` rounds a run-time address down; the source register is a plain Xn, only the
 * destination names SP. */
__attribute__((noinline)) static void probe_and_imm(unsigned long *r) {
    __asm__ volatile(
        "mov x9, sp\n\t"
        "sub x10, x9, #0x33\n\t"
        "and sp, x10, #-16\n\t"
        "mov x11, sp\n\t"
        "mov sp, x9\n\t"
        "bic x12, x10, #15\n\t"
        "sub x13, x11, x9\n\t"
        "cmp x11, x12\n\t"
        "cset x12, eq\n\t"
        "and x14, x9, #15\n\t"
        "str x12, [%0]\n\t"
        "str x13, [%0, #8]\n\t"
        "str x14, [%0, #16]\n\t"
        :
        : "r"(r)
        : "x9", "x10", "x11", "x12", "x13", "x14", "cc", "memory");
}

__attribute__((noinline)) static void fill_pattern(char *b, int n) {
    for (int i = 0; i < n; i++) b[i] = (char)(i * 31 + 7);
}

__attribute__((noinline)) static long sum_pattern(const char *b, int n) {
    long s = 0;
    for (int i = 0; i < n; i++) s += (unsigned char)b[i];
    return s;
}

/* A frame sized by an argument, with calls made while it is open. With SP dropped the buffer
 * lands on this function's own saved x29/x30, so the second call returns the sum and the `ret`
 * goes wherever the pattern bytes point. */
__attribute__((noinline)) static long dynamic_frame(int n) {
    char *b = __builtin_alloca((unsigned long)n);
    fill_pattern(b, n);
    long s = sum_pattern(b, n);
    return s + sum_pattern(b, n / 2);
}

__attribute__((noinline)) static long caller_guard(int n) {
    volatile unsigned long guard[8];
    for (int i = 0; i < 8; i++) guard[i] = 0x1111ul * (unsigned long)(i + 1);
    long s = dynamic_frame(n);
    unsigned long check = 0;
    for (int i = 0; i < 8; i++) check += guard[i];
    return (long)(check ^ (unsigned long)s);
}

/* Every level owns a run-time sized buffer and reads it after the levels below it have returned,
 * so one frame placed too high shows up as a mismatch rather than as a skipped case. */
__attribute__((noinline)) static long deep(int level, int n, unsigned long *seen) {
    char *b = __builtin_alloca((unsigned long)n);
    fill_pattern(b, n);
    seen[level] = (unsigned long)b;
    long below = level == 0 ? 0 : deep(level - 1, n, seen);
    long mine = sum_pattern(b, n);
    return mine + below;
}

__attribute__((used)) void GUEST_ENTRY(void) {
    unsigned long r[3];

    probe_reg(0x40, r);
    put_name("sub reg");
    put_hex(r[0]);
    put_name("add reg lsl4");
    put_hex(r[1]);
    put_name("restored");
    put_hex(r[2]);

    probe_ext(0x90, r);
    put_name("sub uxtx");
    put_hex(r[0]);
    put_name("restored");
    put_hex(r[1]);

    probe_and_imm(r);
    put_name("and imm lands");
    put_hex(r[0]);
    put_name("and imm delta");
    put_hex(r[1]);
    put_name("sp alignment");
    put_hex(r[2]);

    put_name("dynamic frame");
    put_hex((unsigned long)dynamic_frame(512));
    put_name("caller guard");
    put_hex((unsigned long)caller_guard(768));

    unsigned long seen[6];
    long total = deep(5, 256, seen);
    put_name("deep sum");
    put_hex((unsigned long)total);
    for (int i = 0; i < 5; i++) {
        put_name("deep gap");
        put_hex(seen[i + 1] - seen[i]);
    }

    GUEST_WRITE(1, out, out_n);
    GUEST_EXIT(0);
}
