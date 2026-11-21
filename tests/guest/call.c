/* Freestanding guest for the koinevm PoC: calls, recursion, a function pointer, division.
 *
 * Built twice from the same source: as a static aarch64 Linux executable (translated to wasm) and
 * as a native macOS arm64 program (the oracle). Only the write/exit shim differs. */

#ifdef __APPLE__
extern long write(int, const void *, unsigned long);
extern void exit(int);
#define GUEST_WRITE(fd, buf, n) write((fd), (buf), (unsigned long)(n))
#define GUEST_EXIT(code) exit((int)(code))
#define GUEST_ENTRY call_main
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

static unsigned long slen(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

static char outbuf[256];
static unsigned long outn;

static void put(const char *s) {
    unsigned long n = slen(s);
    for (unsigned long i = 0; i < n; i++) outbuf[outn++] = s[i];
}

static void putnum(unsigned long v) {
    char tmp[24];
    int i = 0;
    if (v == 0) {
        outbuf[outn++] = '0';
        return;
    }
    while (v && i < 24) {
        tmp[i++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (i > 0) outbuf[outn++] = tmp[--i];
}

static void flush(void) {
    GUEST_WRITE(1, outbuf, outn);
    outn = 0;
}

static unsigned long fib(unsigned long n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

typedef unsigned long (*fn_t)(unsigned long);

static __attribute__((noinline, used)) unsigned long square(unsigned long x) { return x * x; }

static __attribute__((noinline, used)) unsigned long add100(unsigned long x) { return x + 100; }

static fn_t const table[2] = {square, add100};

static __attribute__((noinline, used)) unsigned long apply(fn_t fn, unsigned long x) { return fn(x); }

static __attribute__((noinline, used)) long divloop(long n) {
    volatile long d = 7;
    long acc = 0;
    for (long i = 0; i < n; i++) acc += i / d;
    return acc;
}

__attribute__((used)) void GUEST_ENTRY(void) {
    put("fib(20)=");
    putnum(fib(20));
    put("\n");

    volatile unsigned long which = 0;
    put("apply(table[0],111)=");
    putnum(apply(table[which], 111));
    put("\n");

    volatile unsigned long which1 = 1;
    put("apply(table[1],111)=");
    putnum(apply(table[which1], 111));
    put("\n");

    put("divloop(1000)=");
    putnum((unsigned long)divloop(1000));
    put("\n");

    flush();
    GUEST_EXIT(7);
}
