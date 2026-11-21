/* Freestanding guest for the koinevm PoC.
 *
 * Built twice: as a static aarch64 Linux executable (the guest, translated to wasm) and as a
 * native macOS arm64 program (the oracle, run directly). Only the write/exit shim differs, so
 * the arithmetic, control flow and memory traffic compared between the two are literally the
 * same source. */

#ifdef __APPLE__
extern long write(int, const void *, unsigned long);
extern void exit(int);
#define GUEST_WRITE(fd, buf, n) write((fd), (buf), (unsigned long)(n))
#define GUEST_EXIT(code) exit((int)(code))
#define GUEST_ENTRY guest_main
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

static unsigned long guest_strlen(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

static void guest_print(const char *s) { GUEST_WRITE(1, s, guest_strlen(s)); }

__attribute__((used)) void GUEST_ENTRY(void) {
    guest_print("hello from aarch64\n");

    volatile unsigned long limit = 10;
    unsigned long acc = 0;
    for (unsigned long i = 1; i <= limit; i++) acc += i * i;

    char buf[4];
    buf[0] = (char)('0' + acc / 100);
    buf[1] = (char)('0' + (acc / 10) % 10);
    buf[2] = (char)('0' + acc % 10);
    buf[3] = '\n';
    GUEST_WRITE(1, buf, 4);

    GUEST_EXIT(0);
}
