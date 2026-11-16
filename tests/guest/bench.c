/* Integer benchmark guest: ALU-bound mixing plus a memory-bound pass.
 *
 * Same source builds to the aarch64 Linux guest (translated to wasm) and to the native macOS
 * program (timed directly), so the comparison is the same instruction stream both ways. */

#ifdef __APPLE__
extern long write(int, const void *, unsigned long);
extern void exit(int);
#define GUEST_WRITE(fd, buf, n) write((fd), (buf), (unsigned long)(n))
#define GUEST_EXIT(code) exit((int)(code))
#define GUEST_ENTRY bench_main
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

#define ARRAY 4096

static unsigned long array[ARRAY];

static unsigned long mix(unsigned long x) {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

__attribute__((used)) void GUEST_ENTRY(void) {
    volatile unsigned long rounds = 2000;
    volatile unsigned long inner = 250000;

    unsigned long seed = 0x9e3779b97f4a7c15UL;
    for (unsigned long r = 0; r < rounds; r++) {
        for (unsigned long i = 0; i < inner; i++) seed = mix(seed + i);
        for (unsigned long i = 0; i < ARRAY; i++) array[i] += seed ^ i;
    }

    unsigned long sum = seed;
    for (unsigned long i = 0; i < ARRAY; i++) sum += array[i];

    // Print the checksum as 16 hex digits, so wasm and native can be compared exactly.
    char buf[17];
    for (int i = 15; i >= 0; i--) {
        unsigned long d = sum & 0xf;
        buf[i] = (char)(d < 10 ? '0' + d : 'a' + (d - 10));
        sum >>= 4;
    }
    buf[16] = '\n';
    GUEST_WRITE(1, buf, 17);
    GUEST_EXIT(0);
}
