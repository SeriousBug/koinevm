/* A stand-in for /lib/ld-linux-aarch64.so.1.
 *
 * It does what the translator needs from a loader and nothing else: take the initial stack the
 * kernel built, find the auxv, report AT_BASE/AT_ENTRY/AT_PHDR and its own load address, then hand
 * control to the program it was started for. Built as ET_DYN so the translator has to place it at
 * a base the image was not linked for, the same way it will place the real loader.
 *
 * `_start` reads sp before any prologue can move it, which is why it is assembly and the C part
 * takes the stack as an argument: a real crt stub does the same. */

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

static unsigned long str_len(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

static void put(const char *s) { guest_syscall3(64, 1, (long)s, (long)str_len(s)); }

static void put_hex(unsigned long v) {
    static const char digits[] = "0123456789abcdef";
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; i++) buf[2 + i] = digits[(v >> (60 - 4 * i)) & 0xf];
    buf[18] = 0;
    put(buf);
}

static unsigned long auxv_value(unsigned long *auxv, unsigned long type) {
    for (unsigned long *p = auxv; p[0] != 0; p += 2) {
        if (p[0] == type) return p[1];
    }
    return 0;
}

/// Marks where this image's read-only data ended up, so the test can check the load base.
static const char marker[] = "ld-fake";

__attribute__((used)) void ld_main(unsigned long *sp) {
    unsigned long argc = sp[0];
    unsigned long *p = sp + 1 + argc + 1; // argv, then its NULL
    while (*p) p++;                       // envp
    unsigned long *auxv = p + 1;

    put("ld-fake: marker=");
    put_hex((unsigned long)marker);
    put(" base=");
    put_hex(auxv_value(auxv, 7)); // AT_BASE
    put(" entry=");
    put_hex(auxv_value(auxv, 9)); // AT_ENTRY
    put(" phdr=");
    put_hex(auxv_value(auxv, 3)); // AT_PHDR
    put(" pagesz=");
    put_hex(auxv_value(auxv, 6));
    put("\n");

    unsigned long entry = auxv_value(auxv, 9);
    if (entry == 0) {
        put("ld-fake: no AT_ENTRY\n");
        guest_exit(3);
    }
    ((void (*)(void))entry)();
    guest_exit(0);
}

__asm__(".globl _start\n"
        "_start:\n"
        "  mov x0, sp\n"
        "  b ld_main\n");
