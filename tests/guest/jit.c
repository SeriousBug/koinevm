/* Guest that generates machine code into a page of its own and jumps into it, which is what a JIT
 * does: the page it writes has no file behind it, so nothing about it is known before it runs.
 *
 * The encodings are written as data rather than compiled, so what runs is a word the guest put
 * there and not something the translator saw in an image.
 *
 * No native oracle can run this the same way: macOS needs `MAP_JIT` and a write-protect toggle per
 * thread. So the guest asserts what a Linux kernel owes a JIT and reports each check, and
 * tests/jit.sh requires every check to pass. */

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

#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define PAGE 4096

/// The size of the first wasm memory: the address space past it is a chunk of its own, and a call
/// into code there is a pc the dispatcher has to tell apart from the one 4 GiB below it.
#define CHUNK 0x100000000ul

static void *mmap(void *addr, unsigned long len, long prot) {
    return (void *)sc6(222, (long)addr, (long)len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
static long munmap(void *addr, unsigned long len) { return sc6(215, (long)addr, (long)len, 0, 0, 0, 0); }
static long mprotect(void *addr, unsigned long len, long prot) {
    return sc6(226, (long)addr, (long)len, prot, 0, 0, 0);
}
static long write_(long fd, const void *buf, unsigned long n) { return sc6(64, fd, (long)buf, n, 0, 0, 0); }

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

static void put(const char *s) { write_(1, s, str_len(s)); }

static void put_hex(unsigned long v) {
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; i++) {
        int d = (int)((v >> (60 - 4 * i)) & 0xf);
        buf[2 + i] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    }
    buf[18] = '\n';
    write_(1, buf, 19);
}

static int failed;

static void check(int ok, const char *what, unsigned long got) {
    if (ok) return;
    failed = 1;
    put("FAIL ");
    put(what);
    put(": ");
    put_hex(got);
}

/// The cache maintenance a guest does after writing code, as on any kernel whose caches are not
/// coherent between a store and an instruction fetch.
static void flush(void *start, unsigned long len) {
    unsigned long ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    unsigned long dline = 4ul << ((ctr >> 16) & 0xf);
    unsigned long iline = 4ul << (ctr & 0xf);
    for (unsigned long p = (unsigned long)start; p < (unsigned long)start + len; p += dline)
        __asm__ volatile("dc cvau, %0" ::"r"(p) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    for (unsigned long p = (unsigned long)start; p < (unsigned long)start + len; p += iline)
        __asm__ volatile("ic ivau, %0" ::"r"(p) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
}

// add x0, x0, #1; ret
static const unsigned int add_one[] = {0x91000400u, 0xd65f03c0u};
// movz w0, #7; ret
static const unsigned int yield_seven[] = {0x528000e0u, 0xd65f03c0u};
// add x0, x0, x1; ret
static const unsigned int add_pair[] = {0x8b010000u, 0xd65f03c0u};
// movz x8, #172 (getpid); svc #0; ret
static const unsigned int syscall_tid[] = {0xd2801588u, 0xd4000001u, 0xd65f03c0u};

static void place(unsigned int *at, const unsigned int *words, int n) {
    for (int i = 0; i < n; i++) ((volatile unsigned int *)at)[i] = words[i];
}

/// A function of the guest's own that generated code calls back into.
static long bump(long x) { return x + 1000; }

int main(void) {
    // A page written and then executed: the bytes are the guest's, and no file holds them.
    unsigned int *code = mmap(0, PAGE, PROT_READ | PROT_WRITE);
    check((long)code > 0, "mmap for code", (unsigned long)code);
    place(code, add_one, 2);
    flush(code, 8);
    check(mprotect(code, PAGE, PROT_READ | PROT_EXEC) == 0, "mprotect to execute", (unsigned long)code);
    long (*add1)(long) = (long (*)(long))code;
    check(add1(41) == 42, "code run after mprotect", (unsigned long)add1(41));

    // The same page again, after a write: what runs is what the guest holds now.
    check(mprotect(code, PAGE, PROT_READ | PROT_WRITE) == 0, "mprotect back to write", (unsigned long)code);
    place(code, yield_seven, 2);
    flush(code, 8);
    check(mprotect(code, PAGE, PROT_READ | PROT_EXEC) == 0, "mprotect to execute again", 0);
    check(add1(0) == 7, "rewritten code runs", (unsigned long)add1(0));

    // A page mapped executable and writable in one call, with no mprotect in between.
    unsigned int *rwx = mmap(0, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC);
    check((long)rwx > 0, "mmap RWX", (unsigned long)rwx);
    place(rwx, add_pair, 2);
    flush(rwx, 8);
    check(((long (*)(long, long))rwx)(20, 22) == 42, "code in an RWX page", (unsigned long)rwx);

    // A branch from one page into the next: the run enters a page it has translated nothing of.
    unsigned int *two = mmap(0, 2 * PAGE, PROT_READ | PROT_WRITE);
    check((long)two > 0, "mmap two pages", (unsigned long)two);
    unsigned int *tail = (unsigned int *)((char *)two + PAGE - 8);
    place(tail, add_one, 1);
    // b +4, into the second page
    place(tail + 1, (const unsigned int[]){0x14000001u}, 1);
    unsigned int *next = (unsigned int *)((char *)two + PAGE);
    place(next, (const unsigned int[]){0xf1000421u}, 1);    // subs x1, x1, #1
    place(next + 1, (const unsigned int[]){0x54ffffa1u}, 1); // b.ne tail
    place(next + 2, (const unsigned int[]){0xd65f03c0u}, 1); // ret
    flush(two, 2 * PAGE);
    check(mprotect(two, 2 * PAGE, PROT_READ | PROT_EXEC) == 0, "mprotect two pages", 0);
    long (*count)(long, long) = (long (*)(long, long))tail;
    check(count(0, 5) == 5, "a branch across a page boundary", (unsigned long)count(0, 5));

    // Generated code that calls translated code, and one that makes a syscall. The call is a
    // `movz`/`movk` pair and a `blr`, because the image is a gigabyte below the code page, and the
    // return address goes on the stack because a `blr` overwrites x30.
    check(mprotect(code, PAGE, PROT_READ | PROT_WRITE) == 0, "mprotect for the call page", 0);
    unsigned long target = (unsigned long)bump;
    place(code, (const unsigned int[]){0xa9bf7bfdu}, 1); // stp x29, x30, [sp, #-16]!
    place(code + 1, (const unsigned int[]){0xd2800009u | ((unsigned int)(target & 0xffff) << 5)}, 1);
    place(code + 2, (const unsigned int[]){0xf2a00009u | ((unsigned int)((target >> 16) & 0xffff) << 5)}, 1);
    place(code + 3, (const unsigned int[]){0xd63f0120u}, 1); // blr x9
    place(code + 4, (const unsigned int[]){0xa8c17bfdu}, 1); // ldp x29, x30, [sp], #16
    place(code + 5, (const unsigned int[]){0xd65f03c0u}, 1); // ret
    flush(code, 24);
    check(mprotect(code, PAGE, PROT_READ | PROT_EXEC) == 0, "mprotect the call page", 0);
    check(add1(5) == 1005, "generated code calls the guest", (unsigned long)add1(5));
    check(mprotect(code, PAGE, PROT_READ | PROT_WRITE) == 0, "mprotect for the syscall page", 0);
    place(code, syscall_tid, 3);
    flush(code, 12);
    check(mprotect(code, PAGE, PROT_READ | PROT_EXEC) == 0, "mprotect the syscall page", 0);
    check(add1(0) > 0, "a syscall from generated code", (unsigned long)add1(0));

    // Code above the first chunk, which is where a runtime with a cage of its own puts what it
    // compiles. The page is a different mapping from the one below the boundary, and so is every
    // pc in it: a dispatcher keyed by a 32-bit address would run the block 4 GiB below instead.
    unsigned int *high = mmap((void *)(2 * CHUNK), PAGE, PROT_READ | PROT_WRITE);
    check((unsigned long)high == 2 * CHUNK, "mmap for code above 4 GiB", (unsigned long)high);
    place(high, add_one, 2);
    flush(high, 8);
    check(mprotect(high, PAGE, PROT_READ | PROT_EXEC) == 0, "mprotect to execute above 4 GiB", 0);
    long high_one = ((long (*)(long))high)(41);
    check(high_one == 42, "code above 4 GiB runs", (unsigned long)high_one);
    check(mprotect(high, PAGE, PROT_READ | PROT_WRITE) == 0, "mprotect back to write above 4 GiB", 0);
    place(high, syscall_tid, 3);
    flush(high, 12);
    check(mprotect(high, PAGE, PROT_READ | PROT_EXEC) == 0, "mprotect the syscall page above 4 GiB", 0);
    long high_tid = ((long (*)(long))high)(0);
    check(high_tid > 0, "a syscall made from above 4 GiB answers", (unsigned long)high_tid);
    check(munmap(high, PAGE) == 0, "munmap above 4 GiB", 0);

    // A page given back and mapped again starts over, the way a fresh mapping does.
    check(munmap(code, PAGE) == 0, "munmap the code page", 0);

    if (!failed) put("jit: all checks passed\n");
    guest_exit(failed);
    return 0;
}

void _start(void) {
    long code = (long)main();
    guest_exit(code);
}
