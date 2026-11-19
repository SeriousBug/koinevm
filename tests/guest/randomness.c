/* The bytes a program gets when it asks for entropy: /dev/random, /dev/urandom, getrandom and the
 * AT_RANDOM blob.
 *
 * The guest checks that two reads differ and that a large sample passes distribution tests;
 * tests/random.sh runs the same module twice and compares the printed samples, because a generator
 * seeded the same way every run produces uniform bytes and is still predictable. */

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

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20

#define AT_RANDOM 25

/// 1 MiB keeps the chi-square sensitive to a bias near 2% without making the run measurably slower.
#define SAMPLE (1u << 20)

/// 255 degrees of freedom: the mean of the statistic is 255 and 400 is about six standard
/// deviations out, so a correct generator fails this roughly once in ten million runs.
#define CHI_LIMIT 400

/// Six standard deviations of a half-and-half count over the sample.
#define DEV_LIMIT 3072

static long openat_(const char *path, long flags, long mode) {
    return sc6(56, AT_FDCWD, (long)path, flags, mode, 0, 0);
}

static long read_(long fd, void *buf, unsigned long n) {
    return sc6(63, fd, (long)buf, (long)n, 0, 0, 0);
}

static long write_(long fd, const void *buf, unsigned long n) {
    return sc6(64, fd, (long)buf, (long)n, 0, 0, 0);
}

static long close_(long fd) { return sc6(57, fd, 0, 0, 0, 0, 0); }

static long getrandom_(void *buf, unsigned long n) { return sc6(278, (long)buf, (long)n, 0, 0, 0, 0); }

static void *mmap_(unsigned long len) {
    return (void *)sc6(222, 0, (long)len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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

static void put(const char *s) { write_(1, s, str_len(s)); }

static void put_dec(unsigned long v) {
    char buf[21];
    int i = 20;
    buf[i] = 0;
    do {
        buf[--i] = '0' + v % 10;
        v /= 10;
    } while (v);
    put(buf + i);
}

static void put_hex(const unsigned char *p, unsigned long n) {
    static const char digits[] = "0123456789abcdef";
    char buf[2 * 32 + 1];
    for (unsigned long i = 0; i < n && i < 32; i++) {
        buf[2 * i] = digits[p[i] >> 4];
        buf[2 * i + 1] = digits[p[i] & 0xf];
    }
    buf[2 * (n < 32 ? n : 32)] = 0;
    put(buf);
}

static unsigned long failures;

static void check(int ok, const char *what) {
    put(ok ? "ok   " : "FAIL ");
    put(what);
    put("\n");
    if (!ok) failures++;
}

static void report(int ok, const char *feed, const char *what, unsigned long stat) {
    put(ok ? "ok   " : "FAIL ");
    put(feed);
    put(" ");
    put(what);
    put(" ");
    put_dec(stat);
    put("\n");
    if (!ok) failures++;
}

static int bytes_equal(const unsigned char *a, const unsigned char *b, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static int all_zero(const unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) {
        if (p[i]) return 0;
    }
    return 1;
}

static unsigned long fill(long fd, unsigned char *p, unsigned long n) {
    unsigned long got = 0;
    while (got < n) {
        long r = read_(fd, p + got, n - got);
        if (r <= 0) break;
        got += r;
    }
    return got;
}

static unsigned long counts[256];

/// The chi-square statistic of the byte frequencies, already divided by the expected count.
static unsigned long byte_chi(const unsigned char *p, unsigned long n) {
    for (int i = 0; i < 256; i++) counts[i] = 0;
    for (unsigned long i = 0; i < n; i++) counts[p[i]]++;
    unsigned long want = n / 256;
    unsigned long sum = 0;
    for (int i = 0; i < 256; i++) {
        long d = (long)counts[i] - (long)want;
        sum += (unsigned long)(d * d);
    }
    return sum / want;
}

/// The same over non-overlapping pairs of nibbles, which catches a correlation between neighbours
/// that the byte frequencies hide.
static unsigned long pair_chi(const unsigned char *p, unsigned long n, int high) {
    for (int i = 0; i < 256; i++) counts[i] = 0;
    for (unsigned long i = 0; i + 1 < n; i += 2) {
        unsigned long a = high ? p[i] >> 4 : p[i] & 0xf;
        unsigned long b = high ? p[i + 1] >> 4 : p[i + 1] & 0xf;
        counts[a * 16 + b]++;
    }
    unsigned long want = (n / 2) / 256;
    unsigned long sum = 0;
    for (int i = 0; i < 256; i++) {
        long d = (long)counts[i] - (long)want;
        sum += (unsigned long)(d * d);
    }
    return sum / want;
}

/// The largest distance from half the sample of any bit position's set-bit count.
static unsigned long bit_deviation(const unsigned char *p, unsigned long n) {
    unsigned long ones[8] = {0};
    for (unsigned long i = 0; i < n; i++) {
        for (int bit = 0; bit < 8; bit++) ones[bit] += (p[i] >> bit) & 1;
    }
    unsigned long half = n / 2;
    unsigned long worst = 0;
    for (int bit = 0; bit < 8; bit++) {
        unsigned long d = ones[bit] > half ? ones[bit] - half : half - ones[bit];
        if (d > worst) worst = d;
    }
    return worst;
}

/// How far the number of runs above and below 128 is from its expectation. A counter or a slow
/// drift gives long runs or none at all, which the frequencies do not see.
static unsigned long runs_deviation(const unsigned char *p, unsigned long n) {
    unsigned long runs = 1;
    int prev = p[0] > 127;
    for (unsigned long i = 1; i < n; i++) {
        int cur = p[i] > 127;
        if (cur != prev) runs++;
        prev = cur;
    }
    unsigned long want = n / 2 + 1;
    return runs > want ? runs - want : want - runs;
}

static void battery(const unsigned char *p, const char *feed) {
    unsigned long chi = byte_chi(p, SAMPLE);
    report(chi <= CHI_LIMIT, feed, "byte frequencies", chi);

    chi = pair_chi(p, SAMPLE, 0);
    report(chi <= CHI_LIMIT, feed, "low-nibble pairs", chi);

    chi = pair_chi(p, SAMPLE, 1);
    report(chi <= CHI_LIMIT, feed, "high-nibble pairs", chi);

    unsigned long dev = bit_deviation(p, SAMPLE);
    report(dev <= DEV_LIMIT, feed, "bit balance", dev);

    dev = runs_deviation(p, SAMPLE);
    report(dev <= DEV_LIMIT, feed, "runs above and below 128", dev);
}

/// The stack the kernel handed over, taken before any frame is pushed onto it.
__attribute__((naked)) void _start(void) {
    __asm__ volatile("mov x0, sp\n\tb run");
}

static unsigned long *auxv_find(unsigned long *sp, unsigned long type) {
    unsigned long *p = sp + 1 + sp[0];
    while (*p) p++;
    p++;
    while (*p) p++;
    p++;
    for (; p[0]; p += 2) {
        if (p[0] == type) return p + 1;
    }
    return 0;
}

void run(unsigned long *sp) {
    long urandom = openat_("/dev/urandom", O_RDONLY, 0);
    long random = openat_("/dev/random", O_RDONLY, 0);
    check(urandom >= 3 && random >= 3, "open /dev/urandom and /dev/random");

    unsigned char a[32], b[32], c[32], d[32];
    check(read_(urandom, a, 32) == 32 && read_(urandom, b, 32) == 32, "two reads of /dev/urandom");
    check(!bytes_equal(a, b, 32), "two reads of /dev/urandom differ");
    check(read_(random, c, 32) == 32 && !bytes_equal(a, c, 32),
          "/dev/random differs from /dev/urandom");
    check(getrandom_(d, 32) == 32 && !bytes_equal(a, d, 32), "getrandom differs from /dev/urandom");

    unsigned char *buf = mmap_(SAMPLE);
    int mapped = (long)buf > 0;
    check(mapped, "map the sample buffer");
    if (mapped) {
        unsigned long got = fill(urandom, buf, SAMPLE);
        check(got == SAMPLE, "read the sample from /dev/urandom");
        if (got == SAMPLE) {
            battery(buf, "urandom");
            put("sample ");
            put_hex(buf, 32);
            put("\n");
        }

        got = getrandom_(buf, SAMPLE) == (long)SAMPLE ? SAMPLE : 0;
        check(got == SAMPLE, "read the sample from getrandom");
        if (got == SAMPLE) battery(buf, "getrandom");
    }

    unsigned long *entry = auxv_find(sp, AT_RANDOM);
    unsigned char *at = entry ? (unsigned char *)*entry : 0;
    check(at && !all_zero(at, 16), "AT_RANDOM is present and not zero");
    if (at) {
        put("auxv ");
        put_hex(at, 16);
        put("\n");
    }

    if (urandom >= 3) close_(urandom);
    if (random >= 3) close_(random);
    put(failures ? "randomness: FAILURES\n" : "randomness: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}
