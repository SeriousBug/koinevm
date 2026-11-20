/* Guest that reads and writes the devices a kernel keeps in `/dev`: the ones that answer with
 * nothing, with zeros, with a failure, with random bytes and with the terminal, plus the links a
 * program reaches its own descriptors through.
 *
 * No native oracle can run this: `/dev` on the machine that builds the fixtures is macOS's. tests/
 * dev.sh requires every check to pass, and the bytes the test writes through `/dev/stdout` to have
 * come out. */

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
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0x40
#define O_TRUNC 0x200
#define O_DIRECTORY 0x10000
#define O_CLOEXEC 0x80000
#define S_IFMT 0xf000
#define S_IFCHR 0x2000
#define S_IFDIR 0x4000
#define ENOSPC 28

static long openat_(const char *path, long flags, long mode) {
    return sc6(56, AT_FDCWD, (long)path, flags, mode, 0, 0);
}
static long close_(long fd) { return sc6(57, fd, 0, 0, 0, 0, 0); }
static long read_(long fd, void *buf, unsigned long n) { return sc6(63, fd, (long)buf, (long)n, 0, 0, 0); }
static long write_(long fd, const void *buf, unsigned long n) { return sc6(64, fd, (long)buf, (long)n, 0, 0, 0); }
static long unlinkat_(const char *path) { return sc6(35, AT_FDCWD, (long)path, 0, 0, 0, 0); }
static long readlinkat_(const char *path, char *buf, unsigned long n) {
    return sc6(78, AT_FDCWD, (long)path, (long)buf, (long)n, 0, 0);
}
static long fstatat_(const char *path, void *st, long flags) { return sc6(79, AT_FDCWD, (long)path, (long)st, flags, 0, 0); }
static long fstat_(long fd, void *st) { return sc6(80, fd, (long)st, 0, 0, 0, 0); }
static long getdents64_(long fd, void *buf, unsigned long n) { return sc6(61, fd, (long)buf, (long)n, 0, 0, 0); }

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

static void check(int ok, const char *what, long got) {
    if (ok) return;
    failed = 1;
    put("FAIL ");
    put(what);
    put(": ");
    put_hex((unsigned long)got);
}

static char buf[4096];

static int contains(const char *hay, long n, const char *needle) {
    unsigned long k = str_len(needle);
    for (long i = 0; i + (long)k <= n; i++) {
        unsigned long j = 0;
        while (j < k && hay[i + (long)j] == needle[j]) j++;
        if (j == k) return 1;
    }
    return 0;
}

/// The names in a directory, space separated, or a negative errno.
static long list(const char *path) {
    long fd = openat_(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) return fd;
    long total = 0;
    static char raw[4096];
    for (;;) {
        long got = getdents64_(fd, raw, sizeof raw);
        if (got < 0) {
            close_(fd);
            return got;
        }
        if (got == 0) break;
        for (long at = 0; at < got;) {
            unsigned short reclen = *(unsigned short *)(raw + at + 16);
            const char *name = raw + at + 19;
            at += reclen;
            if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) continue;
            unsigned long k = str_len(name);
            if (total + (long)k + 2 >= (long)sizeof buf) break;
            for (unsigned long i = 0; i < k; i++) buf[total++] = name[i];
            buf[total++] = ' ';
        }
    }
    close_(fd);
    buf[total] = 0;
    return total;
}

static unsigned long file_type(const unsigned char *st) { return (unsigned long)(*(unsigned int *)(st + 16)) & S_IFMT; }

int main(void) {
    static unsigned char st[256];

    // The directory itself, and what is in it.
    check(fstatat_("/dev", st, 0) == 0 && file_type(st) == S_IFDIR, "/dev is a directory", file_type(st));
    long n = list("/dev");
    check(n > 0, "/dev can be listed", n);
    check(contains(buf, n, "null "), "/dev lists null", n);
    check(contains(buf, n, "zero "), "/dev lists zero", n);
    check(contains(buf, n, "full "), "/dev lists full", n);
    check(contains(buf, n, "random "), "/dev lists random", n);
    check(contains(buf, n, "urandom "), "/dev lists urandom", n);
    check(contains(buf, n, "tty "), "/dev lists tty", n);
    check(contains(buf, n, "console "), "/dev lists console", n);
    check(contains(buf, n, "ptmx "), "/dev lists ptmx", n);
    check(contains(buf, n, "fd "), "/dev lists fd", n);
    check(contains(buf, n, "pts "), "/dev lists pts", n);
    check(contains(buf, n, "shm "), "/dev lists shm", n);
    check(contains(buf, n, "stdin "), "/dev lists stdin", n);
    check(contains(buf, n, "stdout "), "/dev lists stdout", n);
    check(contains(buf, n, "stderr "), "/dev lists stderr", n);

    // What a program that reads a device's number out of a stat sees.
    check(fstatat_("/dev/null", st, 0) == 0 && file_type(st) == S_IFCHR, "/dev/null is a character device", file_type(st));
    unsigned long rdev = *(unsigned long *)(st + 32);
    check(rdev == ((1ul << 8) | 3), "/dev/null is major 1 minor 3", (long)rdev);
    check(fstatat_("/dev/ptmx", st, 0) == 0 && (*(unsigned long *)(st + 32)) == ((5ul << 8) | 2),
          "/dev/ptmx is major 5 minor 2", 0);
    unsigned long mode = *(unsigned int *)(st + 16) & 0x1ff;
    check(mode == 0666, "/dev/ptmx is read and write for everyone", (long)mode);

    // A device that answers with nothing, and one that answers with zeros.
    long fd = openat_("/dev/null", O_RDWR, 0);
    check(fd >= 0, "/dev/null opens", fd);
    if (fd >= 0) {
        check(write_(fd, "abc", 3) == 3, "/dev/null takes what it is given", 0);
        check(read_(fd, buf, sizeof buf) == 0, "/dev/null reads as nothing", 0);
        check(fstat_(fd, st) == 0 && file_type(st) == S_IFCHR, "an open /dev/null is a character device", 0);
        close_(fd);
    }
    fd = openat_("/dev/zero", O_RDONLY, 0);
    check(fd >= 0, "/dev/zero opens", fd);
    if (fd >= 0) {
        for (int i = 0; i < 16; i++) buf[i] = 1;
        long got = read_(fd, buf, 16);
        int zero = got == 16;
        for (int i = 0; i < 16 && zero; i++) zero = buf[i] == 0;
        check(zero, "/dev/zero reads as zeros", got);
        close_(fd);
    }
    fd = openat_("/dev/full", O_RDWR, 0);
    check(fd >= 0, "/dev/full opens", fd);
    if (fd >= 0) {
        check(write_(fd, "abc", 3) == -ENOSPC, "/dev/full has no room", 0);
        close_(fd);
    }
    fd = openat_("/dev/urandom", O_RDONLY, 0);
    check(fd >= 0, "/dev/urandom opens", fd);
    if (fd >= 0) {
        for (int i = 0; i < 32; i++) buf[i] = 0;
        long got = read_(fd, buf, 32);
        int any = 0;
        for (int i = 0; i < 32; i++) any |= buf[i];
        check(got == 32 && any, "/dev/urandom reads bytes", got);
        close_(fd);
    }

    // The links to a process's own descriptors: `/dev/stdout` is where its output goes.
    fd = openat_("/dev/stdout", O_WRONLY, 0);
    check(fd >= 0, "/dev/stdout opens", fd);
    if (fd >= 0) {
        const char *line = "dev: wrote through /dev/stdout\n";
        check(write_(fd, line, str_len(line)) == (long)str_len(line), "/dev/stdout writes", 0);
        close_(fd);
    }
    fd = openat_("/dev/fd/1", O_WRONLY, 0);
    check(fd >= 0, "/dev/fd/1 opens", fd);
    if (fd >= 0) close_(fd);
    // The console a test run has is not a terminal: a read from it finds the end of the file.
    fd = openat_("/dev/stdin", O_RDONLY, 0);
    check(fd >= 0, "/dev/stdin opens", fd);
    if (fd >= 0) {
        check(read_(fd, buf, sizeof buf) == 0, "/dev/stdin is at its end", 0);
        close_(fd);
    }
    n = readlinkat_("/dev/stdout", buf, sizeof buf - 1);
    check(n > 0 && contains(buf, n, "fd/1"), "/dev/stdout names the descriptor", n);
    check(openat_("/dev/fd/99", O_RDONLY, 0) < 0, "/dev/fd of a closed descriptor", 0);

    // The terminal, and the directory shared memory lives in.
    fd = openat_("/dev/tty", O_RDWR, 0);
    check(fd >= 0, "/dev/tty opens", fd);
    if (fd >= 0) {
        check(fstat_(fd, st) == 0 && (*(unsigned long *)(st + 32)) == (5ul << 8), "/dev/tty is major 5 minor 0", 0);
        close_(fd);
    }
    fd = openat_("/dev/shm/dev-test", O_RDWR | O_CREAT | O_TRUNC, 0600);
    check(fd >= 0, "/dev/shm holds a file", fd);
    if (fd >= 0) {
        check(write_(fd, "hello", 5) == 5, "the shared memory file takes bytes", 0);
        close_(fd);
        fd = openat_("/dev/shm/dev-test", O_RDONLY, 0);
        check(fd >= 0, "the shared memory file reads back", fd);
        if (fd >= 0) {
            long got = read_(fd, buf, sizeof buf);
            check(got == 5 && buf[0] == 'h' && buf[4] == 'o', "the bytes are the ones written", got);
            close_(fd);
        }
        check(unlinkat_("/dev/shm/dev-test") == 0, "the shared memory file can be removed", 0);
    }

    check(openat_("/dev/nosuchthing", O_RDONLY, 0) < 0, "/dev has no such device", 0);

    if (!failed) put("dev: all checks passed\n");
    guest_exit(failed);
    return 0;
}

void _start(void) {
    long code = (long)main();
    guest_exit(code);
}
