/* Guest that reads the machine's own files: `/proc`. A kernel answers them out of the process
 * table, the address space and the clock, and a program that sizes itself by what the machine says
 * depends on the shape of that answer, so this asserts the shape rather than the numbers.
 *
 * No native oracle can run this: on the machine that builds the fixtures `/proc` is not there. tests/
 * proc.sh requires every check to pass. */

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
#define AT_SYMLINK_NOFOLLOW 0x100
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CLOEXEC 0x80000
#define S_IFMT 0xf000
#define S_IFREG 0x8000
#define S_IFLNK 0xa000

static long openat_(long dirfd, const char *path, long flags) {
    return sc6(56, dirfd, (long)path, flags, 0, 0, 0);
}
static long close_(long fd) { return sc6(57, fd, 0, 0, 0, 0, 0); }
static long read_(long fd, void *buf, unsigned long n) { return sc6(63, fd, (long)buf, (long)n, 0, 0, 0); }
static long write_(long fd, const void *buf, unsigned long n) { return sc6(64, fd, (long)buf, (long)n, 0, 0, 0); }
static long fstatat_(const char *path, void *st, long flags) { return sc6(79, AT_FDCWD, (long)path, (long)st, flags, 0, 0); }
static long readlinkat_(const char *path, char *buf, unsigned long n) {
    return sc6(78, AT_FDCWD, (long)path, (long)buf, (long)n, 0, 0);
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

static char buf[8192];

/// The whole of a file, in `buf`, with the length, or a negative errno.
static long slurp(const char *path) {
    long fd = openat_(AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fd;
    long total = 0;
    while (total < (long)sizeof buf - 1) {
        long got = read_(fd, buf + total, sizeof buf - 1 - (unsigned long)total);
        if (got <= 0) break;
        total += got;
    }
    close_(fd);
    buf[total] = 0;
    return total;
}

static int starts_with(const char *s, const char *prefix) {
    while (*prefix) {
        if (*s++ != *prefix++) return 0;
    }
    return 1;
}

static int contains(const char *hay, long n, const char *needle) {
    unsigned long k = str_len(needle);
    for (long i = 0; i + (long)k <= n; i++) {
        unsigned long j = 0;
        while (j < k && hay[i + (long)j] == needle[j]) j++;
        if (j == k) return 1;
    }
    return 0;
}

/// How many lines begin with `prefix`.
static int lines_with(const char *s, long n, const char *prefix) {
    int count = 0;
    long at = 0;
    while (at < n) {
        long end = at;
        while (end < n && s[end] != '\n') end++;
        int hit = 1;
        for (unsigned long i = 0; prefix[i]; i++) {
            if (at + (long)i >= end || s[at + (long)i] != prefix[i]) {
                hit = 0;
                break;
            }
        }
        if (hit) count++;
        at = end + 1;
    }
    return count;
}

/// The value of a `Field: value` line as a number, or -1.
static long field_value(const char *s, long n, const char *name) {
    unsigned long k = str_len(name);
    for (long at = 0; at < n; at++) {
        if (at > 0 && s[at - 1] != '\n') continue;
        if (at + (long)k > n) break;
        unsigned long i = 0;
        while (i < k && s[at + (long)i] == name[i]) i++;
        if (i != k) continue;
        long p = at + (long)k;
        while (p < n && (s[p] == ':' || s[p] == '\t' || s[p] == ' ')) p++;
        long value = 0;
        int digits = 0;
        while (p < n && s[p] >= '0' && s[p] <= '9') {
            value = value * 10 + (s[p] - '0');
            p++;
            digits++;
        }
        return digits ? value : -1;
    }
    return -1;
}

/// Field `n` of a whitespace-separated line, counting from one, with the parenthesised command in
/// field two skipped as a whole so that a name with a space in it does not move the count.
static long stat_field(const char *s, long n, int want) {
    long at = 0;
    int field = 1;
    while (at < n) {
        while (at < n && (s[at] == ' ' || s[at] == '\n')) at++;
        // The command in the process's own stat is in parentheses, and a name with a space in it
        // must not move the count, so it is skipped whole.
        if (at < n && s[at] == '(') {
            while (at < n && s[at] != ')') at++;
            at++;
            field++;
            continue;
        }
        long start = at;
        while (at < n && s[at] != ' ' && s[at] != '\n') at++;
        if (start == at) return -1;
        if (field == want) {
            long value = 0;
            for (long i = start; i < at; i++) {
                if (s[i] == '-') continue;
                if (s[i] < '0' || s[i] > '9') return -1;
                value = value * 10 + (s[i] - '0');
            }
            return value;
        }
        field++;
    }
    return -1;
}

int main(void) {
    long n = slurp("/proc/version");
    check(n > 0 && starts_with(buf, "Linux version "), "/proc/version says Linux", n);
    check(n > 0 && contains(buf, n, "6.1.0-armjit"), "/proc/version has the release", n);

    n = slurp("/proc/cpuinfo");
    check(n > 0 && lines_with(buf, n, "processor") == 1, "/proc/cpuinfo lists one processor", n);
    check(n > 0 && contains(buf, n, "Features"), "/proc/cpuinfo has features", n);

    n = slurp("/proc/stat");
    check(n > 0 && lines_with(buf, n, "cpu ") == 1, "/proc/stat has the totals line", n);
    check(n > 0 && lines_with(buf, n, "cpu0 ") == 1, "/proc/stat has one cpu line", n);
    check(n > 0 && field_value(buf, n, "btime") > 1000000000, "/proc/stat has the boot time", n);

    n = slurp("/proc/meminfo");
    check(n > 0 && field_value(buf, n, "MemTotal") > 0, "/proc/meminfo has a total", n);
    check(n > 0 && field_value(buf, n, "MemFree") > 0, "/proc/meminfo has a free count", n);

    n = slurp("/proc/uptime");
    check(n > 0 && buf[0] >= '0' && buf[0] <= '9', "/proc/uptime is a number", n);

    n = slurp("/proc/self/stat");
    check(n > 0 && contains(buf, n, "(proc)"), "/proc/self/stat names the program", n);
    check(n > 0 && stat_field(buf, n, 1) > 0, "/proc/self/stat starts with the pid", n);
    check(n > 0 && stat_field(buf, n, 23) > 0, "/proc/self/stat has the address space", n);
    check(n > 0 && stat_field(buf, n, 24) > 0, "/proc/self/stat has the resident pages", n);

    n = slurp("/proc/self/statm");
    check(n > 0 && stat_field(buf, n, 2) > 0, "/proc/self/statm has the resident pages", n);

    n = slurp("/proc/self/status");
    check(n > 0 && field_value(buf, n, "Pid") > 0, "/proc/self/status names the pid", n);
    check(n > 0 && field_value(buf, n, "VmRSS") > 0, "/proc/self/status has the resident size", n);

    n = slurp("/proc/self/cmdline");
    check(n > 0 && contains(buf, n, "proc"), "/proc/self/cmdline holds the argument", n);

    n = slurp("/proc/self/maps");
    check(n > 0 && contains(buf, n, "r-xp"), "/proc/self/maps says what is executable", n);
    check(n > 0 && contains(buf, n, "[stack]"), "/proc/self/maps has the stack", n);

    // A symlink is a symlink to `lstat` and a path out of `readlink`, and the file it names is
    // there when the program opens it.
    static unsigned char st[256];
    check(fstatat_("/proc/self/exe", st, AT_SYMLINK_NOFOLLOW) == 0, "/proc/self/exe can be lstat'd", 0);
    unsigned long mode = (unsigned long)(*(unsigned int *)(st + 16)) & S_IFMT;
    check(mode == S_IFLNK, "/proc/self/exe is a symlink", (long)mode);
    long len = readlinkat_("/proc/self/exe", buf, sizeof buf - 1);
    check(len > 0, "/proc/self/exe names a path", len);
    if (len > 0) {
        buf[len] = 0;
        // A run with a rootfs names the program as the guest sees it, which is a path the guest can
        // open; a bare run has no tree, so there is nothing to check the name against.
        if (buf[0] == '/') {
            long fd = openat_(AT_FDCWD, buf, O_RDONLY | O_CLOEXEC);
            check(fd >= 0, "/proc/self/exe can be opened", fd);
            if (fd >= 0) close_(fd);
        }
    }
    check(fstatat_("/proc/self/stat", st, 0) == 0, "/proc/self/stat can be stat'd", 0);
    mode = (unsigned long)(*(unsigned int *)(st + 16)) & S_IFMT;
    check(mode == S_IFREG, "/proc/self/stat is a regular file", (long)mode);

    // A name that is not there is a missing file, and a file that is there is read-only.
    check(openat_(AT_FDCWD, "/proc/nosuchthing", O_RDONLY) < 0, "/proc of a name with no file", 0);
    check(openat_(AT_FDCWD, "/proc/self/stat", O_WRONLY) < 0, "/proc writes are refused", 0);
    check(openat_(AT_FDCWD, "/proc/1999/stat", O_RDONLY) < 0, "/proc of another pid is not there", 0);

    if (!failed) put("proc: all checks passed\n");
    guest_exit(failed);
    return 0;
}

void _start(void) {
    long code = (long)main();
    guest_exit(code);
}
