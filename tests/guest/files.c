/* Guest that exercises the file side of the ABI against a root filesystem directory.
 *
 * Like the memory fixture, the guest asserts what a kernel owes it and prints one line per check;
 * tests/files.sh builds the tree this expects and requires every line to say ok. */

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

static long openat_(const char *path, long flags, long mode) {
    return sc6(56, AT_FDCWD, (long)path, flags, mode, 0, 0);
}

static long read_(long fd, void *buf, unsigned long n) { return sc6(63, fd, (long)buf, (long)n, 0, 0, 0); }
static long pread_(long fd, void *buf, unsigned long n, long off) {
    return sc6(67, fd, (long)buf, (long)n, off, 0, 0);
}
static long readv_(long fd, const void *iov, long count) {
    return sc6(65, fd, (long)iov, count, 0, 0, 0);
}
static long preadv_(long fd, const void *iov, long count, long off) {
    return sc6(69, fd, (long)iov, count, off, 0, 0);
}
static long write_(long fd, const void *buf, unsigned long n) {
    return sc6(64, fd, (long)buf, (long)n, 0, 0, 0);
}
static long close_(long fd) { return sc6(57, fd, 0, 0, 0, 0, 0); }
static long lseek_(long fd, long off, long whence) { return sc6(62, fd, off, whence, 0, 0, 0); }
static long fstat_(long fd, void *buf) { return sc6(80, fd, (long)buf, 0, 0, 0, 0); }
static long newfstatat_(const char *path, void *buf, long flags) {
    return sc6(79, AT_FDCWD, (long)path, (long)buf, flags, 0, 0);
}
static long readlinkat_(const char *path, char *buf, unsigned long n) {
    return sc6(78, AT_FDCWD, (long)path, (long)buf, (long)n, 0, 0);
}
static long getcwd_(char *buf, unsigned long n) { return sc6(17, (long)buf, (long)n, 0, 0, 0, 0); }

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
    static const char digits[] = "0123456789abcdef";
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; i++) buf[2 + i] = digits[(v >> (60 - 4 * i)) & 0xf];
    buf[18] = 0;
    put(buf);
}

static unsigned long failures;

static void check(int cond, const char *what, unsigned long detail) {
    put(cond ? "ok   " : "FAIL ");
    put(what);
    put(" ");
    put_hex(detail);
    put("\n");
    if (!cond) failures++;
}

static int bytes_equal(const char *a, const char *b, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static char statbuf[128];

__attribute__((used)) void _start(void) {
    static const char expect[] = "hello from the rootfs\n";

    char cwd[64];
    check(getcwd_(cwd, sizeof(cwd)) > 0 && cwd[0] == '/' && cwd[1] == 0, "cwd is root",
          (unsigned long)cwd[0]);

    // open + read: the whole file, then EOF.
    long fd = openat_("/data.txt", O_RDONLY, 0);
    check(fd >= 3, "openat data.txt", (unsigned long)fd);
    char buf[128];
    long n = read_(fd, buf, sizeof(buf));
    check(n == (long)sizeof(expect) - 1, "read length", (unsigned long)n);
    check(bytes_equal(buf, expect, sizeof(expect) - 1), "read contents", (unsigned long)n);
    check(read_(fd, buf, sizeof(buf)) == 0, "read at end is 0", 0);

    // lseek and pread address the same bytes two ways.
    check(lseek_(fd, 6, 0) == 6, "lseek absolute", 6);
    n = read_(fd, buf, 4);
    check(n == 4 && bytes_equal(buf, "from", 4), "read after lseek", (unsigned long)n);
    n = pread_(fd, buf, 5, 0);
    check(n == 5 && bytes_equal(buf, "hello", 5), "pread does not move the offset", (unsigned long)n);
    // 6 from the absolute seek plus 4 read, and pread left the offset where it was.
    check(lseek_(fd, 0, 1) == 10, "lseek relative", 10);

    // The same bytes again into two buffers at once, which is how a library that buffers a file
    // asks for its next chunk.
    struct { unsigned long at; unsigned long len; } iov[2];
    char first[8], second[8];
    iov[0].at = (unsigned long)first;
    iov[0].len = 5;
    iov[1].at = (unsigned long)second;
    iov[1].len = 6;
    n = preadv_(fd, iov, 2, 0);
    check(n == 11, "preadv fills both buffers", (unsigned long)n);
    check(bytes_equal(first, "hello", 5), "preadv fills the first", 5);
    check(bytes_equal(second, " from ", 6), "preadv fills the second", 6);
    check(lseek_(fd, 6, 1) == 16, "preadv does not move the offset", 16);
    check(lseek_(fd, 11, 0) == 11, "lseek to where the last eleven bytes start", 11);
    n = readv_(fd, iov, 2);
    check(n == 11, "readv reads where the offset is", (unsigned long)n);
    check(bytes_equal(first, "the r", 5), "readv fills the first", 5);
    check(bytes_equal(second, "ootfs\n", 6), "readv fills the second", 6);

    // fstat reports a regular file of the right size.
    check(fstat_(fd, statbuf) == 0, "fstat", 0);
    unsigned long size;
    __builtin_memcpy(&size, statbuf + 48, 8);
    check(size == sizeof(expect) - 1, "fstat size", size);
    unsigned int mode;
    __builtin_memcpy(&mode, statbuf + 16, 4);
    check((mode & 0xf000) == 0x8000, "fstat mode is a regular file", mode);
    check(close_(fd) == 0, "close", 0);
    check(close_(fd) == -9, "close twice is EBADF", 0);

    // A missing file is ENOENT, not a trap.
    check(openat_("/missing", O_RDONLY, 0) == -2, "openat missing is -ENOENT", 0);

    // A symlink: newfstatat follows it by default, and AT_SYMLINK_NOFOLLOW reports the link itself.
    check(newfstatat_("/link", statbuf, 0) == 0, "newfstatat follows", 0);
    __builtin_memcpy(&mode, statbuf + 16, 4);
    check((mode & 0xf000) == 0x8000, "followed link is a regular file", mode);
    check(newfstatat_("/link", statbuf, 0x100) == 0, "newfstatat nofollow", 0);
    __builtin_memcpy(&mode, statbuf + 16, 4);
    check((mode & 0xf000) == 0xa000, "nofollow reports a symlink", mode);
    n = readlinkat_("/link", buf, 32);
    check(n == 8 && bytes_equal(buf, "data.txt", 8), "readlinkat", (unsigned long)n);

    // Writing: create a file, then read it back through a second descriptor.
    long out = openat_("/out.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    check(out >= 3, "openat for write", (unsigned long)out);
    check(write_(out, "written by the guest\n", 21) == 21, "write", 21);
    check(lseek_(out, 0, 0) == 0, "lseek on a written file", 0);
    long in = openat_("/out.txt", O_RDONLY, 0);
    n = read_(in, buf, sizeof(buf));
    check(n == 21 && bytes_equal(buf, "written by the guest\n", 21), "read back what was written",
          (unsigned long)n);
    check(close_(in) == 0 && close_(out) == 0, "close written file", 0);

    // A directory is not a file.
    check(openat_("/sub", O_WRONLY, 0) == -21, "openat dir for write is -EISDIR", 0);

    // ".." normalizes inside the root instead of escaping it, so a path that climbs out is a miss.
    check(openat_("/../outside", O_RDONLY, 0) == -2, "dotdot stays inside the root", 0);

    // A temporary file is made by unlinking it straight after opening it, and the bytes stay in the
    // file the descriptor holds: a path can go away, an open file cannot.
    long temp = openat_("/temp.txt", O_RDWR | O_CREAT | O_TRUNC, 0600);
    check(temp >= 3, "openat for a temporary file", (unsigned long)temp);
    check(sc6(35, AT_FDCWD, (long)"/temp.txt", 0, 0, 0, 0) == 0, "unlink a file that is open", 0);
    check(openat_("/temp.txt", O_RDONLY, 0) == -2, "an unlinked name is gone", 0);
    check(write_(temp, "gone but here\n", 14) == 14, "write to an unlinked file", 0);
    check(lseek_(temp, 0, 0) == 0, "lseek an unlinked file", 0);
    n = read_(temp, buf, sizeof(buf));
    check(n == 14 && bytes_equal(buf, "gone but here\n", 14), "read back an unlinked file",
          (unsigned long)n);
    check(fstat_(temp, statbuf) == 0, "fstat an unlinked file", 0);
    check(close_(temp) == 0, "close an unlinked file", 0);

    // Two names that differ only in case are two files: Debian's kernel headers hold both
    // `xt_connmark.h` and `xt_CONNMARK.h`, and a host directory that folds case must still tell
    // them apart, contents and all.
    long low = openat_("/case-a.txt", O_RDWR | O_CREAT | O_TRUNC, 0644);
    long high = openat_("/CASE-A.TXT", O_RDWR | O_CREAT | O_TRUNC, 0644);
    check(low >= 3 && high >= 3 && low != high, "two names that differ in case open twice", 0);
    check(write_(low, "the lower one\n", 14) == 14, "write one of the two names", 0);
    check(write_(high, "THE UPPER ONE\n", 14) == 14, "write the other name", 0);
    check(close_(low) == 0 && close_(high) == 0, "close both names", 0);
    low = openat_("/case-a.txt", O_RDONLY, 0);
    n = low >= 3 ? read_(low, buf, sizeof(buf)) : -1;
    check(n == 14 && bytes_equal(buf, "the lower one\n", 14), "the first name kept its bytes",
          (unsigned long)n);
    if (low >= 3) close_(low);
    high = openat_("/CASE-A.TXT", O_RDONLY, 0);
    n = high >= 3 ? read_(high, buf, sizeof(buf)) : -1;
    check(n == 14 && bytes_equal(buf, "THE UPPER ONE\n", 14), "the second name kept its bytes",
          (unsigned long)n);
    if (high >= 3) close_(high);
    check(openat_("/Case-A.txt", O_RDONLY, 0) == -2, "a third spelling is a third name", 0);
    check(sc6(35, AT_FDCWD, (long)"/case-a.txt", 0, 0, 0, 0) == 0, "unlink the first name", 0);
    high = openat_("/CASE-A.TXT", O_RDONLY, 0);
    check(high >= 3, "the other name survives it", 0);
    if (high >= 3) {
        check(read_(high, buf, sizeof(buf)) == 14 && bytes_equal(buf, "THE UPPER ONE\n", 14),
              "and still holds its own bytes", 0);
        close_(high);
    }
    check(sc6(35, AT_FDCWD, (long)"/CASE-A.TXT", 0, 0, 0, 0) == 0, "unlink the other name", 0);

    put(failures ? "files: FAILURES\n" : "files: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}
