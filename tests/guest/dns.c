/* Guest that resolves a name the way a program does: a DNS query over UDP, written and read by
 * hand, to the address its own resolver file names.
 *
 * This kernel answers that address from the host's resolver, so the checks are about the shape of a
 * resolver's answer and about one name every machine resolves. tests/dns.sh runs it against a
 * rootfs with no nameserver of its own. */

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

#define AF_INET 2
#define SOCK_DGRAM 2
#define POLLIN 0x001
#define AT_FDCWD (-100)
#define O_RDONLY 0

struct sockaddr_in {
    unsigned short family;
    unsigned short port;
    unsigned int addr;
    unsigned char zero[8];
};

struct pollfd {
    int fd;
    short events;
    short revents;
};

struct timespec {
    long sec;
    long nsec;
};

static long socket_(long domain, long type, long protocol) { return sc6(198, domain, type, protocol, 0, 0, 0); }
static long sendto_(long fd, const void *buf, long len, const void *addr, long addrlen) {
    return sc6(206, fd, (long)buf, len, 0, (long)addr, addrlen);
}
static long recvfrom_(long fd, void *buf, long len) { return sc6(207, fd, (long)buf, len, 0, 0, 0); }
static long ppoll_(struct pollfd *fds, long n, long ms) {
    struct timespec ts;
    ts.sec = ms / 1000;
    ts.nsec = (ms % 1000) * 1000000;
    return sc6(73, (long)fds, n, (long)&ts, 0, 0, 0);
}
static long openat_(const char *path, long flags) { return sc6(56, AT_FDCWD, (long)path, flags, 0, 0, 0); }
static long read_(long fd, void *buf, unsigned long n) { return sc6(63, fd, (long)buf, n, 0, 0, 0); }
static long close_(long fd) { return sc6(57, fd, 0, 0, 0, 0, 0); }
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

static int failures;

static void check(int ok, const char *what) {
    put(ok ? "ok   " : "FAIL ");
    put(what);
    put("\n");
    if (!ok) failures++;
}

static int contains(const char *haystack, unsigned long len, const char *needle) {
    unsigned long n = str_len(needle);
    for (unsigned long i = 0; i + n <= len; i++) {
        unsigned long j = 0;
        while (j < n && haystack[i + j] == needle[j]) j++;
        if (j == n) return 1;
    }
    return 0;
}

/// A stub resolver's question: one name, one type, recursion wanted.
static long build_query(unsigned char *out, unsigned id, const char *name, unsigned type) {
    out[0] = id >> 8;
    out[1] = id & 0xff;
    out[2] = 0x01;
    out[3] = 0x00;
    out[4] = 0;
    out[5] = 1; // one question
    for (long i = 6; i < 12; i++) out[i] = 0;
    long at = 12;
    for (const char *p = name; *p;) {
        const char *dot = p;
        while (*dot && *dot != '.') dot++;
        long n = dot - p;
        out[at++] = (unsigned char)n;
        for (long i = 0; i < n; i++) out[at++] = (unsigned char)p[i];
        p = *dot ? dot + 1 : dot;
    }
    out[at++] = 0;
    out[at++] = (unsigned char)(type >> 8);
    out[at++] = (unsigned char)(type & 0xff);
    out[at++] = 0;
    out[at++] = 1; // class IN
    return at;
}

static unsigned get16(const unsigned char *p) { return (unsigned)((p[0] << 8) | p[1]); }

/// The offset just past the question, which is where the answer's records start.
static long past_question(const unsigned char *msg, long len) {
    long at = 12;
    while (at < len && msg[at] != 0) at += 1 + msg[at];
    return at + 5;
}

static unsigned rcode(const unsigned char *msg) { return get16(msg + 2) & 0xf; }

static unsigned record_count(const unsigned char *msg) { return get16(msg + 6); }

/// Ask the resolver in the file one question, and answer how many bytes came back (0 for none).
static long ask(struct sockaddr_in *server, const unsigned char *query, long len, unsigned char *reply,
                long cap) {
    long fd = socket_(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (sendto_(fd, query, len, server, sizeof(*server)) != len) return -1;
    struct pollfd one;
    one.fd = (int)fd;
    one.events = POLLIN;
    one.revents = 0;
    if (ppoll_(&one, 1, 5000) != 1) return 0;
    long n = recvfrom_(fd, reply, cap);
    close_(fd);
    return n;
}

void guest_main(void) {
    // The file the guest is given, and the address in it.
    char conf[512];
    long conf_len = 0;
    long fd = openat_("/etc/resolv.conf", O_RDONLY);
    check(fd >= 3, "a rootfs with no nameserver still has a resolver file");
    if (fd >= 3) {
        conf_len = read_(fd, conf, sizeof(conf));
        close_(fd);
    }
    check(conf_len > 0, "the resolver file has contents");
    check(contains(conf, (unsigned long)conf_len, "nameserver 192.0.2.1"),
          "it names the address the host's resolver answers");

    struct sockaddr_in server;
    unsigned char *raw = (unsigned char *)&server;
    for (unsigned long i = 0; i < sizeof(server); i++) raw[i] = 0;
    server.family = AF_INET;
    raw[2] = 0;
    raw[3] = 53;
    raw[4] = 192;
    raw[5] = 0;
    raw[6] = 2;
    raw[7] = 1;

    unsigned char query[128];
    unsigned char reply[1024];

    // A name every machine resolves, asked over the wire.
    long len = build_query(query, 0x1234, "localhost", 1);
    long got = ask(&server, query, len, reply, sizeof(reply));
    check(got > 12, "a query for localhost is answered");
    if (got > 12) {
        check(get16(reply) == 0x1234, "the answer carries the query's id");
        check((get16(reply + 2) & 0x8000) != 0 && rcode(reply) == 0, "it is a response with no error");
        check(record_count(reply) >= 1, "it has an address record");
        long at = past_question(reply, got);
        check(at + 12 <= got && get16(reply + at + 2) == 1 && get16(reply + at + 10) == 4,
              "the record is an IPv4 address");
        if (at + 16 <= got) {
            check(reply[at + 12] == 127 && reply[at + 13] == 0 && reply[at + 14] == 0 && reply[at + 15] == 1,
                  "localhost is 127.0.0.1");
        }
    }

    // A name in the reserved `.invalid` domain, which no resolver can find.
    len = build_query(query, 0x5678, "no-such-name.invalid", 1);
    got = ask(&server, query, len, reply, sizeof(reply));
    check(got > 12 && get16(reply) == 0x5678 && rcode(reply) == 3,
          "a name that does not exist is NXDOMAIN");

    // A question this kernel does not answer itself: it is forwarded, and the answer comes back.
    len = build_query(query, 0x9abc, "1.0.0.127.in-addr.arpa", 12);
    got = ask(&server, query, len, reply, sizeof(reply));
    check(got > 12 && get16(reply) == 0x9abc && (get16(reply + 2) & 0x8000) != 0,
          "a question this cannot answer is forwarded and answered");

    put(failures ? "dns: FAILURES\n" : "dns: all checks passed\n");
    guest_exit(failures ? 1 : 0);
}
