// What glibc's own printf does with the calls dash makes, measured in the guest and natively.
//
// dash reaches its error printer as `__vsnprintf_chk(NULL, 0, 1, -1, fmt, ap)` for the size and then
// again over a buffer, so the interesting cases are exactly those two calls with a short format.
// Output goes through write(2) and is formatted by hand: a broken printf must not be able to hide
// its own failure.

#include <stdarg.h>
#include <stddef.h>

typedef unsigned long usize;

extern int __vsnprintf_chk(char *, usize, int, usize, const char *, va_list);
extern long write(int, const void *, usize);
extern char *strchrnul(const char *, int);
extern char *strchr(const char *, int);
extern usize strlen(const char *);

static char line[4096];
static usize at;

static void put(const char *s) {
    while (*s) line[at++] = *s++;
}

static void num(long v) {
    if (v < 0) {
        line[at++] = '-';
        v = -v;
    }
    char tmp[32];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n) line[at++] = tmp[--n];
}

static void hex(unsigned v) {
    put("0x");
    int started = 0;
    for (int shift = 28; shift >= 0; shift -= 4) {
        unsigned d = (v >> shift) & 0xf;
        if (d || started || shift == 0) {
            line[at++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
            started = 1;
        }
    }
}

static void flush(void) {
    write(1, line, at);
    at = 0;
}

// One case: the size query dash makes, then the write it makes, both with the flag and object size
// dash passes.
static void one(int idx, const char *fmt, ...) {
    char buf[128];
    va_list ap, aq;
    va_start(ap, fmt);
    va_copy(aq, ap);
    int n = __vsnprintf_chk(0, 0, 1, (usize)-1, fmt, ap);
    int m = __vsnprintf_chk(buf, sizeof buf, 1, (usize)-1, fmt, aq);
    va_end(aq);
    va_end(ap);
    put("fmt ");
    num(idx);
    put(" query=");
    num(n);
    put(" write=");
    num(m);
    put(" text=\"");
    if (m > 0) {
        for (int i = 0; i < m && i < (int)sizeof buf; i++) line[at++] = buf[i];
    }
    put("\"\n");
    flush();
}

// printf's own cursor comes from strchrnul, so where it stops is part of the contract under test.
static void scan(int idx, const char *s, int c) {
    char *p = strchrnul(s, c);
    put("str ");
    num(idx);
    put(" strchrnul=");
    num(p - s);
    put(" char=");
    hex((unsigned char)*p);
    char *q = strchr(s, c);
    put(" strchr=");
    num(q ? q - s : -1);
    put(" strlen=");
    num((long)strlen(s));
    put("\n");
    flush();
}

// glibc's strlen reads a vector at a time, so where it stops is the whole contract.
static void lens(void) {
    static char buf[160];
    for (int n = 0; n <= 96; n++) {
        for (int i = 0; i < n; i++) buf[i] = 'a';
        buf[n] = 0;
        put("len ");
        num(n);
        put(" ");
        num((long)strlen(buf));
        put("\n");
        flush();
    }
}

static void runs(int n) {
    switch (n) {
    case 1: scan(1, "%s: %d: ", '%'); break;
    case 2: scan(2, "no percent here at all", '%'); break;
    case 3: scan(3, "a much longer literal that runs past a sixteen byte vector boundary%", '%'); break;
    case 4: scan(4, "%", '%'); break;
    case 5: scan(5, "x", '%'); break;
    case 6: scan(6, "", '%'); break;
    case 7: scan(7, "0123456789abcdef0123456789abcdef%0123456789abcdef", '%'); break;
    case 20: lens(); break;
    case 101: one(1, "%s: %d: ", "dash", 1); break;
    case 102: one(2, "%s: %d: %s", "dash", 1, "nosuchcommand: not found"); break;
    case 103: one(3, "%d", 42); break;
    case 104: one(4, "%s", "hello"); break;
    case 105: one(5, "%ld", 1234567890123L); break;
    case 106: one(6, "%s: %s", "dash", "x"); break;
    case 107: one(7, "plain"); break;
    case 108: one(8, "%c", 'A'); break;
    default: break;
    }
}

// One case by number, or all of them: a single case is what makes a run short enough to trace.
int main(int argc, char **argv) {
    if (argc > 1) {
        int n = 0;
        for (char *p = argv[1]; *p >= '0' && *p <= '9'; p++) n = n * 10 + (*p - '0');
        runs(n);
        return 0;
    }
    scan(1, "%s: %d: ", '%');
    scan(2, "no percent here at all", '%');
    scan(3, "a much longer literal that runs past a sixteen byte vector boundary%", '%');
    scan(4, "%", '%');
    scan(5, "x", '%');
    scan(6, "", '%');
    scan(7, "0123456789abcdef0123456789abcdef%0123456789abcdef", '%');
    one(1, "%s: %d: ", "dash", 1);
    one(2, "%s: %d: %s", "dash", 1, "nosuchcommand: not found");
    one(3, "%d", 42);
    one(4, "%s", "hello");
    one(5, "%ld", 1234567890123L);
    one(6, "%s: %s", "dash", "x");
    one(7, "plain");
    one(8, "%c", 'A');
    return 0;
}
