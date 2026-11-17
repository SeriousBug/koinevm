// The string routines glibc picks at startup, against the same ones on a real kernel.
//
// These are ifunc-selected: the variant that runs is chosen from the CPU's own features, so a
// mis-translated vector instruction inside one of them shows up as a wrong pointer or a wrong
// length. Each answer is printed as an offset so a failure names the case.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static void show(const char *what, long got, long want) {
    printf("%s %ld %ld %s\n", what, got, want, got == want ? "ok" : "MISMATCH");
}

int main(void) {
    // Which variant of strrchr the loader chose, as an offset into its own library: the choice is
    // made from the CPU features the kernel reports, so the two runs have to agree on it.
    Dl_info info;
    if (dladdr((void *)strrchr, &info)) {
        printf("strrchr variant %ld\n", (long)((char *)strrchr - (char *)info.dli_fbase));
    }
    // Lengths from zero to past a vector register, at every alignment within one.
    static char buf[128] __attribute__((aligned(64)));
    for (int at = 0; at < 4; at++) {
        for (int n = 0; n < 40; n++) {
            memset(buf, 'x', sizeof buf);
            buf[at + n] = 0;
            long got = (long)strlen(buf + at);
            if (got != n) show("strlen", got, n);
        }
    }

    // strrchr and strchr on the program's own name, which is what glibc does with argv[0].
    const char *name = "/bin/grep";
    show("strrchr_slash", (long)(strrchr(name, '/') - name), 4);
    show("strchr_slash", (long)(strchr(name, '/') - name), 0);
    show("strrchr_missing", strrchr(name, 'z') == NULL ? -1 : 1, -1);
    show("strrchr_first", (long)(strrchr("/x", '/') - "/x"), 0);
    show("strrchr_only_slash", (long)(strrchr("/", '/') - "/"), 0);

    // The needle at every position of a haystack that crosses a vector boundary.
    for (int i = 0; i < 33; i++) {
        char hay[64];
        memset(hay, 'a', sizeof hay);
        hay[63] = 0;
        hay[i] = 'b';
        const char *p = strrchr(hay, 'b');
        show("strrchr_every", p ? (long)(p - hay) : -1, i);
        p = strchr(hay, 'b');
        show("strchr_every", p ? (long)(p - hay) : -1, i);
    }

    // memchr past the last full register, and a substring that ends the string.
    for (int i = 0; i < 33; i++) {
        char hay[64];
        memset(hay, 'a', sizeof hay);
        hay[i] = 'q';
        show("memchr", (long)((char *)memchr(hay, 'q', 40) - hay), i);
    }
    const char *hay = "hello world, hello";
    show("strstr", (long)(strstr(hay, "hello") - hay), 0);
    show("strstr_late", (long)(strstr(hay, "world") - hay), 6);
    show("memcmp", memcmp("abcdef", "abcdxf", 6) < 0, 1);
    show("strncmp", strncmp("abcd", "abce", 4) < 0, 1);
    show("strcmp", strcmp("", "a") < 0, 1);
    printf("str: done\n");
    return 0;
}
