/* Floating point through a real libc, against the same binary running natively.
 *
 * The fixture in fp.c proves the instructions; this one proves the library on top of them:
 * printf's conversions, strtod's parser, and the arithmetic and comparisons the printf family and
 * the C library's own scalar loops are made of. Everything here is a builtin or plain arithmetic,
 * so nothing needs libm. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The one place a builtin would call libm instead of the instruction. */
static double sqrt_(double v) {
    double r;
    __asm__("fsqrt %d0, %d1" : "=w"(r) : "w"(v));
    return r;
}

static float sqrtf_(float v) {
    float r;
    __asm__("fsqrt %s0, %s1" : "=w"(r) : "w"(v));
    return r;
}

static const double dvals[] = {
    0.0,
    -0.0,
    1.0,
    -1.0,
    0.5,
    -2.5,
    1.0 / 3.0,
    123456789.125,
    1e-300,
    -0.0 + 7.25,
    4503599627370495.5,
};

static const float fvals[] = {
    0.0f, -0.0f, 1.0f, -1.0f, 0.5f, -2.5f, 1.0f / 3.0f, 16777215.0f, 3.14159265f,
};

int main(void) {
    char line[256];

    for (unsigned i = 0; i < sizeof dvals / sizeof dvals[0]; i++) {
        double v = dvals[i];
        printf("d %a %f %.3f %e %g\n", v, v, v, v, v);
        printf("  sqrt %.17g floor %.1f ceil %.1f trunc %.1f round %.1f abs %a\n",
               sqrt_(v < 0 ? -v : v), __builtin_floor(v), __builtin_ceil(v),
               __builtin_trunc(v), __builtin_round(v), __builtin_fabs(v));
        printf("  cmp %d %d %d %d\n", v < 1.0, v <= 1.0, v == 1.0, v > -1.0);
        printf("  cast %ld %d %.6f\n", (long)v, (int)(v * 4), (double)(int)(v * 2));
        printf("  max %.4f min %.4f fma-ish %.9f\n", __builtin_fmax(v, 1.5), __builtin_fmin(v, 1.5),
               v * v + 0.5 * v + 0.25);
    }

    for (unsigned i = 0; i < sizeof fvals / sizeof fvals[0]; i++) {
        float f = fvals[i];
        printf("f %a %.4f %e | %.5f %.5f | %d %d\n", f, f, f, sqrtf_(f < 0 ? -f : f), f * f,
               f < 1.0f, f == 0.0f);
        printf("  to double %.17g  back to float %a\n", (double)f, (float)(double)f);
    }

    // strtod has to agree digit for digit, and it is the parser the shell's arithmetic uses.
    static const char *text[] = {"0", "-0", "1.5", "-2.5e10", "3.0e-40", "1e400", "0.1", "  7.25"};
    for (unsigned i = 0; i < sizeof text / sizeof text[0]; i++) {
        char *end = NULL;
        double v = strtod(text[i], &end);
        printf("strtod %s -> %a (consumed %ld)\n", text[i], v, (long)(end - text[i]));
    }

    snprintf(line, sizeof line, "%.17g|%.3e|%s", 1.0 / 7.0, 1234.5678, "x");
    printf("snprintf %s\n", line);
    return 0;
}
