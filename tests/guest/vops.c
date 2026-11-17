// Instruction sequences taken from glibc, run on the machine and printed as numbers.
//
// Each one is a function whose result the oracle also computes natively, so a variant that is
// mis-emitted shows up as a difference rather than as a mystery in a library far away. The first
// sequence is the body of aarch64 strrchr: a byte masked into a zero mask, narrowed, and shifted
// down to the bit offset the caller asked for. The second is the whole function, so the loop that
// walks the haystack sixteen bytes at a time is the same code the library runs.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

// x0 = haystack, w1 = byte; result is the raw d5 value shifted down by (hay & 15) * 4.
long vstrrchr_bits(const char *hay, int c);

__asm__(
    ".text\n"
    ".globl vstrrchr_bits\n"
    ".type vstrrchr_bits, %function\n"
    "vstrrchr_bits:\n"
    "  and x2, x0, #-16\n"
    "  dup v0.16b, w1\n"
    "  movi v4.16b, #0x33\n"
    "  ld1 {v1.16b}, [x2]\n"
    "  cmeq v2.16b, v1.16b, #0\n"
    "  cmeq v3.16b, v1.16b, v0.16b\n"
    "  bit v2.16b, v3.16b, v4.16b\n"
    "  shrn v5.8b, v2.8h, #4\n"
    "  lsl x4, x0, #2\n"
    "  fmov x3, d5\n"
    "  lsr x3, x3, x4\n"
    "  mov x0, x3\n"
    "  ret\n"
    ".size vstrrchr_bits, .-vstrrchr_bits\n");

const char *vstrrchr_full(const char *hay, int c);
__asm__(
    ".text\n"
    ".globl vstrrchr_full\n"
    ".type vstrrchr_full, %function\n"
    "vstrrchr_full:\n"
    "    .inst 0xd503201f\n"
    "    .inst 0x927cec02\n"
    "    .inst 0x4e010c20\n"
    "    .inst 0x4f01e664\n"
    "    .inst 0x4c407041\n"
    "    .inst 0x4e209822\n"
    "    .inst 0x6e208c23\n"
    "    .inst 0x6ea41c62\n"
    "    .inst 0x0f0c8445\n"
    "    .inst 0xd37ef404\n"
    "    .inst 0x9e6600a3\n"
    "    .inst 0x9ac42463\n"
    "    .inst 0x9ac42063\n"
    "    .inst 0xf202e465\n"
    "    .inst 0x540002c1\n"
    "    .inst 0xb50003e3\n"
    "    .inst 0x3dc00441\n"
    "    .inst 0x6e208c23\n"
    "    .inst 0x6e213c62\n"
    "    .inst 0x6e22a445\n"
    "    .inst 0x9e6600a3\n"
    "    .inst 0xb5000103\n"
    "    .inst 0x3cc20c41\n"
    "    .inst 0x6e208c23\n"
    "    .inst 0x6e213c62\n"
    "    .inst 0x6e22a445\n"
    "    .inst 0x9e6600a3\n"
    "    .inst 0xb4fffea3\n"
    "    .inst 0xd1004042\n"
    "    .inst 0x91004042\n"
    "    .inst 0x4e209822\n"
    "    .inst 0x6ea41c62\n"
    "    .inst 0x0f0c8445\n"
    "    .inst 0x9e6600a3\n"
    "    .inst 0xf202e465\n"
    "    .inst 0x54000160\n"
    "    .inst 0xd10004a5\n"
    "    .inst 0x9200e466\n"
    "    .inst 0xea0500c6\n"
    "    .inst 0x91003c40\n"
    "    .inst 0xdac010c3\n"
    "    .inst 0xcb430800\n"
    "    .inst 0x9a9f1000\n"
    "    .inst 0xd65f03c0\n"
    "    .inst 0xd503201f\n"
    "    .inst 0xd503201f\n"
    "    .inst 0x91004042\n"
    "    .inst 0x6f079604\n"
    "    .inst 0xf100007f\n"
    "    .inst 0x9a841044\n"
    "    .inst 0x9a861066\n"
    "    .inst 0x4cdf7041\n"
    "    .inst 0x4e209822\n"
    "    .inst 0x6e208c23\n"
    "    .inst 0x6ea41c62\n"
    "    .inst 0x6e22a445\n"
    "    .inst 0x9e6600a3\n"
    "    .inst 0xf202e47f\n"
    "    .inst 0x54fffec0\n"
    "    .inst 0x6f00b5e2\n"
    "    .inst 0x4e22bc45\n"
    "    .inst 0x9e6600a3\n"
    "    .inst 0x9202e465\n"
    "    .inst 0xd10004a5\n"
    "    .inst 0x9200e463\n"
    "    .inst 0xea050063\n"
    "    .inst 0x9a861066\n"
    "    .inst 0x9a841044\n"
    "    .inst 0xd1000484\n"
    "    .inst 0xdac010c3\n"
    "    .inst 0xcb430880\n"
    "    .inst 0xd65f03c0\n"
    "    .inst 0xa9be7bfd\n"
    "    .inst 0x910003fd\n"
    "    .inst 0xa90153f3\n"
    "    .inst 0xf9400013\n"
    "    .inst 0xb4000173\n"
".size vstrrchr_full, .-vstrrchr_full\n");

// The bitwise selects on their own, over three constant vectors.
void vselect(const unsigned char *d, const unsigned char *n, const unsigned char *m,
             unsigned char *bsl, unsigned char *bit, unsigned char *bif);
__asm__(
    ".text\n"
    ".globl vselect\n"
    ".type vselect, %function\n"
    "vselect:\n"
    "  ldr q0, [x0]\n"
    "  ldr q1, [x1]\n"
    "  ldr q2, [x2]\n"
    "  bsl v0.16b, v1.16b, v2.16b\n"
    "  str q0, [x3]\n"
    "  ldr q0, [x0]\n"
    "  bit v0.16b, v1.16b, v2.16b\n"
    "  str q0, [x4]\n"
    "  ldr q0, [x0]\n"
    "  bif v0.16b, v1.16b, v2.16b\n"
    "  str q0, [x5]\n"
    "  ret\n"
    ".size vselect, .-vselect\n");

// The long multiplies a hash round is built from: half-width lanes multiply into full-width ones
// and accumulate, over both halves of the sources and both signs.
void vlong(const unsigned char *a, const unsigned char *b, const unsigned char *acc, unsigned char *out);
__asm__(
    ".text\n"
    ".globl vlong\n"
    ".type vlong, %function\n"
    "vlong:\n"
    "  ldr q2, [x2]\n"
    "  ldr q0, [x0]\n"
    "  ldr q1, [x1]\n"
    "  umlal v2.2d, v0.2s, v1.2s\n"
    "  str q2, [x3], #16\n"
    "  ldr q2, [x2]\n"
    "  smlal v2.2d, v0.2s, v1.2s\n"
    "  str q2, [x3], #16\n"
    "  ldr q2, [x2]\n"
    "  umlsl v2.2d, v0.2s, v1.2s\n"
    "  str q2, [x3], #16\n"
    "  ldr q2, [x2]\n"
    "  umlal2 v2.2d, v0.4s, v1.4s\n"
    "  str q2, [x3], #16\n"
    "  ldr q2, [x2]\n"
    "  smlal2 v2.2d, v0.4s, v1.4s\n"
    "  str q2, [x3], #16\n"
    "  ldr q2, [x2]\n"
    "  umlal v2.4s, v0.4h, v1.4h\n"
    "  str q2, [x3], #16\n"
    "  ldr q2, [x2]\n"
    "  smlal v2.4s, v0.4h, v1.4h\n"
    "  str q2, [x3], #16\n"
    "  ldr q2, [x2]\n"
    "  umlsl v2.4s, v0.4h, v1.4h\n"
    "  str q2, [x3], #16\n"
    "  ldr q2, [x2]\n"
    "  umlal2 v2.4s, v0.8h, v1.8h\n"
    "  str q2, [x3], #16\n"
    "  ldr q2, [x2]\n"
    "  smlal2 v2.4s, v0.8h, v1.8h\n"
    "  str q2, [x3], #16\n"
    "  ret\n"
    ".size vlong, .-vlong\n");

static void hex(const char *what, const unsigned char *p, int n) {
    printf("%s", what);
    for (int i = 0; i < n; i++) printf(" %02x", p[i]);
    printf("\n");
}

static void fill(char *hay) {
    for (int i = 0; i < 64; i++) hay[i] = 'a';
    hay[63] = 0;
}

int main(void) {
    static char hay[64] __attribute__((aligned(64)));
    // The low bits of the first block, at every alignment within a vector.
    for (int off = 0; off < 4; off++) {
        for (int at = 0; at < 32; at++) {
            fill(hay);
            hay[off + at] = 'b';
            printf("bits %d %d %ld\n", off, at, vstrrchr_bits(hay + off, 'b'));
        }
    }
    // The whole function against the library's own, on the same input.
    for (int off = 0; off < 4; off++) {
        for (int at = 0; at < 48; at++) {
            fill(hay);
            hay[off + at] = 'b';
            const char *a = vstrrchr_full(hay + off, 'b');
            const char *b = strrchr(hay + off, 'b');
            printf("cmp %d %d %ld %ld\n", off, at, a ? (long)(a - (hay + off)) : -1,
                   b ? (long)(b - (hay + off)) : -1);
        }
    }
    unsigned char d[16], n[16], m[16], bsl[16], bit[16], bif[16];
    for (int i = 0; i < 16; i++) {
        d[i] = (unsigned char)(i * 5);
        n[i] = (unsigned char)(255 - i * 3);
        m[i] = (unsigned char)(i * 17);
    }
    vselect(d, n, m, bsl, bit, bif);
    hex("bsl", bsl, 16);
    hex("bit", bit, 16);
    hex("bif", bif, 16);
    // Values chosen so the signed and unsigned readings of every lane differ.
    unsigned char a[16], b[16], acc[16], out[160];
    for (int i = 0; i < 16; i++) {
        a[i] = (unsigned char)(0xf0 + i * 3);
        b[i] = (unsigned char)(0x11 * (i + 1));
        acc[i] = (unsigned char)(i * 29 + 7);
    }
    vlong(a, b, acc, out);
    const char *names[] = {"umlal2d", "smlal2d", "umlsl2d", "umlal2_2d", "smlal2_2d",
                           "umlal4s", "smlal4s", "umlsl4s", "umlal2_4s", "smlal2_4s"};
    for (int i = 0; i < 10; i++) hex(names[i], out + i * 16, 16);
    printf("vops: done\n");
    return 0;
}
