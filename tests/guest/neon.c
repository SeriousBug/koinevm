// The widening arithmetic a byte sum is built from: GCC turns a loop of byte additions into
// widening shifts and adds, and a library's checksum loop is that loop. Every step is printed as
// hex, so the value that is wrong says which instruction it was.
#include <stdio.h>
#include <string.h>
#include <arm_neon.h>

static void hex(const char *what, const void *p) {
    const unsigned char *b = p;
    printf("%s", what);
    for (int i = 0; i < 16; i++) printf(" %02x", b[i]);
    printf("\n");
}

// The loop GCC emits for a byte sum, instruction for instruction: 16 bytes at a time, widened to
// 64-bit lanes and added up.
unsigned long vsum(const unsigned char *p, unsigned long count);
__asm__(
    ".text\n"
    ".globl vsum\n"
    ".type vsum, @function\n"
    "vsum:\n"
    "  lsl x1, x1, #3\n"
    "  add x2, x0, x1\n"
    "  movi v0.16b, #0\n"
    "1:\n"
    "  ldr q1, [x0], #16\n"
    "  ushll v2.8h, v1.8b, #0\n"
    "  ushll2 v1.8h, v1.16b, #0\n"
    "  ushll v4.4s, v2.4h, #0\n"
    "  ushll2 v2.4s, v2.8h, #0\n"
    "  ushll v3.4s, v1.4h, #0\n"
    "  ushll2 v1.4s, v1.8h, #0\n"
    "  ushll2 v5.2d, v4.4s, #0\n"
    "  uaddw v5.2d, v5.2d, v4.2s\n"
    "  uaddw v5.2d, v5.2d, v2.2s\n"
    "  uaddw2 v5.2d, v5.2d, v2.4s\n"
    "  uaddw v5.2d, v5.2d, v3.2s\n"
    "  uaddw2 v5.2d, v5.2d, v3.4s\n"
    "  uaddw v5.2d, v5.2d, v1.2s\n"
    "  uaddw2 v5.2d, v5.2d, v1.4s\n"
    "  add v0.2d, v0.2d, v5.2d\n"
    "  cmp x2, x0\n"
    "  b.ne 1b\n"
    "  addp d0, v0.2d\n"
    "  fmov x0, d0\n"
    "  ret\n"
    ".size vsum, .-vsum\n");

// Every step of one pass of the sum loop, each stored as it is computed.
void vtrace(const unsigned char *in, unsigned char *out);
__asm__(
    ".text\n"
    ".globl vtrace\n"
    ".type vtrace, @function\n"
    "vtrace:\n"
    "  ldr q1, [x0]\n"
    "  ushll v2.8h, v1.8b, #0\n"
    "  ushll2 v1.8h, v1.16b, #0\n"
    "  str q2, [x1], #16\n"
    "  str q1, [x1], #16\n"
    "  ushll v4.4s, v2.4h, #0\n"
    "  ushll2 v2.4s, v2.8h, #0\n"
    "  str q4, [x1], #16\n"
    "  str q2, [x1], #16\n"
    "  ushll v3.4s, v1.4h, #0\n"
    "  ushll2 v1.4s, v1.8h, #0\n"
    "  str q3, [x1], #16\n"
    "  str q1, [x1], #16\n"
    "  ushll2 v5.2d, v4.4s, #0\n"
    "  str q5, [x1], #16\n"
    "  uaddw v5.2d, v5.2d, v4.2s\n"
    "  str q5, [x1], #16\n"
    "  uaddw v5.2d, v5.2d, v2.2s\n"
    "  str q5, [x1], #16\n"
    "  uaddw2 v5.2d, v5.2d, v2.4s\n"
    "  str q5, [x1], #16\n"
    "  uaddw v5.2d, v5.2d, v3.2s\n"
    "  str q5, [x1], #16\n"
    "  uaddw2 v5.2d, v5.2d, v3.4s\n"
    "  str q5, [x1], #16\n"
    "  uaddw v5.2d, v5.2d, v1.2s\n"
    "  str q5, [x1], #16\n"
    "  uaddw2 v5.2d, v5.2d, v1.4s\n"
    "  str q5, [x1], #16\n"
    "  addp d0, v5.2d\n"
    "  fmov x0, d0\n"
    "  ret\n"
    ".size vtrace, .-vtrace\n");

int main(void) {
    unsigned char bytes[16];
    for (int i = 0; i < 16; i++) bytes[i] = (unsigned char)(0x10 + i * 17);
    uint8x16_t b = vld1q_u8(bytes);
    hex("bytes", bytes);

    uint16x8_t w = vmovl_u8(vget_low_u8(b));
    hex("ushll", &w);
    uint16x8_t w2 = vmovl_high_u8(b);
    hex("ushll2", &w2);

    uint32x4_t d = vmovl_u16(vget_low_u16(w));
    hex("ushll_s", &d);
    uint32x4_t d2 = vmovl_high_u16(w);
    hex("ushll2_s", &d2);

    uint64x2_t q = vmovl_u32(vget_low_u32(d));
    hex("ushll_d", &q);
    uint64x2_t q2 = vmovl_high_u32(d);
    hex("ushll2_d", &q2);

    uint64x2_t acc = vdupq_n_u64(0x0102030405060708ull);
    uint64x2_t sum = vaddw_u32(acc, vget_low_u32(d));
    hex("uaddw", &sum);
    sum = vaddw_high_u32(acc, d);
    hex("uaddw2", &sum);

    uint32x4_t acc32 = vdupq_n_u32(0x0a0b0c0d);
    uint32x4_t sum32 = vaddw_u16(acc32, vget_low_u16(w));
    hex("uaddw_s", &sum32);
    sum32 = vaddw_high_u16(acc32, w);
    hex("uaddw2_s", &sum32);

    uint64x2_t both = vaddq_u64(q, q2);
    hex("add_d", &both);
    printf("addp %llx\n", (unsigned long long)vaddvq_u64(q));

    // GCC's own vectorised sum of 512 bytes, which is the shape the library uses.
    unsigned char block[512];
    for (int i = 0; i < 512; i++) block[i] = (unsigned char)(i * 7 + 3);
    unsigned long total = 0;
    for (int i = 0; i < 512; i++) total += 0xFF & block[i];
    printf("total %lx\n", total);
    printf("vsum %lx\n", vsum(block, 32));
    // One pass of the loop over the first sixteen bytes, which is one widening and eight adds.
    unsigned char one[16];
    for (int i = 0; i < 16; i++) one[i] = (unsigned char)(i * 16 + 1);
    unsigned long want = 0;
    for (int i = 0; i < 16; i++) want += one[i];
    printf("vsum one %lx want %lx\n", vsum(one, 2), want);
    for (int i = 0; i < 16; i++) one[i] = 0xff;
    printf("vsum ff %lx want %lx\n", vsum(one, 2), 16UL * 0xff);
    for (int i = 0; i < 16; i++) one[i] = (unsigned char)(0x80 + i);
    want = 0;
    for (int i = 0; i < 16; i++) want += one[i];
    printf("vsum hi %lx want %lx\n", vsum(one, 2), want);
    unsigned char trace[14 * 16];
    vtrace(one, trace);
    for (int i = 0; i < 14; i++) hex("step", trace + i * 16);
    return 0;
}
