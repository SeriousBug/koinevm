/* Every access width a translated instruction has a form for, applied to memory above the first
 * 4 GiB. A library is translated a page at a time, when the guest reaches it, so these pages are
 * where an image and a page module meet: the page asks the image for the code that reaches past the
 * boundary rather than carrying nineteen functions of its own.
 *
 * Each width is a pass of its own so that the compiler emits it, and the seam functions put the
 * accesses where one starts in a memory and ends in the next. A 4-byte vector access is a lane, not
 * a two-lane register store, which is 8 bytes and would have to be a different width. */

#include <stddef.h>
#include <stdint.h>
#include <arm_neon.h>

typedef unsigned long ulong;
typedef unsigned uint;

#define STORES(T, expr)                                              \
    for (unsigned long i = 0; i + sizeof(T) <= n; i += sizeof(T)) *(T *)(p + i) = (expr);

#define LOADS(T, cast)                                               \
    for (unsigned long i = 0; i + sizeof(T) <= n; i += sizeof(T))     \
        sum += (ulong)((cast) * (T *)(p + i));

void highmem_fill(unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i + 16 <= n; i += 16) vst1q_u8(p + i, vdupq_n_u8((unsigned char)i));
    for (unsigned long i = 0; i + 8 <= n; i += 8) vst1_u64((uint64_t *)(p + i), vdup_n_u64(i));
    for (unsigned long i = 0; i + 4 <= n; i += 4)
        vst1_lane_u32((uint32_t *)(p + i), vdup_n_u32(i), 0);
    STORES(uint64_t, i * 0x0101010101010101ul)
    STORES(uint32_t, i * 0x01010101u)
    STORES(uint16_t, (uint16_t)(i * 3 + 1))
    STORES(uint8_t, (uint8_t)(i * 5 + 3))
}

void highmem_seam(unsigned char *at, uint64_t v) {
    *(uint64_t *)(at - 4) = v;
    *(uint32_t *)(at - 3) = (uint32_t)(v >> 16);
    *(uint16_t *)(at - 1) = (uint16_t)(v >> 32);
    vst1q_u8(at + 6, vdupq_n_u8((unsigned char)(v >> 40)));
    vst1_u64((uint64_t *)(at - 6), vdup_n_u64(v));
    vst1_lane_u32((uint32_t *)(at + 2), vdup_n_u32((uint32_t)(v >> 8)), 0);
}

unsigned long highmem_seam_read(const unsigned char *at) {
    unsigned long sum = 0;
    sum += *(const uint64_t *)(at - 4);
    sum += (unsigned long)*(const int32_t *)(at - 3);
    sum += *(const uint32_t *)(at - 2);
    sum += (unsigned long)*(const int16_t *)(at - 1);
    sum += *(const uint16_t *)(at - 1);
    sum += *(const uint8_t *)(at + 3);
    sum += vgetq_lane_u8(vld1q_u8(at - 8), 5);
    sum += vgetq_lane_u16(vld1q_u16((const uint16_t *)(at - 6)), 2);
    sum += vgetq_lane_u32(vld1q_u32((const uint32_t *)(at - 4)), 1);
    sum += vgetq_lane_u8(vld1q_dup_u8(at - 1), 7);
    sum += vgetq_lane_u32(vld1q_dup_u32((const uint32_t *)(at - 2)), 3);
    return sum;
}

unsigned long highmem_sum(const unsigned char *p, unsigned long n) {
    unsigned long sum = 0;
    for (unsigned long i = 0; i + 16 <= n; i += 16) {
        uint8x16_t b = vld1q_u8(p + i);
        sum += vgetq_lane_u8(b, 0) + vgetq_lane_u8(b, 15);
        sum += vgetq_lane_u8(vld1q_dup_u8(p + i), 3);
        sum += vgetq_lane_u16(vld1q_dup_u16((const uint16_t *)(p + i)), 3);
        sum += vgetq_lane_u32(vld1q_dup_u32((const uint32_t *)(p + i)), 3);
        sum += (unsigned long)(vgetq_lane_u64(vld1q_dup_u64((const uint64_t *)(p + i)), 1) & 0xff);
    }
    for (unsigned long i = 0; i + 8 <= n; i += 8)
        sum += vget_lane_u64(vld1_u64((const uint64_t *)(p + i)), 0);
    for (unsigned long i = 0; i + 4 <= n; i += 4) {
        uint32x2_t zero = {0, 0};
        sum += vget_lane_u32(vld1_lane_u32((const uint32_t *)(p + i), zero, 0), 0);
    }
    LOADS(uint64_t, ulong)
    LOADS(uint32_t, uint)
    LOADS(uint16_t, uint)
    LOADS(uint8_t, uint)
    LOADS(int64_t, ulong)
    LOADS(int32_t, ulong)
    LOADS(int16_t, ulong)
    LOADS(int8_t, ulong)
    LOADS(int32_t, uint)
    LOADS(int16_t, uint)
    LOADS(int8_t, uint)
    return sum;
}
