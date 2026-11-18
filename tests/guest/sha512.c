/* The SHA-512 block transform, as OpenSSL's generated assembly writes it.
 *
 * Every SHA-512 digest the guest computes goes through this code, and it came out wrong while the
 * same instructions one at a time did not. The function is the one libcrypto runs on a machine
 * whose HWCAP claims no crypto extensions, copied here without the check that chooses between
 * them, so the guest and the oracle run it literally and their eight words compare.
 *
 * Generated from openssl's crypto/sha/asm/sha512-armv8.pl, which is Apache-2.0. */

#ifdef __APPLE__
extern long write(int, const void *, unsigned long);
extern void exit(int);
#define GUEST_WRITE(fd, buf, n) write((fd), (buf), (unsigned long)(n))
#define GUEST_EXIT(code) exit((int)(code))
#define GUEST_ENTRY sha512_main
#define SHA512_SYM "_sha512_rounds"
#else
static inline long guest_syscall3(long nr, long a, long b, long c) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
static void guest_exit(long code) {
    register long x8 __asm__("x8") = 93;
    register long x0 __asm__("x0") = code;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0) : "memory");
    __builtin_unreachable();
}
#define GUEST_WRITE(fd, buf, n) guest_syscall3(64, (fd), (long)(buf), (long)(n))
#define GUEST_EXIT(code) guest_exit(code)
#define GUEST_ENTRY _start
#define SHA512_SYM "sha512_rounds"
#endif

void sha512_rounds(unsigned long *h, const void *in, unsigned long num) __asm__(SHA512_SYM);

#include "sha512asm.h"

static const unsigned long iv[8] = {
    0x6a09e667f3bcc908ul, 0xbb67ae8584caa73bul, 0x3c6ef372fe94f82bul, 0xa54ff53a5f1d36f1ul,
    0x510e527fade682d1ul, 0x9b05688c2b3e6c1ful, 0x1f83d9abfb41bd6bul, 0x5be0cd19137e2179ul,
};

static unsigned char block[128];
static char out[4096];
static int out_n;
static void put(char c) { out[out_n++] = c; }
static void put_hex(unsigned long v) {
    static const char digits[] = "0123456789abcdef";
    put('0');
    put('x');
    for (int i = 0; i < 16; i++) put(digits[(v >> (60 - 4 * i)) & 0xf]);
    put('\n');
}

__attribute__((used)) void GUEST_ENTRY(void) {
    /* A block of every byte value, so a wrong schedule word shows up in a word of the result
     * rather than being cancelled by a run of zeros. */
    for (int i = 0; i < 128; i++) block[i] = (unsigned char)(i * 7 + 3);
    for (int c = 0; c < 3; c++) {
        unsigned long h[8];
        for (int i = 0; i < 8; i++) h[i] = iv[i] ^ (unsigned long)c;
        sha512_rounds(h, block, 1);
        for (int i = 0; i < 8; i++) put_hex(h[i]);
    }
    GUEST_WRITE(1, out, out_n);
    GUEST_EXIT(0);
}
