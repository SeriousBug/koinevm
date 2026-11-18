/* The SHA-512 block transform called through a shared library.
 *
 * libcrypto's copy of it is wrong in the guest while the same code linked into the image is right,
 * so what differs is where the code lives: a library is translated a page at a time, when the
 * guest reaches it, and this fixture puts the transform behind a library boundary to reach the
 * same path. The library is `sha512dyn.lib.c`, loaded from `/tmp/libsha512dyn.so`. */

#include <stdio.h>

void sha512_rounds(unsigned long *h, const void *in, unsigned long num);

static const unsigned long iv[8] = {
    0x6a09e667f3bcc908ul, 0xbb67ae8584caa73bul, 0x3c6ef372fe94f82bul, 0xa54ff53a5f1d36f1ul,
    0x510e527fade682d1ul, 0x9b05688c2b3e6c1ful, 0x1f83d9abfb41bd6bul, 0x5be0cd19137e2179ul,
};

int main(void) {
    unsigned char block[128];
    for (int i = 0; i < 128; i++) block[i] = (unsigned char)(i * 7 + 3);
    for (int c = 0; c < 3; c++) {
        unsigned long h[8];
        for (int i = 0; i < 8; i++) h[i] = iv[i] ^ (unsigned long)c;
        sha512_rounds(h, block, 1);
        for (int i = 0; i < 8; i++) printf("0x%016lx\n", h[i]);
    }
    return 0;
}
