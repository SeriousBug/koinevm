/* Memory above the first 4 GiB touched by a library.
 *
 * The address space past the first 4 GiB is a second wasm memory, so an access there is a different
 * instruction sequence than one below it. A library is the other half: its pages are translated
 * while the guest runs, and the code that reaches past the boundary is the image's, which is what
 * this exercises - including a store that starts in one memory and ends in the next.
 *
 * The oracle is the same program running natively, where these addresses are ordinary ones. */

#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

void highmem_fill(unsigned char *p, unsigned long n);
void highmem_seam(unsigned char *at, uint64_t v);
unsigned long highmem_seam_read(const unsigned char *at);
unsigned long highmem_sum(const unsigned char *p, unsigned long n);

#define FOUR_GIB 0x100000000ul
#define EIGHT_GIB 0x200000000ul
#define TWELVE_GIB 0x300000000ul

static unsigned char *map(unsigned long at, unsigned long len) {
    void *p = mmap((void *)at, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED) {
        printf("map 0x%lx of 0x%lx failed\n", at, len);
        return 0;
    }
    if ((unsigned long)p != at) {
        printf("map 0x%lx of 0x%lx landed at 0x%lx\n", at, len, (unsigned long)p);
        return 0;
    }
    return p;
}

static void show(const char *what, unsigned char *p, unsigned long from, unsigned long to) {
    printf("%s", what);
    for (unsigned long i = from; i < to; i++) printf(" %02x", p[i]);
    printf("\n");
}

int main(void) {
    unsigned char *low = map(FOUR_GIB, 1 << 20);
    unsigned char *seam = map(EIGHT_GIB - 0x10000, 0x20000);
    unsigned char *high = map(TWELVE_GIB, 0x10000);
    if (!low || !seam || !high) return 1;

    highmem_fill(low, 1 << 20);
    printf("4GiB  sum=0x%016lx\n", highmem_sum(low, 1 << 20));

    highmem_fill(seam, 0x20000);
    highmem_seam(seam + 0x10000, 0x1122334455667788ul);
    printf("8GiB  sum=0x%016lx\n", highmem_sum(seam, 0x20000));
    printf("8GiB  across=0x%016lx\n", highmem_seam_read(seam + 0x10000));
    show("8GiB  seam=", seam, 0x10000 - 8, 0x10000 + 8);

    highmem_fill(high, 0x10000);
    printf("12GiB sum=0x%016lx\n", highmem_sum(high, 0x10000));

    munmap(low, 1 << 20);
    munmap(seam, 0x20000);
    munmap(high, 0x10000);
    return 0;
}
