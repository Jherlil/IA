#ifdef __AVX2__
#include "sha256.h"

void sha256_avx2_8(uint32_t *i0, uint32_t *i1, uint32_t *i2, uint32_t *i3,
                   uint32_t *i4, uint32_t *i5, uint32_t *i6, uint32_t *i7,
                   uint8_t *d0, uint8_t *d1, uint8_t *d2, uint8_t *d3,
                   uint8_t *d4, uint8_t *d5, uint8_t *d6, uint8_t *d7) {
    sha256sse_1B(i0, i1, i2, i3, d0, d1, d2, d3);
    sha256sse_1B(i4, i5, i6, i7, d4, d5, d6, d7);
}
#endif