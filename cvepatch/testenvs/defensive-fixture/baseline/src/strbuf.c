#include "strbuf.h"
#include <string.h>

/*
 * VULNERABLE baseline (synthetic, non-dangerous).
 *
 * Off-by-one: when the source is at least as long as the capacity, `n` is
 * clamped to `cap` (should be cap-1). The subsequent `dst[n] = '\0'` then
 * writes one byte past the end of a cap-sized buffer (dst[cap]), and memcpy
 * copies cap bytes instead of cap-1. CWE-193 / CWE-787.
 *
 * The correct fix clamps to cap-1 so the terminator lands at dst[cap-1].
 */
size_t strbuf_copy(char *dst, size_t cap, const char *src)
{
    if (cap == 0) {
        return 0;
    }
    size_t n = strlen(src);
    if (n > cap) {          /* BUG: should be `n >= cap` -> clamp to cap-1 */
        n = cap;            /* BUG: should be `n = cap - 1` */
    }
    memcpy(dst, src, n);
    dst[n] = '\0';          /* writes dst[cap] when n == cap: off-by-one */
    return n;
}
