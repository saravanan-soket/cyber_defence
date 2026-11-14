#include "strbuf.h"
#include <string.h>

/* Bounded string copy; see strbuf.h for the contract. */
size_t strbuf_copy(char *dst, size_t cap, const char *src)
{
    if (cap == 0) {
        return 0;
    }
    size_t n = strlen(src);
    if (n > cap) {
        n = cap;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
    return n;
}
