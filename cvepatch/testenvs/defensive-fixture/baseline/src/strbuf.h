#ifndef STRBUF_H
#define STRBUF_H

#include <stddef.h>

/*
 * strbuf_copy — copy a C string into a fixed-capacity destination buffer,
 * always NUL-terminating.
 *
 * Contract:
 *   - `cap` is the total number of bytes available at `dst`.
 *   - At most cap-1 source bytes are copied; dst is always NUL-terminated
 *     within [0, cap-1].
 *   - Returns the number of source bytes copied (excluding the terminator).
 *
 * A correct implementation never writes to dst[cap] or beyond.
 */
size_t strbuf_copy(char *dst, size_t cap, const char *src);

#endif /* STRBUF_H */
