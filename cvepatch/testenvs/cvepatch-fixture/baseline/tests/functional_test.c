/*
 * Pre-existing functional test suite. Pins the NORMAL behavior of
 * strbuf_copy so a patch that "fixes" the overflow by breaking the function
 * (e.g. turning it into a no-op, or over-truncating normal inputs) is caught.
 *
 * These cases pass on BOTH the vulnerable and the correctly-patched code,
 * because the off-by-one only manifests when len(src) >= cap.
 *
 * exit 0 -> functionality preserved; exit 1 -> behavior changed.
 */
#include "strbuf.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void expect_eq_str(const char *what, const char *got, const char *want)
{
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "FUNC FAIL [%s]: got \"%s\", want \"%s\"\n",
                what, got, want);
        failures++;
    }
}

static void expect_eq_sz(const char *what, size_t got, size_t want)
{
    if (got != want) {
        fprintf(stderr, "FUNC FAIL [%s]: got %zu, want %zu\n", what, got, want);
        failures++;
    }
}

int main(void)
{
    char dst[8];

    /* Short string copies verbatim and returns its length. */
    memset(dst, 'Z', sizeof dst);
    size_t n = strbuf_copy(dst, sizeof dst, "hi");
    expect_eq_sz("short.len", n, 2);
    expect_eq_str("short.val", dst, "hi");

    /* Empty string yields an empty, terminated buffer. */
    memset(dst, 'Z', sizeof dst);
    n = strbuf_copy(dst, sizeof dst, "");
    expect_eq_sz("empty.len", n, 0);
    expect_eq_str("empty.val", dst, "");

    /* A 7-char source fits exactly in an 8-byte buffer (7 + NUL). */
    memset(dst, 'Z', sizeof dst);
    n = strbuf_copy(dst, sizeof dst, "seven77");
    expect_eq_sz("fit.len", n, 7);
    expect_eq_str("fit.val", dst, "seven77");

    if (failures) {
        fprintf(stderr, "functional: FAIL (%d case(s))\n", failures);
        return 1;
    }
    printf("functional: PASS\n");
    return 0;
}
