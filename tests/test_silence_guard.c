/* test_silence_guard.c -- verify the KPA silence-cache over-tagging guard
 * (payload_io.c). A capture whose frames are (almost) all tagged SILENCE is
 * untrustworthy and must yield NO silence cache, so the KPA pre-filter cannot
 * prune the correct key (GitHub issue #4: best candidate stuck on a false key).
 * Usage: test_silence_guard <file.bin> <expected_n_silence_is_zero:0|1> */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../include/payload_io.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s file.bin [expect_zero]\n", argv[0]); return 2; }
    PayloadSet ps; payload_set_init(&ps);
    char err[256] = {0};
    if (!load_payload_file(argv[1], 0, &ps, err, sizeof(err))) {
        fprintf(stderr, "load failed: %s\n", err); return 2;
    }
    printf("%s: count=%zu n_silence=%u\n", argv[1], ps.count, (unsigned)ps.n_silence);
    if (argc >= 3) {
        int expect_zero = atoi(argv[2]);
        int ok = expect_zero ? (ps.n_silence == 0) : (ps.n_silence > 0);
        printf(ok ? "  ok\n" : "  FAIL (unexpected n_silence)\n");
        return ok ? 0 : 1;
    }
    return 0;
}
