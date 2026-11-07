/* Measures key setup time and encryption throughput: lc-bench [R] [seconds] [k]. The defaults are the demo set's,
 * R = 16 and k = 4. The key isn't vetted, so the key check's refusal is off (no_key_check); the check still runs and
 * is timed. */
#define _POSIX_C_SOURCE 200809L
#include "lifecipher.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
    lc_params p;
    lc_params_default(&p);
    p.no_key_check = 1;
    if (argc > 1) p.R = (uint32_t)atoi(argv[1]);
    if (argc > 3) p.k = (uint32_t)atoi(argv[3]);
    p.measurement = p.R < 16;
    double budget = argc > 2 ? atof(argv[2]) : 2.0;

    uint8_t key[LC_GRID_BYTES], iv[LC_GRID_BYTES] = {0}, tag[LC_TAG_BYTES];
    for (int i = 0; i < LC_GRID_BYTES; i++) key[i] = (uint8_t)(i * 37 + 11);

    int setups = 0;
    lc_key *k = NULL;
    double t0 = now();
    while (now() - t0 < budget / 2 || setups < 3) {
        lc_key_free(k);
        k = lc_key_setup(&p, key);
        if (!k) return fprintf(stderr, "key setup failed: %s\n", lc_params_check(&p)), 1;
        setups++;
    }
    double setup_ms = (now() - t0) / setups * 1e3;

    size_t len = 1 << 20;
    uint8_t *buf = calloc(len, 1);
    size_t bytes = 0;
    t0 = now();
    while (now() - t0 < budget / 2 || bytes < len) {
        lc_encrypt(k, iv, NULL, 0, buf, len, buf, tag);
        bytes += len;
    }
    double mbs = bytes / (now() - t0) / 1e6;
    printf("R = %u, k = %u: key setup %.1f ms, encryption %.1f MB/s (one core)\n", p.R, p.k, setup_ms, mbs);
    lc_key_free(k);
    free(buf);
    return 0;
}
