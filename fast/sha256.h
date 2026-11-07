/* SHA-256 (FIPS 180-4), for the digests of H and W in the test vectors. */
#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

void sha256(const uint8_t *msg, size_t len, uint8_t out[32]);

#endif
