/* Life Cipher: a fast, constant-time implementation of SPEC.md (draft 0.4, algorithm version 1). The switches in
 * lc_params are test-only: they build the variants and most of the flawed controls that the tests measured (HARNESS.md). With all
 * of them 0, the library is the cipher as specified.
 *
 * Grids are 32 row words (SPEC.md §2.2): row r as an unsigned 32-bit integer, with column c in bit 31 - c.
 * Byte strings use the spec's byte layout: a grid's 128 bytes are its row words, big-endian, in order.
 */
#ifndef LIFECIPHER_H
#define LIFECIPHER_H

#include <stddef.h>
#include <stdint.h>

#define LC_GRID_BYTES 128
#define LC_TAG_BYTES 16

typedef struct { uint32_t w[32]; } lc_grid;

/* A parameter set (SPEC.md §3), plus test-only switches. All switches 0 means the spec.
 * R_init and R_final are always 2R. */
typedef struct {
    uint32_t T, S, k, R, version;
    uint32_t measurement;       /* test-only: 1 allows R below 16, for reduced-round analysis and the challenge */
    uint32_t rk_inside_life;    /* test-only variant: B' = Life(B ^ RK) ^ A, instead of Life(B) ^ A ^ RK (§5.6) */
    uint32_t message_mode1;     /* test-only variant: messages run in mode 1, with the setup table H, instead of W */
    uint32_t selector_v1;       /* test-only control: a selector that also reads A, which breaks reversibility */
    uint32_t no_marker;         /* test-only control: no end marker */
    uint32_t no_separator;      /* test-only control: no separator */
    uint32_t secret_index;      /* test-only control: a secret index over all of W, with plain table lookups */
    uint32_t keep_G;            /* test-only: keep the key table G after setup, for white-box tests */
    uint32_t fast_setup;        /* test-only: key setup with a plain sort and direct table reads. Same results, about
                                   2.5 times faster, but NOT constant time; the constant-time tests cover the default
                                   path. */
    uint32_t no_shuffle;        /* test-only control: every shuffle is the identity (tags replaced by i) */
    uint32_t m_is_k;            /* test-only control, with no_shuffle: M = K instead of Z_0 */
    uint32_t selector_v3;       /* test-only variant: selector rule v3, (h * 0x9E3779B9 mod 2^32) >> 18, so every bit
                                   of F(B) moves the selector */
    uint32_t setup_2r;          /* test-only variant: the setup run takes 2R rounds between blocks instead of R */
    uint32_t selector_v4;       /* test-only variant: selector rule v4, ((F(B) ^ rotl(F(Life(B)), 16) ^ counter)
                                   * 0x9E3779B9) >> 18 */
    uint32_t selector_v5;       /* test-only: rule v5, the spec's rule, so this switch changes nothing */
    uint32_t setup_g4;          /* test-only variant: the setup run's table entry i is G[i] ^ G[i + T/4] ^ G[i + T/2]
                                   ^ G[i + 3T/4] (indices mod T), about 29% live */
    uint32_t mask_w;            /* test-only variant: the setup stream runs T blocks longer, and
                                   W[i] ^= Z[1 + kT/16 + i], so W entries are about half live */
    uint32_t setup_gk;          /* test-only: the setup table H (SPEC.md §6.1), the spec's, so this switch changes
                                   nothing */
    uint32_t selector_v2;       /* test-only variant: selector rule v2, h = F(B) ^ r * 0x9E3779B9, bits 0-13, which
                                   reads B only through the linear fold */
    uint32_t setup_g;           /* test-only variant: the setup run's round keys come from G itself, not H */
    uint32_t no_key_check;      /* test-only: don't refuse a key that fails the key check (SPEC.md §6.1). The check
                                   still runs, so the constant-time tests still cover it. Tests that use random grids,
                                   or keys with a cell flipped, need it */
} lc_params;

typedef struct {
    lc_grid A, B;
    uint64_t r;                 /* the round counter */
    uint32_t o;                 /* the IV offset */
} lc_state;

typedef struct lc_key lc_key;

/* The demo parameter set (SPEC.md §3.3): T = 6000, S = 16, k = 4, R = 16, version 1. */
void lc_params_default(lc_params *p);
/* NULL if the parameters meet SPEC.md §3.2 (with R below 16 allowed when measuring) and T is at most 65,535, this
 * implementation's limit; else the broken rule. */
const char *lc_params_check(const lc_params *p);

/* Key setup (SPEC.md §6). The key must have passed vetting (§9). Setup checks one thing, the key check (§6.1): the
 * key's first T generations must all differ. Returns NULL on bad parameters, when out of memory, or when the key fails
 * the check (unless no_key_check); lc_key_check tells which. */
lc_key *lc_key_setup(const lc_params *p, const uint8_t key[LC_GRID_BYTES]);
void lc_key_free(lc_key *k);
/* The key check (SPEC.md §6.1) alone, for any T from 1 up: 1 if the key's first T generations all differ, 0 if not,
 * -1 for T = 0 or when out of memory. It compares G[T - 1] with every earlier generation, each in full, in constant
 * time. */
int lc_key_check(const uint8_t key[LC_GRID_BYTES], uint32_t T);

/* Encryption (SPEC.md §7). The ciphertext is exactly len bytes; pt and ct may be the same buffer. */
void lc_encrypt(const lc_key *k, const uint8_t iv[LC_GRID_BYTES], const uint8_t *ad, size_t adlen,
                const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[LC_TAG_BYTES]);
/* Decryption and verification (SPEC.md §8). Returns 0 and the plaintext if the tag matches; otherwise returns -1
 * and erases pt. ct and pt may be the same buffer. */
int lc_decrypt(const lc_key *k, const uint8_t iv[LC_GRID_BYTES], const uint8_t *ad, size_t adlen,
               const uint8_t *ct, size_t len, const uint8_t tag[LC_TAG_BYTES], uint8_t *pt);

/* A message that never ends, for statistical tests: Init, AD and the separator as in lc_encrypt,
 * then whole blocks one call at a time (pt NULL means zeros). There's no end marker and no tag. Each block's output
 * is exactly what lc_encrypt would give for the same block. */
typedef struct lc_stream lc_stream;
lc_stream *lc_stream_new(const lc_key *k, const uint8_t iv[LC_GRID_BYTES], const uint8_t *ad, size_t adlen);
void lc_stream_blocks(lc_stream *s, const uint8_t *pt, uint8_t *out, size_t blocks);
void lc_stream_free(lc_stream *s);

/* Building blocks and white-box access, for tests. */
void lc_grid_from_bytes(const uint8_t b[LC_GRID_BYTES], lc_grid *g);
void lc_grid_to_bytes(const lc_grid *g, uint8_t b[LC_GRID_BYTES]);
void lc_life(const lc_grid *in, lc_grid *out);                                    /* §5.1 */
void lc_shift(const lc_grid *in, uint32_t dx, uint32_t dy, lc_grid *out);         /* §5.2 */
uint32_t lc_fold(const lc_grid *g);                                               /* §5.3 */
void lc_selectors(const lc_params *p, const lc_grid *A, const lc_grid *B, uint64_t r, uint32_t o,
                  uint32_t out[4]);                                                /* §5.4: g, j, dx, dy */
void lc_mix_round(const lc_key *k, int mode, lc_state *st);                       /* §5.6, mode 1 (H) or 2 (W) */
void lc_mix_round_table(const lc_params *p, const lc_grid *table, lc_state *st);  /* §5.6 with any table */
void lc_setup_constant(const lc_params *p, lc_grid *out);                         /* §6.2 */
const lc_params *lc_key_params(const lc_key *k);
const lc_grid *lc_key_K(const lc_key *k);
const lc_grid *lc_key_M(const lc_key *k);
const lc_grid *lc_key_W(const lc_key *k);              /* T entries */
const lc_grid *lc_key_G(const lc_key *k);              /* T entries, or NULL unless kept */
const lc_grid *lc_key_H(const lc_key *k);              /* the setup table H (§6.1), kept with keep_G or message_mode1 */
const uint16_t *lc_key_shuffles(const lc_key *k);      /* k rows of T: shuffle s is entries s*T ... s*T + T - 1 */
/* The setup run's stream (SPEC.md §6.3), Z_0 ... Z_{blocks - 1}, for testing it (S9 in HARNESS.md). Fails (-1)
 * like key setup when the key fails the key check. */
int lc_setup_stream(const lc_params *p, const uint8_t key[LC_GRID_BYTES], uint8_t *out, size_t blocks);

#endif
