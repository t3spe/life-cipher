/* Life Cipher: a fast, constant-time implementation of SPEC.md (draft 0.4, algorithm version 1).
 *
 * No secret decides a branch or a memory address (SPEC.md §14):
 * - Life is bit-parallel on row words.
 * - The round key is read by touching all S entries of the public group and keeping one with masks.
 * - Rows move for the secret dy in five masked steps, and dx is a rotation.
 * - The shuffles are a bitonic sorting network that carries each generation along with its tag, so W is built
 *   without ever reading G at a secret position.
 * - The tag comparison always looks at all 16 bytes.
 * The switches in lc_params (variants, controls, measurement) are test-only (HARNESS.md).
 *
 * Built with AVX2 (as by -march=native on most x86-64 machines), runs of Mix rounds keep A and B in vector registers
 * (the "AVX2 kernel" below). Without AVX2, or for the secret_index control, the portable functions run instead.
 * Both paths give the same results; the tests run each.
 */
#include "lifecipher.h"

#include <stdlib.h>
#include <string.h>

/* K2 (Valgrind) builds mark secrets as undefined; LC_PUBLIC tells it a value derived from them is public by design. */
#ifdef LC_CTGRIND
#include <valgrind/memcheck.h>
#define LC_PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED(p, n)
#else
#define LC_PUBLIC(p, n) ((void)0)
#endif

#define GOLDEN 0x9E3779B9u              /* floor(2^32 / golden ratio), SPEC.md §12.1 */
#define MARKER 0x80u

static const uint32_t SETUP0[32] = {     /* SPEC.md Appendix A: the first 1,024 bits of pi's fractional part */
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
    0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69,
};

struct lc_key {
    lc_params p;
    lc_grid K, M;
    lc_grid *W, *G, *H;                 /* G and H are NULL after setup unless kept; H is NULL when it's G */
    uint16_t *shuffles;                 /* k * T generation numbers, for white-box tests */
};

/* ---- constant-time helpers ------------------------------------------------------------------------------------- */

static inline uint32_t rotl32(uint32_t x, uint32_t n) { n &= 31; return (x << n) | (x >> ((32 - n) & 31)); }
static inline uint32_t rotr32(uint32_t x, uint32_t n) { n &= 31; return (x >> n) | (x << ((32 - n) & 31)); }

/* Keeps the compiler from turning a mask back into a branch. */
static inline uint32_t barrier32(uint32_t x) { __asm__ volatile("" : "+r"(x)); return x; }
static inline uint64_t barrier64(uint64_t x) { __asm__ volatile("" : "+r"(x)); return x; }

static inline uint32_t mask_eq32(uint32_t a, uint32_t b)   /* all ones if a == b, else 0 */
{
    uint32_t x = a ^ b;
    return barrier32(((x | (0u - x)) >> 31) - 1u);
}

static inline uint64_t gt64(uint64_t a, uint64_t b)        /* 1 if a > b, else 0 */
{
    uint64_t z = b - a;
    return (z ^ ((a ^ b) & (a ^ z))) >> 63;
}

static inline uint64_t eq64(uint64_t a, uint64_t b)        /* 1 if a == b, else 0 */
{
    uint64_t x = a ^ b;
    return 1 ^ ((x | (0 - x)) >> 63);
}

static void erase(void *p, size_t n)
{
    memset(p, 0, n);
    __asm__ volatile("" : : "r"(p) : "memory");                     /* so the compiler can't drop the memset */
}

/* ---- §2 data layout ------------------------------------------------------------------------------------------- */

void lc_grid_from_bytes(const uint8_t b[LC_GRID_BYTES], lc_grid *g)
{
    for (int r = 0; r < 32; r++)
        g->w[r] = (uint32_t)b[4 * r] << 24 | (uint32_t)b[4 * r + 1] << 16 | (uint32_t)b[4 * r + 2] << 8 | b[4 * r + 3];
}

void lc_grid_to_bytes(const lc_grid *g, uint8_t b[LC_GRID_BYTES])
{
    for (int r = 0; r < 32; r++) {
        b[4 * r] = (uint8_t)(g->w[r] >> 24);
        b[4 * r + 1] = (uint8_t)(g->w[r] >> 16);
        b[4 * r + 2] = (uint8_t)(g->w[r] >> 8);
        b[4 * r + 3] = (uint8_t)g->w[r];
    }
}

static inline uint8_t get_byte(const lc_grid *g, size_t i) { return (uint8_t)(g->w[i >> 2] >> (24 - 8 * (i & 3))); }
static inline void xor_byte(lc_grid *g, size_t i, uint8_t v) { g->w[i >> 2] ^= (uint32_t)v << (24 - 8 * (i & 3)); }

static inline void put_byte(lc_grid *g, size_t i, uint8_t v)
{
    uint32_t sh = 24 - 8 * (uint32_t)(i & 3);
    g->w[i >> 2] = (g->w[i >> 2] & ~(0xFFu << sh)) | (uint32_t)v << sh;
}

/* ---- §3 parameters ------------------------------------------------------------------------------------------- */

void lc_params_default(lc_params *p)
{
    memset(p, 0, sizeof *p);
    p->T = 6000;
    p->S = 16;
    p->k = 4;
    p->R = 16;
    p->version = 1;
}

const char *lc_params_check(const lc_params *p)
{
    if (p->S != 16) return "S must be 16: the selector draws a 4-bit entry index";
    if (p->T == 0 || p->T > 65535 || p->T % p->S) return "T must be a multiple of S, at most 65,535";
    if (p->k == 0 || p->T % p->k) return "k must divide T";
    if (p->R == 0 || (p->R < 16 && !p->measurement)) return "R must be at least 16 (or measurement on)";
    if (p->setup_g4 && p->T % 4) return "setup_g4 needs T divisible by 4";
    if ((p->setup_g != 0) + (p->setup_g4 != 0) + (p->setup_gk != 0) > 1) return "setup_g, setup_g4 and setup_gk are alternatives";
    return NULL;
}

/* ---- §5 building blocks -------------------------------------------------------------------------------------- */

void lc_life(const lc_grid *in, lc_grid *out)
{
    /* For each row: the 3-cell and 2-cell horizontal sums in two bits each, then the 8-neighbour count. The 3-cell
     * sums are padded with their torus neighbours (row 31 above row 0, row 0 below row 31), so the loops read
     * plain array slots and vectorize. */
    uint32_t lo3[34], hi3[34], lo2[32], hi2[32];
    for (int r = 0; r < 32; r++) {
        uint32_t x = in->w[r], l = rotl32(x, 1), rt = rotr32(x, 1);
        lo3[r + 1] = l ^ x ^ rt;
        hi3[r + 1] = (l & x) | (l & rt) | (x & rt);
        lo2[r] = l ^ rt;
        hi2[r] = l & rt;
    }
    lo3[0] = lo3[32];
    hi3[0] = hi3[32];
    lo3[33] = lo3[1];
    hi3[33] = hi3[1];
    lc_grid o;
    for (int r = 0; r < 32; r++) {                 /* up: slot r, middle: lo2/hi2, down: slot r + 2 */
        uint32_t ones = lo3[r] ^ lo2[r] ^ lo3[r + 2];
        uint32_t carry = (lo3[r] & lo2[r]) | (lo3[r] & lo3[r + 2]) | (lo2[r] & lo3[r + 2]);
        uint32_t a = hi3[r] ^ hi2[r], b = hi3[r] & hi2[r];
        uint32_t c = hi3[r + 2] ^ carry, e = hi3[r + 2] & carry;
        /* live next if the count is 3, or 2 and live now */
        o.w[r] = (a ^ c) & ~(b | e | (a & c)) & (ones | in->w[r]);
    }
    *out = o;
}

void lc_shift(const lc_grid *in, uint32_t dx, uint32_t dy, lc_grid *out)
{
    uint32_t t[64];                             /* t[32 ...] repeats t[0 ...], so row r - s is t[r + 32 - s] */
    memcpy(t, in->w, sizeof in->w);
    for (int b = 0; b < 5; b++) {               /* rows down by dy, as five steps each kept or dropped by a mask */
        uint32_t m = barrier32(0u - ((dy >> b) & 1u));
        int s = 1 << b;
        memcpy(t + 32, t, sizeof in->w);
        for (int r = 0; r < 32; r++) t[r] = (t[r + 32 - s] & m) | (t[r] & ~m);
    }
    for (int r = 0; r < 32; r++) out->w[r] = rotr32(t[r], dx);    /* columns right: column c is bit 31 - c */
}

uint32_t lc_fold(const lc_grid *g)
{
    uint32_t f = 0;
    for (uint32_t r = 0; r < 32; r++) f ^= rotl32(g->w[r], r);
    return f;
}

static uint32_t selector_hash(const lc_params *p, const lc_grid *A, const lc_grid *B, uint64_t r)
{
    uint32_t counter = (uint32_t)r * GOLDEN;                         /* r * 0x9E3779B9 mod 2^32 */
    if (p->selector_v1) return lc_fold(A) ^ rotl32(lc_fold(B), 16) ^ counter;
    if (p->selector_v2) return lc_fold(B) ^ counter;                 /* rule v2 */
    if (p->selector_v3) return ((lc_fold(B) ^ counter) * GOLDEN) >> 18;   /* every bit of F(B) reaches bits 0-13 */
    if (p->selector_v4) {                                            /* also F(Life(B)), which a difference rarely spares */
        lc_grid L;
        lc_life(B, &L);
        return ((lc_fold(B) ^ rotl32(lc_fold(&L), 16) ^ counter) * GOLDEN) >> 18;
    }
    uint32_t h = counter;                                            /* rule v5, §5.4.2: a chain over every row of B */
    for (int k = 0; k < 32; k++) h = rotl32(h ^ B->w[k], 13) * GOLDEN;
    return h >> 18;
}

void lc_selectors(const lc_params *p, const lc_grid *A, const lc_grid *B, uint64_t r, uint32_t o, uint32_t out[4])
{
    uint32_t h = selector_hash(p, A, B, r);
    out[0] = (uint32_t)(((uint64_t)o + r) % (p->T / p->S));
    out[1] = h & 0xF;
    out[2] = (h >> 4) & 0x1F;
    out[3] = (h >> 9) & 0x1F;
}

/* §5.5: entry j of a group, reading all S entries and keeping one with masks. */
static void read_entry(const lc_grid *group, uint32_t j, uint32_t S, lc_grid *out)
{
    lc_grid e;
    memset(&e, 0, sizeof e);
    for (uint32_t i = 0; i < S; i++) {
        uint32_t m = mask_eq32(i, j);
        for (int r = 0; r < 32; r++) e.w[r] |= group[i].w[r] & m;
    }
    *out = e;
}

/* One Mix round (§5.6) with the portable functions. */
static void mix_round_portable(const lc_params *p, const lc_grid *table, lc_state *st)
{
    uint32_t h = selector_hash(p, &st->A, &st->B, st->r);
    uint32_t g = (uint32_t)(((uint64_t)st->o + st->r) % (p->T / p->S));
    lc_grid entry, rk, next;
    if (p->secret_index)
        entry = table[h % p->T];                                      /* the control: a secret address */
    else
        read_entry(table + (size_t)p->S * g, h & 0xF, p->S, &entry);
    lc_shift(&entry, (h >> 4) & 0x1F, (h >> 9) & 0x1F, &rk);
    if (p->rk_inside_life) {
        lc_grid t;
        for (int r = 0; r < 32; r++) t.w[r] = st->B.w[r] ^ rk.w[r];
        lc_life(&t, &next);
        for (int r = 0; r < 32; r++) next.w[r] ^= st->A.w[r];
    } else {
        lc_life(&st->B, &next);
        for (int r = 0; r < 32; r++) next.w[r] ^= st->A.w[r] ^ rk.w[r];
    }
    st->A = st->B;
    st->B = next;
    st->r++;
}

#if defined(__AVX2__)
#include <immintrin.h>

/* ---- the AVX2 kernel: the same Mix round, with A and B held in registers across a run of rounds ---------------- */

/* A grid in four AVX2 registers: v[k] holds rows 8k ... 8k + 7, row 8k + i in lane i. */
typedef struct { __m256i v[4]; } vgrid;

static inline vgrid vload(const lc_grid *g)
{
    vgrid x;
    for (int k = 0; k < 4; k++) x.v[k] = _mm256_loadu_si256((const __m256i *)(g->w + 8 * k));
    return x;
}

static inline void vstore(lc_grid *g, vgrid x)
{
    for (int k = 0; k < 4; k++) _mm256_storeu_si256((__m256i *)(g->w + 8 * k), x.v[k]);
}

static inline __m256i vsel(__m256i a, __m256i b, __m256i m)          /* a where m is all ones, else b */
{
    return _mm256_or_si256(_mm256_and_si256(m, a), _mm256_andnot_si256(m, b));
}

/* Rows down by s (1, 2 or 4): rotate each register by s lanes, then take the first s lanes from the register above. */
#define ROWS_DOWN_SMALL(x, s, imm, out)                                                                                \
    do {                                                                                                             \
        const __m256i idx_ = _mm256_setr_epi32((0 - (s)) & 7, (1 - (s)) & 7, (2 - (s)) & 7, (3 - (s)) & 7,           \
                                               (4 - (s)) & 7, (5 - (s)) & 7, (6 - (s)) & 7, (7 - (s)) & 7);           \
        __m256i r0_ = _mm256_permutevar8x32_epi32((x).v[0], idx_), r1_ = _mm256_permutevar8x32_epi32((x).v[1], idx_); \
        __m256i r2_ = _mm256_permutevar8x32_epi32((x).v[2], idx_), r3_ = _mm256_permutevar8x32_epi32((x).v[3], idx_); \
        (out).v[0] = _mm256_blend_epi32(r0_, r3_, imm);                                                              \
        (out).v[1] = _mm256_blend_epi32(r1_, r0_, imm);                                                              \
        (out).v[2] = _mm256_blend_epi32(r2_, r1_, imm);                                                              \
        (out).v[3] = _mm256_blend_epi32(r3_, r2_, imm);                                                              \
    } while (0)

static inline vgrid rows_up1(vgrid x)        /* row r gets row r + 1 */
{
    const __m256i idx = _mm256_setr_epi32(1, 2, 3, 4, 5, 6, 7, 0);
    __m256i r0 = _mm256_permutevar8x32_epi32(x.v[0], idx), r1 = _mm256_permutevar8x32_epi32(x.v[1], idx);
    __m256i r2 = _mm256_permutevar8x32_epi32(x.v[2], idx), r3 = _mm256_permutevar8x32_epi32(x.v[3], idx);
    vgrid y;
    y.v[0] = _mm256_blend_epi32(r0, r1, 0x80);
    y.v[1] = _mm256_blend_epi32(r1, r2, 0x80);
    y.v[2] = _mm256_blend_epi32(r2, r3, 0x80);
    y.v[3] = _mm256_blend_epi32(r3, r0, 0x80);
    return y;
}

static inline __m256i rotl1(__m256i x) { return _mm256_or_si256(_mm256_slli_epi32(x, 1), _mm256_srli_epi32(x, 31)); }
static inline __m256i rotr1(__m256i x) { return _mm256_or_si256(_mm256_srli_epi32(x, 1), _mm256_slli_epi32(x, 31)); }

static inline vgrid vlife(vgrid x)
{
    vgrid lo3, hi3, lo2, hi2, out;
    for (int k = 0; k < 4; k++) {
        __m256i c = x.v[k], l = rotl1(c), r = rotr1(c);
        lo3.v[k] = _mm256_xor_si256(_mm256_xor_si256(l, c), r);
        hi3.v[k] = _mm256_or_si256(_mm256_and_si256(l, c), _mm256_and_si256(r, _mm256_or_si256(l, c)));
        lo2.v[k] = _mm256_xor_si256(l, r);
        hi2.v[k] = _mm256_and_si256(l, r);
    }
    vgrid lo3u, hi3u, lo3d = rows_up1(lo3), hi3d = rows_up1(hi3);   /* u: the row above, d: the row below */
    ROWS_DOWN_SMALL(lo3, 1, 0x01, lo3u);
    ROWS_DOWN_SMALL(hi3, 1, 0x01, hi3u);
    for (int k = 0; k < 4; k++) {
        __m256i lu = lo3u.v[k], ld = lo3d.v[k], lm = lo2.v[k];
        __m256i ones = _mm256_xor_si256(_mm256_xor_si256(lu, lm), ld);
        __m256i carry = _mm256_or_si256(_mm256_and_si256(lu, lm), _mm256_and_si256(ld, _mm256_or_si256(lu, lm)));
        __m256i a = _mm256_xor_si256(hi3u.v[k], hi2.v[k]), b = _mm256_and_si256(hi3u.v[k], hi2.v[k]);
        __m256i c = _mm256_xor_si256(hi3d.v[k], carry), e = _mm256_and_si256(hi3d.v[k], carry);
        __m256i dead = _mm256_or_si256(_mm256_or_si256(b, e), _mm256_and_si256(a, c));
        out.v[k] = _mm256_andnot_si256(dead, _mm256_and_si256(_mm256_xor_si256(a, c), _mm256_or_si256(ones, x.v[k])));
    }
    return out;
}

static inline uint32_t vfold(vgrid x)
{
    __m256i acc = _mm256_setzero_si256();
    for (int k = 0; k < 4; k++) {
        const __m256i n = _mm256_setr_epi32(8 * k, 8 * k + 1, 8 * k + 2, 8 * k + 3, 8 * k + 4, 8 * k + 5, 8 * k + 6, 8 * k + 7);
        const __m256i m = _mm256_sub_epi32(_mm256_set1_epi32(32), n);
        acc = _mm256_xor_si256(acc, _mm256_or_si256(_mm256_sllv_epi32(x.v[k], n), _mm256_srlv_epi32(x.v[k], m)));
    }
    __m128i h = _mm_xor_si128(_mm256_castsi256_si128(acc), _mm256_extracti128_si256(acc, 1));
    h = _mm_xor_si128(h, _mm_shuffle_epi32(h, 0x4E));
    h = _mm_xor_si128(h, _mm_shuffle_epi32(h, 0xB1));
    return (uint32_t)_mm_cvtsi128_si32(h);
}

static inline vgrid vread_entry(const lc_grid *group, uint32_t j)
{
    vgrid e;
    for (int k = 0; k < 4; k++) e.v[k] = _mm256_setzero_si256();
    for (uint32_t i = 0; i < 16; i++) {
        __m256i m = _mm256_set1_epi32((int)mask_eq32(i, j));
        const __m256i *g = (const __m256i *)group[i].w;
        for (int k = 0; k < 4; k++) e.v[k] = _mm256_or_si256(e.v[k], _mm256_and_si256(m, _mm256_loadu_si256(g + k)));
    }
    return e;
}

static inline vgrid vshift(vgrid x, uint32_t dx, uint32_t dy)
{
    vgrid y;
    __m256i m = _mm256_set1_epi32((int)barrier32(0u - (dy & 1u)));
    ROWS_DOWN_SMALL(x, 1, 0x01, y);
    for (int k = 0; k < 4; k++) x.v[k] = vsel(y.v[k], x.v[k], m);
    m = _mm256_set1_epi32((int)barrier32(0u - ((dy >> 1) & 1u)));
    ROWS_DOWN_SMALL(x, 2, 0x03, y);
    for (int k = 0; k < 4; k++) x.v[k] = vsel(y.v[k], x.v[k], m);
    m = _mm256_set1_epi32((int)barrier32(0u - ((dy >> 2) & 1u)));
    ROWS_DOWN_SMALL(x, 4, 0x0F, y);
    for (int k = 0; k < 4; k++) x.v[k] = vsel(y.v[k], x.v[k], m);
    m = _mm256_set1_epi32((int)barrier32(0u - ((dy >> 3) & 1u)));
    for (int k = 0; k < 4; k++) y.v[k] = vsel(x.v[(k + 3) & 3], x.v[k], m);
    m = _mm256_set1_epi32((int)barrier32(0u - ((dy >> 4) & 1u)));
    for (int k = 0; k < 4; k++) x.v[k] = vsel(y.v[(k + 2) & 3], y.v[k], m);
    /* Columns right by dx. Lane-wise shifts (counts of 32 give 0, which handles dx = 0) take the count in every lane;
     * like any shift, their time doesn't depend on it, and Valgrind's K2 check can follow a secret count through them. */
    __m256i r = _mm256_set1_epi32((int)dx), l = _mm256_set1_epi32((int)(32 - dx));
    __asm__("" : "+x"(r), "+x"(l));        /* keeps the compiler from turning these back into shifts by one count */
    for (int k = 0; k < 4; k++) x.v[k] = _mm256_or_si256(_mm256_srlv_epi32(x.v[k], r), _mm256_sllv_epi32(x.v[k], l));
    return x;
}

/* n Mix rounds with A and B kept in registers. Handles every switch but secret_index. */
static void rounds_avx2(const lc_params *p, const lc_grid *table, lc_state *st, uint32_t n)
{
    vgrid A = vload(&st->A), B = vload(&st->B);
    uint64_t r = st->r;
    const uint32_t groups = p->T / p->S;
    uint32_t g = (uint32_t)(((uint64_t)st->o + r) % groups);
    while (n--) {
        uint32_t h;
        vgrid lifeB;
        if (p->selector_v1 || p->selector_v2 || p->selector_v3 || p->selector_v4) {
            h = vfold(B) ^ (uint32_t)r * GOLDEN;
            if (p->selector_v1) h = vfold(A) ^ rotl32(h ^ (uint32_t)r * GOLDEN, 16) ^ (uint32_t)r * GOLDEN;
            if (p->selector_v3) h = (h * GOLDEN) >> 18;
            if (p->selector_v4) {
                lifeB = vlife(B);
                h = ((h ^ rotl32(vfold(lifeB), 16)) * GOLDEN) >> 18;
            }
        } else {                                                     /* rule v5 */
            uint32_t rows[32];
            for (int k = 0; k < 4; k++) _mm256_storeu_si256((__m256i *)(rows + 8 * k), B.v[k]);
            h = (uint32_t)r * GOLDEN;
            for (int k = 0; k < 32; k++) h = rotl32(h ^ rows[k], 13) * GOLDEN;
            h >>= 18;
        }
        vgrid rk = vshift(vread_entry(table + (size_t)p->S * g, h & 0xF), (h >> 4) & 0x1F, (h >> 9) & 0x1F);
        vgrid next;
        if (p->rk_inside_life) {
            vgrid t;
            for (int k = 0; k < 4; k++) t.v[k] = _mm256_xor_si256(B.v[k], rk.v[k]);
            next = vlife(t);
            for (int k = 0; k < 4; k++) next.v[k] = _mm256_xor_si256(next.v[k], A.v[k]);
        } else {
            next = p->selector_v4 ? lifeB : vlife(B);
            for (int k = 0; k < 4; k++) next.v[k] = _mm256_xor_si256(next.v[k], _mm256_xor_si256(A.v[k], rk.v[k]));
        }
        A = B;
        B = next;
        r++;
        if (++g == groups) g = 0;
    }
    vstore(&st->A, A);
    vstore(&st->B, B);
    st->r = r;
}

#endif

static void run_rounds(const lc_params *p, const lc_grid *table, lc_state *st, uint32_t n)
{
#if defined(__AVX2__)
    if (!p->secret_index) {
        rounds_avx2(p, table, st, n);
        return;
    }
#endif
    while (n--) mix_round_portable(p, table, st);
}

void lc_mix_round_table(const lc_params *p, const lc_grid *table, lc_state *st)
{
    run_rounds(p, table, st, 1);
}

static const lc_grid *mode1_table(const lc_key *k) { return k->H ? k->H : k->G; }   /* H, or G under setup_g */

void lc_mix_round(const lc_key *k, int mode, lc_state *st)
{
    lc_mix_round_table(&k->p, mode == 1 ? mode1_table(k) : k->W, st);
}

/* ---- §6 key setup -------------------------------------------------------------------------------------------- */

void lc_setup_constant(const lc_params *p, lc_grid *out)
{
    memcpy(out->w, SETUP0, sizeof SETUP0);
    out->w[0] ^= p->T;
    out->w[1] ^= p->k;
    out->w[2] ^= p->S;
    out->w[3] ^= p->R;
    out->w[4] ^= p->version;
}

static lc_grid *key_table(const lc_params *p, const lc_grid *K)
{
    lc_grid *G = malloc((size_t)p->T * sizeof *G);
    if (!G) return NULL;
    G[0] = *K;
    for (uint32_t t = 1; t < p->T; t++) lc_life(&G[t - 1], &G[t]);
    return G;
}

/* §6.1, the key check: 1 if G[T - 1] differs from every earlier generation, else 0. That holds exactly when all T
 * differ: once Life repeats a grid it cycles, so the last generation repeats too. Every grid is compared in full,
 * with no early exit, so the time doesn't depend on the key. */
static uint32_t key_check(const lc_grid *G, size_t T)
{
    uint32_t repeat = 0;
    for (size_t t = 0; t + 1 < T; t++) {
        uint32_t diff = 0;
        for (int r = 0; r < 32; r++) diff |= G[t].w[r] ^ G[T - 1].w[r];
        repeat = barrier32(repeat | mask_eq32(diff, 0));
    }
    return 1 & ~repeat;
}

int lc_key_check(const uint8_t key[LC_GRID_BYTES], uint32_t T)
{
    if (!T) return -1;
    lc_params p;
    lc_params_default(&p);
    p.T = T;
    lc_grid K, *G;
    lc_grid_from_bytes(key, &K);
    if (!(G = key_table(&p, &K))) return -1;
    uint32_t ok = key_check(G, T);
    LC_PUBLIC(&ok, sizeof ok);                                        /* passing or failing it is public */
    erase(G, (size_t)T * sizeof *G);
    erase(&K, sizeof K);
    free(G);
    return (int)ok;
}

/* §6.1: the setup run's table H, each entry the XOR of n generations T/n apart, with n = k (or 4 under setup_g4).
 * Fixed positions only, so it's constant time. Under setup_g the table is G itself, and G is returned. */
static lc_grid *setup_table(const lc_params *p, lc_grid *G)
{
    if (p->setup_g) return G;
    const size_t T = p->T, n = p->setup_g4 ? 4 : p->k, step = T / n;
    lc_grid *Gn = calloc(T, sizeof *Gn);
    if (!Gn) return NULL;
    for (size_t i = 0; i < T; i++)
        for (size_t m = 0; m < n; m++)
            for (int r = 0; r < 32; r++) Gn[i].w[r] ^= G[(i + m * step) % T].w[r];
    return Gn;
}

static void free_setup_table(const lc_params *p, lc_grid *tab)
{
    if (p->setup_g || !tab) return;
    erase(tab, (size_t)p->T * sizeof *tab);
    free(tab);
}

/* The setup run (§6.3): Init from SETUP and K, R_init rounds in mode 1, then Z_0 and one block every R rounds. */
static void setup_run(const lc_params *p, const lc_grid *K, const lc_grid *G, lc_grid *blocks, size_t n)
{
    lc_state st;
    lc_setup_constant(p, &st.A);
    st.B = *K;
    st.r = 0;
    st.o = 0;
    run_rounds(p, G, &st, 2 * p->R);
    for (size_t i = 0; i < n; i++) {
        if (i) run_rounds(p, G, &st, p->setup_2r ? 2 * p->R : p->R);
        blocks[i] = st.B;
    }
    erase(&st, sizeof st);
}

/* The sort keeps (tag, number) pairs and the generations they carry in separate arrays: the comparisons touch only
 * the small pairs, and the masked swaps of the grids vectorize. */
typedef struct {
    uint64_t tag, idx;
} sortkey;

static inline void cswap(sortkey *restrict ka, sortkey *restrict kb, lc_grid *restrict ga, lc_grid *restrict gb,
                         uint64_t swap)                               /* swap if swap is 1, without branching */
{
    uint64_t m = barrier64(0 - swap);
    uint64_t dt = (ka->tag ^ kb->tag) & m, di = (ka->idx ^ kb->idx) & m;
    ka->tag ^= dt;
    kb->tag ^= dt;
    ka->idx ^= di;
    kb->idx ^= di;
    uint32_t m32 = (uint32_t)m;
    for (int r = 0; r < 32; r++) {
        uint32_t d = (ga->w[r] ^ gb->w[r]) & m32;
        ga->w[r] ^= d;
        gb->w[r] ^= d;
    }
}

static inline uint64_t key_gt(const sortkey *a, const sortkey *b)    /* (tag, idx) order: ties go to the smaller number */
{
    return gt64(a->tag, b->tag) | (eq64(a->tag, b->tag) & gt64(a->idx, b->idx));
}

/* One stage of the bitonic network (merge size k, distance j) over records lo ... hi - 1. */
static void bitonic_stage(sortkey *key, lc_grid *g, size_t k, size_t j, size_t lo, size_t hi)
{
    for (size_t base = lo; base < hi; base += 2 * j) {
        if ((base & k) == 0)                                          /* this run ascends */
            for (size_t i = base; i < base + j; i++)
                cswap(&key[i], &key[i + j], &g[i], &g[i + j], key_gt(&key[i], &key[i + j]));
        else
            for (size_t i = base; i < base + j; i++)
                cswap(&key[i], &key[i + j], &g[i], &g[i + j], key_gt(&key[i + j], &key[i]));
    }
}

/* The bitonic sorting network (n a power of two; ascending), with its stages in a cache-friendly order: stages whose
 * comparisons stay within a block of SPAN records run block by block, so a block's grids stay in the L1 cache, and
 * only the longer-distance stages pass over the whole array. The network, and so the result, is the same. */
#define SPAN 128
static void bitonic_sort(sortkey *key, lc_grid *g, size_t n)
{
    size_t span = SPAN < n ? SPAN : n;
    for (size_t lo = 0; lo < n; lo += span)                           /* merge sizes up to the span */
        for (size_t k = 2; k <= span; k <<= 1)
            for (size_t j = k >> 1; j > 0; j >>= 1) bitonic_stage(key, g, k, j, lo, lo + span);
    for (size_t k = 2 * span; k <= n; k <<= 1) {
        size_t j = k >> 1;
        for (; j >= span; j >>= 1) bitonic_stage(key, g, k, j, 0, n);
        for (size_t lo = 0; lo < n; lo += span)
            for (size_t jj = j; jj > 0; jj >>= 1) bitonic_stage(key, g, k, jj, lo, lo + span);
    }
}

static int key_order(const void *a, const void *b)                  /* (tag, idx), for the fast_setup path */
{
    const sortkey *x = a, *y = b;
    if (x->tag != y->tag) return x->tag < y->tag ? -1 : 1;
    return x->idx < y->idx ? -1 : x->idx > y->idx;
}

lc_key *lc_key_setup(const lc_params *p, const uint8_t key[LC_GRID_BYTES])
{
    if (lc_params_check(p)) return NULL;
    const size_t T = p->T, k = p->k, tag_blocks = k * T / 16, blocks = 1 + tag_blocks + (p->mask_w ? T : 0);
    size_t n = 1;
    while (n < T) n <<= 1;

    lc_key *ks = calloc(1, sizeof *ks);
    lc_grid *Z = malloc(blocks * sizeof *Z), *g = malloc(n * sizeof *g);
    sortkey *v = malloc(n * sizeof *v);
    if (ks) {
        ks->p = *p;
        ks->W = malloc(T * sizeof *ks->W);
        ks->shuffles = malloc(k * T * sizeof *ks->shuffles);
        lc_grid_from_bytes(key, &ks->K);
        ks->G = key_table(p, &ks->K);
    }
    if (!ks || !Z || !g || !v || !ks->W || !ks->shuffles || !ks->G) {
        free(Z);
        free(g);
        free(v);
        lc_key_free(ks);
        return NULL;
    }
    uint32_t ok = key_check(ks->G, T);                                /* §6.1, the key check */
    LC_PUBLIC(&ok, sizeof ok);                                        /* passing or failing it is public */
    if (!ok && !p->no_key_check) {
        free(Z);
        free(g);
        free(v);
        lc_key_free(ks);
        return NULL;
    }

    lc_grid *tab = setup_table(p, ks->G);
    if (!tab) {
        free(Z);
        free(g);
        free(v);
        lc_key_free(ks);
        return NULL;
    }
    setup_run(p, &ks->K, tab, Z, blocks);
    if ((p->keep_G || p->message_mode1) && tab != ks->G) ks->H = tab; /* kept for mode-1 messages and white-box tests */
    else free_setup_table(p, tab);
    ks->M = p->m_is_k ? ks->K : Z[0];                                 /* §6.4 */
    for (size_t s = 0; s < k; s++) {                                  /* §6.5 and §6.6 */
        for (size_t i = 0; i < n; i++) {
            if (i < T) {
                const lc_grid *zb = &Z[1 + (s * T + i) / 16];         /* tag s*T + i: 8 bytes of Z_1 Z_2 ..., big-endian */
                size_t t = (s * T + i) % 16;
                v[i].tag = p->no_shuffle ? i : (uint64_t)zb->w[2 * t] << 32 | zb->w[2 * t + 1];
                if (!p->fast_setup) g[i] = ks->G[i];
            } else {
                v[i].tag = UINT64_MAX;                                /* padding sorts after every real tag */
                memset(&g[i], 0, sizeof g[i]);
            }
            v[i].idx = i;
        }
        if (p->fast_setup) {                                          /* test-only: secret-dependent order */
            qsort(v, T, sizeof *v, key_order);
            for (size_t i = 0; i < T; i++) g[i] = ks->G[v[i].idx];
        } else {
            bitonic_sort(v, g, n);
        }
        for (size_t i = 0; i < T; i++) ks->shuffles[s * T + i] = (uint16_t)v[i].idx;
        for (size_t q = 0; q < T / k; q++) {
            lc_grid w;
            memset(&w, 0, sizeof w);
            for (size_t m = 0; m < k; m++)
                for (int r = 0; r < 32; r++) w.w[r] ^= g[k * q + m].w[r];
            ks->W[s * (T / k) + q] = w;
        }
    }
    if (p->mask_w)                                                    /* variant: each entry XORed with its own block */
        for (size_t i = 0; i < T; i++)
            for (int r = 0; r < 32; r++) ks->W[i].w[r] ^= Z[1 + tag_blocks + i].w[r];
    erase(Z, blocks * sizeof *Z);
    erase(g, n * sizeof *g);
    erase(v, n * sizeof *v);
    free(Z);
    free(g);
    free(v);
    if (!p->keep_G && !p->message_mode1) {
        erase(ks->G, T * sizeof *ks->G);
        free(ks->G);
        ks->G = NULL;
    }
    return ks;
}

void lc_key_free(lc_key *k)
{
    if (!k) return;
    if (k->W) erase(k->W, (size_t)k->p.T * sizeof *k->W);
    if (k->G) erase(k->G, (size_t)k->p.T * sizeof *k->G);
    if (k->H) erase(k->H, (size_t)k->p.T * sizeof *k->H);
    if (k->shuffles) erase(k->shuffles, (size_t)k->p.k * k->p.T * sizeof *k->shuffles);
    free(k->W);
    free(k->G);
    free(k->H);
    free(k->shuffles);
    erase(k, sizeof *k);
    free(k);
}

int lc_setup_stream(const lc_params *p, const uint8_t key[LC_GRID_BYTES], uint8_t *out, size_t blocks)
{
    if (lc_params_check(p)) return -1;
    lc_grid K, *Z = malloc(blocks * sizeof *Z);
    lc_grid_from_bytes(key, &K);
    lc_grid *G = key_table(p, &K), *tab = G ? setup_table(p, G) : NULL;
    if (!Z || !G || !tab) {
        if (tab && tab != G) free(tab);
        free(Z);
        free(G);
        return -1;
    }
    uint32_t ok = key_check(G, p->T);                                 /* §6.1: refused like key setup */
    LC_PUBLIC(&ok, sizeof ok);
    if (!ok && !p->no_key_check) {
        free_setup_table(p, tab);
        erase(G, (size_t)p->T * sizeof *G);
        free(G);
        free(Z);
        return -1;
    }
    setup_run(p, &K, tab, Z, blocks);
    free_setup_table(p, tab);
    for (size_t i = 0; i < blocks; i++) lc_grid_to_bytes(&Z[i], out + LC_GRID_BYTES * i);
    erase(G, (size_t)p->T * sizeof *G);
    erase(Z, blocks * sizeof *Z);
    free(G);
    free(Z);
    return 0;
}

const lc_params *lc_key_params(const lc_key *k) { return &k->p; }
const lc_grid *lc_key_K(const lc_key *k) { return &k->K; }
const lc_grid *lc_key_M(const lc_key *k) { return &k->M; }
const lc_grid *lc_key_W(const lc_key *k) { return k->W; }
const lc_grid *lc_key_G(const lc_key *k) { return k->G; }
const lc_grid *lc_key_H(const lc_key *k) { return mode1_table(k); }
const uint16_t *lc_key_shuffles(const lc_key *k) { return k->shuffles; }

/* ---- §7 encryption and §8 decryption ------------------------------------------------------------------------- */

/* §7.1 Init, §7.2 associated data and §7.3 the separator: everything before the message. */
static void begin(const lc_key *k, const lc_grid *table, const uint8_t iv[LC_GRID_BYTES], const uint8_t *ad,
                  size_t adlen, lc_state *st)
{
    const lc_params *p = &k->p;
    lc_grid ivg;
    lc_grid_from_bytes(iv, &ivg);
    for (int r = 0; r < 32; r++) st->A.w[r] = ivg.w[r] ^ k->M.w[r];
    st->B = k->K;
    st->r = 0;
    st->o = lc_fold(&ivg) % (p->T / p->S);
    run_rounds(p, table, st, 2 * p->R);

    if (adlen) {
        for (size_t off = 0;; off += LC_GRID_BYTES) {
            size_t L = adlen - off < LC_GRID_BYTES ? adlen - off : LC_GRID_BYTES;
            for (size_t i = 0; i < L; i++) xor_byte(&st->B, i, ad[off + i]);
            if (L < LC_GRID_BYTES && !p->no_marker) xor_byte(&st->B, L, MARKER);
            run_rounds(p, table, st, p->R);
            if (L < LC_GRID_BYTES) break;
        }
    }

    if (!p->no_separator) st->A.w[31] ^= 1;                           /* cell (31, 31) */
}

static void process(const lc_key *k, const uint8_t iv[LC_GRID_BYTES], const uint8_t *ad, size_t adlen,
                    const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[LC_TAG_BYTES], int decrypting)
{
    const lc_params *p = &k->p;
    const lc_grid *table = p->message_mode1 ? mode1_table(k) : k->W;
    lc_state st;
    begin(k, table, iv, ad, adlen, &st);

    for (size_t off = 0;; off += LC_GRID_BYTES) {                     /* §7.4 message */
        size_t L = len - off < LC_GRID_BYTES ? len - off : LC_GRID_BYTES;
        if (L == LC_GRID_BYTES) {                                     /* a whole block, a row word at a time */
            lc_grid x, y;
            lc_grid_from_bytes(in + off, &x);                         /* read before writing: in may be out */
            for (int r = 0; r < 32; r++) y.w[r] = x.w[r] ^ st.B.w[r];
            st.B = decrypting ? x : y;
            lc_grid_to_bytes(&y, out + off);
            run_rounds(p, table, &st, p->R);
            continue;
        }
        uint8_t block[LC_GRID_BYTES];
        if (L) memcpy(block, in + off, L);                            /* in and out may be the same buffer */
        for (size_t i = 0; i < L; i++) out[off + i] = block[i] ^ get_byte(&st.B, i);
        for (size_t i = 0; i < L; i++) put_byte(&st.B, i, decrypting ? block[i] : out[off + i]);
        if (!p->no_marker) xor_byte(&st.B, L, MARKER);
        break;
    }

    run_rounds(p, table, &st, 2 * p->R);                              /* §7.5 finish */
    for (size_t i = 0; i < LC_TAG_BYTES; i++) tag[i] = get_byte(&st.B, i);
    erase(&st, sizeof st);
}

void lc_encrypt(const lc_key *k, const uint8_t iv[LC_GRID_BYTES], const uint8_t *ad, size_t adlen,
                const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[LC_TAG_BYTES])
{
    process(k, iv, ad, adlen, pt, len, ct, tag, 0);
}

struct lc_stream {
    const lc_key *k;
    const lc_grid *table;
    lc_state st;
};

lc_stream *lc_stream_new(const lc_key *k, const uint8_t iv[LC_GRID_BYTES], const uint8_t *ad, size_t adlen)
{
    lc_stream *s = malloc(sizeof *s);
    if (!s) return NULL;
    s->k = k;
    s->table = k->p.message_mode1 ? mode1_table(k) : k->W;
    begin(k, s->table, iv, ad, adlen, &s->st);
    return s;
}

void lc_stream_blocks(lc_stream *s, const uint8_t *pt, uint8_t *out, size_t blocks)
{
    for (size_t b = 0; b < blocks; b++) {
        lc_grid x, y;
        if (pt) lc_grid_from_bytes(pt + LC_GRID_BYTES * b, &x);
        else memset(&x, 0, sizeof x);
        for (int r = 0; r < 32; r++) y.w[r] = x.w[r] ^ s->st.B.w[r];
        s->st.B = y;                                                  /* absorb the ciphertext */
        lc_grid_to_bytes(&y, out + LC_GRID_BYTES * b);
        run_rounds(&s->k->p, s->table, &s->st, s->k->p.R);
    }
}

void lc_stream_free(lc_stream *s)
{
    if (!s) return;
    erase(s, sizeof *s);
    free(s);
}

int lc_decrypt(const lc_key *k, const uint8_t iv[LC_GRID_BYTES], const uint8_t *ad, size_t adlen,
               const uint8_t *ct, size_t len, const uint8_t tag[LC_TAG_BYTES], uint8_t *pt)
{
    uint8_t expected[LC_TAG_BYTES];
    uint32_t diff = 0;
    process(k, iv, ad, adlen, ct, len, pt, expected, 1);
    for (size_t i = 0; i < LC_TAG_BYTES; i++) diff |= (uint32_t)(expected[i] ^ tag[i]);   /* all 16 bytes, always */
    uint32_t accept = mask_eq32(diff, 0);
    LC_PUBLIC(&accept, sizeof accept);                                /* accept or reject is public */
    if (accept) return 0;
    if (len) erase(pt, len);                                          /* §8: release nothing */
    return -1;
}
