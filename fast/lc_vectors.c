/* lc-vectors: writes the test vectors from the C implementation alone.
 *
 *   build/lc-vectors | cmp - ../vectors/demo-v1.json                       the demo parameter set
 *   build/lc-vectors recommended | cmp - ../vectors/recommended-v1.json    the recommended set (SPEC.md §3.3)
 *   build/lc-vectors key-check | cmp - ../vectors/key-check-v1.json        the key check (SPEC.md §6.1)
 * (in fast/; any other argument gives the demo set)
 *
 * The output must match the file reference/make_vectors.py writes, byte for byte: the same values in the same JSON
 * layout (Python's json.dumps with indent=2).
 */
#include <stdio.h>
#include <string.h>

#include "lifecipher.h"
#include "sha256.h"

static const char *DEMO_KEY_HEX =       /* SPEC.md Appendix B: the burned demo key, as 32 row words */
    "6B3028A8DB46016A318DA71385D82A926489431E9A2B00E11CB1E6844106B26D"
    "90FC90AC77361985884930EB551A3B5281186009E814409482842900D88996D1"
    "9514CC133A81EC3447580B9DF304B45184A2B2742412283808F6D9343A69CBB8"
    "6A04296A5F54D36A425497691420992C30F902067215518A1CE02869BA961C3B";
static const char *AD = "Life Cipher test vector";

/* ---- a minimal emitter for Python's json.dumps(indent=2) layout ------------------------------------------------ */

static int depth, first = 1;

static void start(const char *key)
{
    if (!first) putchar(',');
    putchar('\n');
    for (int i = 0; i < depth; i++) fputs("  ", stdout);
    if (key) printf("\"%s\": ", key);
    first = 0;
}

static void open_(const char *key, char c)
{
    start(key);
    putchar(c);
    depth++;
    first = 1;
}

static void close_(char c)
{
    depth--;
    putchar('\n');
    for (int i = 0; i < depth; i++) fputs("  ", stdout);
    putchar(c);
    first = 0;
}

static void str(const char *key, const char *v) { start(key); printf("\"%s\"", v); }
static void num(const char *key, unsigned long v) { start(key); printf("%lu", v); }
static void boolean(const char *key, int v) { start(key); fputs(v ? "true" : "false", stdout); }

static void grid(const char *key, const lc_grid *g)    /* 32 row words in hex, as SPEC.md's appendices */
{
    start(key);
    putchar('"');
    for (int r = 0; r < 32; r++) printf(r ? " %08X" : "%08X", g->w[r]);
    putchar('"');
}

static void hex(const char *key, const uint8_t *b, size_t n)
{
    start(key);
    putchar('"');
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    putchar('"');
}

/* ---- the vectors, in make_vectors.py's order -------------------------------------------------------------------- */

static void glider(int dr, int dc, lc_grid *g)  /* moves one row down and one column right every 4 steps */
{
    static const int cells[5][2] = {{0, 1}, {1, 2}, {2, 0}, {2, 1}, {2, 2}};
    memset(g, 0, sizeof *g);
    for (int i = 0; i < 5; i++) g->w[(cells[i][0] + dr) % 32] |= 1u << (31 - (cells[i][1] + dc) % 32);
}

static uint32_t first_repeat(const lc_grid *K)   /* D (SPEC.md §9.1): distinct generations before the first repeat */
{
    static lc_grid seen[8192];
    seen[0] = *K;
    for (uint32_t n = 1; n < 8192; n++) {
        lc_life(&seen[n - 1], &seen[n]);
        for (uint32_t i = 0; i < n; i++)
            if (!memcmp(&seen[i], &seen[n], sizeof seen[n])) return n;
    }
    return 0;
}

/* The key check's vectors (SPEC.md §6.1): a key, its D, and whether the check passes for a few T. */
static int key_check_vectors(const uint8_t demo_key[LC_GRID_BYTES], const uint8_t iv[LC_GRID_BYTES])
{
    static const char *names[5] = {"the demo key (Appendix B)", "an empty grid", "a blinker", "a glider",
                                   "the vectors' IV, used as a key"};
    static const uint32_t Ts[5][3] = {{6000, 6199, 6200}, {6000}, {6000}, {128, 129, 6000}, {6000}};
    lc_grid K[5];
    lc_grid_from_bytes(demo_key, &K[0]);
    memset(&K[1], 0, sizeof K[1]);
    memset(&K[2], 0, sizeof K[2]);
    K[2].w[10] = 7u << (31 - 12);                       /* cells (10, 10), (10, 11) and (10, 12) */
    glider(0, 0, &K[3]);
    lc_grid_from_bytes(iv, &K[4]);

    putchar('{');
    depth = 1;
    str("description", "Test vectors for the Life Cipher's key check (SPEC.md \\u00a76.1, \\u00a715)");
    str("status", "published with SPEC.md draft 0.4 (\\u00a71.1, \\u00a715): any change that alters an output needs a "
                  "new algorithm version");
    str("spec", "SPEC.md draft 0.4");
    num("algorithm_version", 1);
    str("conventions", "grids are 32 row words in hex (SPEC.md \\u00a72.2); D is the number of distinct generations "
                       "before the first repeat (\\u00a79.1), and the check passes exactly when D is at least T");
    open_("cases", '[');
    for (int c = 0; c < 5; c++) {
        uint8_t key[LC_GRID_BYTES];
        lc_grid_to_bytes(&K[c], key);
        open_(NULL, '{');
        str("name", names[c]);
        grid("key", &K[c]);
        num("D", first_repeat(&K[c]));
        open_("checks", '[');
        for (int t = 0; t < 3 && Ts[c][t]; t++) {
            int ok = lc_key_check(key, Ts[c][t]);
            if (ok < 0) return 1;
            open_(NULL, '{');
            num("T", Ts[c][t]);
            boolean("passes", ok);
            close_('}');
        }
        close_(']');
        close_('}');
    }
    close_(']');
    close_('}');
    putchar('\n');
    return 0;
}

int main(int argc, char **argv)
{
    lc_params p;
    lc_params_default(&p);
    int recommended = argc > 1 && !strcmp(argv[1], "recommended");
    if (recommended) {
        p.k = 30;
        p.R = 24;
    }
    p.keep_G = 1;                                       /* keeps H too, for its vectors; it changes no output */
    uint8_t key[LC_GRID_BYTES], iv[LC_GRID_BYTES];
    for (int i = 0; i < LC_GRID_BYTES; i++) {
        unsigned v;
        sscanf(DEMO_KEY_HEX + 2 * i, "%2x", &v);
        key[i] = (uint8_t)v;
        iv[i] = (uint8_t)((13 + 7 * i) & 0xFF);         /* 0D 14 1B ...; a counting IV would fold to 0 */
    }
    if (argc > 1 && !strcmp(argv[1], "key-check")) return key_check_vectors(key, iv);
    lc_key *ks = lc_key_setup(&p, key);
    if (!ks) return 1;
    const lc_grid *K = lc_key_K(ks), *M = lc_key_M(ks), *W = lc_key_W(ks);
    lc_grid ivg, g, a;
    lc_grid_from_bytes(iv, &ivg);

    putchar('{');
    depth = 1;
    str("description", recommended ? "Test vectors for the Life Cipher, recommended parameter set (SPEC.md \\u00a73.3, "
                                     "\\u00a715)"
                                   : "Test vectors for the Life Cipher, demo parameter set (SPEC.md \\u00a73.3, "
                                     "\\u00a715)");
    str("status", "published 2026-11-01 (SPEC.md \\u00a71.1, \\u00a715): any change that alters an output needs a new "
                  "algorithm version");
    str("spec", "SPEC.md draft 0.3");
    num("algorithm_version", p.version);
    open_("parameters", '{');
    num("T", p.T);
    num("S", p.S);
    num("k", p.k);
    num("R", p.R);
    num("R_init", 2 * p.R);
    num("R_final", 2 * p.R);
    close_('}');
    str("conventions", "grids are 32 row words in hex (SPEC.md \\u00a72.2); byte strings are hex");
    grid("key", K);
    hex("iv", iv, sizeof iv);

    open_("life", '[');                                                           /* §5.1 */
    open_(NULL, '{');
    str("name", "glider across the corner");
    glider(30, 30, &g);
    grid("input", &g);
    lc_life(&g, &a);
    grid("after_1", &a);
    for (int i = 0; i < 3; i++) lc_life(&a, &a);
    grid("after_4", &a);
    close_('}');
    open_(NULL, '{');
    str("name", "demo key");
    grid("input", K);
    lc_life(K, &a);
    grid("after_1", &a);
    close_('}');
    close_(']');

    open_("shift", '[');                                                          /* §5.2 */
    open_(NULL, '{');
    str("input", "key");
    num("dx", 5);
    num("dy", 3);
    lc_shift(K, 5, 3, &a);
    grid("output", &a);
    close_('}');
    close_(']');

    char word[9];
    open_("fold", '[');                                                           /* §5.3 */
    const lc_grid *folded[2] = {K, &ivg};
    for (int i = 0; i < 2; i++) {
        open_(NULL, '{');
        str("input", i ? "iv" : "key");
        snprintf(word, sizeof word, "%08X", lc_fold(folded[i]));
        str("output", word);
        close_('}');
    }
    close_(']');

    uint32_t sel[4];
    open_("selectors", '[');                                                      /* §5.4.2 */
    for (unsigned r = 0; r < 3; r++) {
        lc_selectors(&p, K, K, r, 0, sel);
        open_(NULL, '{');
        str("B", "key");
        num("r", r);
        num("o", 0);
        num("g", sel[0]);
        num("j", sel[1]);
        num("dx", sel[2]);
        num("dy", sel[3]);
        close_('}');
    }
    close_(']');

    uint32_t o = lc_fold(&ivg) % (p.T / p.S);
    num("iv_offset", o);                                                          /* §5.4.3 */

    lc_state st;                                                                  /* §5.6: the first round of Init (r = 0) */
    for (int r = 0; r < 32; r++) st.A.w[r] = ivg.w[r] ^ M->w[r];
    st.B = *K;
    st.r = 0;
    st.o = o;
    open_("mix_round", '{');
    grid("A", &st.A);
    grid("B", &st.B);
    num("r", 0);
    num("o", o);
    lc_selectors(&p, &st.A, &st.B, 0, o, sel);
    num("g", sel[0]);
    num("j", sel[1]);
    num("dx", sel[2]);
    num("dy", sel[3]);
    lc_mix_round(ks, 2, &st);
    grid("A_after", &st.A);
    grid("B_after", &st.B);
    close_('}');

    open_("key_setup", '{');                                                      /* §6 */
    const lc_grid *H = lc_key_H(ks);
    grid("H[0]", &H[0]);
    grid("H[1]", &H[1]);
    static uint8_t hbytes[6000 * LC_GRID_BYTES];
    for (uint32_t i = 0; i < p.T; i++) lc_grid_to_bytes(&H[i], hbytes + LC_GRID_BYTES * i);
    uint8_t hdigest[32];
    sha256(hbytes, (size_t)p.T * LC_GRID_BYTES, hdigest);
    hex("H_sha256", hdigest, sizeof hdigest);
    lc_setup_constant(&p, &a);
    grid("setup_constant", &a);
    grid("M", M);
    grid("W[0]", &W[0]);
    grid("W[1]", &W[1]);
    grid("W[5999]", &W[p.T - 1]);
    static uint8_t wbytes[6000 * LC_GRID_BYTES];
    for (uint32_t i = 0; i < p.T; i++) lc_grid_to_bytes(&W[i], wbytes + LC_GRID_BYTES * i);
    uint8_t digest[32];
    sha256(wbytes, (size_t)p.T * LC_GRID_BYTES, digest);
    hex("W_sha256", digest, sizeof digest);
    close_('}');

    open_("aead", '[');                                                           /* §7, with the IV above */
    static const size_t lengths[6] = {0, 1, 127, 128, 129, 256};
    for (int with_ad = 0; with_ad < 2; with_ad++)
        for (int i = 0; i < 6; i++) {
            size_t n = lengths[i], adlen = with_ad ? strlen(AD) : 0;
            uint8_t pt[256], ct[256], tag[LC_TAG_BYTES];
            for (size_t b = 0; b < n; b++) pt[b] = (uint8_t)b;
            lc_encrypt(ks, iv, (const uint8_t *)AD, adlen, pt, n, ct, tag);
            open_(NULL, '{');
            hex("ad", (const uint8_t *)AD, adlen);
            hex("plaintext", pt, n);
            hex("ciphertext", ct, n);
            hex("tag", tag, sizeof tag);
            close_('}');
        }
    close_(']');
    close_('}');
    putchar('\n');
    lc_key_free(ks);
    return 0;
}
