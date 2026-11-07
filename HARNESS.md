# How the Life Cipher was tested

The Life Cipher was tested with a harness that isn't part of this repository. The harness needs the private pool of mined keys, and its deep tier runs for a day and a half. This document describes how it worked, what it checked and what it found. `SPEC.md` §11 summarizes the security analysis and how the round count was chosen.

## What the harness is

It's a test bench for authenticated encryption. Every cipher, the Life Cipher and the controls alike, is driven through the same interface:
- encrypt(key, IV, AD, plaintext) → (ciphertext, tag)
- decrypt(key, IV, AD, ciphertext, tag) → plaintext, or a rejection that releases nothing

Most checks are black-box: automated attackers that see ciphertexts, choose IVs or plaintexts, or tamper with messages, and try to tell the output from random or to get a forgery accepted. A few look inside: Mix run backwards (T5), the key setup's shuffles, table and mask (U1–U3), and the constant-time checks (K1, K2).

- **Implementation.** The Life Cipher ran on the C implementation in `fast/`, through tools that aren't in this repository: a stream writer for the statistical tests, a server for external programs, and drivers for the timing and Valgrind checks. The library's test-only switches (`fast/lifecipher.h`) build the variants that were measured and most of the Life controls; life_raw_pad, a keystream of plain Life generations, is separate code.
- **Reproducibility.** Every key, IV and message comes from a seeded generator, and every run keeps a record of its seeds, tool versions, statistics and results.
- **Keys.** The Life Cipher needs vetted keys (`SPEC.md` §9), so the harness drew them from the pool of 387,874 mined keys that pass vetting. Reports name a key by its place in the pool, never by its value. A random grid isn't a valid key: it usually settles into a short cycle, and then its table W collapses; in tests, such keystreams failed PractRand within a megabyte. The checks that flip key cells (A1, A4, A5 and S3) need unvetted keys, so vetting is off for the flipped keys. The key check runs in every key setup, but its refusal is switched off throughout, so that random and flipped keys can be tested; vetted keys pass it either way.

## The checks

There are 48 checks in ten families.

| Family | Checks | What they catch |
|---|---|---|
| T, correctness | T1 round trips, with AD lengths of 0, 1, 127, 128 and 129 bytes, plaintext lengths of 0, 1, 127, 128, 129 and 256 bytes, and random lengths up to 4 KB; T2 determinism; T3 lengths; T4 the key-vetting tool, against known patterns, crafted fields and the miners' records; T5 Mix run backwards | broken implementations, and a Mix that isn't reversible |
| F, forgery and tampering | F1 one flipped bit in the IV, AD, ciphertext or tag; F2 1–16 bytes cut or appended, also after trailing zero bytes; F3 bytes moved across the AD/message boundary; F4 blocks swapped, dropped, duplicated, reordered or spliced from another message; F5 random tags | any accepted forgery |
| S, statistical streams | S1a–S9, below, through PractRand and TestU01 | bias and structure in long outputs |
| A, avalanche | A1 key cells, A2 IV cells and A3 AD and plaintext bits, each measured on early blocks, a block deep into the message and the tag; A4 input bits that affect nothing; A5 independence of output-bit flips | poor mixing of an input |
| G, grid statistics | G1 cell balance; G2 neighbour correlations at distances 1–4; G3 live-cell counts; G4 row and column parities; G5 likeness of consecutive blocks, also under the best torus shift; G6 frequencies of the 512 3 × 3 patterns; G7 each cell against the same cell 1 and 2 blocks later, over a whole stream | Life-like structure, and cell persistence |
| C, collisions | C1 repeated blocks; C2 smallest Hamming distance between blocks; C3 the same over all torus shifts; C4 key collisions; C5 IV collisions | repeats and near-repeats |
| P, predictability | P1 linear complexity; P2 linear prediction over GF(2); P3 a small convolutional network, which can represent any local rule, Life included; P4 prediction from one IV to the next | linear and local-rule structure |
| U, setup | U1 shuffle uniformity; U2 how generations share W entries; U3 the mask M against the key | a weak setup run |
| K, constant time | K1 dudect-style timing of setup, encryption and decryption on the AVX2 build, fixed against random secrets, with Welch's t-test (a leak from \|t\| = 4.5); K2 Valgrind tracking secrets into branches and memory addresses, on the AVX2 and portable builds | timing and cache leaks |
| M, misuse | M1 a repeated IV; M2 plaintext released before the tag check. Informational: the cipher makes no claim here | how bad misuse gets |

### The statistical streams

| Stream | What it is | What the attacker does |
|---|---|---|
| S1a | one key and IV, one long all-zero plaintext | sees keystream for known plaintext |
| S1b | short messages under fresh keys and IVs, concatenated | sees many message starts |
| S2 | one key, IVs from a counter, the same plaintext; the first bytes of each output | chooses sequential IVs |
| S3 | the XOR of the outputs under K and under K with one cell flipped | uses related keys |
| S4 | the same with IV cells flipped | uses related IVs |
| S5 | the same with one plaintext bit flipped, keeping only what follows its block | chooses plaintexts |
| S6 | special IVs: zeros, ones, stripes, checkerboards and single cells | chooses IVs |
| S7 | plaintext XOR ciphertext, for random plaintexts | knows plaintexts |
| S8 | a key against its torus shifts, rotations and reflections; S8a keeps the IV, and S8b transforms it too and maps the output back | uses structured related keys |
| S9 | each key's whole setup stream, one key after another | sees nothing directly; this tests the source of the shuffles and M |

The suites are PractRand 0.96, which doubles the data until something fails or the tier's size is reached, and TestU01 1.2.3's SmallCrush, Crush and BigCrush. S3 and S8 stay graded even though the cipher makes no related-key claim (`SPEC.md` §10.1): they check how the key is mixed in.

### The tiers

| Tier | What it runs | Time for the Life Cipher |
|---|---|---|
| Smoke | a sample of the catalog, PractRand to 16 MB on S1a, and four controls | under a minute |
| Standard | every check, each stream to 1 GB with PractRand, SmallCrush, and all 17 controls | one and a half to two hours on 14 worker processes |
| Deep | S1a, S2 and S9 to 256 GB, the other streams to 4–16 GB, Crush and BigCrush, G7 on 64 GB, and 10^8 random tags. Two controls check what it adds | about 36 hours on 14 worker processes |

## Calibration and grading

A result on the Life Cipher counts only if the controls come out as expected. Two must pass everything, and fifteen have a known flaw that specific checks must catch:

| Control | What it is | Must fail |
|---|---|---|
| chacha20poly1305 | ChaCha20-Poly1305 | nothing |
| ascon | Ascon-AEAD128 | nothing |
| identity | ciphertext = plaintext, constant tag | nearly everything |
| repeat_xor | the key repeated as the keystream, an unkeyed hash as the tag | F1, A2, C1, C5, S1a, S2, S3, S4 |
| chacha_no_iv | ChaCha20-Poly1305 that ignores the IV | A2, C5, P4, S2, S4, S6 |
| chacha_20bit_key | ChaCha20-Poly1305 keyed from 20 bits | A1, A4, C4, S3 |
| lfsr | a 127-bit linear feedback shift register | P1, P2 |
| mt19937 | Mersenne Twister seeded with the key and IV | P1 |
| life_raw_pad | consecutive Life generations of K ⊕ IV as the keystream | G1, G5, G6, G7, C2, C3, P3, S8a, S8b |
| life_no_marker | the Life Cipher without the end marker | F2 |
| life_no_separator | the Life Cipher without the separator | F3 |
| life_selector_v1 | the Life Cipher with a selector that also reads A | T5 |
| life_weak | the Life Cipher at R = 2 | A3, G7, P3, S1a, S5, S9 |
| life_no_shuffle | the Life Cipher with identity shuffles and M = K | U1–U3 |
| life_secret_index | the Life Cipher reading its table at secret positions | K1, K2 |
| chacha_short_tag | ChaCha20-Poly1305 that checks only the tag's first byte | F1, F5 |
| broken | not a cipher: an extra byte, and a decryption that returns its input | T1–T3 |

Every graded check is failed by at least one control, so none of them is decoration. T4 is the exception: it checks the vetting tool against known answers.

The grading rules:
- **FAIL** at p < 10⁻⁶, on any accepted forgery, on any K2 finding, or when PractRand fails.
- **SUSPICIOUS** at 10⁻⁶ ≤ p < 10⁻³, or on PractRand's "very suspicious". The check is rerun with a new seed and four times the data, at most twice. A flaw that reproduces and grows becomes a FAIL.
- **A TestU01 battery** gives one result: its smallest two-sided p-value, Bonferroni-corrected for the number of p-values it reports, 144 for Crush.
- **Statistics without a textbook distribution** are judged against the same procedure run on ChaCha20-Poly1305.
- **Results outside a cipher's claims** are reported as information, not graded.

## The round count

`SPEC.md` §11.4 uses a heuristic minimum, R ≥ 3 max(r_min, r_attack).
- **r_min** comes from strength sweeps: the candidate alone at a list of round counts, first at smoke sizes, then at full size. The recommended design passes all 71 standard-tier results at R = 6.
- **r_attack** comes from dedicated measurements on reduced rounds (`SPEC.md` §11.3), outside the harness.
- **The ChaCha comparison.** Swept by rounds the same way, ChaCha fails the harness at 3 rounds and passes it at 4, at small samples and at full size alike. Published attacks reach about 7 rounds, and 3 × 7 = 21 is close to the 20 rounds ChaCha20 uses. That checks the factor's scale; one comparison doesn't validate it for a different design.

## The two implementations

The C implementation was fuzzed against the Python reference on both builds: 1,000,000 random cases of the building blocks (Life, shift, fold, the selectors and one Mix round), and 300 whole messages across 20 configurations (the demo set, k = 8, R = 8, and 17 test-only variants and controls), with no disagreement. Both implementations reproduce the three vector files in `vectors/` byte for byte.

## Results on the recommended set (R = 24)

- **Standard tier:** all 71 graded results pass, and every control behaves as expected. They pass again with the key check (`SPEC.md` §6.1) running in every key setup.
- **Deep tier:** all 72 graded results pass.
  - PractRand is clean to 256 GB on S1a, byte-swapped too, on S2, and on S9 across 190,872 keys. The other streams are clean to 4–16 GB.
  - Crush passes on S1a (p = 0.85), S2 (p = 0.59) and S9 (p = 0.23). BigCrush on S1a has 0 of 160 p-values outside [0.001, 0.999] (p = 0.62).
  - G7 on 64 GB finds correlations of 2.19 × 10⁻⁶ at lag 1 and −1.51 × 10⁻⁶ at lag 2 (p = 0.21).
  - None of 10^8 random tags is accepted (F5).
  - S9's Crush failed on the first run because of a harness bug: the battery's key list covered only 1 GB of the setup stream, so Crush read the same data about 120 times. With the bug fixed, the rerun read 126 GB from 93,996 keys, none reused. It has 1 of 144 p-values outside [0.001, 0.999], the worst p = 0.0008, for a graded p of 0.23.
- **Constant time:** K1's largest |t| is 2.52, against 4.5, and K2 finds nothing on either build. The secret-index control fails both, with |t| = 407 in K1.

## What the tests can't show

Passing statistical tests is weak evidence. Rule 30 passed the tests of its time and fell to an attack they couldn't see. Here too, at the demo set's k = 4 and R = 16, cell persistence in messages passes PractRand, and G5, which tests the same relation on 64 MB, misses it; only G7, which looks over a whole stream, catches it. The ChaCha comparison shows the gap: the harness breaks 3 rounds, published cryptanalysis 7. The harness doesn't attempt algebraic attacks, and related keys and multiple users are outside the cipher's goals. A pass means these tests found nothing, not that the cipher is secure.
