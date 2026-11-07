# Life Cipher specification

Draft 0.4, 2026-11-07. Algorithm version 1, with published test vectors (§15).

This repository also holds `HARNESS.md`, which describes how the cipher was tested, the test vectors (`vectors/`), the Python reference implementation (`reference/`), the constant-time C implementation (`fast/`) and the reduced-round challenge (`challenge/`).

## Contents

1. Introduction
2. Notation and data layout
3. Parameters
4. Interface
5. Building blocks
6. Key setup
7. Encryption
8. Decryption and verification
9. Key vetting
10. Security goals and threat model
11. Security analysis
12. Design rationale
13. Advantages and limitations
14. Implementation requirements
15. Test vectors
16. References
- Appendix A. The setup constant
- Appendix B. Burned keys

## 1. Introduction

The Life Cipher is an authenticated encryption scheme with associated data (AEAD), built on Conway's Game of Life on a 32 × 32 torus. It encrypts a plaintext of any length into a ciphertext of the same length, and it produces a 16-byte tag that covers the plaintext, the associated data and the IV.

It's an experiment. Nobody outside this project has analyzed it, and nothing in it is proven secure. Don't use it to protect real data.

### 1.1 Versions

- **Document version.** This is draft 0.4, 2026-11-07.
- **Algorithm version.** This is version 1, the value XORed into the setup constant (§6.2). Its test vectors are published (§15), so any change that alters an output MUST increase it.
- **Name.** "Life Cipher" is a working name.

### 1.2 Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals.

- The text and the test vectors (§15) are normative. Pseudocode is there to help. Where it disagrees with the text, the text wins.
- Paragraphs that start with "Why", and the sections on rationale, analysis, and advantages and limitations, are informative.

### 1.3 Overview

The cipher is a duplex construction, the same overall shape as Ascon. Its secret state is two grids, A and B (2,048 bits), plus a round counter. Data is absorbed into B. A round function, Mix, stirs the state, and B is read out as the pad.

- **Mix** is one step of second-order Game of Life, with a round key XORed in: (A, B) ← (B, Life(B) ⊕ A ⊕ RK). Each round key is an entry of a key-derived table W, picked and shifted by values read from B.
- **Key setup** runs once per key. It grows the key's first 6,000 generations under Life. Then it runs the cipher itself on them, starting from a fixed constant, to build the round-key table W and a secret mask M.
- **Per message:** Init (A = IV ⊕ M, B = K), absorb the associated data, flip a separator cell, encrypt and absorb the message block by block, absorb an end marker, mix, and read the tag from B.
- **Keys** are long-lived Life configurations, vetted offline before use (§9).

## 2. Notation and data layout

### 2.1 Grids and cells

A **grid** is a 32 × 32 array of cells on a torus. Each cell is live (1) or dead (0). Cell (r, c) is in row r = 0 … 31, counted from the top, and column c = 0 … 31, counted from the left. Row and column numbers are taken mod 32, so the edges wrap.

### 2.2 Bytes and row words

**Byte layout.** A grid and a 128-byte string correspond as follows: cell (r, c) is bit 7 − (c mod 8) of byte 4r + ⌊c / 8⌋, where bit 0 is the least significant bit. So the bytes run through the rows from top to bottom, each row left to right, with each byte's most significant bit on the left. "Byte i of grid X" and "the first L bytes of X" refer to this layout.

**Row words.** X[r] is row r of grid X as an unsigned 32-bit integer: bytes 4r … 4r + 3 read big-endian. Column c is bit 31 − c.

**Integers.** Multi-byte integers (row words, parameter words, tags) are big-endian. "n mod m" is the non-negative remainder.

### 2.3 Operations

| Notation | Meaning |
|---|---|
| X ⊕ Y | XOR: cell by cell for grids, byte by byte for byte strings, bit by bit for integers |
| B ⊕ (v at byte i) | XOR the byte value v into byte i of grid B |
| rotl(x, n) | rotate the 32-bit word x left by n mod 32 places, toward the most significant bit |
| Life(X) | one Game of Life step on the torus, rule B3/S23 (§5.1) |
| Life^t(X) | t steps; Life^0(X) = X |
| shift(X, dx, dy) | X moved dx columns right and dy rows down, wrapping (§5.2) |
| F(X) | the fold of grid X into a 32-bit word (§5.3) |
| \|X\| | length of a byte string, in bytes |
| X[a … b] | bytes a through b of a byte string, inclusive |

## 3. Parameters

### 3.1 Parameter table

| Name | Meaning | Value in this draft |
|---|---|---|
| K | the key, a vetted grid (§9) | 1,024 bits |
| IV | initialization vector, never repeated under one key | 1,024 bits (128 bytes) |
| τ | the tag | 16 bytes |
| T | generations in the key table | 6,000 |
| S | entries per group in the round-key lookup | 16 |
| T / S | number of groups | 375 |
| k | generations XORed into each W entry, and the number of shuffles | 30 (§11.3, §12) |
| R | Mix rounds after each block | 24 (§11.4); at least 16 |
| R_init | Mix rounds at Init, and at the start of the setup run | 2R |
| R_final | Mix rounds before the tag | 2R |
| version | algorithm version | 1 |

### 3.2 Constraints

- T MUST NOT exceed the minimum generations used in key vetting (§9), so that G[0] … G[T−1] are all distinct.
- S MUST be 16. Selector rule v5 (§5.4.2) produces a 4-bit entry index, so a different S would need a different rule.
- T MUST be a positive multiple of S and of k.
- R MUST be at least 16. Smaller values are for analysis only, such as the challenge's reduced-round tiers. The bound doesn't come from diffusion: Life spreads a change at most one cell per round, but the selectors can change the round key across the whole grid in one round.
- R_init and R_final MUST both equal 2R.
- Each parameter MUST fit in 32 bits, because T, k, S, R and the version are XORed into the setup constant as row words (§6.2).

### 3.3 Parameter sets

- **Recommended set:** T = 6,000, S = 16, k = 30, R = 24, R_init = R_final = 48, version 1, with at most 2^48 blocks per key (§4.4). §11.4 explains R.
- **Demo set:** T = 6,000, S = 16, k = 4, R = 16, R_init = R_final = 32, version 1. It's for teaching, and one of the vector files uses it (§15). It's not a recommendation: at k = 4, cell persistence gives a distinguisher at R = 16 from a few GB (§11.3).

## 4. Interface

### 4.1 Key setup

KeySetup(K) → key state (K, W, M), or FAIL.

K MUST be a key that passed vetting (§9). Setup checks one thing, the key check (§6.1): it returns FAIL if the key's first T generations aren't all different. A key that passed vetting always passes.

### 4.2 Encryption

Encrypt(key state, IV, AD, P) → (C, τ)

- IV: 128 bytes, never used before with this key.
- AD: associated data, a byte string of any length within the limits (§4.4). It's authenticated, not encrypted.
- P: plaintext, a byte string of any length within the limits.
- C: ciphertext, exactly |P| bytes.
- τ: the tag, 16 bytes.

The sender transmits IV, C and τ. AD travels in the clear or by some other channel, as long as the receiver feeds in the same bytes.

### 4.3 Decryption

Decrypt(key state, IV, AD, C, τ) → P, or FAIL.

On FAIL, no part of P may be released (§8).

### 4.4 Limits

**Data per key: at most 2^48 blocks.** Under one key, encryption and decryption together MUST NOT absorb more than 2^48 blocks, whether the tag verifies or not. Every absorbed block counts, the last one with the end marker included (§7.2, §7.4): a message counts ⌊|P|/128⌋ + 1 blocks for its plaintext or ciphertext, plus ⌊|AD|/128⌋ + 1 when it has AD. So every message counts at least one block, an empty one too, and the limit also bounds the number of messages, tags and forgery attempts. With full blocks, the limit is 2^55 bytes (32 PiB). A single message, AD included, may use the whole limit; there's no separate per-message cap.

Why 2^48: the strongest attack measured is cell persistence (§11.3). At k = 30 its correlation fades about 4.2 bits per R, so the data a key may process decides how many rounds the attack could reach. Extrapolated, 2^48 blocks reach about 6 rounds for an average sampled key and 7 for the weakest. These are estimates, not bounds. R = 24 is more than three times either (§11.4). The limit is far above any realistic use, and above the 2^50 bytes NIST's lightweight-cipher competition asked for. A larger limit would cut into the margin, and a key can't be replaced cheaply, since keys are mined (§9).

What else holds:
- Inputs are byte strings. Lengths that aren't a whole number of bytes aren't supported.
- The round counter r (§5.6) MUST be kept exactly, without wrapping. A 64-bit counter is enough for any input within reasonable limits.
- IVs MUST NOT repeat under one key. Random 1,024-bit IVs make an accidental repeat negligible. A counter MAY be used where a repeat can be ruled out.

## 5. Building blocks

Each building block's test vectors are in §15's files. The line after each definition names the field.

### 5.1 Life step

Life(X) is one step of Conway's Game of Life on the torus, rule B3/S23. The neighbors of cell (r, c) are the 8 cells (r + a, c + b) with a, b ∈ {−1, 0, 1}, not both 0, taken mod 32. A cell is live in Life(X) if and only if it has exactly 3 live neighbors in X, or it's live in X and has exactly 2 live neighbors.

**Test vectors:** `life` (§15): one step of a glider crossing the corner, four steps of it, and one step of the key.

### 5.2 Shift

shift(X, dx, dy), for dx, dy ∈ 0 … 31, is the grid Y with Y(r, c) = X(r − dy, c − dx), indices mod 32. In row words, Y[r] is X[(r − dy) mod 32] rotated right by dx places.

**Test vectors:** `shift` (§15): the key shifted by (5, 3).

### 5.3 The fold F

F(X) = rotl(X[0], 0) ⊕ rotl(X[1], 1) ⊕ … ⊕ rotl(X[31], 31)

Each row word is rotated left by its row number, and all 32 are XORed. Bit b of F(X) is the XOR of one cell from each row.

Known properties (informative):
- F is linear: F(X ⊕ Y) = F(X) ⊕ F(Y).
- Shifting a grid rotates its fold: F(shift(X, dx, dy)) = rotl(F(X), dy − dx).

**Test vectors:** `fold` (§15): F of the key and of the IV.

### 5.4 Selectors

Each round needs one public value, the group g, and 14 secret bits: the entry j and the shift (dx, dy). §5.4.1 states what any selector rule must provide, and §5.4.2 gives the current rule, which can be replaced without touching anything else.

#### 5.4.1 Contract

| Output | Range | Public or secret | Used for |
|---|---|---|---|
| g, the group | 0 … T/S − 1 | public | which S table entries are read this round |
| j, the entry | 0 … 15 | secret | which entry of the group becomes the round key |
| dx, the column shift | 0 … 31 | secret | shifting the round key |
| dy, the row shift | 0 … 31 | secret | shifting the round key |

Any selector rule MUST be:
- **Computed only from grid B, the round counter r and the IV offset o.** Then sender and receiver get the same values. Using B and never A is what makes Mix reversible (§5.6), because B survives the round as A′. A still reaches the selectors one round later, through B′.
- **Dependent on r**, so rounds differ even if the state repeated.
- **Close to unbiased:** each secret bit is close to 50/50 when B looks random.
- **Dependent on all of B**, not a small region of it.
- **Constant-time:** the secret outputs come from fixed positions, with only bit operations, rotations and 32-bit multiplication modulo 2^32. The multiplication MUST take the same time for any operands (§14). The group g depends only on public values, so any arithmetic may compute it.
- **The same in mode 1 and mode 2.**

#### 5.4.2 Rule v5

```
h  = r × 0x9E3779B9 mod 2^32
for k = 0 … 31:
    h = rotl(h ⊕ B[k], 13) × 0x9E3779B9 mod 2^32      B[k] is row word k (§2.2)
s  = ⌊h / 2^18⌋                  the top 14 bits of h
j  = s mod 16                    bits 18–21 of h
dx = ⌊s / 16⌋ mod 32             bits 22–26
dy = ⌊s / 512⌋                   bits 27–31
g  = (o + r) mod (T / S)
```

0x9E3779B9 is ⌊2^32 / φ⌋, where φ is the golden ratio, and 13 is the rotation (§12.1).

Why a chain: a multiplication carries every bit of h upward, and the rotation brings the high bits back down for the next row. So a change anywhere in B changes all of h's top bits, short of a chance collision in the 14 that are used.

Known properties (informative):
- **Every change in B moves the selectors,** except when the 14 bits happen to collide, about 2^−14 per round. A rule that read B only through the fold F would miss every change that cancels in F (§11.3).
- **One public choice per full block.** Right after a full ciphertext block is absorbed, B is that ciphertext, so the next round's selectors are public. The chosen W entry's contents stay secret. Every other round's selectors depend on secret state.
- **Serial work.** The 32 steps depend on each other. Life and the chain both read only B, so an implementation can compute them side by side.

#### 5.4.3 IV offset

o = F(IV) mod (T / S)

The setup run uses o = 0 (§6.3).

Why: it uses all 1,024 IV bits, it's even to about 1 part in 11 million, and it reveals nothing, because the IV is public.

**Test vectors:** `selectors` (§15): (g, j, dx, dy) with the key as B, for r = 0, 1 and 2. `iv_offset`: o for the IV.

### 5.5 Reading a table entry

Each round reads entry S·g + j of a table: H in mode 1, W in mode 2.

The read MUST NOT reveal j through memory access or timing (§14). The standard way is to read all S entries of group g and keep entry j with masks.

### 5.6 The Mix round

One round of Mix, on state (A, B, r) with IV offset o and table Tab:

```
(g, j, dx, dy) ← selectors(B, r, o)            §5.4
RK ← shift(Tab[S·g + j], dx, dy)               §5.2, §5.5
(A, B) ← (B, Life(B) ⊕ A ⊕ RK)
r ← r + 1
```

"Run n rounds" means applying this n times.

- **Mode 1** uses Tab = H, the setup table (§6.1). It runs only during key setup (§6).
- **Mode 2** uses Tab = W. All message processing uses mode 2.

**Reversibility** (informative). Given (A′, B′) after a round, B = A′. The selectors, and so RK, can be recomputed from B, r and o. Then A = B′ ⊕ Life(A′) ⊕ RK. So for any key, with r and o fixed, each round is a permutation of the 2,048-bit state (A, B), and no two states ever merge. That alone says nothing about the grids' density or statistics.

**Why the round key comes after the Life step** (informative): inside it, B′ = Life(B ⊕ RK) ⊕ A, the round keeps all of Life's bias, and in quick sweeps at k = 4, 6 tests still fail at R = 12.

**Test vectors:** `mix_round` (§15): the first round of Init (r = 0, A = IV ⊕ M, B = K), with the state before, the selectors and the state after.

## 6. Key setup

Key setup runs once per key and produces the key state (K, W, M), or FAIL if the key check refuses the key (§6.1).

### 6.1 Key table G, key check and setup table H

G[t] = Life^t(K), for t = 0 … T − 1.

**The key check.** Setup MUST return FAIL unless G[T − 1] differs from each of G[0] … G[T − 2]. That holds exactly when all T generations are different, which is when D(K) ≥ T (§9.1). Life is deterministic, so once a grid repeats, the generations cycle, and G[T − 1] is then a repeat too. A key that passed vetting always passes. The comparison MUST take the same time for every key (§14).

Why the check: vetting runs offline, and a key that skipped it fails silently and badly. Random grids mostly fall into short cycles, and then their table W collapses: in tests, such keystreams failed statistical tests within a megabyte. In one mining run, only about 1 random grid in 43 million survived 6,000 generations, so the check stops the likeliest misuse, random bytes used as a key, for 5,999 grid comparisons on a table setup computes anyway. It doesn't replace vetting: fields with long periods and little complexity pass it, and only the score catches them (§9.1). Whether a key passes is public, and a vetted key always passes, so the check reveals nothing about the key.

**Test vectors:** the key check's are in `vectors/key-check-v1.json` (§15).

The setup run's table H XORs k generations spaced T/k apart:

```
H[i] = G[i] ⊕ G[(i + T/k) mod T] ⊕ G[(i + 2T/k) mod T] ⊕ … ⊕ G[(i + (k − 1)T/k) mod T],   for i = 0 … T − 1
```

Why H: a generation is only about 9% live. Used directly as round keys, generations can't hide Life's bias, and the setup stream's cells persist from block to block (§11.3). H is as dense as W (about 50% live at k = 30), it needs no secret, and it introduces no constant of its own. Its positions are fixed, so building it is constant-time.

### 6.2 Setup constant

SETUP₀ is the first 1,024 bits of π's fractional part (π = 3.243F6A88… in hexadecimal): cell (r, c) of SETUP₀ is bit 32r + c + 1 after the point. Appendix A gives it in full. It has 501 live cells.

SETUP is SETUP₀ with the parameters XORed into its first five row words, each as an unsigned 32-bit integer:

```
SETUP[0] = SETUP₀[0] ⊕ T
SETUP[1] = SETUP₀[1] ⊕ k
SETUP[2] = SETUP₀[2] ⊕ S
SETUP[3] = SETUP₀[3] ⊕ R
SETUP[4] = SETUP₀[4] ⊕ version
SETUP[i] = SETUP₀[i]          for i = 5 … 31
```

Why π: the constant has to be fixed, public and irregular, and the rule that picks it should leave no room for choice. Taking π from its first bit is such a rule. Blowfish and BLAKE take their constants from the same digits for the same reason. Sharing public constants is harmless.

Why the parameter words: without them, one key used under two settings could run the same setup stream. With R = 16 and R = 32, for example, the setup table and the rounds would be identical, so every block of the R = 32 run, its mask M included, would also be a block of the R = 16 run, and the two W tables would be related. The version keeps versions of the cipher apart the same way.

### 6.3 Setup run and stream

```
A ← SETUP;  B ← K;  r ← 0;  o ← 0
run R_init rounds in mode 1
Z_0 ← B as 128 bytes
for i = 1 … k·T/16:
    run R rounds in mode 1
    Z_i ← B as 128 bytes
```

Why a run from a constant: no message run can reproduce it, because messages start from A = IV ⊕ M, and M is secret.

### 6.4 The mask M and the tags

- M is Z_0, as a grid.
- Let Y = Z_1 ‖ Z_2 ‖ … ‖ Z_{k·T/16}. Tag t, for t = 0 … k·T − 1, is Y[8t … 8t + 7], read as an unsigned 64-bit big-endian integer. Each block gives 16 tags. Because T is a multiple of 16, the tags fill whole blocks.

### 6.5 Shuffles

For each s = 0 … k − 1, shuffle π_s is the sequence 0 … T − 1 sorted in ascending order by tag s·T + i, where i is the generation number. Ties go to the smaller i.

The sort MUST NOT reveal the tags through memory access or timing (§14). A fixed sorting network does this.

Why sorting by tags: it gives a uniform shuffle without discarding any draws, and it can run in constant time. Fisher–Yates with rejection sampling can't.

### 6.6 Round-key table W

For s = 0 … k − 1 and q = 0 … T/k − 1:

```
W[s · T/k + q] = G[π_s[k·q]] ⊕ G[π_s[k·q + 1]] ⊕ … ⊕ G[π_s[k·q + k − 1]]
```

That gives T entries. Every generation appears in exactly k entries, once per shuffle, and never twice in the same entry.

### 6.7 Result

The key state is (K, W, M). Implementations SHOULD erase G, H, the stream and the tags once W is built.

**Test vectors:** `key_setup` (§15): H[0], H[1] and a digest of all of H, the setup constant, M, W[0], W[1] and W[5999], and a digest of all of W.

## 7. Encryption

### 7.1 Init

```
A ← IV ⊕ M;  B ← K;  r ← 0;  o ← F(IV) mod (T/S)
run R_init rounds in mode 2
```

Why mask the IV: an attacker who chooses IVs still can't choose A's contents, and the whole state starts secret.

### 7.2 Associated data

If |AD| = 0, this step is skipped entirely, with no marker.

Otherwise, AD is processed in blocks of up to 128 bytes. For each block of L bytes:
1. B ← B ⊕ the block, into bytes 0 … L − 1.
2. If L < 128, this is the last block: B ← B ⊕ (0x80 at byte L).
3. Run R rounds in mode 2.

When |AD| is a multiple of 128, the last block has L = 0 and absorbs only the end marker. Nothing is output.

### 7.3 Separator

Flip cell (31, 31) of A, the last cell: A[31] ← A[31] ⊕ 1, which is bit 0 of byte 127. This step happens every time, even when there is no AD.

Why: absorbing message data changes B exactly as absorbing AD does. Without a mark between the two phases, some different (AD, message) pairs would absorb the same blocks and get the same tag. The flip must be in A, because data and end markers only touch B. Any cell of A would be equally secure. The last cell can never coincide with an end marker, which always lands in column 0, 8, 16 or 24.

### 7.4 Message

The plaintext is processed in blocks of up to 128 bytes. For each block of L bytes, with L = min(128, |P| − off):
1. pad ← the first L bytes of B.
2. C[off … off + L − 1] ← P[off … off + L − 1] ⊕ pad.
3. Replace the first L bytes of B with C[off … off + L − 1]. This is the same as XORing the plaintext block into B.
4. If L < 128, this is the last block: B ← B ⊕ (0x80 at byte L), and the message step ends.
5. Otherwise, run R rounds in mode 2 and continue with the next block.

When |P| is a multiple of 128, including the empty message, the last pass has L = 0 and absorbs only the end marker.

### 7.5 Finish

```
run R_final rounds in mode 2
τ ← the first 16 bytes of B
```

### 7.6 Pseudocode

```
Init:       A ← IV ⊕ M;  B ← K;  r ← 0;  o ← F(IV) mod (T/S)
            run R_init rounds

AD:         if |AD| > 0:
                off ← 0
                loop:
                    L ← min(128, |AD| − off)
                    B ← B ⊕ AD[off … off+L−1]          (into bytes 0 … L−1)
                    if L < 128:
                        B ← B ⊕ (0x80 at byte L)
                        run R rounds
                        stop
                    run R rounds
                    off ← off + 128

Separator:  A[31] ← A[31] ⊕ 1                          (cell (31, 31); always)

Message:    off ← 0
            loop:
                L ← min(128, |P| − off)
                pad ← first L bytes of B
                C[off … off+L−1] ← P[off … off+L−1] ⊕ pad
                replace the first L bytes of B with C[off … off+L−1]
                if L < 128:                             (a partial block, or the marker-only block)
                    B ← B ⊕ (0x80 at byte L)
                    stop
                run R rounds
                off ← off + 128

Finish:     run R_final rounds
            τ ← first 16 bytes of B

Output:     C (exactly |P| bytes), τ
```

**Test vectors:** `aead` (§15): messages of 0, 1, 127, 128, 129 and 256 bytes, each with no AD and with 23 bytes of AD.

## 8. Decryption and verification

Decryption runs the same steps as encryption. The only difference is in the message step (§7.4): P[off … off + L − 1] ← C[off … off + L − 1] ⊕ pad, and the received ciphertext block is absorbed exactly as the sender absorbed it.

After the finish, the receiver computes the tag τ′:
- It MUST compare τ′ with the received τ over all 16 bytes, in constant time.
- If they differ, it MUST return FAIL and MUST NOT release any part of the plaintext. An implementation that decrypts into the caller's buffer MUST erase that buffer before returning FAIL.
- Plaintext MAY be computed before the comparison, but it MUST NOT be released or used until the tags match.

## 9. Key vetting

Key vetting is a precondition, not part of the cipher. Each key is vetted once, offline, on a trusted machine, before anyone uses it. The cipher assumes its key passed. At runtime it checks only that the key's first T generations are all different (§6.1), which a vetted key always passes, so nothing about the key is exposed.

The keys behind this document were found by the miners: programs that draw random grids, run them, and score the long-lived ones with their complexity scorer. Neither the programs nor their pool of keys is published.

### 9.1 Tests

A key passes vetting if all three hold:
1. **D(K) ≥ minimum generations** (default 6,000). D(K) is the number of distinct generations before the first repeat: G[0] … G[D−1] are all different, and G[D] equals one of them. The minimum MUST be at least T.
2. **Complexity score ≥ minimum complexity** (default 10,000). §9.3 defines the score, over the key's D + 1 generations.
3. **Live cells between the minimum and the maximum** (defaults 64 and 960).

All four thresholds are parameters of vetting, with the defaults above.

Why the second test: D can be inflated without any real complexity. A field built from oscillators and spaceships with different prime periods doesn't repeat until the least common multiple of those periods. Its D can reach millions while every cell's history stays trivial. The ten crafted fields we tried score 181 to 3,273, while every key in the miners' pool with D ≥ 6,000 scores 11,107 or more.

Why the live-cell range: there are C(1024, n) grids with n live cells, 2^341 at 64, and a grid with 64 dead cells is just as easy to guess, hence the cap of 960. These counts describe the candidates before vetting, not the entropy of accepted keys or a bound on the work to recover one.

### 9.2 Key generation

The security goals (§10) assume keys made the way the miners make them: pick a density uniformly from 1–99%, then place that many live cells uniformly at random, using a strong random source. Given its live-cell count n, a key is then uniform over the valid grids with n live cells.

Each key MUST come from its own draw. A key derived from another, by a torus shift, rotation or reflection or by editing cells, is a related key, and the goals don't cover related keys (§10.1).

In one mining run, about 1 grid in 43 million survived past 6,000 generations. One classifier on counts of local 3 × 3 patterns told mined keys from random grids with the same live-cell counts no better than chance (§11.2), but that doesn't rule out cheaper ways to recognize or enumerate valid keys. Before vetting there are about 2^994 grids at the pool's median of 418 live cells, and at least 2^341 at every count in the permitted range. How much vetting shrinks that set at each count isn't bounded.

Keys published anywhere MUST NOT be used. Appendix B lists them. A key picked from a published collection of mined keys is only as strong as a search of that collection.

Vetting doesn't need to run in constant time, because it runs offline and its results never reach the cipher's runtime.

### 9.3 The complexity score

The score rewards a key whose population, single cells and pairs of cells all behave unpredictably over its life. It multiplies three measures, each between 0 and 1, and scales them by the log of the life's length. This definition follows the miners' scorer exactly, including two details that the scorer's documentation describes differently or leaves out (notes below). Logarithms are natural.

**Inputs.** The key K and its D (§9.1). Let N = D + 1, and X_t = Life^t(K) for t = 0 … N − 1: every distinct generation, then the first repeat. Number the cells in row order, i = 32r + c for cell (r, c), and write x_t(i) for cell i of X_t (1 if live). If N ≤ 1, the score is 0.

**Population entropy, H_pop.** P_t is the number of live cells in X_t. Each of the first min(N, 20,000) generations goes into one of 32 bins, bin min(⌊P_t / 32⌋, 31), so a full grid shares the last bin with populations 992–1,023. With h_b the count in bin b:

```
H_pop = −(1 / ln 32) · Σ over bins with h_b > 0 of (h_b / N) · ln(h_b / N)
```

The shares divide by N even when N is over 20,000, so for lives that long they add up to less than 1.

**Cell entropy, H_cell.** p_i = (1/N) Σ_t x_t(i) is the share of generations in which cell i is live. With the binary entropy h(p) = −p ln p − (1 − p) ln(1 − p), and h(0) = h(1) = 0:

```
H_cell = (1/1024) · Σ_i h(p_i) / ln 2
```

**Independence, I.** Cell i is static if v_i = p_i(1 − p_i) < 10⁻¹⁰, which for any N below 10¹⁰ means it never changes. For each pair of cells i < j:
- if cell i is static, the pair is left out
- otherwise, if cell j is static, the pair counts, with ρ_ij = 0
- otherwise ρ_ij = (q_ij − p_i p_j) / √(v_i v_j), clamped to [−1, 1], where q_ij = (1/N) Σ_t x_t(i) x_t(j) is the share of generations in which both are live

With n the number of pairs that count, I = 1 − (1/n) Σ |ρ_ij| over them, or I = 0 if n = 0.

**The score:**

```
score = ⌊H_pop · H_cell · I · ln N · 10,000⌋
```

Notes:
- **Static cells.** The scorer's documentation says a pair with a static cell counts as correlation 0, whichever cell is static. The code, which produced the miners' scores, leaves the pair out when the lower-numbered cell is static. So the score of a field with static cells shifts a little when the field moves on the torus. No sampled pool key has a static cell (§11.2), and for those keys the two readings agree.
- **The 20,000 cap** is the scorer's limit on the population history. It changes nothing for a key with D below 19,999.
- **Floating point.** The scorer computes in IEEE 754 double precision. An implementation that evaluates in another order can differ by 1 only when the exact value lies within about a millionth of an integer. The threshold sits far from every pool key's score (§9.1), so no verdict depends on it.

## 10. Security goals and threat model

### 10.1 Goals

These are design goals, not proven claims (§11).

| Property | Goal |
|---|---|
| Key recovery | at least 2^256 work |
| Confidentiality: telling ciphertexts from random under adaptive chosen plaintexts, with IVs never repeated | at least 2^256 work |
| Integrity of the IV, AD, ciphertext and tag | a forgery succeeds with probability about 2^−128 per attempt |
| Idealized capacity benchmark | 2^512, for the 1,024-bit hidden grid A; not a bound for this construction |
| Limits on data per key | 2^48 blocks, counted as in §4.4 |

- **The capacity benchmark.** Duplex security results model the permutation as public and random, with the key in the state. Here the key selects the permutation itself, through W, so those results don't apply directly, and 2^512 is a benchmark, not a claim.
- **Related keys.** No goal. The goals assume independent keys (§9.2): a key MUST NOT be derived from another, for example by a torus shift, rotation or reflection, or by editing cells.
  - Why: it's the usual stance. AES-GCM and ChaCha20-Poly1305 make no related-key claim, and AES-256 is still used everywhere despite a related-key attack at about 2^99.5 work.
  - It matters more here than for most ciphers. Life commutes with the torus's 8,192 symmetries, so a key σ(K) has the generation table σ(G), and a vetted key's symmetry orbit holds up to 8,192 grids that pass vetting, fewer if a symmetry fixes the key. Only the setup constant, the selector chain and the IV handling break the symmetry.
  - Independent keys aren't scarce. The miners' pool holds 387,874 vetted keys, and no two of them have the same next generation, even allowing for symmetry.
  - The tests still check how the key is mixed in, with one-cell flips (S3) and torus symmetries (S8a, S8b), and both pass (`HARNESS.md`). That's evidence about the design, not a related-key claim.
- **Multiple users.** The goals are per key. No claim covers an attacker who targets many keys at once.

### 10.2 IV reuse

There's no confidentiality or integrity goal when an IV repeats.

What leaks: two messages under the same key, IV and AD start from the same state, so they get the same pads up to and including their first differing block. That block leaks P ⊕ P′ = C ⊕ C′. Identical earlier blocks show as identical ciphertext. After the first differing block, the absorbed ciphertexts differ, so the pads differ.

### 10.3 Threat model

The attacker:
- knows the whole algorithm
- sees every IV, AD, ciphertext and tag
- may know or choose plaintexts
- may change messages in transit and submit forgeries
- may run code on the same computer, and watch its cache use and timing

Out of scope:
- physical attacks, such as measuring power or electromagnetic emissions
- replayed messages, which the protocol on top must handle, for example by numbering messages

Users MUST:
- never reuse an IV under the same key
- keep keys secret
- use only keys that passed vetting (§9) and were never published
- draw every key independently, never deriving one key from another (§10.1)
- count the blocks each key absorbs, in encryption and decryption, and stop using the key before it reaches 2^48 (§4.4)
- verify the tag before using any plaintext

## 11. Security analysis

**Status:** analyzed only within this project. No one else has analyzed the cipher, and nothing about its security is proven. `HARNESS.md` describes the tests and their results in full.

### 11.1 Method

The cipher was tested as a black box, and in places as a white box, by a harness of 48 checks in three tiers: smoke (under a minute), standard (each statistical stream to 1 GB) and deep (to 256 GB). Seventeen controls of known quality calibrate it: ChaCha20-Poly1305 and Ascon-AEAD128 must pass everything, and each graded test must be failed by at least one deliberately flawed control, except T4, which checks the key-vetting tool against known answers. Attacks on reduced rounds measure how far each known weakness reaches. Two quantities set the round count (§11.4):
- **r_min,** the smallest tested R at which every graded test passes, for the stated tier and sample sizes
- **r_attack,** the most rounds an attack reaches within a stated data budget, with demonstrated results kept apart from extrapolated estimates

### 11.2 Observed properties

- **Mix is a permutation** of (A, B) for every key, with r and o fixed (§5.6), so states never merge. That alone says nothing about the grids' statistics.
- **The key table,** measured on mined keys:
  - It stays active to its end. About 70 cells change from one generation to the next, and 80–90 against the generation two back, which leaves out blinkers. Activity drops only in the last ~100 generations before a key repeats.
  - Activity reaches every cell within 1,000–2,000 generations, and no cell of a sampled key is static (§9.3).
  - Generations 100 or more apart are about as different as two unrelated grids, even at the best torus shift. They aren't independent, though: each is a function of K.
  - Generations are sparse, at about 9% live. W entries, as XORs of k of them, are about 27% live at k = 4, 39% at k = 8, 47% at k = 16 and 49.7% at k = 30.
- **Recognizing valid keys.** One classifier on counts of local 3 × 3 patterns told mined keys from random grids with the same live-cell counts no better than chance: 50.5% accuracy, AUC 0.507. That tests one feature set and one classifier.

### 11.3 Attacks

**Cell persistence** is the strongest attack measured. Write X_t for B after round t. Each round gives X_{t+1} ⊕ X_{t−1} = Life(X_t) ⊕ RK_t. Life's output is about 27% live, so its correlation with the constant 0 is 0.453, the largest in its Walsh spectrum. With sparse round keys the right-hand side is mostly 0, and a cell tends to agree with itself two rounds later. With R even, consecutive pads of one message, which a known-plaintext attacker sees, are linked cell by cell through R/2 such terms. Detecting a correlation c at z standard deviations takes about z²/(1024 c²) blocks.
- At k = 4, the demo set's value, the correlation at R = 16 is 3.0 × 10⁻⁵, measured on 8 GB of keystream from 8 keys: a distinguisher from a few GB.
- At k = 30, the round keys are 49.7% live. Over 32 keys the correlation at R = 2 averages 0.0029, with 0.0045 for the weakest sampled key, and at R = 4 it's about 8 × 10⁻⁶, measured on 32 GB of keystream from 8 keys. It fades about 4.2 bits per R between R = 2 and 4.
- Extrapolated from those two round counts, a key's 2^48 blocks (§4.4) would detect it, at one standard deviation, up to about R = 6 for an average sampled key and 7 for the weakest. These are estimates, not demonstrated attacks at those rounds, and not bounds over all vetted keys.
- Each key's W density sets its correlation, so keys with a sparser W are weaker.

**Cell persistence in the setup run.** The setup run has the same relation, with H's entries as round keys. H is about 50% live at k = 30, and over 400 keys' setup streams it shows no persistence at R = 4, 6 or 8. Raw generations, about 9% live, would leave a correlation of 0.092 at R = 8, fading only about 0.27 bits per R.

**The chosen-IV differential.** IVs that differ in two cells on one wrapped diagonal, (r, c) and (r + d, c + d), have the same fold, so they get the same IV offset and the same round-key groups. The difference enters A and reaches B a round later. Life often ignores a small difference: a single changed cell alters no cell of the next generation about one time in 15. If the selectors ignore it too, the round keys don't change, and the difference moves back into A untouched.
- A selector that read B only through a linear fold would miss every difference that cancels in the fold. Rule v5's chain sees every change in B, so the difference survives a round only if the 14 selector bits also collide. Treating that as probability 2^−14 per round is a modeling assumption, since the two events need not be independent.
- With k = 30, no pair of first output blocks differed in fewer than 400 of 1,024 bits among 160 million pairs at R = 2. For random outputs that probability is about 8.4 × 10⁻¹³ per pair. Under an independent-trial model, zero hits bound the rate below 1.9 × 10⁻⁸ (one-sided, 95%), which is neither an attack rate nor a bound for each vetted key.
- One-cell IV differences always change the IV offset, and so the groups, which this differential needs to stay equal. That doesn't rule out other attacks that use them.
- No round limit within the data limit is claimed for this differential.

**One round.** At R = 1 the cipher is broken outright: with known plaintext, each block reveals one table entry, unshifted, since that round's selectors come from public values.

**Not attempted:** algebraic attacks beyond one round, including SAT-based recovery of states or keys. The 6.1-Mbit table W and the hidden states are all determined by the 1,024-bit key, so their size says nothing about how hard such attacks are.

### 11.4 Results and the round count

**The final tests on the recommended set,** at R = 24:
- The standard tier, run with every control, passes all 71 graded results, and again with the key check (§6.1) running in every key setup.
- The deep tier passes all 72. Crush on the setup stream passes on a rerun after a fix to the harness (`HARNESS.md`).
  - PractRand is clean to 256 GB on one long message, byte-swapped too, on the counter-IV stream, and on the setup stream across 190,872 keys.
  - TestU01's Crush passes on all three, and BigCrush on the long message.
  - The block-to-block persistence test on 64 GB finds a correlation of 2.2 × 10⁻⁶ at lag 1 (p = 0.21).
  - None of 10^8 random tags is accepted.
- **Constant time.** Key setup, encryption and decryption in the C implementation pass a dudect-style timing test on the AVX2 build, with |t| at most 2.52 against a threshold of 4.5, and Valgrind secret tracking on both builds. A control with a secret table index fails both.

**The round count.** R ≥ 3 max(r_min, r_attack) is a heuristic minimum.
- **r_min ≤ 6.** The recommended design passes all 71 standard-tier results at R = 6. Smaller R wasn't run at full size.
- **r_attack ≈ 7** within 2^48 blocks per key: cell persistence's extrapolated reach for the weakest sampled key (§11.3).
- **R = 24.** The heuristic asks for at least 21. R = 24 is about 3.4 times the weakest sampled key's estimated reach, which leaves room for an estimate of eight rounds, but it isn't a security margin against unmeasured attacks or unsampled keys.
- **The factor 3** is an allowance for attacks the tests miss, not a bound on their reach. As a check on its scale: the same tests break ChaCha at 3 rounds and pass it at 4, published attacks reach about 7, and 3 × 7 = 21 is close to the 20 rounds ChaCha20 uses. One comparison doesn't validate the factor for a different design.

### 11.5 Properties to watch

- **The fold now sets only the IV offset** (§5.4.3). Some simple IVs fold to exactly 0, for example the counting bytes 00 01 … 7F, which pins o to 0.
- **Public selectors** in the round after each full ciphertext block (§5.4.2).
- **The selector's 14 secret bits** cap what one round contributes against differentials in which Life ignores a difference.
- **Keys whose W is sparser than average** are weaker against cell persistence.
- **Multi-cell linear relations,** such as a cell against the parity of its neighbours, Life's next-largest Walsh coefficient at 0.328, are untried.
- **Exact linear relations among W's entries.** Each shuffle partitions all T generations, so the T/k entries made from one shuffle XOR to the same grid, the XOR of all generations. At k = 30 that gives 29 exact relations.
- **The setup table repeats.** H[i] depends only on i mod T/k, so H has at most T/k = 200 distinct entries, each appearing k times, and the setup run's round keys are shifts of those 200 grids. The setup stream's tests found no effect, but the structure is there.
- **Generations determine their successors.** Any one generation gives every later one by running Life forward. Earlier ones need predecessor search, which SAT-based tools for Life can do; how they fare on full 32 × 32 fields hasn't been measured.
- **Sharper distinguishers,** using the whole distribution of difference weights rather than a threshold, are untried.

## 12. Design rationale

This section summarizes the reasons for the design's choices.

- **The key is the configuration itself.** It's the simplest choice, and the miners already produce such keys.
- **Offline vetting**, with three tests (§9), and one cheap check in setup (§6.1). The score is costly, and its timing depends on the key, so vetting runs offline, once per key. Setup checks only that the first T generations are all different: 5,999 grid comparisons, in constant time, which stop random bytes used as a key.
- **A duplex built on second-order Life.** Plain Life loses information every step, so states merge and grids thin out. Second-order Life, next = Life(current) ⊕ previous, is reversible, and two grids are the minimum it needs.
- **Round keys from a shuffled table.** Each W entry XORs k generations chosen by a key-dependent shuffle. Fixed spacing (G[t], G[t+100], …) was rejected as predictable. The table is precomputed, so each round costs one lookup.
- **Selectors from B only, through a nonlinear chain** (rule v5).
  - A selector that also read A, which the round overwrites, would let states merge. Reading only B keeps Mix reversible, at the cost of one public choice per full block.
  - A selector that read B only through the linear fold F would miss a difference that cancels in F, and when Life ignores the difference too, it survives into later rounds: a chosen-IV differential (§11.3). The chain sees every change in B.
- **Dense round keys in both modes** (k = 30, and the setup table H). A sparse round key can't hide Life's bias, and cells then persist from block to block (§11.3).
- **A public group, with a secret pick inside it.** A lookup at a secret index leaks through the cache, so only the pick among 16 entries is secret, and it's made with masked reads.
- **A 1,024-bit IV, masked by M.** An IV only has to be unique, and a full grid reaches every cell from round 0. M stops chosen IVs from setting A.
- **The separator and the end marker.** Together they make every (AD, message) pair absorb a different sequence. Without the marker, trailing zero bytes could be cut; without the separator, bytes could move across the AD/message boundary.
- **T = 6,000.** Past 6,000, each extra ~234 generations halves the pool of usable keys, and the table stays busy to its end.
- **R ≥ 3 max(r_min, r_attack),** a heuristic minimum (§11.4). The factor 3 is an allowance for attacks the tests miss, not a bound on their reach, and standard proof tools don't cover state-picked round keys.

### 12.1 Where the constants come from

| Constant | Where it comes from |
|---|---|
| SETUP₀ | the first 1,024 bits of π's fractional part (§6.2) |
| 0x9E3779B9 | ⌊2^32 / φ⌋, φ the golden ratio. It's an odd multiplier: it spreads the round counter across all 32 bits of h, and in rule v5 it mixes each row of B into h. The same constant appears in TEA and other designs. |
| 13, rule v5's rotation | It brings the high bits of each product back to the low end of h for the next row. It was chosen when rule v5 was first measured, and kept as measured. Other rotations that do the same would serve as well. |
| 0x80 end marker | a single 1 bit after the data, then zeros, in this document's bit order (§2.2): the usual padding rule. Ascon applies the same rule as 0x01, under its little-endian convention |
| cell (31, 31) | the last cell of A, a position no end marker can reach (§7.3) |
| 16-byte tag | forging is an online attack, and each attempt succeeds with probability 2^−128 |

## 13. Advantages and limitations

Advantages:
- **Simple operations.** A Life step, XORs, rotations and masked reads, all bit-parallel on 32-bit row words, plus a chain of 32 multiplications per round for the selectors.
- **A reversible state update.** The state can't degrade over long messages.
- **No length expansion.** The ciphertext has exactly the plaintext's length, with no padding.
- **Constant time by design**, including key setup.

Limitations:
- **Unanalyzed.** Nothing about its security is proven or independently checked.
- **Large per-message overhead.** 128 bytes of IV plus a 16-byte tag.
- **Expensive keys.** Keys must be mined (in one mining run, about 1 grid in 43 million qualified) and vetted offline.
- **Expensive setup.** T Life steps, building H (k·T grid XORs), then a setup run of R_init + R · k·T/16 rounds, then k constant-time sorts of T entries. For the recommended set, that's about 112 ms on one performance core of an Intel Core i5-1240P, with AVX2.
- **Memory.** W takes T × 128 bytes = 768,000 bytes per key. G takes as much again during setup.
- **Per-block cost.** R rounds, each a Life step, the selector chain, a constant-time read of 16 entries (2 KB), a shift and some XORs. The C implementation encrypts at about 55 MB/s at R = 24, and 82 MB/s at R = 16, on the same core.

## 14. Implementation requirements

The cipher assumes it runs on shared computers, where other programs can observe which memory it touches and how long it takes. So no secret may decide a branch or a memory address.

| Operation | Requirement |
|---|---|
| Life step | MUST do the same work for any data (bit-parallel) |
| Selector multiplication (§5.4.2) | MUST take the same time for any operands. Current x86 and 64-bit ARM cores do. On cores where a multiplication can finish early, use a constant-time replacement |
| Table read (§5.5) | MUST read all S entries of the public group and keep one with masks |
| Shift by a secret (dx, dy) | MUST use rotations, and row moves in 5 fixed steps (1, 2, 4, 8, 16 rows), each kept or dropped with masks |
| Shuffles (§6.5) | MUST sort with a fixed sorting network, with no data-dependent branches or discarded draws |
| Building H (§6.1) | reads G at fixed positions only, so it's constant-time as written |
| Building W (§6.6) | MUST NOT read G at a position that depends on a shuffle. One way: carry each generation through the sorting network along with its tag, then XOR neighbours in the sorted order |
| Key check (§6.1) | MUST compare G[T − 1] with all T − 1 earlier generations, each in full, with no early exit. Only its result, which is public, may decide a branch |
| Tag comparison (§8) | MUST compare all 16 bytes, always |

- Implementations SHOULD erase G, the setup stream, the tags and all message state when they're no longer needed.
- A reference implementation used only to produce test vectors MAY ignore the timing requirements. It MUST say so.
- Key vetting (§9) runs offline, so these requirements don't apply to it.

## 15. Test vectors

These are algorithm version 1's test vectors, published and fixed (§1.1):

| File | What it covers |
|---|---|
| `vectors/demo-v1.json` | the demo set: T = 6,000, S = 16, k = 4, R = 16 |
| `vectors/recommended-v1.json` | the recommended set: T = 6,000, S = 16, k = 30, R = 24 |
| `vectors/key-check-v1.json` | the key check (§6.1), which depends only on the key and T |

Their SHA-256 digests, in the format `sha256sum -c` reads:

```
5d1538e5070c80ba4d0df27602add802561040624772c9aca7c3ea678ce0fcf1  vectors/demo-v1.json
4bd29e0ada05c9fd3814f2c2619376e313932363523dcf72993648b39055c580  vectors/recommended-v1.json
1924cc8b6b9e834791d419cc6bda52dc6b532b36d8396895231ce77c801f3430  vectors/key-check-v1.json
```

An implementation MUST reproduce every value in the file of each parameter set it supports, and every result in the key-check file.

- **Inputs.** The key is the burned demo key (Appendix B). Byte i of the IV is (13 + 7i) mod 256. The simpler counting IV `00 01 … 7F` folds to 0 (§11.5), which would pin o to 0 and leave the vectors blind to it.
- **Format.** Grids are 32 row words in hexadecimal (§2.2), and byte strings are hexadecimal.
- **Who reproduces them.** The reference implementation wrote them (`reference/make_vectors.py`), and the C implementation reproduces all three files byte for byte (`lc-vectors`, built in `fast/`).

| Field | Section | What it checks |
|---|---|---|
| `life` | §5.1 | One step of a glider crossing the corner, four steps of it, and one step of the key |
| `shift` | §5.2 | The key shifted by (5, 3) |
| `fold` | §5.3 | F of the key and of the IV |
| `selectors` | §5.4.2 | (g, j, dx, dy) by rule v5 with the key as B, for r = 0, 1, 2 |
| `iv_offset` | §5.4.3 | o for the IV |
| `mix_round` | §5.6 | The first round of Init (r = 0): the state before, the selectors, and the state after |
| `key_setup` | §6 | H[0], H[1] and a SHA-256 of all of H; the setup constant; M; W[0], W[1], W[5999]; and a SHA-256 of all of W. Each SHA-256 is over the table's T entries in order, 128 bytes each (§2.2) |
| `aead` | §7 | Ciphertext and tag for messages of 0, 1, 127, 128, 129 and 256 bytes (byte i is i mod 256), each with no AD and with a 23-byte AD |

The key-check file lists five keys, each with its D and the check's result for one to three values of T: the demo key at T = 6,000, 6,199 and 6,200 (D = 6,199), an empty grid (D = 1), a blinker (D = 2), a glider at T = 128, 129 and 6,000 (D = 128), and the vectors' IV used as a key (D = 1,006).

## 16. References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, 1997.
- [RFC 8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, 2017.
- [RFC 8439] Nir, Y. and A. Langley, "ChaCha20 and Poly1305 for IETF Protocols", RFC 8439, 2018. The model for this document's conventions and its placement of test vectors.
- [NIST-LWC] NIST, "Submission Requirements and Evaluation Criteria for the Lightweight Cryptography Standardization Process", August 2018. The model for this document's contents.
- [SP 800-232] NIST, "Ascon-Based Lightweight Cryptography Standards for Constrained Devices", SP 800-232. Ascon is the closest relative: a duplex AEAD built on a permutation.
- [Blowfish] Schneier, B., "Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)", Fast Software Encryption, 1993. It's the precedent for key setup by running the cipher itself.
- [Life] Gardner, M., "Mathematical Games: The fantastic combinations of John Conway's new solitaire game 'life'", Scientific American, October 1970.

## Appendix A. The setup constant

SETUP₀, the first 1,024 bits of π's fractional part, as row words (§2.2):

```
rows  0–7   243F6A88 85A308D3 13198A2E 03707344 A4093822 299F31D0 082EFA98 EC4E6C89
rows  8–15  452821E6 38D01377 BE5466CF 34E90C6C C0AC29B7 C97C50DD 3F84D5B5 B5470917
rows 16–23  9216D5D9 8979FB1B D1310BA6 98DFB5AC 2FFD72DB D01ADFB7 B8E1AFED 6A267E96
rows 24–31  BA7C9045 F12C7F99 24A19947 B3916CF7 0801F2E2 858EFC16 636920D8 71574E69
```

It has 501 live cells. It was computed with Machin's formula and checked against the BBP digit-extraction formula.

For the demo parameter set (T = 6,000, k = 4, S = 16, R = 16, version 1), SETUP's first five row words are:

```
rows  0–4   243F7DF8 85A308D7 13198A3E 03707354 A4093823
```

## Appendix B. Burned keys

These keys have been published, so they MUST NOT be used to protect anything. Vetting SHOULD reject them, and every torus shift, rotation and reflection of them (§10.1).

**The demo key**, used by the test vectors (§15): D = 6,199, complexity score 15,133, 421 live cells. It settles into a still life after its last distinct generation. As row words:

```
rows  0–7   6B3028A8 DB46016A 318DA713 85D82A92 6489431E 9A2B00E1 1CB1E684 4106B26D
rows  8–15  90FC90AC 77361985 884930EB 551A3B52 81186009 E8144094 82842900 D88996D1
rows 16–23  9514CC13 3A81EC34 47580B9D F304B451 84A2B274 24122838 08F6D934 3A69CBB8
rows 24–31  6A04296A 5F54D36A 42549769 1420992C 30F90206 7215518A 1CE02869 BA961C3B
```
