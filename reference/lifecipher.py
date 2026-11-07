"""Life Cipher reference implementation: SPEC.md draft 0.4, algorithm version 1.

Read it side by side with SPEC.md. The sections below follow the spec's order, and each function names the section
it implements. It's written for clarity, not speed, and it is not constant-time, which SPEC.md §14 allows for an
implementation that only produces test vectors. Don't use it to protect anything.

Grids are tuples of 32 row words (SPEC.md §2.2): row r as an unsigned 32-bit integer, with column c in bit 31 − c.
Byte strings are `bytes`.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass, replace

# --------------------------------------------------------------------------------------------------------------------
# §2 Notation and data layout
# --------------------------------------------------------------------------------------------------------------------

N = 32                      # a grid is N × N cells on a torus
GRID_BYTES = 128            # and 128 bytes in the byte layout of §2.2
MASK32 = 0xFFFFFFFF

Grid = tuple                # 32 row words


def rotl(x: int, n: int) -> int:
    """§2.3: rotate the 32-bit word x left by n mod 32 places."""
    n %= 32
    return ((x << n) | (x >> (32 - n))) & MASK32 if n else x


def rotr(x: int, n: int) -> int:
    """Rotate the 32-bit word x right by n mod 32 places."""
    return rotl(x, 32 - n % 32)


def grid_from_bytes(data: bytes) -> Grid:
    """§2.2: 128 bytes to a grid. Row word r is bytes 4r … 4r + 3, read big-endian."""
    if len(data) != GRID_BYTES:
        raise ValueError(f"a grid is {GRID_BYTES} bytes, not {len(data)}")
    return tuple(int.from_bytes(data[4 * r:4 * r + 4], "big") for r in range(N))


def grid_to_bytes(g: Grid) -> bytes:
    """§2.2: a grid to its 128 bytes."""
    return b"".join(w.to_bytes(4, "big") for w in g)


def cell(g: Grid, r: int, c: int) -> int:
    """§2.1–§2.2: cell (r, c), with indices taken mod 32. Column c is bit 31 − c of row word r."""
    return (g[r % N] >> (31 - c % N)) & 1


def xor(*grids: Grid) -> Grid:
    """§2.3: the cell-by-cell XOR of grids."""
    out = [0] * N
    for g in grids:
        for r in range(N):
            out[r] ^= g[r]
    return tuple(out)


def xor_at(g: Grid, data: bytes, at: int = 0) -> Grid:
    """§2.3: XOR the bytes `data` into grid g, starting at byte `at` of its byte layout."""
    b = bytearray(grid_to_bytes(g))
    for i, v in enumerate(data):
        b[at + i] ^= v
    return grid_from_bytes(bytes(b))


def replace_bytes(g: Grid, data: bytes) -> Grid:
    """Replace the first len(data) bytes of grid g with `data` (§7.4, step 3)."""
    return grid_from_bytes(data + grid_to_bytes(g)[len(data):])


# --------------------------------------------------------------------------------------------------------------------
# §3 Parameters
# --------------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Params:
    """§3.1: a parameter set. R_init and R_final are always 2R (§3.2).

    `measurement` allows R below 16, for analysis only, such as the challenge's reduced-round tiers. It's not part of
    the cipher.
    """
    T: int
    S: int
    k: int
    R: int
    version: int = 1
    measurement: bool = False

    def __post_init__(self):
        """§3.2: the constraints."""
        if self.S != 16:
            raise ValueError("S must be 16: selector rule v5 draws a 4-bit entry index")
        if self.k < 1 or self.T % self.S or self.T % self.k:
            raise ValueError("T must be a multiple of S and of k")
        if self.R < 1 or (self.R < 16 and not self.measurement):
            raise ValueError("R must be at least 16")
        if not all(0 <= v <= MASK32 for v in (self.T, self.S, self.k, self.R, self.version)):
            raise ValueError("every parameter must fit in 32 bits")

    @property
    def R_init(self) -> int:
        return 2 * self.R

    @property
    def R_final(self) -> int:
        return 2 * self.R

    @property
    def groups(self) -> int:
        """T / S, the number of groups in the round-key lookup."""
        return self.T // self.S


DEMO = Params(T=6000, S=16, k=4, R=16)     # §3.3: the demo set, used by demo-v1.json. Not a recommendation.
RECOMMENDED = Params(T=6000, S=16, k=30, R=24)     # §3.3: the recommended set, at most 2^48 blocks per key (§4.4)


# --------------------------------------------------------------------------------------------------------------------
# §5 Building blocks
# --------------------------------------------------------------------------------------------------------------------

def life(g: Grid) -> Grid:
    """§5.1: one Game of Life step on the torus, rule B3/S23.

    A cell is live in the result if it has exactly 3 live neighbours, or if it's live and has exactly 2. This
    evaluates all 32 cells of a row at once. Each neighbour direction is the row word rotated so that the neighbour's
    bit lines up with the cell's bit, and a 3-bit counter per cell adds the 8 neighbours up. The tests check this
    against the rule evaluated cell by cell.
    """
    out = []
    for r in range(N):
        up, row, down = g[(r - 1) % N], g[r], g[(r + 1) % N]
        # Column c sits in bit 31 − c, so rotating right by one lines up column c − 1, and left by one, column c + 1.
        neighbours = (rotr(up, 1), up, rotl(up, 1), rotr(row, 1), rotl(row, 1), rotr(down, 1), down, rotl(down, 1))
        c0 = c1 = c2 = 0                    # each cell's count in binary, c0 + 2·c1 + 4·c2, kept mod 8
        for n in neighbours:
            carry = c0 & n
            c0 ^= n
            carry, c1 = c1 & carry, c1 ^ carry
            c2 ^= carry
        two_or_three = c1 & ~c2 & MASK32    # a count of 8 wraps to 0, which is fine: only 2 and 3 matter
        out.append(two_or_three & (c0 | row))
    return tuple(out)


def shift(g: Grid, dx: int, dy: int) -> Grid:
    """§5.2: g moved dx columns right and dy rows down, wrapping. Y(r, c) = X(r − dy, c − dx)."""
    return tuple(rotr(g[(r - dy) % N], dx) for r in range(N))


def fold(g: Grid) -> int:
    """§5.3: F(X) = rotl(X[0], 0) ⊕ rotl(X[1], 1) ⊕ … ⊕ rotl(X[31], 31)."""
    f = 0
    for r in range(N):
        f ^= rotl(g[r], r)
    return f


GOLDEN = 0x9E3779B9         # ⌊2^32 / φ⌋, φ the golden ratio (§12.1)


def selectors(B: Grid, r: int, o: int, params: Params) -> tuple:
    """§5.4.2, rule v5: the public group g, and the secret entry j and shift (dx, dy), from grid B and r."""
    h = r * GOLDEN & MASK32
    for row in B:               # a chain over every row word of B
        h = rotl(h ^ row, 13) * GOLDEN & MASK32
    s = h >> 18                 # the top 14 bits of h
    j = s & 0xF                 # bits 18–21 of h
    dx = (s >> 4) & 0x1F        # bits 22–26
    dy = s >> 9                 # bits 27–31
    g = (o + r) % params.groups
    return g, j, dx, dy


def iv_offset(iv: Grid, params: Params) -> int:
    """§5.4.3: o = F(IV) mod (T / S)."""
    return fold(iv) % params.groups


@dataclass(frozen=True)
class State:
    """The working state (§5.6): grids A and B, the round counter r, and the IV offset o."""
    A: Grid
    B: Grid
    r: int
    o: int


def mix_round(st: State, table: list, params: Params) -> State:
    """§5.6: one round of Mix. `table` is H in mode 1 (key setup) or W in mode 2 (messages).

    §5.5 requires the entry read to hide j; this reference reads the entry directly, as §14 allows here.
    """
    g, j, dx, dy = selectors(st.B, st.r, st.o, params)
    rk = shift(table[params.S * g + j], dx, dy)
    return State(A=st.B, B=xor(life(st.B), st.A, rk), r=st.r + 1, o=st.o)


def run_rounds(st: State, n: int, table: list, params: Params) -> State:
    """§5.6: run n rounds of Mix."""
    for _ in range(n):
        st = mix_round(st, table, params)
    return st


# --------------------------------------------------------------------------------------------------------------------
# §6 Key setup
# --------------------------------------------------------------------------------------------------------------------

SETUP0 = (                  # Appendix A: the first 1,024 bits of π's fractional part, as row words
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
    0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69,
)


def key_table(K: Grid, params: Params) -> list:
    """§6.1: G[t] = Life^t(K), for t = 0 … T − 1."""
    G = [K]
    while len(G) < params.T:
        G.append(life(G[-1]))
    return G


class KeyCheckError(ValueError):
    """§6.1: the key's first T generations aren't all different, so key setup returns FAIL."""


def key_check(G: list) -> bool:
    """§6.1, the key check: the last generation differs from every earlier one. That holds exactly when all of them
    differ, since once Life repeats a grid it cycles, and the last generation repeats too. Not constant-time here."""
    return G[-1] not in G[:-1]


def setup_table(G: list, params: Params) -> list:
    """§6.1: H[i] = G[i] ⊕ G[i + T/k] ⊕ … ⊕ G[i + (k − 1)T/k], indices mod T: the setup run's round keys."""
    T, k = params.T, params.k
    return [xor(*(G[(i + m * (T // k)) % T] for m in range(k))) for i in range(T)]


def setup_constant(params: Params) -> Grid:
    """§6.2: SETUP₀ with T, k, S, R and the version XORed into row words 0–4."""
    words = list(SETUP0)
    for i, v in enumerate((params.T, params.k, params.S, params.R, params.version)):
        words[i] ^= v
    return tuple(words)


def setup_stream(K: Grid, H: list, params: Params) -> list:
    """§6.3: the setup run in mode 1, on the setup table H. Returns the stream blocks Z_0 … Z_{k·T/16} as bytes."""
    st = State(A=setup_constant(params), B=K, r=0, o=0)
    st = run_rounds(st, params.R_init, H, params)
    blocks = [grid_to_bytes(st.B)]
    for _ in range(params.k * params.T // 16):
        st = run_rounds(st, params.R, H, params)
        blocks.append(grid_to_bytes(st.B))
    return blocks


def setup_tags(blocks: list, params: Params) -> list:
    """§6.4: tag t is bytes 8t … 8t + 7 of Z_1 ‖ Z_2 ‖ …, read as a big-endian 64-bit integer."""
    Y = b"".join(blocks[1:])
    return [int.from_bytes(Y[8 * t:8 * t + 8], "big") for t in range(params.k * params.T)]


def shuffles(tags: list, params: Params) -> list:
    """§6.5: shuffle s is 0 … T − 1 sorted by (tag s·T + i, i), ascending."""
    T = params.T
    return [sorted(range(T), key=lambda i: (tags[s * T + i], i)) for s in range(params.k)]


def round_key_table(G: list, perms: list, params: Params) -> list:
    """§6.6: W[s·T/k + q] is the XOR of the k generations in group q of shuffle s."""
    T, k = params.T, params.k
    return [xor(*(G[perms[s][k * q + m]] for m in range(k))) for s in range(k) for q in range(T // k)]


@dataclass(frozen=True)
class KeyState:
    """§6.7: what key setup keeps: the key K, the round-key table W, and the mask M."""
    K: Grid
    W: tuple
    M: Grid
    params: Params


def key_setup(key: bytes, params: Params = DEMO, check: bool = True) -> KeyState:
    """§6, §4.1: expand a vetted key (§9). Raises KeyCheckError if the key fails the key check (§6.1). check=False
    skips only the refusal, for tests that use keys that aren't vetted on purpose."""
    K = grid_from_bytes(bytes(key))
    G = key_table(K, params)
    if check and not key_check(G):
        raise KeyCheckError("the key's first T generations aren't all different (SPEC.md §6.1)")
    blocks = setup_stream(K, setup_table(G, params), params)
    M = grid_from_bytes(blocks[0])
    W = round_key_table(G, shuffles(setup_tags(blocks, params), params), params)
    return KeyState(K=K, W=tuple(W), M=M, params=params)


# --------------------------------------------------------------------------------------------------------------------
# §7 Encryption and §8 Decryption
# --------------------------------------------------------------------------------------------------------------------

MARKER = 0x80               # the end marker (§7.2, §7.4)
TAG_BYTES = 16


def process(ks: KeyState, iv: bytes, ad: bytes, data: bytes, decrypting: bool) -> tuple:
    """§7 and §8: the steps both sides run. Returns the output bytes (C or P) and the computed tag."""
    p, W = ks.params, ks.W
    iv_grid = grid_from_bytes(bytes(iv))
    ad, data = bytes(ad), bytes(data)

    # §7.1 Init
    st = State(A=xor(iv_grid, ks.M), B=ks.K, r=0, o=iv_offset(iv_grid, p))
    st = run_rounds(st, p.R_init, W, p)

    # §7.2 Associated data: skipped entirely when there is none
    if ad:
        off = 0
        while True:
            L = min(GRID_BYTES, len(ad) - off)
            B = xor_at(st.B, ad[off:off + L])
            if L < GRID_BYTES:
                B = xor_at(B, bytes([MARKER]), at=L)
            st = run_rounds(replace(st, B=B), p.R, W, p)
            if L < GRID_BYTES:
                break
            off += GRID_BYTES

    # §7.3 Separator: flip cell (31, 31) of A, which is bit 0 of row word 31
    A = list(st.A)
    A[31] ^= 1
    st = replace(st, A=tuple(A))

    # §7.4 Message
    out = bytearray()
    off = 0
    while True:
        L = min(GRID_BYTES, len(data) - off)
        pad = grid_to_bytes(st.B)[:L]
        block = data[off:off + L]
        result = bytes(x ^ y for x, y in zip(block, pad))
        out += result
        ciphertext = block if decrypting else result
        B = replace_bytes(st.B, ciphertext)
        if L < GRID_BYTES:          # a partial block, or the marker-only block
            st = replace(st, B=xor_at(B, bytes([MARKER]), at=L))
            break
        st = run_rounds(replace(st, B=B), p.R, W, p)
        off += GRID_BYTES

    # §7.5 Finish
    st = run_rounds(st, p.R_final, W, p)
    return bytes(out), grid_to_bytes(st.B)[:TAG_BYTES]


def encrypt(ks: KeyState, iv: bytes, ad: bytes, plaintext: bytes) -> tuple:
    """§7, §4.2: returns (ciphertext, tag). The IV must never repeat under one key."""
    return process(ks, iv, ad, plaintext, decrypting=False)


class AuthenticationError(Exception):
    """§8: the tag didn't match. Decryption returns FAIL and releases nothing."""


def decrypt(ks: KeyState, iv: bytes, ad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """§8, §4.3: returns the plaintext, or raises AuthenticationError and releases nothing.

    The plaintext is computed before the comparison but returned only after it. Python can't reliably erase memory,
    so on a mismatch it's simply never handed out.
    """
    plaintext, expected = process(ks, iv, ad, ciphertext, decrypting=True)
    if not hmac.compare_digest(expected, bytes(tag)):     # compares all 16 bytes, wherever they differ
        raise AuthenticationError("tag mismatch")
    return plaintext
