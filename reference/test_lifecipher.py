"""Tests for the reference implementation (SPEC.md draft 0.4).

Run in this folder: uv run pytest       (LC_SLOW=1 also checks the recommended set's vectors, ~3 min)
"""
import json
import os
import random

import pytest

import lifecipher as lc
import make_vectors
from make_vectors import GLIDER, IV, grid_with

DEMO_KEY = bytes.fromhex(make_vectors.DEMO_KEY_HEX)


def random_grid(rnd: random.Random, density: float = 0.5) -> lc.Grid:
    if density == 0.5:
        return tuple(rnd.getrandbits(32) for _ in range(lc.N))
    return tuple(sum(1 << b for b in range(32) if rnd.random() < density) for _ in range(lc.N))


def life_by_rule(g: lc.Grid) -> lc.Grid:
    """§5.1, evaluated cell by cell exactly as the spec words it."""
    rows = [0] * lc.N
    for r in range(lc.N):
        for c in range(lc.N):
            n = sum(lc.cell(g, r + a, c + b) for a in (-1, 0, 1) for b in (-1, 0, 1) if (a, b) != (0, 0))
            if n == 3 or (lc.cell(g, r, c) and n == 2):
                rows[r] |= 1 << (31 - c)
    return tuple(rows)


@pytest.fixture(scope="session")
def demo() -> lc.KeyState:
    """The demo key under the demo parameter set (SPEC.md §3.3, Appendix B). Setup takes a few seconds."""
    return lc.key_setup(DEMO_KEY, lc.DEMO)


# §2.2 byte layout ----------------------------------------------------------------------------------------------------

def test_byte_layout():
    data = bytes(random.Random(1).randrange(256) for _ in range(128))
    g = lc.grid_from_bytes(data)
    assert lc.grid_to_bytes(g) == data
    for r in range(32):
        for c in range(32):
            assert lc.cell(g, r, c) == (data[4 * r + c // 8] >> (7 - c % 8)) & 1


# §3.2 parameter constraints -------------------------------------------------------------------------------------------

def test_parameter_constraints():
    for bad in ({"S": 8}, {"k": 7}, {"R": 8}, {"T": 6008}):
        with pytest.raises(ValueError):
            lc.Params(**{"T": 6000, "S": 16, "k": 4, "R": 16, **bad})
    assert (lc.DEMO.R_init, lc.DEMO.R_final, lc.DEMO.groups) == (32, 32, 375)


# §5 building blocks ---------------------------------------------------------------------------------------------------

def test_life_matches_the_rule():
    rnd = random.Random(2)
    for density in (0.05, 0.1, 0.3, 0.5, 0.7) * 12:
        g = random_grid(rnd, density)
        assert lc.life(g) == life_by_rule(g)


def test_life_patterns():
    block = grid_with({(10, 10), (10, 11), (11, 10), (11, 11)})
    assert lc.life(block) == block
    blinker = grid_with({(5, 4), (5, 5), (5, 6)})
    assert lc.life(blinker) != blinker and lc.life(lc.life(blinker)) == blinker
    glider = grid_with(GLIDER, 30, 30)          # across the bottom-right corner
    g = glider
    for _ in range(4):
        g = lc.life(g)
    assert g == lc.shift(glider, 1, 1)


def test_shift_definition():
    rnd = random.Random(3)
    for _ in range(20):
        x, dx, dy = random_grid(rnd), rnd.randrange(32), rnd.randrange(32)
        y = lc.shift(x, dx, dy)
        assert all(lc.cell(y, r, c) == lc.cell(x, r - dy, c - dx) for r in range(32) for c in range(32))


def test_fold_properties():
    rnd = random.Random(4)
    for _ in range(50):
        x, y, dx, dy = random_grid(rnd), random_grid(rnd), rnd.randrange(32), rnd.randrange(32)
        assert lc.fold(lc.xor(x, y)) == lc.fold(x) ^ lc.fold(y)                  # linear
        assert lc.fold(lc.shift(x, dx, dy)) == lc.rotl(lc.fold(x), dy - dx)      # shifting rotates the fold


def test_mix_round_runs_backwards():
    """§5.6: the round key can be recomputed from A′, so A comes back (T5 in ../HARNESS.md)."""
    rnd = random.Random(5)
    table = [random_grid(rnd) for _ in range(lc.DEMO.T)]
    for _ in range(50):
        st = lc.State(A=random_grid(rnd), B=random_grid(rnd), r=rnd.randrange(2**40), o=rnd.randrange(375))
        after = lc.mix_round(st, table, lc.DEMO)
        B = after.A
        g, j, dx, dy = lc.selectors(B, st.r, st.o, lc.DEMO)
        A = lc.xor(after.B, lc.life(after.A), lc.shift(table[16 * g + j], dx, dy))
        assert (A, B) == (st.A, st.B)


def test_selectors_see_every_cell():
    """§5.4.2, rule v5: one changed cell anywhere in B moves the selectors, short of a 2^-14 collision. That
    includes two cells on one diagonal, whose bits cancel in the fold F, which rule v2 used."""
    rnd = random.Random(6)
    moved = total = 0
    for _ in range(200):
        B, r = random_grid(rnd), rnd.randrange(2 ** 20)
        a, c, d = rnd.randrange(32), rnd.randrange(32), 1 + rnd.randrange(31)
        one = list(B)
        one[a] ^= 1 << (31 - c)
        two = list(one)
        two[(a + d) % 32] ^= 1 << (31 - (c + d) % 32)       # the diagonal partner: F(two) == F(B)
        assert lc.fold(tuple(two)) == lc.fold(B)
        for other in (one, two):
            total += 1
            moved += lc.selectors(tuple(other), r, 0, lc.DEMO)[1:] != lc.selectors(B, r, 0, lc.DEMO)[1:]
    assert moved == total


def test_setup_table_definition():
    """§6.1: H[i] XORs k generations T/k apart."""
    rnd = random.Random(7)
    G = [random_grid(rnd) for _ in range(6000)]
    H = lc.setup_table(G, lc.DEMO)
    for i in (0, 1, 1499, 1500, 5999):
        assert H[i] == lc.xor(G[i], G[(i + 1500) % 6000], G[(i + 3000) % 6000], G[(i + 4500) % 6000])
    H30 = lc.setup_table(G, lc.RECOMMENDED)
    assert H30[5999] == lc.xor(*(G[(5999 + 200 * m) % 6000] for m in range(30)))


# §6.2 and Appendix A: the setup constant -------------------------------------------------------------------------------

def test_setup_constant_is_pi():
    scale = 16 ** (256 + 16)

    def arctan_inv(x):
        total, term, k, sign = 0, scale // x, 1, 1
        while term:
            total += sign * (term // k)
            term //= x * x
            k, sign = k + 2, -sign
        return total

    fraction = 16 * arctan_inv(5) - 4 * arctan_inv(239) - 3 * scale         # Machin's formula
    assert "".join(format(w, "08x") for w in lc.SETUP0) == format(fraction, "x").zfill(256 + 16)[:256]
    assert sum(bin(w).count("1") for w in lc.SETUP0) == 501
    assert lc.setup_constant(lc.DEMO)[:5] == (0x243F7DF8, 0x85A308D7, 0x13198A3E, 0x03707354, 0xA4093823)


# §9 and Appendix B: the demo key ----------------------------------------------------------------------------------------

def test_demo_key():
    K = lc.grid_from_bytes(DEMO_KEY)
    assert sum(bin(w).count("1") for w in K) == 421
    seen, g = set(), K
    while g not in seen:
        seen.add(g)
        g = lc.life(g)
    assert len(seen) == 6199                    # D(K), the distinct generations before the first repeat


def test_key_check():
    """§6.1: the check passes exactly when the first T generations all differ, that is when D ≥ T. Key setup refuses a
    key that fails it, unless the refusal is switched off."""
    glider = grid_with(GLIDER)
    G = [glider]
    while len(G) < 130:
        G.append(lc.life(G[-1]))
    assert make_vectors.first_repeat(glider) == 128
    assert [T for T in range(1, 131) if lc.key_check(G[:T])] == list(range(1, 129))
    for grid in (grid_with(()), grid_with(make_vectors.BLINKER), glider):
        with pytest.raises(lc.KeyCheckError):
            lc.key_setup(lc.grid_to_bytes(grid), lc.DEMO)
    assert lc.key_setup(lc.grid_to_bytes(glider), lc.DEMO, check=False).K == glider


# §7 and §8: encryption and decryption -----------------------------------------------------------------------------------

@pytest.mark.parametrize("ad_len", [0, 7, 128, 129])
@pytest.mark.parametrize("n", [0, 1, 127, 128, 129, 256, 300])
def test_round_trip(demo, n, ad_len):
    ad = bytes(3 * i & 0xFF for i in range(ad_len))
    pt = bytes(5 * i + 1 & 0xFF for i in range(n))
    ct, tag = lc.encrypt(demo, IV, ad, pt)
    assert len(ct) == n and len(tag) == 16
    assert lc.decrypt(demo, IV, ad, ct, tag) == pt


def test_any_change_is_rejected(demo):
    """§8: flipping one bit of the ciphertext, the tag, the AD or the IV makes decryption fail (F1 in ../HARNESS.md)."""
    ad, pt = b"to: bob, msg 7", bytes(range(200))
    ct, tag = lc.encrypt(demo, IV, ad, pt)

    def flip(b, i):
        return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]

    for args in ((IV, ad, flip(ct, 150), tag), (IV, ad, ct, flip(tag, 15)), (IV, flip(ad, 0), ct, tag),
                 (flip(IV, 127), ad, ct, tag)):
        with pytest.raises(lc.AuthenticationError):
            lc.decrypt(demo, *args)


def test_end_marker(demo):
    """§7.4: a trailing zero byte changes the tag, so it can't be cut or added unnoticed (F2 in ../HARNESS.md)."""
    _, tag1 = lc.encrypt(demo, IV, b"", b"attack at dawn")
    _, tag2 = lc.encrypt(demo, IV, b"", b"attack at dawn\x00")
    assert tag1 != tag2


def test_separator(demo):
    """§7.3: the crafted pair that collides without the separator gets different tags (F3 in ../HARNESS.md)."""
    x, y = bytes(range(128)), b"\x80" + bytes(127)
    _, tag1 = lc.encrypt(demo, IV, x, y)
    _, tag2 = lc.encrypt(demo, IV, x + y, b"")
    assert tag1 != tag2


# §15: the stored vectors ------------------------------------------------------------------------------------------------

def test_vectors_still_match(demo):
    if not make_vectors.PATH.exists():
        pytest.skip("no vectors yet: run make_vectors.py")
    assert make_vectors.build(demo) == json.loads(make_vectors.PATH.read_text())


def test_key_check_vectors_still_match():
    assert make_vectors.build_key_check() == json.loads(make_vectors.KEY_CHECK_PATH.read_text())


@pytest.mark.skipif(not os.environ.get("LC_SLOW"), reason="key setup for the recommended set takes minutes: LC_SLOW=1")
def test_recommended_vectors_still_match():
    params, path = make_vectors.SETS["recommended"]
    assert make_vectors.build(p=params) == json.loads(path.read_text())
