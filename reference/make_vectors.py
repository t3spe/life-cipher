"""Write the test vectors to ../vectors/ (SPEC.md §15): demo-v1.json for the demo parameter set,
recommended-v1.json for the recommended set (§3.3), whose key setup takes a few minutes here, and key-check-v1.json
for the key check (§6.1), which depends only on the key and T.

Run in this folder: uv run python make_vectors.py [demo|recommended|key-check|all]   (all by default)
"""
import hashlib
import json
import pathlib

import lifecipher as lc

DEMO_KEY_HEX = (            # SPEC.md Appendix B: the burned demo key, as 32 row words
    "6B3028A8DB46016A318DA71385D82A926489431E9A2B00E11CB1E6844106B26D"
    "90FC90AC77361985884930EB551A3B5281186009E814409482842900D88996D1"
    "9514CC133A81EC3447580B9DF304B45184A2B2742412283808F6D9343A69CBB8"
    "6A04296A5F54D36A425497691420992C30F902067215518A1CE02869BA961C3B"
)
VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors"
PATH = VECTORS / "demo-v1.json"
SETS = {"demo": (lc.DEMO, PATH), "recommended": (lc.RECOMMENDED, VECTORS / "recommended-v1.json")}
KEY_CHECK_PATH = VECTORS / "key-check-v1.json"
IV = bytes((13 + 7 * i) & 0xFF for i in range(128))    # 0D 14 1B …; not 00 01 … 7F, whose fold is 0, so o would be 0
AD = b"Life Cipher test vector"
GLIDER = {(0, 1), (1, 2), (2, 0), (2, 1), (2, 2)}      # moves one row down and one column right every 4 steps
BLINKER = {(10, 10), (10, 11), (10, 12)}


def grid_with(cells, dr: int = 0, dc: int = 0) -> lc.Grid:
    """A grid with the given live cells (row, column), moved by (dr, dc) with wrapping."""
    rows = [0] * lc.N
    for r, c in cells:
        rows[(r + dr) % lc.N] |= 1 << (31 - (c + dc) % lc.N)
    return tuple(rows)


def words(g: lc.Grid) -> str:
    """A grid as its 32 row words in hex, as in SPEC.md's appendices."""
    return " ".join(format(w, "08X") for w in g)


def build(ks: lc.KeyState = None, p: lc.Params = lc.DEMO) -> dict:
    """Every vector for parameter set p, as JSON-ready data. Pass the demo key's state under p to skip key setup."""
    ks = ks or lc.key_setup(bytes.fromhex(DEMO_KEY_HEX), p)
    G = lc.key_table(ks.K, p)
    H = lc.setup_table(G, p)
    K, iv = ks.K, lc.grid_from_bytes(IV)

    glider = grid_with(GLIDER, 30, 30)                  # across the bottom-right corner
    after = [glider]
    for _ in range(4):
        after.append(lc.life(after[-1]))
    life = [
        {"name": "glider across the corner", "input": words(glider), "after_1": words(after[1]), "after_4": words(after[4])},
        {"name": "demo key", "input": words(K), "after_1": words(lc.life(K))},
    ]

    selectors = []
    for r in range(3):
        g, j, dx, dy = lc.selectors(K, r, 0, p)
        selectors.append({"B": "key", "r": r, "o": 0, "g": g, "j": j, "dx": dx, "dy": dy})

    init = lc.State(A=lc.xor(iv, ks.M), B=K, r=0, o=lc.iv_offset(iv, p))
    g, j, dx, dy = lc.selectors(init.B, init.r, init.o, p)
    one = lc.mix_round(init, ks.W, p)

    aead = []
    for ad in (b"", AD):
        for n in (0, 1, 127, 128, 129, 256):
            pt = bytes(i & 0xFF for i in range(n))
            ct, tag = lc.encrypt(ks, IV, ad, pt)
            aead.append({"ad": ad.hex(), "plaintext": pt.hex(), "ciphertext": ct.hex(), "tag": tag.hex()})

    name = "demo parameter set" if p == lc.DEMO else "recommended parameter set" if p == lc.RECOMMENDED else str(p)
    vectors = {
        "description": f"Test vectors for the Life Cipher, {name} (SPEC.md §3.3, §15)",
        "status": "published 2026-11-01 (SPEC.md §1.1, §15): any change that alters an output needs a new "
                  "algorithm version",
        "spec": "SPEC.md draft 0.3",
        "algorithm_version": p.version,
        "parameters": {"T": p.T, "S": p.S, "k": p.k, "R": p.R, "R_init": p.R_init, "R_final": p.R_final},
        "conventions": "grids are 32 row words in hex (SPEC.md §2.2); byte strings are hex",
        "key": words(K),
        "iv": IV.hex(),
        "life": life,                                                               # §5.1
        "shift": [{"input": "key", "dx": 5, "dy": 3, "output": words(lc.shift(K, 5, 3))}],      # §5.2
        "fold": [{"input": "key", "output": format(lc.fold(K), "08X")},             # §5.3
                 {"input": "iv", "output": format(lc.fold(iv), "08X")}],
        "selectors": selectors,                                                     # §5.4.2
        "iv_offset": lc.iv_offset(iv, p),                                           # §5.4.3
        "mix_round": {                                                              # §5.6, mode 2, the first round of Init (r = 0)
            "A": words(init.A), "B": words(init.B), "r": 0, "o": init.o,
            "g": g, "j": j, "dx": dx, "dy": dy,
            "A_after": words(one.A), "B_after": words(one.B),
        },
        "key_setup": {                                                              # §6
            "H[0]": words(H[0]),
            "H[1]": words(H[1]),
            "H_sha256": hashlib.sha256(b"".join(lc.grid_to_bytes(h) for h in H)).hexdigest(),
            "setup_constant": words(lc.setup_constant(p)),
            "M": words(ks.M),
            "W[0]": words(ks.W[0]),
            "W[1]": words(ks.W[1]),
            "W[5999]": words(ks.W[-1]),
            "W_sha256": hashlib.sha256(b"".join(lc.grid_to_bytes(w) for w in ks.W)).hexdigest(),
        },
        "aead": aead,                                                               # §7, with the IV above
    }
    return json.loads(json.dumps(vectors))      # exactly what a reader of the file gets back


def first_repeat(K: lc.Grid) -> int:
    """D (SPEC.md §9.1): the number of distinct generations before the first repeat."""
    seen, g = set(), K
    while g not in seen:
        seen.add(g)
        g = lc.life(g)
    return len(seen)


def build_key_check() -> dict:
    """The key check's vectors (SPEC.md §6.1): a key, its D, and whether the check passes for a few T. It passes exactly
    when D ≥ T, so the T values sit on both sides of D where that's cheap: the glider's 128 and the demo key's 6,199."""
    cases = [("the demo key (Appendix B)", lc.grid_from_bytes(bytes.fromhex(DEMO_KEY_HEX)), (6000, 6199, 6200)),
             ("an empty grid", grid_with(()), (6000,)),
             ("a blinker", grid_with(BLINKER), (6000,)),
             ("a glider", grid_with(GLIDER), (128, 129, 6000)),
             ("the vectors' IV, used as a key", lc.grid_from_bytes(IV), (6000,))]
    out = []
    for name, K, Ts in cases:
        G = [K]
        while len(G) < max(Ts):
            G.append(lc.life(G[-1]))
        out.append({"name": name, "key": words(K), "D": first_repeat(K),
                    "checks": [{"T": T, "passes": lc.key_check(G[:T])} for T in Ts]})
    vectors = {
        "description": "Test vectors for the Life Cipher's key check (SPEC.md §6.1, §15)",
        "status": "published with SPEC.md draft 0.4 (§1.1, §15): any change that alters an output needs a new "
                  "algorithm version",
        "spec": "SPEC.md draft 0.4",
        "algorithm_version": 1,
        "conventions": "grids are 32 row words in hex (SPEC.md §2.2); D is the number of distinct generations before "
                       "the first repeat (§9.1), and the check passes exactly when D is at least T",
        "cases": out,
    }
    return json.loads(json.dumps(vectors))


if __name__ == "__main__":
    import sys
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    for name in ([*SETS, "key-check"] if which == "all" else [which]):
        VECTORS.mkdir(exist_ok=True)
        path, data = ((KEY_CHECK_PATH, build_key_check()) if name == "key-check"
                      else (SETS[name][1], build(p=SETS[name][0])))
        path.write_text(json.dumps(data, indent=2) + "\n")
        print("wrote", path)
