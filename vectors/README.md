# Test vectors

Test vectors for the Life Cipher, algorithm version 1 (`../SPEC.md` §15), written by the reference implementation (`../reference/make_vectors.py`):

| File | Parameter set |
|---|---|
| `demo-v1.json` | the demo set: T = 6,000, S = 16, k = 4, R = 16. It's not a recommendation (§3.3) |
| `recommended-v1.json` | the recommended set: T = 6,000, S = 16, k = 30, R = 24 (§3.3) |
| `key-check-v1.json` | the key check (§6.1), which depends only on the key and T |

- **Key:** the burned demo key (Appendix B), in the two parameter-set files.
- **IV:** byte i is (13 + 7i) mod 256. The simpler counting IV `00 01 … 7F` folds to 0, which would make the IV offset 0 and the vectors blind to it.
- **Status:** published and fixed (`SPEC.md` §1.1 and §15): a change that alters any value here needs a new algorithm version, and new files. `SPEC.md` §15 lists the files' SHA-256 digests. Each file's `spec` field names the draft it was published with; later drafts change no value.

## What's in them

The two parameter-set files have the same fields. Grids are 32 row words in hex (§2.2), and byte strings are hex.

| Field | Section | What it checks |
|---|---|---|
| `life` | §5.1 | One step of a glider crossing the corner, four steps of it, and one step of the key |
| `shift` | §5.2 | The key shifted by (5, 3) |
| `fold` | §5.3 | F of the key and of the IV |
| `selectors` | §5.4.2 | (g, j, dx, dy) by rule v5 from the key as B, for r = 0, 1, 2 |
| `iv_offset` | §5.4.3 | o for the IV |
| `mix_round` | §5.6 | The first round of Init (r = 0): the state before, the selectors, and the state after |
| `key_setup` | §6 | H[0], H[1] and a SHA-256 of all of H; the setup constant; M; W[0], W[1], W[5999]; and a SHA-256 of all of W. Each SHA-256 is over the table's T entries in order, 128 bytes each (§2.2) |
| `aead` | §7 | Ciphertext and tag for messages of 0, 1, 127, 128, 129 and 256 bytes (byte i is i mod 256), each with no AD and with a 23-byte AD |

`key-check-v1.json` lists five keys, each with its D (distinct generations before the first repeat) and whether the check passes for one to three values of T. It passes exactly when D ≥ T. The keys: the demo key at T = 6,000, 6,199 and 6,200 (D = 6,199), an empty grid, a blinker, a glider at T = 128, 129 and 6,000 (D = 128), and the IV above used as a key (D = 1,006).

Checks:
- `../reference/test_lifecipher.py` checks that the reference still produces `demo-v1.json` and `key-check-v1.json` exactly, and with `LC_SLOW=1`, `recommended-v1.json` too. Key setup for the recommended set takes a few minutes in Python.
- The C implementation's `lc-vectors` writes all three files from the C code alone. `../fast/README.md` shows how to compare its output with them.
- `sha256sum -c` checks the files against the digests in `SPEC.md` §15.
