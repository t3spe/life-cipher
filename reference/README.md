# Reference implementation

A Python reference implementation of `../SPEC.md` (draft 0.4, algorithm version 1), meant to be read side by side with the spec. `lifecipher.py` is one module, in the spec's order, and each function names the section it implements. It wrote the test vectors in `../vectors/`, and other implementations are checked against those vectors.

It's neither fast nor constant-time, which `SPEC.md` §14 allows for an implementation that only produces test vectors. Don't use it to protect anything.

## Running

The module uses only the Python standard library, from Python 3.10 on. The tests need pytest. In this folder, with [uv](https://docs.astral.sh/uv/):

```
uv sync                             # creates .venv/ here, with pytest
uv run pytest                       # about half a minute; LC_SLOW=1 adds the recommended set's vectors, minutes more
uv run python make_vectors.py       # rewrites the three files in ../vectors/; the recommended set takes a few minutes
```

Without uv, in a virtual environment: `pip install pytest`, then `python3 -m pytest` and `python3 make_vectors.py`. `make_vectors.py demo`, `recommended` or `key-check` writes one file.

## Files

| File | What it is |
|---|---|
| `lifecipher.py` | The cipher: notation (§2), parameters (§3), building blocks (§5), key setup (§6), encryption and decryption (§7, §8) |
| `test_lifecipher.py` | Tests: the building blocks against the spec's definitions, round trips, tampering, the end marker and the separator, and the stored vectors |
| `make_vectors.py` | Builds the test vectors: the demo and recommended parameter sets, and the key check (SPEC.md §15) |

## Notes

- **The Life step** evaluates a whole row at once: each neighbor direction is a rotated row word, and a 3-bit counter per cell adds them up. Cell by cell, key setup would take about a minute instead of about 5 seconds. The tests check it against the §5.1 rule, evaluated cell by cell.
- **The table read** indexes the entry directly. §5.5 requires a read that hides the entry index, and §14 waives that here.
- **Failed decryption** raises `AuthenticationError`. The plaintext is computed, but it's never returned when the tag doesn't match.
