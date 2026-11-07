# The Life Cipher

An experimental authenticated cipher (AEAD) built on Conway's Game of Life on a 32 × 32 torus. Its key is a starting
configuration, mined because it lives for thousands of generations before repeating, and the generations it passes
through become the cipher's round keys.

It's an experiment. Nothing about it is proven, nobody outside the project has analyzed it yet, and it must not
protect real data. It's published to get outside cryptanalysis, and the reduced-round challenge in `challenge/` is the
easiest place to start.

## What's here

| Path | What it is |
|---|---|
| `SPEC.md` | The specification, draft 0.4, algorithm version 1: the design, its security goals, our own analysis (§11) and the rationale |
| `HARNESS.md` | How the cipher was tested: the checks, the controls that calibrate them, and the results |
| `vectors/` | The test vectors, published and fixed for algorithm version 1 (`SPEC.md` §15) |
| `reference/` | The Python reference implementation, which wrote the vectors. It isn't constant-time. |
| `fast/` | The C implementation: constant-time, with AVX2 and portable builds, a tool that reproduces the vectors, and a benchmark |
| `challenge/` | The reduced-round challenge: recover a key at R = 4, 8, 12, 16 or 24 |

## Checking the implementations

```
cd reference
uv run pytest                                      # or, in a virtual environment: pip install pytest; python3 -m pytest
cd ../fast
make                                               # GCC or Clang
build/lc-vectors | cmp - ../vectors/demo-v1.json   # prints nothing when the vectors match
```

## Keys

A key is a grid that runs through at least 6,000 distinct generations and passes the other vetting tests
(`SPEC.md` §9). Keys are found by random search: in one mining run, about one random grid in 43 million qualified. The
pool of mined keys isn't published, since a published key must never be used. The test vectors use a burned demo key
(`SPEC.md` Appendix B).

## License

The code is under the MIT license (`LICENSE`). The specification, the other Markdown documents, the test vectors
(`vectors/`) and `challenge/challenge.json` are under CC BY 4.0 (`LICENSE-docs`).

## Contact

Open an issue on this repository: attacks, challenge claims and questions are all welcome there.
