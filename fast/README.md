# The C implementation

A C11 implementation of the Life Cipher (`../SPEC.md`, draft 0.4, algorithm version 1), designed to run in constant time (SPEC.md §14). Its AVX2 build and its portable build give the same results.

## Building

With GCC or Clang (C11 with GNU extensions) on a POSIX system, in this folder:

```
make                 # or: make CC=clang
```

It writes `build/`:

| File | What it is |
|---|---|
| `liblifecipher.so` | The library, built for this machine (`-march=native`). With AVX2, runs of Mix rounds go through a vector kernel. |
| `portable/liblifecipher.so` | The same library without `-march=native`, which leaves out AVX2 unless the compiler enables it by default |
| `lc-vectors` | Writes the test vectors from the C code alone |
| `lc-bench` | Measures key setup and encryption speed |

A compiler that doesn't accept `-march=native` builds the portable code everywhere with `make NATIVE=`.

## Checking it against the test vectors

```
build/lc-vectors | cmp - ../vectors/demo-v1.json
build/lc-vectors recommended | cmp - ../vectors/recommended-v1.json
build/lc-vectors key-check | cmp - ../vectors/key-check-v1.json
```

Each prints nothing when the output equals the published file byte for byte.

## Speed

`build/lc-bench [R] [seconds] [k]` measures encryption speed at R rounds and the time of a key setup at k. The defaults are the demo set's, R = 16 and k = 4. Encryption speed doesn't depend on k.

On one performance core of an Intel Core i5-1240P, with AVX2, encryption runs at about 55 MB/s at R = 24 and 82 MB/s at R = 16. Key setup for the recommended set (`build/lc-bench 24 2 30`) takes about 112 ms.

## Using the library

```c
lc_params p;
lc_params_default(&p);                            /* the demo set; p.k = 30 and p.R = 24 give the recommended set */
lc_key *k = lc_key_setup(&p, key);                /* NULL if the key fails the key check (SPEC.md §6.1) */
lc_encrypt(k, iv, ad, adlen, pt, len, ct, tag);
if (lc_decrypt(k, iv, ad, adlen, ct, len, tag, pt) != 0) {    /* -1: the tag didn't match, and pt is erased */
    /* reject the message */
}
lc_key_free(k);
```

- Keys must have passed vetting (SPEC.md §9).
- Each key may absorb at most 2^48 blocks (SPEC.md §4.4). The library doesn't count them.
- T can be at most 65,535 in this implementation.
- R below 16 needs `p.measurement = 1`. It's for analysis only, such as the challenge's reduced-round tiers (`../challenge/`).

## Source files

| File | What it is |
|---|---|
| `lifecipher.h` | The interface: parameters, key setup, encryption and decryption, an endless stream for statistical tests, and the building blocks for white-box tests |
| `lifecipher.c` | The cipher. The portable code follows the spec's sections in order. With AVX2, runs of Mix rounds go through a kernel that keeps A and B in vector registers. |
| `lc_vectors.c`, `lc_bench.c` | The two tools |
| `sha256.c`, `sha256.h` | SHA-256, for the digests of H and W in the test vectors |

## Constant time (SPEC.md §14)

No secret decides a branch or a memory address:
- **Life** is bit-parallel on row words.
- **The table read** touches all 16 entries of the public group and keeps one with masks.
- **The shift** moves rows in five steps of 1, 2, 4, 8 and 16 rows, each kept or dropped with a mask. Columns move by rotation.
- **The shuffles** are a bitonic sorting network that carries each generation along with its tag, so W is built without reading G at a secret position.
- **The key check and the tag comparison** run in full every time. Decryption erases the plaintext when the tag doesn't match.

A dudect-style timing test checked the AVX2 build, and Valgrind secret tracking checked both builds (`../HARNESS.md`, K1 and K2). Key setup erases G, H, the setup stream and the tags, and decryption erases the plaintext when the tag doesn't match. Copies of message state on the stack aren't scrubbed, though SPEC.md §14 recommends it. The selector's 32-bit multiplication must take the same time for any operands, which holds on current x86 and 64-bit ARM cores, and not on some older or embedded ones.

## Test-only switches

`lc_params` also has switches that build the variants and most of the flawed controls the tests measured (`../HARNESS.md`). Leave them all 0: that's the cipher as specified. Some weaken it on purpose. For example, `fast_setup` isn't constant time, and `no_key_check` accepts keys that fail the key check.
