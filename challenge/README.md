# The Life Cipher challenge

Recover the key of a reduced-round Life Cipher.

The Life Cipher is an experimental authenticated cipher built on Conway's Game of Life (`../SPEC.md`, draft 0.4). Its recommended parameter set runs R = 24 rounds per block. This challenge offers the same cipher at R = 4, 8, 12 and 16 as well, so attacks can be measured by how many rounds they break. Our own attacks are in `../SPEC.md` §11. Nobody outside the project has analyzed the cipher yet.

## The tiers

| Tier | Rounds per block | Init and finish rounds | Data |
|---|---|---|---|
| R = 4 | 4 | 8 | `life-challenge-R4.bin` |
| R = 8 | 8 | 16 | `life-challenge-R8.bin` |
| R = 12 | 12 | 24 | `life-challenge-R12.bin` |
| R = 16 | 16 | 32 | `life-challenge-R16.bin` |
| R = 24 | 24 | 48 | `life-challenge-R24.bin` (the recommended set) |

Every tier uses T = 6,000, S = 16, k = 30 and algorithm version 1, with its own key. `challenge.json` lists the parameters, each data file's SHA-256, and each tier's key commitment.

- **The keys** are real mined keys that pass vetting (`../SPEC.md` §9): at least 6,000 distinct generations, a complexity score of at least 10,000, and 64 to 960 live cells. The five keys are unrelated to each other.
- **The data:** each file holds 1,024 messages under that tier's key. Each message has a random IV, no associated data, and 1,024 blocks of zero bytes as plaintext, so its ciphertext is the keystream itself: 2^20 blocks (128 MiB) of known plaintext per tier. Each message is stored as the IV (128 bytes), then the ciphertext (131,072 bytes), then the tag (16 bytes).
- **Where the files are:** on Zenodo, https://doi.org/10.5281/zenodo.24020075, with `challenge.json`.

## Winning

**Recover the key of any tier.** `verify.py` checks a claim with the reference implementation:

```
python3 challenge/verify.py 24 "6B3028A8 DB46016A …" life-challenge-R24.bin
```

The key must reproduce the tier's first message from its IV. Open an issue on this repository with the key and a description of the attack: the issue's timestamp settles who was first. The first correct key for each tier is credited below, with the attack.

Distinguishers and partial results are welcome too, with a write-up. You're free to publish any attack.

## The commitments

Each tier's commitment is SHA-256(salt ‖ key): the 32-byte salt, then the key's 128 bytes (`../SPEC.md` §2.2). Two years after the challenge opens on 10 November 2026, on 10 November 2028, the keys and salts will be published here, so anyone can check that the keys didn't change. From then on, those keys are burned.

## What we know

From `../SPEC.md` §11:
- **Cell persistence,** a known-plaintext distinguisher, would show up with this much data at R = 2. At R = 4 its correlation is about 8 × 10⁻⁶, and telling that from chance at four standard deviations takes about 2^28 blocks, hundreds of times what's here.
- **The chosen-IV differential** needs chosen IVs, which this data doesn't offer.
- **No key-recovery attack** on any number of rounds is known to us.

So even the R = 4 tier is past every attack we know.

## Solved

None yet.
