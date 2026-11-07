"""Checks a claimed key for one tier of the Life Cipher challenge, with the reference implementation: the key must
reproduce the tier's first message, ciphertext and tag, from its IV and its all-zero plaintext.

    python3 challenge/verify.py R KEY DATAFILE

R is the tier (4, 8, 12, 16 or 24). KEY is the key as 256 hex digits, its 32 row words (SPEC.md §2.2); spaces are
fine. DATAFILE is the tier's data file. Key setup in Python takes from about half a minute (R = 4) to a few minutes
(R = 24).
"""
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "reference"))
import lifecipher as lc  # noqa: E402

BLOCKS = 1024                                   # blocks per message (challenge.json)


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    R, key, data = int(sys.argv[1]), bytes.fromhex("".join(sys.argv[2].split())), pathlib.Path(sys.argv[3])
    with data.open("rb") as f:
        iv, ct, tag = f.read(128), f.read(128 * BLOCKS), f.read(16)
    params = lc.Params(T=6000, S=16, k=30, R=R, measurement=R < 16)
    try:
        ks = lc.key_setup(key, params)
    except lc.KeyCheckError:
        sys.exit("no: the key check refuses this key (SPEC.md §6.1), so it can't be the challenge's key")
    if lc.encrypt(ks, iv, b"", bytes(128 * BLOCKS)) == (ct, tag):
        print(f"yes: this key reproduces the first message of the R = {R} tier")
    else:
        sys.exit(f"no: this key doesn't reproduce the first message of the R = {R} tier")


if __name__ == "__main__":
    main()
