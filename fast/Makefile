# Builds the Life Cipher's C library and its two tools with GCC or Clang: make   (or: make CC=clang)
# A compiler that doesn't accept -march=native builds the portable code everywhere with: make NATIVE=
CFLAGS ?= -std=c11 -O3 -Wall -Wextra -fPIC
NATIVE ?= -march=native
BUILD = build

all: $(BUILD)/liblifecipher.so $(BUILD)/portable/liblifecipher.so $(BUILD)/lc-vectors $(BUILD)/lc-bench

# For this machine: with AVX2, runs of Mix rounds go through the vector kernel.
$(BUILD)/liblifecipher.so: lifecipher.c lifecipher.h | $(BUILD)
	$(CC) $(CFLAGS) $(NATIVE) -shared -o $@ lifecipher.c

# Without -march=native: the portable code, unless the compiler enables AVX2 by default. It gives the same results.
$(BUILD)/portable/liblifecipher.so: lifecipher.c lifecipher.h | $(BUILD)
	mkdir -p $(BUILD)/portable
	$(CC) $(CFLAGS) -shared -o $@ lifecipher.c

$(BUILD)/lc-vectors: lc_vectors.c sha256.c sha256.h lifecipher.c lifecipher.h | $(BUILD)
	$(CC) $(CFLAGS) $(NATIVE) -o $@ lc_vectors.c sha256.c lifecipher.c

$(BUILD)/lc-bench: lc_bench.c lifecipher.c lifecipher.h | $(BUILD)
	$(CC) $(CFLAGS) $(NATIVE) -o $@ lc_bench.c lifecipher.c

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)

.PHONY: all clean
