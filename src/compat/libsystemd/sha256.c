/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * SHA-256 per FIPS 180-4: 64-byte blocks, big-endian words throughout.
 * Checked against the FIPS 180-4 one-block and two-block test vectors in
 * test-sd-id128.c (via hmac_sha256(), its only caller).
 */

#include "sha256.h"

#include <string.h>

/* FIPS 180-4 4.2.2: first 32 bits of the fractional part of the cube root
 * of each of the first 64 primes. */
static const uint32_t sha256_k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t rotr32(uint32_t x, unsigned n) {
        return (x >> n) | (x << (32 - n));
}

static void sha256_compress(struct sha256_ctx *ctx, const uint8_t block[SHA256_BLOCK_SIZE]) {
        uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, h;

        for (unsigned i = 0; i < 16; i++)
                w[i] = ((uint32_t) block[i * 4] << 24) | ((uint32_t) block[i * 4 + 1] << 16) |
                                ((uint32_t) block[i * 4 + 2] << 8) | (uint32_t) block[i * 4 + 3];

        for (unsigned i = 16; i < 64; i++) {
                uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);

                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        a = ctx->state[0];
        b = ctx->state[1];
        c = ctx->state[2];
        d = ctx->state[3];
        e = ctx->state[4];
        f = ctx->state[5];
        g = ctx->state[6];
        h = ctx->state[7];

        for (unsigned i = 0; i < 64; i++) {
                uint32_t big_s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t temp1 = h + big_s1 + ch + sha256_k[i] + w[i];
                uint32_t big_s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = big_s0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
        }

        ctx->state[0] += a;
        ctx->state[1] += b;
        ctx->state[2] += c;
        ctx->state[3] += d;
        ctx->state[4] += e;
        ctx->state[5] += f;
        ctx->state[6] += g;
        ctx->state[7] += h;
}

void sha256_init(struct sha256_ctx *ctx) {
        /* FIPS 180-4 5.3.3: the first 32 bits of the fractional part of the
         * square root of each of the first eight primes. */
        ctx->state[0] = 0x6a09e667;
        ctx->state[1] = 0xbb67ae85;
        ctx->state[2] = 0x3c6ef372;
        ctx->state[3] = 0xa54ff53a;
        ctx->state[4] = 0x510e527f;
        ctx->state[5] = 0x9b05688c;
        ctx->state[6] = 0x1f83d9ab;
        ctx->state[7] = 0x5be0cd19;

        ctx->total_len = 0;
        ctx->buf_len = 0;
}

void sha256_update(struct sha256_ctx *ctx, const void *data, size_t len) {
        const uint8_t *p = data;

        ctx->total_len += len;

        while (len > 0) {
                size_t n = SHA256_BLOCK_SIZE - ctx->buf_len;

                if (n > len)
                        n = len;

                memcpy(ctx->buf + ctx->buf_len, p, n);
                ctx->buf_len += n;
                p += n;
                len -= n;

                if (ctx->buf_len == SHA256_BLOCK_SIZE) {
                        sha256_compress(ctx, ctx->buf);
                        ctx->buf_len = 0;
                }
        }
}

void sha256_final(struct sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]) {
        uint64_t bit_len = ctx->total_len * 8;

        /* FIPS 180-4 5.1.1: append a single '1' bit, then zeros, then the
         * 64-bit big-endian bit length, padding out to a block boundary --
         * two blocks' worth if the '1' bit doesn't leave room for the
         * length in the current one. */
        ctx->buf[ctx->buf_len++] = 0x80;

        if (ctx->buf_len > SHA256_BLOCK_SIZE - 8) {
                memset(ctx->buf + ctx->buf_len, 0, SHA256_BLOCK_SIZE - ctx->buf_len);
                sha256_compress(ctx, ctx->buf);
                ctx->buf_len = 0;
        }

        memset(ctx->buf + ctx->buf_len, 0, SHA256_BLOCK_SIZE - 8 - ctx->buf_len);

        for (unsigned i = 0; i < 8; i++)
                ctx->buf[SHA256_BLOCK_SIZE - 8 + i] = (uint8_t) (bit_len >> (56 - 8 * i));

        sha256_compress(ctx, ctx->buf);

        for (unsigned i = 0; i < 8; i++) {
                digest[i * 4] = (uint8_t) (ctx->state[i] >> 24);
                digest[i * 4 + 1] = (uint8_t) (ctx->state[i] >> 16);
                digest[i * 4 + 2] = (uint8_t) (ctx->state[i] >> 8);
                digest[i * 4 + 3] = (uint8_t) ctx->state[i];
        }
}
