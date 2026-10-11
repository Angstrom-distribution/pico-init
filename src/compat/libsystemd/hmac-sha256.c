/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * RFC 2104 HMAC, instantiated with sha256.h: a too-long key is hashed down
 * first, ipad/opad are XORed in per the RFC, and the result is
 * SHA256(okey || SHA256(ikey || input)). Tested against the RFC 4231
 * HMAC-SHA-256 vectors in test-sd-id128.c.
 */

#include "hmac-sha256.h"

#include <string.h>

#define HMAC_SHA256_BLOCK_SIZE SHA256_BLOCK_SIZE

void hmac_sha256(
                const void *key,
                size_t key_len,
                const void *input,
                size_t input_len,
                uint8_t res[SHA256_DIGEST_SIZE]) {
        uint8_t key_block[HMAC_SHA256_BLOCK_SIZE] = { 0 };
        uint8_t ipad[HMAC_SHA256_BLOCK_SIZE];
        uint8_t opad[HMAC_SHA256_BLOCK_SIZE];
        uint8_t inner_digest[SHA256_DIGEST_SIZE];
        struct sha256_ctx ctx;

        /* RFC 2104 step 1: a key longer than one block is replaced by its
         * own hash; a shorter one is zero-padded out to a full block. */
        if (key_len > HMAC_SHA256_BLOCK_SIZE) {
                sha256_init(&ctx);
                sha256_update(&ctx, key, key_len);
                sha256_final(&ctx, key_block);
        } else
                memcpy(key_block, key, key_len);

        for (size_t i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++) {
                ipad[i] = key_block[i] ^ 0x36;
                opad[i] = key_block[i] ^ 0x5c;
        }

        sha256_init(&ctx);
        sha256_update(&ctx, ipad, sizeof(ipad));
        sha256_update(&ctx, input, input_len);
        sha256_final(&ctx, inner_digest);

        sha256_init(&ctx);
        sha256_update(&ctx, opad, sizeof(opad));
        sha256_update(&ctx, inner_digest, sizeof(inner_digest));
        sha256_final(&ctx, res);
}
