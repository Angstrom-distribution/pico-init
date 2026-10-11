/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * A small, self-contained SHA-256 (FIPS 180-4). hmac-sha256.c is its only
 * caller (for sd_id128_get_app_specific()), so it has no streaming wrappers
 * and no HMAC of its own.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

struct sha256_ctx {
        uint32_t state[8];
        uint64_t total_len;
        uint8_t buf[SHA256_BLOCK_SIZE];
        size_t buf_len;
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const void *data, size_t len);
void sha256_final(struct sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
