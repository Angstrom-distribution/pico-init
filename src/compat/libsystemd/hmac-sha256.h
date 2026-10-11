/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * HMAC-SHA256 (RFC 2104, instantiated with the SHA-256 in sha256.h). The
 * one caller is sd_id128_get_app_specific() in sd-id128.c.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

void hmac_sha256(
                const void *key,
                size_t key_len,
                const void *input,
                size_t input_len,
                uint8_t res[SHA256_DIGEST_SIZE]);
