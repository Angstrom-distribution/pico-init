/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The record-parsing half of logd_kmsg_read(), split out so test-logd-kmsg.c
 * can drive it with a synthetic buffer. Not a public interface.
 */

#pragma once

#include <stddef.h>

/*
 * Parses one kmsg record in `buf` (one read() off /dev/kmsg, format in
 * logd-kmsg.c). `buf[n]` must be a valid NUL byte.
 *
 * Returns 1 with *ret_line (malloc'd, the caller frees it) / *ret_len /
 * *ret_priority set, or 0 (nothing set) for a record with no ';', which is
 * skipped.
 */
int logd_kmsg_parse_record(const char *buf, size_t n, char **ret_line, size_t *ret_len, int *ret_priority);
