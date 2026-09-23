/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The record-parsing half of logd_kmsg_read(), split out purely so
 * test-logd-kmsg.c can drive it with a synthetic buffer instead of a real
 * /dev/kmsg -- there is no way to make a plain fd hand back the exact bytes
 * (or the EPIPE-on-overrun errno) a real kernel ring does. Not a public
 * interface: nothing outside logd-kmsg.c and its test includes this.
 */

#pragma once

#include <stddef.h>

/*
 * Parses one kmsg record already sitting in `buf` (as one non-blocking
 * read() off /dev/kmsg hands back -- see logd_kmsg_read()'s comment for the
 * "<pri>,<seq>,<timestamp>,<flags>[,extra];message" format). `buf[n]` must
 * be a valid, NUL byte: the caller reads into a buffer sized `n + 1` and
 * terminates it there first, exactly as logd_kmsg_read() already did before
 * this split existed.
 *
 * Same return contract as logd_kmsg_read(): 1 with *ret_line (malloc'd, the
 * caller frees it) / *ret_len / *ret_priority set, or 0 (nothing set) for a
 * record with no ';' at all -- skipped rather than surfaced, exactly as
 * before.
 */
int logd_kmsg_parse_record(const char *buf, size_t n, char **ret_line, size_t *ret_len, int *ret_priority);
