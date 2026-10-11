/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The /dev/kmsg reader, with whole-ring backfill. A fresh open() of
 * /dev/kmsg positions at the start of the current kernel ring, not at
 * "now": the first read()s return every message already in the ring, oldest
 * first, before live messages arrive. A logd started mid-boot therefore
 * backfills the kernel ring just by opening /dev/kmsg and draining it.
 *
 * Not lifted from systemd; src/journal/journald-kmsg.c was the reference for
 * record framing and overrun handling.
 */

#pragma once

#include <stddef.h>

#include "logd-write.h"

typedef struct LogdKmsg LogdKmsg;

/* Opens /dev/kmsg non-blocking. 0 or -errno (-ENOENT without a /dev/kmsg
 * node, -EACCES without CAP_SYSLOG). */
int logd_kmsg_new(LogdKmsg **ret);
LogdKmsg *logd_kmsg_free(LogdKmsg *k);

/* The fd, for registration in a caller's own epoll set. */
int logd_kmsg_fd(LogdKmsg *k);

/*
 * One non-blocking read() = one kmsg record (the kernel's own per-record
 * read contract). Parses the record's priority (the leading "<N>," --
 * only the severity, value & 7, is kept; the log
 * entry has no facility field) and the message text up to the record's own first
 * embedded newline; any further "KEY=VALUE" dictionary continuation lines
 * are not surfaced.
 *
 * Returns 1 with *ret_line (a malloc'd, NUL-terminated buffer the caller
 * frees) / *ret_len / *ret_priority set; 0 (nothing set) at EAGAIN,
 * on a malformed record (skipped), or after an EPIPE overrun (logged as
 * a warning; the next read() resumes after the gap); or -errno for a real
 * I/O failure.
 */
int logd_kmsg_read(LogdKmsg *k, char **ret_line, size_t *ret_len, int *ret_priority);

/*
 * Drain every record currently available (non-blocking, stops at EAGAIN),
 * writing each one to `writer` with _TRANSPORT=kernel and the parsed
 * PRIORITY. Run against a freshly opened LogdKmsg this is the backfill;
 * the same loop serves live messages. Returns the number of records
 * written, or -errno.
 */
int logd_kmsg_drain(LogdKmsg *k, LogdWriter *writer);
