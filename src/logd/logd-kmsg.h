/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The /dev/kmsg reader, with whole-ring backfill (plan §3.2, milestone
 * J2). A fresh open() of /dev/kmsg positions at the start of the CURRENT
 * kernel ring, not at "now" (verified empirically in a real container,
 * not assumed): the first read()s return every message already in the
 * ring, oldest first, before live messages start arriving. That single
 * kernel property is the whole mechanism -- a logd started mid-boot
 * backfills the entire kernel ring for free, with no persistent state of
 * its own, simply by opening /dev/kmsg and draining it the same way it
 * drains any other input.
 *
 * Reference only (plan §3.5): src/journal/journald-kmsg.c for record
 * framing and overrun handling. Nothing is lifted; this is new code.
 */

#pragma once

#include <stddef.h>

#include "logd-write.h"

typedef struct LogdKmsg LogdKmsg;

/* Opens /dev/kmsg non-blocking. 0 or -errno (e.g. -ENOENT on a kernel/
 * container with no /dev/kmsg node at all, -EACCES without CAP_SYSLOG or
 * root -- both real, both simply mean "no kernel transport this run"). */
int logd_kmsg_new(LogdKmsg **ret);
LogdKmsg *logd_kmsg_free(LogdKmsg *k);

/* The fd, for registration in a caller's own epoll set. */
int logd_kmsg_fd(LogdKmsg *k);

/*
 * One non-blocking read() = one kmsg record (the kernel's own per-record
 * read contract). Parses the record's priority (the leading "<N>," --
 * only the severity, value & 7, is kept; pico's field set (plan §3.3)
 * carries no facility) and the message text up to the record's own first
 * embedded newline; any further "KEY=VALUE" dictionary continuation lines
 * are intentionally not surfaced -- pico's field set has nowhere to put
 * them.
 *
 * Returns 1 with *ret_line (a malloc'd, NUL-terminated buffer the caller
 * frees) / *ret_len / *ret_priority set; 0 (nothing set) at EAGAIN,
 * on a malformed record (skipped rather than surfaced), or after an
 * EPIPE overrun -- logged as a warning and treated as "nothing this
 * call", since the next read() resumes right after the gap on its own;
 * or -errno for a real I/O failure.
 */
int logd_kmsg_read(LogdKmsg *k, char **ret_line, size_t *ret_len, int *ret_priority);

/*
 * Drain every record currently available (non-blocking, stops at EAGAIN),
 * writing each one to `writer` with _TRANSPORT=kernel and the parsed
 * PRIORITY. The backfill-for-free property this file's header describes
 * is exactly this loop run to completion against a freshly opened
 * LogdKmsg -- the same read() contract serves both the initial backfill
 * and every live message after it, so no separate "backfill mode" exists
 * or is needed. Returns the number of records written, or -errno.
 */
int logd_kmsg_drain(LogdKmsg *k, LogdWriter *writer);
