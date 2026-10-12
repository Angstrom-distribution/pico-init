/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The record-parsing half of logd_kmsg_read(), split out so test-logd-kmsg.c
 * can drive it with a synthetic buffer. Not a public interface.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "logd-kmsg.h"

/* Defined in logd-recv.c; also used for userspace-written kmsg records. */
bool logd_syslog_parse_tag(const char **p, const char **ident, size_t *ident_len);

/* Wraps an already open descriptor (one record per read()), so tests can
 * feed synthetic records. Takes ownership of fd. */
int logd_kmsg_new_from_fd(int fd, LogdKmsg **ret);

/* Sentinel for "no sequence number in the record". */
#define LOGD_KMSG_NO_SEQNUM UINT64_MAX

/*
 * Parses one kmsg record in `buf` (one read() off /dev/kmsg, format in
 * logd-kmsg.c). `buf[n]` must be a valid NUL byte. The kernel's "\xNN"
 * escapes in the message are decoded.
 *
 * Returns 1 with *ret_line (malloc'd, the caller frees it) / *ret_len /
 * *ret_priority (severity) set, or 0 (nothing set) for a record with no ';',
 * which is skipped. ret_facility and ret_seqnum may be NULL; *ret_seqnum is
 * LOGD_KMSG_NO_SEQNUM when the field does not parse.
 */
int logd_kmsg_parse_record(
                const char *buf,
                size_t n,
                char **ret_line,
                size_t *ret_len,
                int *ret_priority,
                int *ret_facility,
                uint64_t *ret_seqnum);
