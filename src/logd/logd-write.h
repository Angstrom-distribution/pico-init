/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The export-format writer and the /run ring.
 *
 * Not lifted from systemd; upstream was the reference:
 *   - docs/JOURNAL_EXPORT_FORMATS.md (systemd v261.2) for the wire format:
 *     field lines, the binary-safe FIELD\n<len><data>\n encoding, the
 *     blank-line entry separator.
 *   - src/shared/journal-importer.c for what a real reader accepts. The
 *     tests round-trip against it. systemd-journal-remote drops an entry
 *     with a missing/zero __REALTIME_TIMESTAMP or a missing/all-zero
 *     _BOOT_ID (EBADMSG), and accepts one without __MONOTONIC_TIMESTAMP
 *     with a silently wrong 0; all three are therefore always emitted.
 *
 * LogdField/logd_writer_append() assemble one entry; both clocks and
 * _BOOT_ID are the writer's job, not each caller's.
 * logd_writer_open()/_set_runtime_dir()/_set_max_bytes() own the two-file
 * /run ring, rotating at half the cap so a rotated file is always the
 * complete former active file.
 */

#pragma once

#include <stddef.h>

typedef struct LogdWriter LogdWriter;

/*
 * One export-format field: a name and a byte string value, not a
 * NUL-terminated C string -- callers hand this attacker-
 * influenceable bytes (a service's stdout, a syslog datagram) that may
 * contain an embedded NUL or any other byte, and logd_writer_append() must
 * never assume otherwise. It picks the plain "NAME=value\n" form or the
 * binary-safe "NAME\n<8-byte-LE-length><data>\n" form per field
 * automatically, keyed off whether `value` is clean non-control UTF-8 with
 * no embedded newline -- exactly the distinction JOURNAL_EXPORT_FORMATS.md
 * draws and the real importer's line/data state machine depends on.
 */
typedef struct LogdField {
        const char *name;
        const void *value;
        size_t value_len;
} LogdField;

int logd_writer_new(LogdWriter **ret);
LogdWriter *logd_writer_free(LogdWriter *w);

/*
 * Settable ring location and cap, so a test needs neither root nor a real
 * /run. Both must be called, if at all,
 * before logd_writer_open(); changing the directory after opening is
 * refused rather than silently orphaning the live fd.
 */
int logd_writer_set_runtime_dir(LogdWriter *w, const char *dir);
int logd_writer_set_max_bytes(LogdWriter *w, size_t max_bytes);

/*
 * Override the boot ID logd_writer_open() would otherwise read from
 * /proc/sys/kernel/random/boot_id -- for golden-byte fixtures that need a
 * fixed, reproducible value. `id` is exactly 32 lowercase hex characters, no
 * dashes: the canonical form _BOOT_ID= itself uses. Must be called before
 * logd_writer_open(), which never overwrites an explicitly set boot ID.
 */
int logd_writer_set_boot_id(LogdWriter *w, const char *id);

/*
 * Create the ring directory if missing and open (or resume, if one already
 * has content -- a restart within the same boot must not lose it) the
 * active file. Idempotent: a second call is a no-op success.
 */
int logd_writer_open(LogdWriter *w);

/*
 * Assemble one entry -- writer-generated __REALTIME_TIMESTAMP,
 * __MONOTONIC_TIMESTAMP and _BOOT_ID first, then every field in `fields` in
 * the order given, then the blank-line separator -- and append it to the
 * ring in a single write(), rotating first if the active file has already
 * reached half the configured cap. `fields`/`n_fields` may be NULL/0 for an
 * entry carrying only the three writer-generated fields. 0 or -errno;
 * -EMSGSIZE if the assembled entry would alone exceed the configured cap,
 * -EINVAL for a field name that fails journal_field_valid()'s own rules
 * (uppercase A-Z/0-9/_, <=64 chars, not starting with a digit); the
 * field list is checked before anything is written.
 */
int logd_writer_append(LogdWriter *w, const LogdField *fields, size_t n_fields);

/*
 * The two ring file paths as currently configured, each a freshly allocated
 * string the caller frees -- for tests and picolog. Valid before logd_writer_open() too: the paths are a
 * pure function of the configured runtime_dir, not of what's actually on disk.
 */
int logd_writer_active_path(LogdWriter *w, char **ret);
int logd_writer_rotated_path(LogdWriter *w, char **ret);
