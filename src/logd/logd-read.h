/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The ring reader, shared by picolog and picoctl (per-unit log tail). It
 * formats nothing: output is picolog.c's job.
 *
 * Not lifted from systemd; the reference for the format this reads back is
 * docs/JOURNAL_EXPORT_FORMATS.md and src/shared/journal-importer.c.
 *
 * LogdReadField is distinct from LogdField (logd-write.h), which is the
 * input-shaped struct for appending an entry.
 *
 * Every LogdReadField/LogdEntry below is a view into a buffer held by the
 * owning object (LogdRing, or one follow batch), and is not NUL-terminated
 * (a value may contain an embedded NUL). Compare with the explicit length,
 * never strcmp/strlen on `value`.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct LogdReadField {
        const char *name;
        size_t name_len;
        const void *value;
        size_t value_len;
        bool binary; /* true if this field was framed with the binary-safe encoding on disk */
} LogdReadField;

typedef struct LogdEntry {
        LogdReadField *fields; /* owned by the entry (small per-entry allocation); values alias the ring's buffer */
        size_t n_fields;
        const void *raw; /* this entry's exact on-disk bytes, including its trailing blank-line separator --
                          * what -o export re-emits verbatim rather than re-serializing from parsed fields */
        size_t raw_len;
} LogdEntry;

/* NULL if `e` has no field named `name` (a plain NUL-terminated C string --
 * field *names* are always plain ASCII by construction, only values may be
 * arbitrary bytes). The first match wins if a name somehow repeats. */
const LogdReadField *logd_entry_field(const LogdEntry *e, const char *name);

/* True if field `f` is non-NULL and its value is byte-for-byte equal to the
 * NUL-terminated string `s`. */
bool logd_field_equals(const LogdReadField *f, const char *s);

/* logd_entry_field(e, "_SYSTEMD_UNIT") equals `unit`; `unit` == NULL always
 * matches (no filter). A bare `unit` with no suffix pico-init has a unit
 * type for (.service/.socket/.target) is mangled to `unit`.service first,
 * the same default unit_name_mangle() applies for systemctl/journalctl. */
bool logd_entry_matches_unit(const LogdEntry *e, const char *unit);

/* logd_entry_field(e, "PRIORITY") parses as a syslog priority <=
 * `max_priority` (lower number is more severe, journalctl's own -p sense).
 * An entry with no PRIORITY field, or one that fails to parse as a plain
 * small integer, does not match -- absence is not "unbounded severity". */
bool logd_entry_matches_priority(const LogdEntry *e, int max_priority);

/* logd_entry_field(e, "_TRANSPORT") equals "kernel". */
bool logd_entry_is_kernel(const LogdEntry *e);

typedef struct LogdRing LogdRing;

/*
 * Read every complete entry currently in rotated-then-active ring files
 * under `runtime_dir`, oldest first (rotated file's content, then the
 * active file's). A missing ring -- nothing written yet -- is not an
 * error and yields zero entries. A trailing incomplete entry (a crash mid-append) is
 * dropped. 0 or -errno.
 */
int logd_ring_read(const char *runtime_dir, LogdRing **ret);
LogdRing *logd_ring_free(LogdRing *r);

/*
 * As logd_ring_read(), but for explicit export-format files, read in the
 * order given. Unlike the ring's own two files, a missing file is an error.
 */
int logd_ring_read_files(const char * const *paths, size_t n_paths, LogdRing **ret);

size_t logd_ring_n_entries(const LogdRing *r);
const LogdEntry *logd_ring_entry(const LogdRing *r, size_t index); /* index must be < logd_ring_n_entries() */

/*
 * A full ring read for picoctl's status verb, filtered to
 * _SYSTEMD_UNIT == `unit` (NULL for no unit filter), keeping at most the
 * last `max_entries` of those (0 for unlimited). 0 or -errno.
 */
int logd_ring_read_filtered(const char *runtime_dir, const char *unit, size_t max_entries, LogdRing **ret);

typedef struct LogdFollow LogdFollow;

/*
 * Start following the active ring file under `runtime_dir` from its
 * current end -- no historical entries; a caller wanting `-n` history
 * first does an ordinary logd_ring_read() before this. 0 or -errno.
 */
int logd_follow_new(const char *runtime_dir, LogdFollow **ret);
LogdFollow *logd_follow_free(LogdFollow *f);

/*
 * One non-blocking poll: read whatever complete new entries have appeared
 * since the last call (or since logd_follow_new(), on the first one), and
 * transparently reopen the active file if rotation replaced it underneath
 * (detected by (st_dev, st_ino) changing at the same path). A still-
 * incomplete trailing record is left unread and is picked up whole on a
 * later call once it completes -- it is never delivered partial.
 *
 * *ret is NULL (not an error) when nothing new has arrived since the last
 * call -- callers loop this on a timer/sleep. When non-NULL, *ret is an
 * ordinary LogdRing (same three accessors above, same logd_ring_free())
 * holding just this poll's newly-completed entries, in order, with its own
 * buffer independent of both `f`'s internal state and any earlier poll's
 * result -- freeing one never invalidates another still in the caller's
 * hands. 0 or -errno.
 */
int logd_follow_poll(LogdFollow *f, LogdRing **ret);
