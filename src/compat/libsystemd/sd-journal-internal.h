/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Private state and helpers shared by the sd_journal_*() read-side files
 * (sd-journal-open.c/-navigate.c/-data.c/-info.c/-util.c). The write-side
 * files (sd-journal-send.c/-sendv.c/-stream.c) never open a journal object.
 *
 * `struct sd_journal` is a snapshot reader over logd's ring
 * (src/logd/logd-read.h): one logd_ring_read() at open, replaced wholesale
 * by sd_journal_process() when the ring files change.
 *
 * Position is a location plus, only while ON_ENTRY, an index into the
 * current ring. A pending boundary seek (realtime/monotonic/cursor) is
 * tracked separately from ON_ENTRY rather than as pos +/- 1: "the boundary
 * just before ring[i]" and "sitting on ring[i-1]" need different answers
 * from a following sd_journal_previous() (ring[i-1] vs ring[i-2]).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#include "../../logd/logd-read.h"
#include "sd-journal.h"

typedef enum SdJournalLoc {
        SD_J_BEFORE_HEAD,
        SD_J_ON_ENTRY,
        SD_J_AFTER_TAIL,
} SdJournalLoc;

/* One caller-supplied add_match() pair, stored verbatim (upstream compares
 * raw bytes, not a parsed value). */
typedef struct SdJournalMatch {
        void *data;
        size_t size;
        size_t name_len; /* bytes before '=', cached so filtering doesn't re-scan it every entry */
} SdJournalMatch;

/* Dedup set of previously-returned byte strings, for
 * sd_journal_enumerate_unique() values and sd_journal_enumerate_fields() names. */
typedef struct SdJournalSeenSet {
        void **items;
        size_t *lens;
        size_t n;
        size_t cap;
} SdJournalSeenSet;

struct sd_journal {
        LogdRing *ring;
        char *runtime_dir;
        int flags;

        SdJournalLoc loc;
        size_t pos; /* valid iff loc == SD_J_ON_ENTRY */

        /* Set by seek_realtime/monotonic_usec() and seek_cursor(); consumed
         * (and cleared) by the very next next()/previous() call. See the
         * file comment above for why this can't just be pos +/- 1. */
        bool seek_pending;
        size_t seek_boundary; /* next() wants first index >= this; previous() wants last index < this */

        SdJournalMatch *matches;
        size_t n_matches;

        size_t data_idx; /* sd_journal_enumerate_data()'s cursor into the current entry's fields */
        size_t data_threshold;
        void *data_scratch;
        size_t data_scratch_cap;

        char *unique_field;     /* set by sd_journal_query_unique(); NULL means "no query yet" */
        size_t unique_scan_idx; /* next ring entry to inspect */
        SdJournalSeenSet unique_seen;
        void *unique_scratch;
        size_t unique_scratch_cap;

        size_t fields_scan_entry_idx;
        size_t fields_scan_field_idx;
        SdJournalSeenSet fields_seen;
        char *fields_scratch;
        size_t fields_scratch_cap;

        int inotify_fd; /* -1 until sd_journal_get_fd() is first called */
        int inotify_wd;
        struct stat active_st; /* ring file identity at last (re)load, for sd_journal_process() */
        struct stat rotated_st;
        bool have_active_st;  /* active.export may not exist yet on an empty ring */
        bool have_rotated_st; /* rotated.export may not exist at all */
};

/* --- shared across the read-side files (sd-journal-util.c) --- */

/* Same rule as logd-write.c's field_name_valid() (static there, so
 * duplicated): 1-64 bytes, first byte not a digit, every byte in [A-Z0-9_]. */
bool journal_field_name_valid(const char *name, size_t len);

/* Reads /proc/sys/kernel/random/boot_id once per process and caches it. 0 or -errno. */
int journal_current_boot_id(sd_id128_t *ret);

/* 32 lowercase hex chars -> 16 bytes, the canonical _BOOT_ID= form
 * (logd-write.h's own rule). false on anything else. */
bool journal_parse_boot_id(const char *hex, size_t len, sd_id128_t *ret);

/* Grows *buf to at least `need` bytes via realloc(); *cap is updated in
 * place. 0 or -ENOMEM, in which case *buf and *cap are left as they were. */
int journal_scratch_grow(void **buf, size_t *cap, size_t need);

/* True if `e` survives every stored match (grouped OR-within-name,
 * AND-across-name; no matches at all always passes). */
bool journal_entry_matches(const struct sd_journal *j, const LogdEntry *e);

/* *ret_monotonic and *ret_realtime are the parsed __MONOTONIC_TIMESTAMP and
 * __REALTIME_TIMESTAMP of entry `e` (writer-guaranteed present, per
 * logd-write.h); -EBADMSG if either is missing or unparsable. */
int journal_entry_clocks(const LogdEntry *e, uint64_t *ret_monotonic, uint64_t *ret_realtime);

/* Add (data,len) to the dedup set if not already present. Returns 1 if it
 * was added (new), 0 if the set already had an equal entry, -ENOMEM on
 * allocation failure. */
int journal_seen_add(SdJournalSeenSet *set, const void *data, size_t len);
bool journal_seen_contains(const SdJournalSeenSet *set, const void *data, size_t len);
void journal_seen_clear(SdJournalSeenSet *set);

/* The current entry, or NULL if loc != SD_J_ON_ENTRY. */
const LogdEntry *journal_current_entry(const struct sd_journal *j);

/* Runtime dir lookup shared by sd_journal_open(): LOGD_RUNTIME_DIR the env
 * var, then the logd.h macro of the same name -- same order picolog.c uses.
 * Returns a freshly strdup'd string, or NULL on ENOMEM. */
char *journal_default_runtime_dir(void);

/* "<runtime_dir>/<name>" freshly allocated, or NULL on ENOMEM. */
char *journal_ring_path(const char *runtime_dir, const char *name);

/* stat()s both ring files under `runtime_dir`. A missing file is not an
 * error -- it sets *have_active or *have_rotated false and leaves that stat
 * buffer untouched -- any other stat() failure is -errno and aborts both. */
int journal_stat_ring(
                const char *runtime_dir,
                struct stat *active_st,
                bool *have_active,
                struct stat *rotated_st,
                bool *have_rotated);
