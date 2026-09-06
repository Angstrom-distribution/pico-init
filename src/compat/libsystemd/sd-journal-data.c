/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Per-entry field access (get_data/enumerate_data), match filtering
 * (add_match and friends), and the two ring-wide dedup scans
 * (enumerate_unique, enumerate_fields). All real, all built directly on
 * logd-read.h's LogdEntry/LogdReadField views -- nothing here touches a
 * binary journal file.
 */

#include "sd-journal-internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* --- data threshold --- */

int sd_journal_set_data_threshold(sd_journal *j, size_t sz) {
        if (!j)
                return -EINVAL;

        j->data_threshold = sz;
        return 0;
}

int sd_journal_get_data_threshold(sd_journal *j, size_t *sz) {
        if (!j || !sz)
                return -EINVAL;

        *sz = j->data_threshold;
        return 0;
}

/* Assembles "NAME=value" into *scratch (growing it as needed), applying
 * `threshold` (0 = unlimited) the same way for get_data/enumerate_data and
 * enumerate_unique: never truncate into the "NAME=" prefix itself. */
static int assemble_field(void **scratch, size_t *scratch_cap, size_t threshold, const void *name, size_t name_len,
                           const void *value, size_t value_len, const void **ret_data, size_t *ret_size) {
        size_t total = name_len + 1 + value_len;
        size_t out_len = total;
        int r;

        if (threshold > 0) {
                size_t floor = name_len + 1;
                size_t cap = threshold > floor ? threshold : floor;

                if (out_len > cap)
                        out_len = cap;
        }

        r = sd_journal_scratch_grow(scratch, scratch_cap, total > 0 ? total : 1);
        if (r < 0)
                return r;

        memcpy(*scratch, name, name_len);
        ((char *) *scratch)[name_len] = '=';
        if (value_len > 0)
                memcpy((char *) *scratch + name_len + 1, value, value_len);

        *ret_data = *scratch;
        *ret_size = out_len;
        return 0;
}

int sd_journal_get_data(sd_journal *j, const char *field, const void **ret_data, size_t *ret_size) {
        const LogdEntry *e;
        const LogdReadField *f;
        size_t field_len;

        if (!j || !field || !ret_data || !ret_size)
                return -EINVAL;

        e = sd_journal_current_entry(j);
        if (!e)
                return -EADDRNOTAVAIL;

        field_len = strlen(field);
        if (!sd_journal_field_name_valid(field, field_len))
                return -EINVAL;

        f = logd_entry_field(e, field);
        if (!f)
                return -ENOENT;

        return assemble_field(&j->data_scratch, &j->data_scratch_cap, j->data_threshold, field, field_len, f->value,
                               f->value_len, ret_data, ret_size);
}

/* Writer-private address fields (logd-write.h): not returned by enumerate,
 * same as upstream's own __REALTIME_TIMESTAMP/__MONOTONIC_TIMESTAMP
 * exclusion from SD_JOURNAL_FOREACH_DATA. */
static bool is_double_underscore(const char *name, size_t len) {
        return len >= 2 && name[0] == '_' && name[1] == '_';
}

int sd_journal_enumerate_data(sd_journal *j, const void **ret_data, size_t *ret_size) {
        const LogdEntry *e;

        if (!j || !ret_data || !ret_size)
                return -EINVAL;

        e = sd_journal_current_entry(j);
        if (!e)
                return -EADDRNOTAVAIL;

        while (j->data_idx < e->n_fields) {
                const LogdReadField *f = &e->fields[j->data_idx];
                int r;

                j->data_idx++;

                if (is_double_underscore(f->name, f->name_len))
                        continue;

                r = assemble_field(&j->data_scratch, &j->data_scratch_cap, j->data_threshold, f->name, f->name_len,
                                    f->value, f->value_len, ret_data, ret_size);
                return r < 0 ? r : 1;
        }

        return 0;
}

int sd_journal_enumerate_available_data(sd_journal *j, const void **ret_data, size_t *ret_size) {
        return sd_journal_enumerate_data(j, ret_data, ret_size);
}

void sd_journal_restart_data(sd_journal *j) {
        if (!j)
                return;

        j->data_idx = 0;
}

/* --- matches --- */

int sd_journal_add_match(sd_journal *j, const void *data, size_t size) {
        const char *eq;
        SdJournalMatch *new_matches;
        void *copy;

        if (!j || !data || size == 0)
                return -EINVAL;

        eq = memchr(data, '=', size);
        if (!eq || eq == data)
                return -EINVAL;

        if (!sd_journal_field_name_valid((const char *) data, (size_t) (eq - (const char *) data)))
                return -EINVAL;

        copy = malloc(size);
        if (!copy)
                return -ENOMEM;
        memcpy(copy, data, size);

        new_matches = realloc(j->matches, (j->n_matches + 1) * sizeof(*new_matches));
        if (!new_matches) {
                free(copy);
                return -ENOMEM;
        }
        j->matches = new_matches;

        j->matches[j->n_matches].data = copy;
        j->matches[j->n_matches].size = size;
        j->matches[j->n_matches].name_len = (size_t) (eq - (const char *) data);
        j->n_matches++;

        return 0;
}

int sd_journal_add_disjunction(sd_journal *j) {
        (void) j;
        return -EOPNOTSUPP; /* v1 filter is flat AND-of-ORs; no OR-of-groups tree */
}

int sd_journal_add_conjunction(sd_journal *j) {
        (void) j;
        return -EOPNOTSUPP;
}

void sd_journal_flush_matches(sd_journal *j) {
        if (!j)
                return;

        for (size_t i = 0; i < j->n_matches; i++)
                free(j->matches[i].data);
        free(j->matches);
        j->matches = NULL;
        j->n_matches = 0;
}

/* --- unique --- */

static void reset_unique_iterator(sd_journal *j) {
        j->unique_scan_idx = 0;
        sd_journal_seen_clear(&j->unique_seen);
}

int sd_journal_query_unique(sd_journal *j, const char *field) {
        size_t field_len;
        char *dup;

        if (!j || !field)
                return -EINVAL;

        field_len = strlen(field);
        if (!sd_journal_field_name_valid(field, field_len))
                return -EINVAL;

        dup = strdup(field);
        if (!dup)
                return -ENOMEM;

        free(j->unique_field);
        j->unique_field = dup;
        reset_unique_iterator(j);

        return 0;
}

int sd_journal_enumerate_unique(sd_journal *j, const void **ret_data, size_t *ret_size) {
        size_t n, field_len;

        if (!j || !ret_data || !ret_size)
                return -EINVAL;
        if (!j->unique_field)
                return -ENODATA;

        n = logd_ring_n_entries(j->ring);
        field_len = strlen(j->unique_field);

        while (j->unique_scan_idx < n) {
                const LogdEntry *e = logd_ring_entry(j->ring, j->unique_scan_idx);
                const LogdReadField *f;
                int r;

                j->unique_scan_idx++;

                f = logd_entry_field(e, j->unique_field);
                if (!f)
                        continue;

                if (sd_journal_seen_contains(&j->unique_seen, f->value, f->value_len))
                        continue;

                r = sd_journal_seen_add(&j->unique_seen, f->value, f->value_len);
                if (r < 0)
                        return r;

                r = assemble_field(&j->unique_scratch, &j->unique_scratch_cap, j->data_threshold, j->unique_field,
                                    field_len, f->value, f->value_len, ret_data, ret_size);
                return r < 0 ? r : 1;
        }

        return 0;
}

int sd_journal_enumerate_available_unique(sd_journal *j, const void **ret_data, size_t *ret_size) {
        return sd_journal_enumerate_unique(j, ret_data, ret_size);
}

void sd_journal_restart_unique(sd_journal *j) {
        if (!j)
                return;

        reset_unique_iterator(j);
}

/* --- fields --- */

int sd_journal_enumerate_fields(sd_journal *j, const char **ret) {
        size_t n;

        if (!j || !ret)
                return -EINVAL;

        n = logd_ring_n_entries(j->ring);

        while (j->fields_scan_entry_idx < n) {
                const LogdEntry *e = logd_ring_entry(j->ring, j->fields_scan_entry_idx);

                while (j->fields_scan_field_idx < e->n_fields) {
                        const LogdReadField *f = &e->fields[j->fields_scan_field_idx];
                        int r;

                        j->fields_scan_field_idx++;

                        if (sd_journal_seen_contains(&j->fields_seen, f->name, f->name_len))
                                continue;

                        r = sd_journal_seen_add(&j->fields_seen, f->name, f->name_len);
                        if (r < 0)
                                return r;

                        r = sd_journal_scratch_grow((void **) &j->fields_scratch, &j->fields_scratch_cap,
                                                     f->name_len + 1);
                        if (r < 0)
                                return r;
                        memcpy(j->fields_scratch, f->name, f->name_len);
                        j->fields_scratch[f->name_len] = '\0';

                        *ret = j->fields_scratch;
                        return 1;
                }

                j->fields_scan_entry_idx++;
                j->fields_scan_field_idx = 0;
        }

        return 0;
}

void sd_journal_restart_fields(sd_journal *j) {
        if (!j)
                return;

        j->fields_scan_entry_idx = 0;
        j->fields_scan_field_idx = 0;
        sd_journal_seen_clear(&j->fields_seen);
}
