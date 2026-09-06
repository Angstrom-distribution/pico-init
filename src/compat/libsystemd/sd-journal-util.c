/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Helpers shared by the read-side sd_journal_*() files. See
 * sd-journal-internal.h for what each one is for.
 */

/* asprintf() is a glibc extension; -std=gnu17 alone does not imply
 * _GNU_SOURCE (socket.c's own note, same reasoning here). */
#define _GNU_SOURCE

#include "sd-journal-internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../../logd/logd.h"

bool sd_journal_field_name_valid(const char *name, size_t len) {
        if (!name || len == 0 || len > 64)
                return false;

        if (name[0] >= '0' && name[0] <= '9')
                return false;

        for (size_t i = 0; i < len; i++) {
                char c = name[i];

                if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
                        return false;
        }

        return true;
}

bool sd_journal_parse_boot_id(const char *hex, size_t len, sd_id128_t *ret) {
        sd_id128_t id;

        if (len != 32)
                return false;

        for (size_t i = 0; i < 16; i++) {
                int hi = -1, lo = -1;
                char ch = hex[i * 2], cl = hex[i * 2 + 1];

                if (ch >= '0' && ch <= '9')
                        hi = ch - '0';
                else if (ch >= 'a' && ch <= 'f')
                        hi = 10 + (ch - 'a');
                if (cl >= '0' && cl <= '9')
                        lo = cl - '0';
                else if (cl >= 'a' && cl <= 'f')
                        lo = 10 + (cl - 'a');

                if (hi < 0 || lo < 0)
                        return false;

                id.bytes[i] = (uint8_t) ((hi << 4) | lo);
        }

        *ret = id;
        return true;
}

/* Cached process-wide: the kernel's boot ID cannot change under a running
 * process, so every caller sharing one cache is correct, not just cheap. */
static bool boot_id_cached = false;
static sd_id128_t boot_id_cache;

int sd_journal_current_boot_id(sd_id128_t *ret) {
        FILE *f;
        char buf[64];
        size_t n_hex = 0;
        char hex[33];

        if (boot_id_cached) {
                *ret = boot_id_cache;
                return 0;
        }

        f = fopen("/proc/sys/kernel/random/boot_id", "re");
        if (!f)
                return -errno;

        if (!fgets(buf, sizeof(buf), f)) {
                int r = ferror(f) ? -EIO : -ENODATA;

                fclose(f);
                return r;
        }
        fclose(f);

        /* /proc's form is dashed ("xxxxxxxx-xxxx-..."); strip the dashes down
         * to the canonical 32-hex form sd_journal_parse_boot_id() expects. */
        for (size_t i = 0; buf[i] != '\0' && n_hex < sizeof(hex) - 1; i++)
                if (buf[i] != '-')
                        hex[n_hex++] = buf[i];
        hex[n_hex] = '\0';

        if (!sd_journal_parse_boot_id(hex, n_hex, &boot_id_cache))
                return -EINVAL;

        boot_id_cached = true;
        *ret = boot_id_cache;
        return 0;
}

int sd_journal_scratch_grow(void **buf, size_t *cap, size_t need) {
        void *n;

        if (*cap >= need)
                return 0;

        n = realloc(*buf, need);
        if (!n)
                return -ENOMEM;

        *buf = n;
        *cap = need;
        return 0;
}

int sd_journal_seen_add(SdJournalSeenSet *set, const void *data, size_t len) {
        void *copy;

        if (sd_journal_seen_contains(set, data, len))
                return 0;

        if (set->n == set->cap) {
                size_t new_cap = set->cap ? set->cap * 2 : 8;
                void **new_items = realloc(set->items, new_cap * sizeof(*new_items));
                size_t *new_lens;

                if (!new_items)
                        return -ENOMEM;
                set->items = new_items;

                new_lens = realloc(set->lens, new_cap * sizeof(*new_lens));
                if (!new_lens)
                        return -ENOMEM;
                set->lens = new_lens;

                set->cap = new_cap;
        }

        copy = malloc(len ? len : 1);
        if (!copy)
                return -ENOMEM;
        if (len)
                memcpy(copy, data, len);

        set->items[set->n] = copy;
        set->lens[set->n] = len;
        set->n++;

        return 1;
}

bool sd_journal_seen_contains(const SdJournalSeenSet *set, const void *data, size_t len) {
        for (size_t i = 0; i < set->n; i++)
                if (set->lens[i] == len && memcmp(set->items[i], data, len) == 0)
                        return true;

        return false;
}

void sd_journal_seen_clear(SdJournalSeenSet *set) {
        for (size_t i = 0; i < set->n; i++)
                free(set->items[i]);

        free(set->items);
        free(set->lens);
        set->items = NULL;
        set->lens = NULL;
        set->n = 0;
        set->cap = 0;
}

const LogdEntry *sd_journal_current_entry(const struct sd_journal *j) {
        if (!j || j->loc != SD_J_ON_ENTRY)
                return NULL;

        return logd_ring_entry(j->ring, j->pos);
}

int sd_journal_entry_clocks(const LogdEntry *e, uint64_t *ret_monotonic, uint64_t *ret_realtime) {
        const LogdReadField *mt = logd_entry_field(e, "__MONOTONIC_TIMESTAMP");
        const LogdReadField *rt = logd_entry_field(e, "__REALTIME_TIMESTAMP");
        char numbuf[24];

        if (ret_monotonic) {
                if (!mt || mt->binary || mt->value_len == 0 || mt->value_len >= sizeof(numbuf))
                        return -EBADMSG;
                memcpy(numbuf, mt->value, mt->value_len);
                numbuf[mt->value_len] = '\0';
                *ret_monotonic = strtoull(numbuf, NULL, 10);
        }

        if (ret_realtime) {
                if (!rt || rt->binary || rt->value_len == 0 || rt->value_len >= sizeof(numbuf))
                        return -EBADMSG;
                memcpy(numbuf, rt->value, rt->value_len);
                numbuf[rt->value_len] = '\0';
                *ret_realtime = strtoull(numbuf, NULL, 10);
        }

        return 0;
}

/* NAME=value bytes for `e`'s field `name` (name_len bytes, not NUL-
 * terminated), compared against one stored match's raw bytes. Constructs
 * the comparison locally rather than materializing a buffer, since matches
 * are typically short and this runs per-entry, per-match. */
static bool field_equals_match(const LogdEntry *e, const char *name, size_t name_len, const SdJournalMatch *m) {
        char namebuf[65];
        const LogdReadField *f;

        if (name_len >= sizeof(namebuf))
                return false;
        memcpy(namebuf, name, name_len);
        namebuf[name_len] = '\0';

        f = logd_entry_field(e, namebuf);
        if (!f)
                return false;

        if (m->size != name_len + 1 + f->value_len)
                return false;
        if (memcmp(m->data, name, name_len) != 0)
                return false;
        if (((const char *) m->data)[name_len] != '=')
                return false;
        if (f->value_len > 0 && memcmp((const char *) m->data + name_len + 1, f->value, f->value_len) != 0)
                return false;

        return true;
}

bool sd_journal_entry_matches(const struct sd_journal *j, const LogdEntry *e) {
        if (j->n_matches == 0)
                return true;

        for (size_t i = 0; i < j->n_matches; i++) {
                const SdJournalMatch *mi = &j->matches[i];
                bool is_first_of_name = true;
                bool any_equal = false;

                /* Only evaluate each distinct name once, the first time it's
                 * seen -- an AND group already resolved by an earlier index
                 * would otherwise be re-checked (harmlessly, but O(n^2) for
                 * no reason) every time a later match shares its name. */
                for (size_t k = 0; k < i; k++)
                        if (j->matches[k].name_len == mi->name_len &&
                            memcmp(j->matches[k].data, mi->data, mi->name_len) == 0) {
                                is_first_of_name = false;
                                break;
                        }
                if (!is_first_of_name)
                        continue;

                for (size_t k = i; k < j->n_matches; k++) {
                        const SdJournalMatch *mk = &j->matches[k];

                        if (mk->name_len != mi->name_len || memcmp(mk->data, mi->data, mi->name_len) != 0)
                                continue;

                        if (field_equals_match(e, (const char *) mk->data, mk->name_len, mk)) {
                                any_equal = true;
                                break;
                        }
                }

                if (!any_equal)
                        return false;
        }

        return true;
}

char *sd_journal_default_runtime_dir(void) {
        const char *dir = getenv("LOGD_RUNTIME_DIR");

        if (!dir || dir[0] == '\0')
                dir = LOGD_RUNTIME_DIR;

        return strdup(dir);
}

char *sd_journal_ring_path(const char *runtime_dir, const char *name) {
        char *path;

        if (asprintf(&path, "%s/%s", runtime_dir, name) < 0)
                return NULL;

        return path;
}

int sd_journal_stat_ring(
                const char *runtime_dir,
                struct stat *active_st,
                bool *have_active,
                struct stat *rotated_st,
                bool *have_rotated) {
        char *active_path, *rotated_path;

        *have_active = false;
        *have_rotated = false;

        active_path = sd_journal_ring_path(runtime_dir, LOGD_RING_ACTIVE_NAME);
        if (!active_path)
                return -ENOMEM;
        rotated_path = sd_journal_ring_path(runtime_dir, LOGD_RING_ROTATED_NAME);
        if (!rotated_path) {
                free(active_path);
                return -ENOMEM;
        }

        if (stat(active_path, active_st) == 0)
                *have_active = true;
        else if (errno != ENOENT) {
                int r = -errno;

                free(active_path);
                free(rotated_path);
                return r;
        }

        if (stat(rotated_path, rotated_st) == 0)
                *have_rotated = true;
        else if (errno != ENOENT) {
                int r = -errno;

                free(active_path);
                free(rotated_path);
                return r;
        }

        free(active_path);
        free(rotated_path);
        return 0;
}
