/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Per-entry timestamps, ring-wide cutoffs/usage, and the small honest-
 * failure group (get_seqnum, get_catalog*) that pico genuinely has no data
 * for. The ring is oldest-first by construction (logd-read.h), so cutoffs
 * are a plain first/last-entry read, never a scan.
 */

#include "sd-journal-internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../../logd/logd.h"

int sd_journal_get_realtime_usec(sd_journal *j, uint64_t *ret) {
        const LogdEntry *e;

        if (!j || !ret)
                return -EINVAL;

        e = sd_journal_current_entry(j);
        if (!e)
                return -EADDRNOTAVAIL;

        return sd_journal_entry_clocks(e, NULL, ret);
}

int sd_journal_get_monotonic_usec(sd_journal *j, uint64_t *ret_monotonic, sd_id128_t *ret_boot_id) {
        const LogdEntry *e;
        const LogdReadField *boot;
        sd_id128_t parsed;
        int r;

        if (!j || !ret_monotonic)
                return -EINVAL;

        e = sd_journal_current_entry(j);
        if (!e)
                return -EADDRNOTAVAIL;

        r = sd_journal_entry_clocks(e, ret_monotonic, NULL);
        if (r < 0)
                return r;

        boot = logd_entry_field(e, "_BOOT_ID");
        if (!boot || boot->binary ||
            !sd_journal_parse_boot_id((const char *) boot->value, boot->value_len, &parsed))
                return -EBADMSG;

        if (ret_boot_id) {
                *ret_boot_id = parsed;
                return 0;
        }

        {
                sd_id128_t current;

                r = sd_journal_current_boot_id(&current);
                if (r < 0)
                        return r;

                return memcmp(&parsed, &current, sizeof(parsed)) == 0 ? 0 : -ESTALE;
        }
}

int sd_journal_get_seqnum(sd_journal *j, uint64_t *ret_seqnum, sd_id128_t *ret_seqnum_id) {
        (void) j;
        (void) ret_seqnum;
        (void) ret_seqnum_id;
        return -EOPNOTSUPP; /* logd-write.c emits no __SEQNUM field to synthesize this from */
}

int sd_journal_get_cutoff_realtime_usec(sd_journal *j, uint64_t *from, uint64_t *to) {
        size_t n;
        int r;

        if (!j)
                return -EINVAL;

        n = logd_ring_n_entries(j->ring);
        if (n == 0)
                return 0;

        r = sd_journal_entry_clocks(logd_ring_entry(j->ring, 0), NULL, from);
        if (r < 0)
                return r;
        r = sd_journal_entry_clocks(logd_ring_entry(j->ring, n - 1), NULL, to);
        if (r < 0)
                return r;

        return 1;
}

int sd_journal_get_cutoff_monotonic_usec(sd_journal *j, sd_id128_t boot_id, uint64_t *from, uint64_t *to) {
        size_t n;
        sd_id128_t current;
        int r;

        if (!j)
                return -EINVAL;

        n = logd_ring_n_entries(j->ring);
        if (n == 0)
                return 0;

        r = sd_journal_current_boot_id(&current);
        if (r < 0)
                return r;
        if (memcmp(&boot_id, &current, sizeof(boot_id)) != 0)
                return 0; /* no data for a boot other than the one this /run ring holds */

        r = sd_journal_entry_clocks(logd_ring_entry(j->ring, 0), from, NULL);
        if (r < 0)
                return r;
        r = sd_journal_entry_clocks(logd_ring_entry(j->ring, n - 1), to, NULL);
        if (r < 0)
                return r;

        return 1;
}

int sd_journal_get_usage(sd_journal *j, uint64_t *ret_bytes) {
        struct stat st;
        uint64_t total = 0;
        char *path;

        if (!j || !ret_bytes)
                return -EINVAL;

        path = sd_journal_ring_path(j->runtime_dir, LOGD_RING_ACTIVE_NAME);
        if (!path)
                return -ENOMEM;
        if (stat(path, &st) == 0)
                total += (uint64_t) st.st_size;
        else if (errno != ENOENT) {
                int r = -errno;

                free(path);
                return r;
        }
        free(path);

        path = sd_journal_ring_path(j->runtime_dir, LOGD_RING_ROTATED_NAME);
        if (!path)
                return -ENOMEM;
        if (stat(path, &st) == 0)
                total += (uint64_t) st.st_size;
        else if (errno != ENOENT) {
                int r = -errno;

                free(path);
                return r;
        }
        free(path);

        *ret_bytes = total;
        return 0;
}

int sd_journal_get_catalog(sd_journal *j, char **ret) {
        (void) j;
        (void) ret;
        return -ENOENT; /* pico ships no message catalog; logd records no MESSAGE_ID */
}

int sd_journal_get_catalog_for_message_id(sd_id128_t id, char **ret) {
        (void) id;
        (void) ret;
        return -ENOENT;
}

int sd_journal_has_runtime_files(sd_journal *j) {
        struct stat active_st, rotated_st;
        bool have_active, have_rotated;
        int r;

        if (!j)
                return -EINVAL;

        r = sd_journal_stat_ring(j->runtime_dir, &active_st, &have_active, &rotated_st, &have_rotated);
        if (r < 0)
                return r;

        return ((have_active && active_st.st_size > 0) || (have_rotated && rotated_st.st_size > 0)) ? 1 : 0;
}

int sd_journal_has_persistent_files(sd_journal *j) {
        (void) j;
        return 0; /* genuinely true: the ring lives on /run tmpfs only, logd.h */
}
