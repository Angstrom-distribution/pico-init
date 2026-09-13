/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_journal_open() and friends: a snapshot reader over logd's own /run
 * ring (src/logd/logd-read.h), never the binary .journal file format.
 *
 * open()/open_namespace() are real. Every other open_*() variant (directory,
 * directory_fd, files, files_fd, container) is an honest -EOPNOTSUPP: each
 * names a binary-journal-file input
 * this shim never reads, and pretending to open one and then reporting zero
 * entries would read to a caller as "directory empty" rather than "format
 * not supported" -- a much worse failure to hide behind.
 */

#include "sd-journal-internal.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#define ACCEPTED_OPEN_FLAGS                                                                              \
        (SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_RUNTIME_ONLY | SD_JOURNAL_SYSTEM | SD_JOURNAL_CURRENT_USER | \
         SD_JOURNAL_ALL_NAMESPACES | SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE | SD_JOURNAL_ASSUME_IMMUTABLE)

int sd_journal_open(sd_journal **ret, int flags) {
        sd_journal *j;
        int r;

        if (!ret || (flags & ~ACCEPTED_OPEN_FLAGS) != 0)
                return -EINVAL;

        j = calloc(1, sizeof(*j));
        if (!j)
                return -ENOMEM;

        j->flags = flags;
        j->loc = SD_J_BEFORE_HEAD;
        j->data_threshold = 64 * 1024;
        j->inotify_fd = -1;
        j->inotify_wd = -1;

        j->runtime_dir = journal_default_runtime_dir();
        if (!j->runtime_dir) {
                free(j);
                return -ENOMEM;
        }

        r = logd_ring_read(j->runtime_dir, &j->ring);
        if (r < 0) {
                free(j->runtime_dir);
                free(j);
                return r;
        }

        r = journal_stat_ring(
                        j->runtime_dir, &j->active_st, &j->have_active_st, &j->rotated_st, &j->have_rotated_st);
        if (r < 0) {
                logd_ring_free(j->ring);
                free(j->runtime_dir);
                free(j);
                return r;
        }

        *ret = j;
        return 0;
}

int sd_journal_open_namespace(sd_journal **ret, const char *name_space, int flags) {
        if (name_space)
                return -EOPNOTSUPP; /* pico has no log namespaces */

        return sd_journal_open(ret, flags);
}

int sd_journal_open_directory(sd_journal **ret, const char *path, int flags) {
        (void) ret;
        (void) path;
        (void) flags;
        return -EOPNOTSUPP;
}

int sd_journal_open_directory_fd(sd_journal **ret, int fd, int flags) {
        (void) ret;
        (void) fd;
        (void) flags;
        return -EOPNOTSUPP;
}

int sd_journal_open_files(sd_journal **ret, const char **paths, int flags) {
        (void) ret;
        (void) paths;
        (void) flags;
        return -EOPNOTSUPP;
}

int sd_journal_open_files_fd(sd_journal **ret, int fds[], unsigned n_fds, int flags) {
        (void) ret;
        (void) fds;
        (void) n_fds;
        (void) flags;
        return -EOPNOTSUPP;
}

int sd_journal_open_container(sd_journal **ret, const char *machine, int flags) {
        (void) ret;
        (void) machine;
        (void) flags;
        return -EOPNOTSUPP;
}

void sd_journal_close(sd_journal *j) {
        if (!j)
                return;

        if (j->inotify_fd >= 0)
                close(j->inotify_fd);

        logd_ring_free(j->ring);
        free(j->runtime_dir);

        for (size_t i = 0; i < j->n_matches; i++)
                free(j->matches[i].data);
        free(j->matches);

        free(j->data_scratch);

        free(j->unique_field);
        journal_seen_clear(&j->unique_seen);
        free(j->unique_scratch);

        journal_seen_clear(&j->fields_seen);
        free(j->fields_scratch);

        free(j);
}
