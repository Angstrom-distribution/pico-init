/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "machine-id-setup.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#include "id128-internal.h"
#include "util.h"

#define MACHINE_ID_SUFFIX "/etc/machine-id"
#define RUN_MACHINE_ID_SUFFIX "/run/machine-id"

static sd_id128_t cached_id;
static bool cached_valid = false;

sd_id128_t machine_id_setup_get(void) {
        return cached_valid ? cached_id : (sd_id128_t){ 0 };
}

static int join_root(const char *root, const char *suffix, char *buf, size_t bufsize) {
        int n;

        if (root && root[0])
                n = snprintf(buf, bufsize, "%s%s", root, suffix);
        else
                n = snprintf(buf, bufsize, "%s", suffix);

        if (n < 0 || (size_t) n >= bufsize)
                return -ENAMETOOLONG;
        return 0;
}

/*
 * 0 with *ret set on a genuinely usable existing id, or whatever
 * id128_read_fd() returned to say why not: -errno from open() (ENOENT: no
 * file at all), or -ENOMEDIUM/-ENOPKG/-EUCLEAN from the content itself
 * (empty/null, literally "uninitialized", or unparseable). Every one of
 * those is upstream's own first-boot signal (log_execution_mode(),
 * src/core/main.c checks exactly the missing-or-"uninitialized" pair; this
 * also folds in empty and garbage, which that same check's read_one_line_file()
 * would otherwise hand back as a confusing non-"uninitialized" short read).
 */
static int read_existing(const char *path, sd_id128_t *ret) {
        int fd, r;

        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (fd < 0)
                return -errno;

        r = id128_read_fd(fd, false, ret);
        close(fd);
        return r;
}

/* Render `id` the one way sd_id128_get_machine() accepts for /etc/machine-id:
 * 32 lowercase hex chars plus a trailing newline, nothing else. */
static void format_id_line(sd_id128_t id, char line[_SD_ARRAY_STATIC SD_ID128_STRING_MAX + 1]) {
        char text[SD_ID128_STRING_MAX];

        sd_id128_to_string(id, text);
        memcpy(line, text, SD_ID128_STRING_MAX - 1);
        line[SD_ID128_STRING_MAX - 1] = '\n';
        line[SD_ID128_STRING_MAX] = '\0';
}

/*
 * Write `line` to `path` by creating a sibling tmp file and rename()-ing it
 * into place -- manager-state.c's own tmp-then-rename convention, so a
 * reader's open() of `path` never sees a partially-written id. Mode 0444,
 * matching upstream: the file is not meant to be edited, and root (PID 1
 * always is) can still write through the fd it already holds regardless of
 * the mode just given to the inode it created.
 *
 * -EROFS (propagated from the tmp file's own open(), which fails exactly
 * when /etc/ itself is not writable) is the caller's cue to fall back to
 * the transient bind mount; any other error is a real, unexpected failure.
 */
static int write_machine_id_file(const char *path, const char *line, size_t len) {
        char tmp[PATH_MAX];
        int fd, n;
        ssize_t w;

        n = snprintf(tmp, sizeof(tmp), "%s.pico-tmp", path);
        if (n < 0 || (size_t) n >= sizeof(tmp))
                return -ENAMETOOLONG;

        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0444);
        if (fd < 0)
                return -errno;

        w = write(fd, line, len);
        if (w < 0 || (size_t) w != len) {
                int saved = w < 0 ? errno : EIO;
                close(fd);
                unlink(tmp);
                return -saved;
        }

        if (fsync(fd) < 0) {
                int saved = errno;
                close(fd);
                unlink(tmp);
                return -saved;
        }
        close(fd);

        if (rename(tmp, path) < 0) {
                int saved = errno;
                unlink(tmp);
                return -saved;
        }

        return 0;
}

/*
 * The read-only-/etc fallback: write the id to /run/machine-id (tmpfs,
 * always writable -- mount_setup() mounted it long before this runs) and
 * bind-mount that file over /etc/machine-id, matching upstream's own
 * transient-file mechanism (src/shared/machine-id-setup.c). Requires
 * `etc_path` to already exist as a regular file -- true for every
 * angstrom-pico image, which ships /etc/machine-id as an empty 0-byte file
 * for exactly this reason. Remounting the bind read-only is best-effort:
 * a failure there leaves a working, merely less-hardened, machine id.
 */
static int bind_transient_machine_id(const char *run_path, const char *etc_path, const char *line, size_t len) {
        int fd, r;
        ssize_t w;

        fd = open(run_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0444);
        if (fd < 0)
                return -errno;

        w = write(fd, line, len);
        if (w < 0 || (size_t) w != len) {
                int saved = w < 0 ? errno : EIO;
                close(fd);
                unlink(run_path);
                return -saved;
        }
        close(fd);

        if (mount(run_path, etc_path, NULL, MS_BIND, NULL) < 0) {
                r = -errno;
                unlink(run_path);
                return r;
        }

        if (mount(NULL, etc_path, NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL) < 0)
                pico_log(PICO_LOG_WARNING,
                         "remounting the transient machine-id read-only: %s",
                         strerror(errno));

        return 0;
}

int machine_id_setup(const char *root, sd_id128_t *ret_id, bool *ret_first_boot) {
        char etc_path[PATH_MAX], run_path[PATH_MAX];
        char line[SD_ID128_STRING_MAX + 1];
        sd_id128_t id;
        bool first_boot;
        int r;

        if (join_root(root, MACHINE_ID_SUFFIX, etc_path, sizeof(etc_path)) < 0)
                return -ENAMETOOLONG;

        r = read_existing(etc_path, &id);
        if (r == 0) {
                first_boot = false;
                goto done;
        }

        /* -errno (ENOENT: missing), -ENOMEDIUM (empty or all-zero),
         * -ENOPKG ("uninitialized"), -EUCLEAN (garbage): every one of these
         * is a first-boot signal, not a distinct error to report. */
        first_boot = true;

        r = sd_id128_randomize(&id);
        if (r < 0)
                return r; /* getrandom() itself failing is genuinely fatal */

        format_id_line(id, line);

        r = write_machine_id_file(etc_path, line, SD_ID128_STRING_MAX);
        if (r == -EROFS) {
                if (join_root(root, RUN_MACHINE_ID_SUFFIX, run_path, sizeof(run_path)) < 0)
                        return -ENAMETOOLONG;

                r = bind_transient_machine_id(run_path, etc_path, line, SD_ID128_STRING_MAX);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "/etc/machine-id is read-only and the transient fallback failed: %s",
                                 strerror(-r));
        } else if (r < 0)
                pico_log(PICO_LOG_WARNING, "writing /etc/machine-id: %s", strerror(-r));

done:
        cached_id = id;
        cached_valid = true;

        if (ret_id)
                *ret_id = id;
        if (ret_first_boot)
                *ret_first_boot = first_boot;

        return 0;
}
