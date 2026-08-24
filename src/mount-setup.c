/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Mounting the API virtual filesystems. See mount-setup.h for why this is
 * PID 1's job and nobody else's.
 *
 * The table and its ordering follow systemd's own mount_setup_early() rather
 * than being invented here: /proc and /sys first because everything else
 * (including the is-it-already-mounted test) wants them, /dev before its own
 * subdirectories, and /sys/fs/cgroup last because it lives inside /sys.
 *
 * The mount flags are not decoration. nosuid/noexec/nodev on the pseudo
 * filesystems is what stops a writable API mount from being a place to stage a
 * setuid binary; systemd carries exactly these and dropping them because
 * "it is only /proc" would be a real weakening.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mount-setup.h"
#include "util.h"

typedef struct MountPoint {
        const char *what;
        const char *where;
        const char *type;
        const char *options;
        unsigned long flags;

        /*
         * Whether booting can continue without it. /proc and /sys are not
         * negotiable -- almost nothing works without them, and continuing
         * would only postpone the failure into somewhere harder to diagnose.
         * The rest are best-effort: a board that reaches a console with a
         * missing /dev/shm is still a board someone can debug.
         */
        bool required;
} MountPoint;

static const MountPoint mount_table[] = {
        {     "proc",          "/proc",     "proc",             NULL,      MS_NOSUID | MS_NOEXEC | MS_NODEV,  true },
        {    "sysfs",           "/sys",    "sysfs",             NULL,      MS_NOSUID | MS_NOEXEC | MS_NODEV,  true },

        /* Usually already mounted by the kernel (CONFIG_DEVTMPFS_MOUNT) or by
         * an initramfs; mounted here only for the case where it is not. */
        { "devtmpfs",           "/dev", "devtmpfs",      "mode=0755",            MS_NOSUID | MS_STRICTATIME, false },

        {   "devpts",       "/dev/pts",   "devpts", "gid=5,mode=620",                 MS_NOSUID | MS_NOEXEC, false },
        {    "tmpfs",       "/dev/shm",    "tmpfs",      "mode=1777", MS_NOSUID | MS_NODEV | MS_STRICTATIME, false },
        {    "tmpfs",           "/run",    "tmpfs",      "mode=0755", MS_NOSUID | MS_NODEV | MS_STRICTATIME, false },

        /*
         * The unified cgroup hierarchy this project's whole supervision layer
         * is built on. Not marked required only because a board with no
         * console is worse than a board with unsupervised services -- but
         * cgroups-v2.c degrades loudly when it is missing, and that warning in
         * the boot log is the thing to chase.
         */
        {  "cgroup2", "/sys/fs/cgroup",  "cgroup2",     "nsdelegate",      MS_NOSUID | MS_NOEXEC | MS_NODEV, false },
};

/*
 * Is `where` already a mount point?
 *
 * Compares the st_dev of the path against that of its parent: a mount point is
 * precisely a path whose device differs from the directory containing it. This
 * works before /proc exists, which /proc/self/mountinfo parsing obviously does
 * not -- and /proc is the first thing this file mounts.
 *
 * The root directory is its own parent, so it would report "not a mount
 * point"; that is fine, nothing in the table is "/".
 */
static bool is_mount_point(const char *where) {
        char parent[PATH_MAX];
        struct stat a, b;
        char *slash;
        size_t len;

        if (stat(where, &a) < 0)
                return false;

        len = strlen(where);
        if (len == 0 || len >= sizeof(parent))
                return false;

        memcpy(parent, where, len + 1);

        slash = strrchr(parent, '/');
        if (!slash)
                return false;

        if (slash == parent)
                parent[1] = '\0'; /* "/foo" -> "/" */
        else
                *slash = '\0';

        if (stat(parent, &b) < 0)
                return false;

        return a.st_dev != b.st_dev;
}

/* Create the mount point if it is missing. Failure is the caller's problem. */
static int make_dir(const char *where) {
        if (mkdir(where, 0755) < 0 && errno != EEXIST)
                return -errno;

        return 0;
}

int mount_setup(void) {
        size_t i;
        int n = 0;

        for (i = 0; i < sizeof(mount_table) / sizeof(mount_table[0]); i++) {
                const MountPoint *p = &mount_table[i];
                int r;

                if (is_mount_point(p->where)) {
                        pico_log(PICO_LOG_DEBUG, "%s is already mounted, leaving it alone", p->where);
                        continue;
                }

                r = make_dir(p->where);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING, "%s: cannot create mount point: %s", p->where, strerror(-r));
                        if (p->required)
                                return r;
                        continue;
                }

                if (mount(p->what, p->where, p->type, p->flags, p->options) < 0) {
                        /* EBUSY means something got there first, which is a
                         * success for our purposes rather than a failure. */
                        if (errno == EBUSY) {
                                pico_log(PICO_LOG_DEBUG, "%s was mounted concurrently, continuing", p->where);
                                continue;
                        }

                        pico_log(PICO_LOG_WARNING, "%s: mount %s failed: %s", p->where, p->type, strerror(errno));

                        if (p->required)
                                return -errno;

                        continue;
                }

                pico_log(PICO_LOG_DEBUG, "mounted %s on %s", p->type, p->where);
                n++;
        }

        return n;
}

void sysctl_setup(void) {
        static const struct {
                const char *path;
                const char *value;
        } tunables[] = {
                { "/proc/sys/net/unix/max_dgram_qlen", "64\n" },
        };
        size_t i;

        for (i = 0; i < sizeof(tunables) / sizeof(tunables[0]); i++) {
                ssize_t len = (ssize_t) strlen(tunables[i].value);
                int fd;

                fd = open(tunables[i].path, O_WRONLY | O_CLOEXEC);
                if (fd < 0) {
                        pico_log(PICO_LOG_DEBUG, "%s: %s", tunables[i].path, strerror(errno));
                        continue;
                }

                if (write(fd, tunables[i].value, (size_t) len) != len)
                        pico_log(PICO_LOG_DEBUG, "%s: write: %s", tunables[i].path, strerror(errno));

                close(fd);
        }
}
