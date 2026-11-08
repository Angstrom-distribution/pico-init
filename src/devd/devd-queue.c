/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The queue state files. devd-queue.h has what each one means and why the
 * counter is the kernel's rather than devd's own.
 */

#include "devd-queue.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int devd_queue_read_u64(const char *path, uint64_t *ret) {
        char buf[32];
        unsigned long long v;
        char *end;
        ssize_t n;
        int fd, r;

        if (!path || !ret)
                return -EINVAL;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        n = read(fd, buf, sizeof(buf) - 1);
        if (n < 0) {
                r = -errno;
                (void) close(fd);
                return r;
        }
        (void) close(fd);

        buf[n] = '\0';
        if (n > 0 && buf[n - 1] == '\n')
                buf[--n] = '\0';

        /* Digits only: strtoull() would take " 12" and "-1" as numbers. */
        if (n == 0 || buf[0] < '0' || buf[0] > '9')
                return -EINVAL;

        errno = 0;
        v = strtoull(buf, &end, 10);
        if (errno != 0 || *end != '\0')
                return -EINVAL;

        *ret = (uint64_t) v;
        return 0;
}

static int ensure_dir(const char *dir) {
        if (mkdir(dir, 0755) < 0 && errno != EEXIST)
                return -errno;

        return 0;
}

int devd_queue_write_u64(const char *dir, const char *name, uint64_t value) {
        char path[PATH_MAX], tmp[PATH_MAX], buf[32];
        int fd, k, r;

        if (!dir || !name)
                return -EINVAL;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, name) >= sizeof(path))
                return -ENAMETOOLONG;

        /* ".#" as devd-udev-db.c uses it: recognisable as a temporary. */
        if ((size_t) snprintf(tmp, sizeof(tmp), "%s/.#%s.devd", dir, name) >= sizeof(tmp))
                return -ENAMETOOLONG;

        k = snprintf(buf, sizeof(buf), "%llu\n", (unsigned long long) value);
        if (k < 0 || (size_t) k >= sizeof(buf))
                return -EINVAL;

        r = ensure_dir(dir);
        if (r < 0)
                return r;

        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
        if (fd < 0)
                return -errno;

        errno = 0;
        if (write(fd, buf, (size_t) k) != k) {
                r = errno > 0 ? -errno : -EIO;
                (void) close(fd);
                (void) unlink(tmp);
                return r;
        }

        if (close(fd) < 0) {
                r = -errno;
                (void) unlink(tmp);
                return r;
        }

        if (rename(tmp, path) < 0) {
                r = -errno;
                (void) unlink(tmp);
                return r;
        }

        return 0;
}

int devd_queue_remove(const char *dir, const char *name) {
        char path[PATH_MAX];

        if (!dir || !name)
                return -EINVAL;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, name) >= sizeof(path))
                return -ENAMETOOLONG;

        if (unlink(path) < 0)
                return errno == ENOENT ? 0 : -errno;

        return 0;
}

int devd_queue_set_flag(const char *dir, const char *name, bool on) {
        char path[PATH_MAX];
        int fd, r;

        if (!on)
                return devd_queue_remove(dir, name);

        if (!dir || !name)
                return -EINVAL;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, name) >= sizeof(path))
                return -ENAMETOOLONG;

        r = ensure_dir(dir);
        if (r < 0)
                return r;

        fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0644);
        if (fd < 0)
                return -errno;

        (void) close(fd);
        return 0;
}
