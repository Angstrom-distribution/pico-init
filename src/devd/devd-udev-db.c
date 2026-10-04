/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The udev database writer. devd-udev-db.h has the format, what is left out
 * of it and why, and why this is a real file at upstream's path at all.
 */

#include "devd-udev-db.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "devd-match.h"

/* A full decimal parse: non-empty, digits only, no overflow. strtoull() alone
 * would take "13abc" as 13 and " 13" as 13, and the id is a filename both
 * sides have to spell the same way. Parsed wider than `unsigned` so the
 * UINT_MAX check is a real one on a 32-bit board too. */
static bool parse_unsigned(const char *s, unsigned *ret) {
        unsigned long long v;
        char *end;

        if (!s || s[0] < '0' || s[0] > '9')
                return false;

        errno = 0;
        v = strtoull(s, &end, 10);
        if (errno != 0 || *end != '\0' || v > UINT_MAX)
                return false;

        *ret = (unsigned) v;
        return true;
}

int devd_udev_db_id(const DevdRuleDevice *dev, char *ret, size_t size) {
        unsigned major_n, minor_n, ifindex;
        int k;

        if (!dev || !ret || size == 0)
                return -EINVAL;

        if (parse_unsigned(devd_rule_device_property(dev, "MAJOR"), &major_n) &&
            parse_unsigned(devd_rule_device_property(dev, "MINOR"), &minor_n))
                k = snprintf(ret,
                             size,
                             "%c%u:%u",
                             strcmp(dev->subsystem, "block") == 0 ? 'b' : 'c',
                             major_n,
                             minor_n);
        else if (parse_unsigned(devd_rule_device_property(dev, "IFINDEX"), &ifindex) && ifindex > 0 &&
                 ifindex <= INT_MAX)
                k = snprintf(ret, size, "n%u", ifindex);
        else if (dev->subsystem[0] != '\0' && dev->kernel[0] != '\0')
                k = snprintf(ret, size, "+%s:%s", dev->subsystem, dev->kernel);
        else
                return -ENOENT;

        if (k < 0 || (size_t) k >= size)
                return -ENAMETOOLONG;

        return 0;
}

/* An id is one path component under db_root and nothing else. A leading '.'
 * is refused on top of '/' because ".#<id>.devd" is this file's own temporary
 * name, and "." / ".." would name a directory. */
static bool id_is_safe(const char *id) {
        return id && id[0] != '\0' && id[0] != '.' && !strchr(id, '/');
}

/* db_root and every missing parent, 0755, the mode upstream's own
 * mkdir_parents() gives /run/udev/data. */
static int mkdir_chain(const char *db_root) {
        char buf[PATH_MAX];

        if ((size_t) snprintf(buf, sizeof(buf), "%s", db_root) >= sizeof(buf))
                return -ENAMETOOLONG;

        for (char *p = buf + 1; *p; p++) {
                if (*p != '/')
                        continue;

                *p = '\0';
                if (mkdir(buf, 0755) < 0 && errno != EEXIST)
                        return -errno;
                *p = '/';
        }

        if (mkdir(buf, 0755) < 0 && errno != EEXIST)
                return -errno;

        return 0;
}

int devd_udev_db_delete(const char *db_root, const char *id) {
        char path[PATH_MAX];

        if (!db_root || !id_is_safe(id))
                return -EINVAL;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", db_root, id) >= sizeof(path))
                return -ENAMETOOLONG;

        if (unlink(path) < 0)
                return errno == ENOENT ? 0 : -errno;

        return 0;
}

int devd_udev_db_write(
                const char *db_root,
                const char *id,
                usec_t usec_initialized,
                const char * const *keys,
                const char * const *values,
                size_t n) {

        char path[PATH_MAX], tmp[PATH_MAX];
        FILE *f;
        int fd, r;

        if (!db_root || !id_is_safe(id) || (n > 0 && (!keys || !values)))
                return -EINVAL;

        /* A newline would end the record early and start a new one out of the
         * rest, and an '=' in a key would move the split point the reader
         * uses -- either way the file would say something nobody wrote. */
        for (size_t i = 0; i < n; i++) {
                if (!keys[i] || keys[i][0] == '\0' || strpbrk(keys[i], "=\n"))
                        return -EINVAL;

                if (!values[i] || strchr(values[i], '\n'))
                        return -EINVAL;
        }

        if (n == 0)
                return devd_udev_db_delete(db_root, id);

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", db_root, id) >= sizeof(path))
                return -ENAMETOOLONG;

        /* ".#" is upstream's fopen_temporary() prefix, so a stray one is
         * recognisable as a temporary to anyone who knows that layout. A fixed
         * name needs no O_EXCL for manager-state.c's reason: devd is one
         * thread, and only one write is ever in flight. */
        if ((size_t) snprintf(tmp, sizeof(tmp), "%s/.#%s.devd", db_root, id) >= sizeof(tmp))
                return -ENAMETOOLONG;

        r = mkdir_chain(db_root);
        if (r < 0)
                return r;

        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
        if (fd < 0)
                return -errno;

        /* 0644 regardless of devd's umask: the readers are unprivileged
         * (an Xorg running as a user, libinput in a compositor), and upstream
         * makes every non-persistent entry 0644 for the same reason. */
        if (fchmod(fd, 0644) < 0) {
                r = -errno;
                (void) close(fd);
                (void) unlink(tmp);
                return r;
        }

        f = fdopen(fd, "w");
        if (!f) {
                r = -errno;
                (void) close(fd);
                (void) unlink(tmp);
                return r;
        }

        if (usec_initialized > 0 && usec_initialized != USEC_INFINITY)
                (void) fprintf(f, "I:%llu\n", (unsigned long long) usec_initialized);

        for (size_t i = 0; i < n; i++)
                (void) fprintf(f, "E:%s=%s\n", keys[i], values[i]);

        (void) fprintf(f, "V:%d\n", DEVD_UDEV_DB_VERSION);

        /* Every stage checked, because each one can be where a full /run
         * surfaces: a buffered fprintf() reports nothing until the flush, and
         * a reader handed a file missing its tail would take the properties it
         * did get as the whole answer. */
        r = 0;
        errno = 0;
        if (fflush(f) != 0 || ferror(f))
                r = errno > 0 ? -errno : -EIO;

        errno = 0;
        if (fclose(f) != 0 && r == 0)
                r = errno > 0 ? -errno : -EIO;

        if (r < 0) {
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
