/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Sysattrs: the name iterator (regular files directly under syspath), the
 * value getter/setter, and the (device, resolved-attr) cache in front of
 * both.
 *
 * "driver", "subsystem" and "module" are symlinks, so
 * sd_device_get_sysattr_first()/_next() never lists them, but
 * sd_device_get_sysattr_value() on one of those names still works, as in
 * upstream.
 *
 * Values are read with a single read(2) call into a fixed buffer rather
 * than a loop to EOF: a sysfs attribute's show() callback writes its whole
 * answer in one shot (real udev's own sysfs_attr code relies on the same
 * property), and a value that does not fit in one page is not something
 * any real attribute on this project's boards produces.
 */

/* vasprintf() is a glibc extension; -std=gnu17 alone does not imply
 * _GNU_SOURCE, so it must be defined first, before any header pulls in
 * features.h. */
#define _GNU_SOURCE

#include "sd-device.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "device-internal.h"

#define SYSATTR_READ_BUF 4096

static const char *last_component(const char *path) {
        const char *slash = strrchr(path, '/');

        return slash ? slash + 1 : path;
}

static bool is_symlink_sysattr(const char *sysattr) {
        return strcmp(sysattr, "driver") == 0 || strcmp(sysattr, "subsystem") == 0 ||
                        strcmp(sysattr, "module") == 0;
}

static DeviceSysattr *cache_find(sd_device *d, const char *sysattr) {
        size_t i;

        for (i = 0; i < d->n_sysattr_cache; i++)
                if (strcmp(d->sysattr_cache[i].name, sysattr) == 0)
                        return &d->sysattr_cache[i];

        return NULL;
}

/* Appends a new (possibly negative) cache entry and returns it, or NULL on
 * OOM building the entry itself -- which the caller reports as -ENOMEM
 * without caching anything, per the "never cache ENOMEM" rule. */
static DeviceSysattr *cache_add(sd_device *d, const char *sysattr) {
        DeviceSysattr *n = realloc(d->sysattr_cache, (d->n_sysattr_cache + 1) * sizeof(*n));

        if (!n)
                return NULL;
        d->sysattr_cache = n;

        d->sysattr_cache[d->n_sysattr_cache] = (DeviceSysattr){ .name = strdup(sysattr) };
        if (!d->sysattr_cache[d->n_sysattr_cache].name)
                return NULL;

        return &d->sysattr_cache[d->n_sysattr_cache++];
}

static int read_symlink_attr(sd_device *d, const char *sysattr, DeviceSysattr *slot) {
        char path[PATH_MAX], target[PATH_MAX];
        ssize_t k;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", d->syspath, sysattr) >= sizeof(path))
                return -ENAMETOOLONG;

        k = readlink(path, target, sizeof(target) - 1);
        if (k < 0)
                return errno == ENOENT ? -ENOENT : -errno;
        target[k] = '\0';

        slot->value = strdup(last_component(target));
        if (!slot->value)
                return -ENOMEM;
        slot->size = strlen(slot->value);
        return 0;
}

static int read_plain_attr(sd_device *d, const char *sysattr, DeviceSysattr *slot) {
        char path[PATH_MAX], buf[SYSATTR_READ_BUF];
        int fd, r;
        struct stat st;
        ssize_t k;
        size_t len;

        if (!device_path_component_is_safe(sysattr))
                return -EINVAL;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", d->syspath, sysattr) >= sizeof(path))
                return -ENAMETOOLONG;

        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (fd < 0)
                return errno == ENOENT ? -ENOENT : -errno;

        if (fstat(fd, &st) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        if (S_ISDIR(st.st_mode)) {
                close(fd);
                return -EISDIR;
        }

        k = read(fd, buf, sizeof(buf) - 1);
        r = k < 0 ? -errno : 0;
        close(fd);
        if (r < 0)
                return r;

        len = (size_t) k;
        if (len > 0 && buf[len - 1] == '\n')
                len--;

        slot->value = malloc(len + 1);
        if (!slot->value)
                return -ENOMEM;
        memcpy(slot->value, buf, len);
        slot->value[len] = '\0';
        slot->size = len;
        return 0;
}

int sd_device_get_sysattr_value_with_size(
                sd_device *device, const char *sysattr, const char **ret_value, size_t *ret_size) {
        DeviceSysattr *slot;
        int r;

        if (!device || !sysattr)
                return -EINVAL;

        slot = cache_find(device, sysattr);
        if (slot) {
                if (!slot->value)
                        return slot->cached_errno;
                if (ret_value)
                        *ret_value = slot->value;
                if (ret_size)
                        *ret_size = slot->size;
                return 0;
        }

        {
                DeviceSysattr tmp = { 0 };

                r = is_symlink_sysattr(sysattr) ? read_symlink_attr(device, sysattr, &tmp) :
                                                  read_plain_attr(device, sysattr, &tmp);

                if (r == -ENOMEM) {
                        free(tmp.value);
                        return -ENOMEM;
                }

                slot = cache_add(device, sysattr);
                if (!slot) {
                        free(tmp.value);
                        return -ENOMEM;
                }

                if (r < 0) {
                        slot->cached_errno = r;
                        return r;
                }

                slot->value = tmp.value;
                slot->size = tmp.size;
        }

        if (ret_value)
                *ret_value = slot->value;
        if (ret_size)
                *ret_size = slot->size;
        return 0;
}

int sd_device_get_sysattr_value(sd_device *device, const char *sysattr, const char **ret) {
        return sd_device_get_sysattr_value_with_size(device, sysattr, ret, NULL);
}

/*
 * Removes the entry rather than nulling it: `value == NULL` means "cached
 * negative result" to the getter, so a nulled positive entry would be
 * mistaken for a cached -ENOENT.
 */
static void cache_invalidate(sd_device *d, const char *sysattr) {
        size_t i;

        for (i = 0; i < d->n_sysattr_cache; i++) {
                if (strcmp(d->sysattr_cache[i].name, sysattr) != 0)
                        continue;

                free(d->sysattr_cache[i].name);
                free(d->sysattr_cache[i].value);
                d->sysattr_cache[i] = d->sysattr_cache[d->n_sysattr_cache - 1];
                d->n_sysattr_cache--;
                return;
        }
}

int sd_device_set_sysattr_value(sd_device *device, const char *sysattr, const char *value) {
        char path[PATH_MAX];
        char *with_nl = NULL;
        const char *out;
        size_t len;
        int fd, r;

        if (!device || !sysattr)
                return -EINVAL;

        if (!value) {
                cache_invalidate(device, sysattr);
                return 0;
        }

        if (!device_path_component_is_safe(sysattr))
                return -EINVAL;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", device->syspath, sysattr) >= sizeof(path))
                return -ENAMETOOLONG;

        len = strlen(value);
        if (len == 0 || value[len - 1] != '\n') {
                with_nl = malloc(len + 2);
                if (!with_nl)
                        return -ENOMEM;
                memcpy(with_nl, value, len);
                with_nl[len] = '\n';
                with_nl[len + 1] = '\0';
                out = with_nl;
                len++;
        } else
                out = value;

        /*
         * O_TRUNC: a sysfs store() callback takes every write as the whole
         * new value, but a plain file (a test fixture) would keep the old
         * value's tail after a shorter write. Matches `echo value > attr`.
         */
        fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0) {
                r = -errno;
                free(with_nl);
                return r;
        }

        r = write(fd, out, len) == (ssize_t) len ? 0 : -errno;
        close(fd);
        free(with_nl);

        if (r < 0)
                return r;

        cache_invalidate(device, sysattr);
        return 0;
}

int sd_device_set_sysattr_valuef(sd_device *device, const char *sysattr, const char *format, ...) {
        va_list ap;
        char *value;
        int len, r;

        if (!device || !sysattr)
                return -EINVAL;

        if (!format) {
                cache_invalidate(device, sysattr);
                return 0;
        }

        va_start(ap, format);
        len = vasprintf(&value, format, ap);
        va_end(ap);
        if (len < 0)
                return -ENOMEM;

        r = sd_device_set_sysattr_value(device, sysattr, value);
        free(value);
        return r;
}

static void sysattr_names_scan(sd_device *d) {
        DIR *dh;
        struct dirent *de;

        d->sysattr_names_scanned = true;

        dh = opendir(d->syspath);
        if (!dh)
                return;

        while ((de = readdir(dh))) {
                char path[PATH_MAX];
                struct stat st;
                char **n;

                if (de->d_name[0] == '.')
                        continue;

                if ((size_t) snprintf(path, sizeof(path), "%s/%s", d->syspath, de->d_name) >= sizeof(path))
                        continue;

                /* lstat, not stat: a symlink attribute (driver/subsystem/
                 * module) is deliberately excluded from this iterator --
                 * see this file's top comment. */
                if (lstat(path, &st) < 0 || !S_ISREG(st.st_mode))
                        continue;

                n = realloc(d->sysattr_names, (d->n_sysattr_names + 1) * sizeof(*n));
                if (!n)
                        break;
                d->sysattr_names = n;

                d->sysattr_names[d->n_sysattr_names] = strdup(de->d_name);
                if (!d->sysattr_names[d->n_sysattr_names])
                        break;
                d->n_sysattr_names++;
        }

        closedir(dh);
}

const char *sd_device_get_sysattr_first(sd_device *device) {
        if (!device)
                return NULL;

        if (!device->sysattr_names_scanned)
                sysattr_names_scan(device);

        device->sysattr_iter = 0;
        if (device->n_sysattr_names == 0)
                return NULL;

        device->sysattr_iter = 1;
        return device->sysattr_names[0];
}

const char *sd_device_get_sysattr_next(sd_device *device) {
        if (!device || device->sysattr_iter >= device->n_sysattr_names)
                return NULL;

        return device->sysattr_names[device->sysattr_iter++];
}
