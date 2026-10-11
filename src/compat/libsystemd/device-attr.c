/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The readlink-/syspath-grammar-based identity getters: subsystem, driver,
 * driver_subsystem, sysname/sysnum. None of these touch the uevent file --
 * see device-uevent.c for the ones that do.
 *
 * subsystem and driver_subsystem both special-case a syspath grammar rather
 * than only readlink()ing a "subsystem" symlink: a real kernel's
 * /sys/bus/<bus>/drivers/<drv> and /sys/module/<name> have no such symlink
 * at all, so the grammar check is the only way either object gets a
 * subsystem.
 */

#include "sd-device.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "device-internal.h"

/* Last path component of `path`. Never NULL for a non-empty path with no
 * trailing slash, which every syspath and readlink target here is. */
static const char *last_component(const char *path) {
        const char *slash = strrchr(path, '/');

        return slash ? slash + 1 : path;
}

static char *readlink_basename(const char *path) {
        char target[PATH_MAX];
        ssize_t k = readlink(path, target, sizeof(target) - 1);

        if (k < 0)
                return NULL;

        target[k] = '\0';
        return strdup(last_component(target));
}

/* "/bus/<bus>/drivers/<drv>" -> bus length via *bus_len, or 0 if devpath
 * does not have this shape. */
static size_t driver_bus_len(const char *devpath) {
        const char *p, *slash;

        if (strncmp(devpath, "/bus/", 5) != 0)
                return 0;

        p = devpath + 5;
        slash = strchr(p, '/');
        if (!slash || strncmp(slash, "/drivers/", 9) != 0)
                return 0;

        return (size_t) (slash - p);
}

static bool is_module_devpath(const char *devpath) {
        return strncmp(devpath, "/module/", 8) == 0 && devpath[8] != '\0';
}

int sd_device_get_subsystem(sd_device *device, const char **ret) {
        char path[PATH_MAX];

        if (!device)
                return -EINVAL;

        if (!device->subsystem_resolved) {
                if (driver_bus_len(device->devpath) > 0)
                        device->subsystem = strdup("drivers");
                else if (is_module_devpath(device->devpath))
                        device->subsystem = strdup("module");
                else {
                        if ((size_t) snprintf(path, sizeof(path), "%s/subsystem", device->syspath) >=
                            sizeof(path)) {
                                device->subsystem_errno = -ENAMETOOLONG;
                                device->subsystem_resolved = true;
                                return device->subsystem_errno;
                        }
                        device->subsystem = readlink_basename(path);
                }

                device->subsystem_errno = device->subsystem ? 0 : -ENOENT;
                device->subsystem_resolved = true;
        }

        if (device->subsystem_errno < 0)
                return device->subsystem_errno;

        if (ret)
                *ret = device->subsystem;
        return 0;
}

int sd_device_get_driver_subsystem(sd_device *device, const char **ret) {
        size_t bus_len;

        if (!device)
                return -EINVAL;

        if (!device->driver_subsystem_resolved) {
                bus_len = driver_bus_len(device->devpath);

                if (bus_len == 0)
                        device->driver_subsystem_errno = -ENOENT;
                else {
                        device->driver_subsystem = strndup(device->devpath + 5, bus_len);
                        device->driver_subsystem_errno = device->driver_subsystem ? 0 : -ENOMEM;
                }

                device->driver_subsystem_resolved = true;
        }

        if (device->driver_subsystem_errno < 0)
                return device->driver_subsystem_errno;

        if (ret)
                *ret = device->driver_subsystem;
        return 0;
}

int sd_device_get_driver(sd_device *device, const char **ret) {
        char path[PATH_MAX];

        if (!device)
                return -EINVAL;

        if (!device->driver_resolved) {
                if ((size_t) snprintf(path, sizeof(path), "%s/driver", device->syspath) >= sizeof(path))
                        device->driver_errno = -ENAMETOOLONG;
                else {
                        device->driver = readlink_basename(path);
                        device->driver_errno = device->driver ? 0 : -ENOENT;
                }

                device->driver_resolved = true;
        }

        if (device->driver_errno < 0)
                return device->driver_errno;

        if (ret)
                *ret = device->driver;
        return 0;
}

static void resolve_sysname(sd_device *device) {
        const char *raw = last_component(device->syspath);
        char *s = strdup(raw);
        size_t len, digits;

        if (s) {
                /* The kernel's own block-name quirk: '!' in a directory name
                 * stands for '/', e.g. "cciss!c0d0" -> "cciss/c0d0". */
                for (char *p = s; *p; p++)
                        if (*p == '!')
                                *p = '/';
        }
        device->sysname = s;

        if (s) {
                len = strlen(s);
                digits = 0;
                while (digits < len && isdigit((unsigned char) s[len - 1 - digits]))
                        digits++;

                if (digits > 0 && digits < len)
                        device->sysnum = strndup(s + len - digits, digits);
        }

        device->sysname_resolved = true;
}

int sd_device_get_sysname(sd_device *device, const char **ret) {
        if (!device)
                return -EINVAL;

        if (!device->sysname_resolved)
                resolve_sysname(device);

        if (!device->sysname)
                return -ENOMEM;

        if (ret)
                *ret = device->sysname;
        return 0;
}

int sd_device_get_sysnum(sd_device *device, const char **ret) {
        if (!device)
                return -EINVAL;

        if (!device->sysname_resolved)
                resolve_sysname(device);

        if (!device->sysnum)
                return -ENOENT;

        if (ret)
                *ret = device->sysnum;
        return 0;
}
