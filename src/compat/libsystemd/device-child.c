/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_device_get_child_first()/_next(): a one-level directory walk of
 * syspath, not a recursive tree walk -- every immediate subdirectory that
 * itself has a "uevent" file is a child device; anything without one
 * (a symlink like "driver", a plain attribute directory like "power") is
 * not. lstat() rather than stat() is what excludes the symlinks: it never
 * follows them, so a symlinked attribute never reports as a directory here.
 */

#include "sd-device.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "device-internal.h"

static void children_scan(sd_device *d) {
        DIR *dh;
        struct dirent *de;

        d->children_scanned = true;

        dh = opendir(d->syspath);
        if (!dh)
                return;

        while ((de = readdir(dh))) {
                char path[PATH_MAX], uevent[PATH_MAX];
                struct stat st;
                sd_device *child = NULL;
                DeviceChild *n;

                if (de->d_name[0] == '.')
                        continue;

                if ((size_t) snprintf(path, sizeof(path), "%s/%s", d->syspath, de->d_name) >= sizeof(path))
                        continue;

                if (lstat(path, &st) < 0 || !S_ISDIR(st.st_mode))
                        continue;

                if ((size_t) snprintf(uevent, sizeof(uevent), "%s/uevent", path) >= sizeof(uevent))
                        continue;
                if (stat(uevent, &st) < 0)
                        continue;

                if (device_new_from_syspath_internal(&child, path, false) < 0)
                        continue;

                n = realloc(d->children, (d->n_children + 1) * sizeof(*n));
                if (!n) {
                        sd_device_unref(child);
                        break;
                }
                d->children = n;

                d->children[d->n_children].suffix = strdup(de->d_name);
                d->children[d->n_children].device = child;
                if (!d->children[d->n_children].suffix) {
                        sd_device_unref(child);
                        break;
                }
                d->n_children++;
        }

        closedir(dh);
}

sd_device *sd_device_get_child_first(sd_device *device, const char **ret_suffix) {
        if (!device)
                return NULL;

        if (!device->children_scanned)
                children_scan(device);

        device->child_iter = 0;
        if (device->n_children == 0)
                return NULL;

        device->child_iter = 1;
        if (ret_suffix)
                *ret_suffix = device->children[0].suffix;
        return device->children[0].device;
}

sd_device *sd_device_get_child_next(sd_device *device, const char **ret_suffix) {
        if (!device || device->child_iter >= device->n_children)
                return NULL;

        if (ret_suffix)
                *ret_suffix = device->children[device->child_iter].suffix;
        return device->children[device->child_iter++].device;
}
