/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_device_get_devlink_first()/_next(): the /dev/disk/by-* and
 * /dev/serial/by-id symlinks pointing at this device, found by scanning
 * exactly the directories devd-symlink.h maintains rather than by tracking
 * what devd itself created (this is a different process; it does not share
 * devd's memory).
 *
 * This is a documented partial: a SYMLINK+= rule link devd created
 * somewhere else entirely (devd-rules.h) is invisible here, because devd
 * tracks those only in its own memory (devd.h's DevdRuleLink), not
 * anywhere on disk this scan can read. Full coverage needs devd to persist
 * that list somewhere -- not scoped here.
 */

#include "sd-device.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "device-internal.h"

#define DEV_ROOT_DEFAULT "/dev"

static char dev_root_buf[PATH_MAX] = DEV_ROOT_DEFAULT;

const char *device_dev_root(void) {
        return dev_root_buf;
}

void device_set_dev_root_for_tests(const char *root) {
        if (!root)
                root = DEV_ROOT_DEFAULT;

        (void) snprintf(dev_root_buf, sizeof(dev_root_buf), "%s", root);
}

/* The five by-* families plus their rule-link home, in the order devd-
 * symlink.h documents them. */
static const char * const devlink_families[] = {
        "disk/by-partuuid", "disk/by-partlabel", "disk/by-uuid",
        "disk/by-label",    "disk/by-id",        "serial/by-id",
};

static int devlinks_append(sd_device *d, const char *path) {
        char **n = realloc(d->devlinks, (d->n_devlinks + 1) * sizeof(*n));

        if (!n)
                return -ENOMEM;
        d->devlinks = n;

        d->devlinks[d->n_devlinks] = strdup(path);
        if (!d->devlinks[d->n_devlinks])
                return -ENOMEM;

        d->n_devlinks++;
        return 0;
}

static void scan_family(sd_device *d, const char *dev_root, const char *family, const char *devname_target) {
        char dirpath[PATH_MAX];
        DIR *dh;
        struct dirent *de;

        if ((size_t) snprintf(dirpath, sizeof(dirpath), "%s/%s", dev_root, family) >= sizeof(dirpath))
                return;

        dh = opendir(dirpath);
        if (!dh)
                return;

        while ((de = readdir(dh))) {
                char linkpath[PATH_MAX], resolved[PATH_MAX];

                if (de->d_name[0] == '.')
                        continue;

                if ((size_t) snprintf(linkpath, sizeof(linkpath), "%s/%s", dirpath, de->d_name) >=
                    sizeof(linkpath))
                        continue;

                if (!realpath(linkpath, resolved))
                        continue;

                if (strcmp(resolved, devname_target) == 0)
                        (void) devlinks_append(d, linkpath);
        }

        closedir(dh);
}

static void devlinks_scan(sd_device *d) {
        const char *devname, *dev_root = device_dev_root();
        char remapped[PATH_MAX], resolved_devname[PATH_MAX];
        const char *target;
        size_t i;

        d->devlinks_scanned = true;

        if (sd_device_get_devname(d, &devname) < 0)
                return; /* no devnode: nothing can link to it */

        /*
         * sd_device_get_devname() always returns a literal "/dev/..."
         * path (that prefix is the real DEVNAME contract, not overridable
         * -- see device-uevent.c). The actual on-disk node a test fixture
         * put down lives under device_dev_root() instead, so the target
         * this scan compares against has to go through the same remap:
         * production has dev_root == "/dev" and this is a no-op there.
         */
        if ((size_t) snprintf(remapped, sizeof(remapped), "%s%s", dev_root, devname + 4) >= sizeof(remapped))
                return;

        target = realpath(remapped, resolved_devname) ? resolved_devname : remapped;

        for (i = 0; i < sizeof(devlink_families) / sizeof(devlink_families[0]); i++)
                scan_family(d, dev_root, devlink_families[i], target);
}

const char *sd_device_get_devlink_first(sd_device *device) {
        if (!device)
                return NULL;

        if (!device->devlinks_scanned)
                devlinks_scan(device);

        device->devlink_iter = 0;
        if (device->n_devlinks == 0)
                return NULL;

        device->devlink_iter = 1;
        return device->devlinks[0];
}

const char *sd_device_get_devlink_next(sd_device *device) {
        if (!device || device->devlink_iter >= device->n_devlinks)
                return NULL;

        return device->devlinks[device->devlink_iter++];
}
