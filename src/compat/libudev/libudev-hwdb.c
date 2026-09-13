/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udev_hwdb over sd_hwdb. sd_hwdb_new() reports -ENOENT here (sd-hwdb.c
 * says why no hwdb.bin ever exists on this image), so udev_hwdb_new()
 * returns NULL with that errno -- the same result real libudev gives on a
 * system without a compiled hwdb, and the case every consumer already
 * handles.
 */

#include "libudev.h"

#include <errno.h>
#include <stdlib.h>

#include "libudev-internal.h"
#include "sd-hwdb.h"

struct udev_hwdb {
        unsigned n_ref;
        sd_hwdb *hwdb;
        struct udev_list *properties;
};

struct udev_hwdb *udev_hwdb_new(struct udev *udev) {
        sd_hwdb *hwdb = NULL;
        struct udev_hwdb *h;
        int r;

        (void) udev;

        r = sd_hwdb_new(&hwdb);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        h = calloc(1, sizeof(*h));
        if (!h) {
                sd_hwdb_unref(hwdb);
                errno = ENOMEM;
                return NULL;
        }
        h->properties = libudev_list_new(true);
        if (!h->properties) {
                sd_hwdb_unref(hwdb);
                free(h);
                errno = ENOMEM;
                return NULL;
        }
        h->n_ref = 1;
        h->hwdb = hwdb;
        return h;
}

struct udev_hwdb *udev_hwdb_ref(struct udev_hwdb *hwdb) {
        if (!hwdb)
                return NULL;
        hwdb->n_ref++;
        return hwdb;
}

struct udev_hwdb *udev_hwdb_unref(struct udev_hwdb *hwdb) {
        if (!hwdb)
                return NULL;
        if (--hwdb->n_ref > 0)
                return NULL;
        sd_hwdb_unref(hwdb->hwdb);
        libudev_list_free(hwdb->properties);
        free(hwdb);
        return NULL;
}

struct udev_list_entry *udev_hwdb_get_properties_list_entry(
                struct udev_hwdb *hwdb, const char *modalias, unsigned flags) {
        const char *key, *value;
        struct udev_list_entry *e;

        (void) flags;

        if (!hwdb || !modalias) {
                errno = EINVAL;
                return NULL;
        }

        libudev_list_clear(hwdb->properties);
        SD_HWDB_FOREACH_PROPERTY(hwdb->hwdb, modalias, key, value)
        if (!libudev_list_add(hwdb->properties, key, value)) {
                errno = ENOMEM;
                return NULL;
        }

        e = libudev_list_first(hwdb->properties);
        if (!e)
                errno = ENODATA;
        return e;
}
