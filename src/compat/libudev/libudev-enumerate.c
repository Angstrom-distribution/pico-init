/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udev_enumerate over sd_device_enumerator. The scan runs when the
 * consumer asks for it (udev_enumerate_scan_*()), or on the first
 * get_list_entry() without one, which is upstream's lazy default; the
 * result is a plain syspath list in the enumerator's own order, plus
 * anything added by hand through udev_enumerate_add_syspath().
 */

#include "libudev.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "libudev-internal.h"

enum scan_kind {
        SCAN_NONE,
        SCAN_DEVICES,
        SCAN_SUBSYSTEMS,
};

struct udev_enumerate {
        struct udev *udev;
        unsigned n_ref;
        sd_device_enumerator *enumerator;

        struct udev_list *devices;
        enum scan_kind scanned;

        char **added; /* canonical syspaths from add_syspath() */
        size_t n_added;
};

static void *fail_errno(int r) {
        errno = -r;
        return NULL;
}

struct udev_enumerate *udev_enumerate_new(struct udev *udev) {
        struct udev_enumerate *e;
        int r;

        e = calloc(1, sizeof(*e));
        if (!e)
                return fail_errno(-ENOMEM);

        r = sd_device_enumerator_new(&e->enumerator);
        if (r < 0) {
                free(e);
                return fail_errno(r);
        }
        (void) sd_device_enumerator_allow_uninitialized(e->enumerator);

        e->devices = libudev_list_new(false);
        if (!e->devices) {
                sd_device_enumerator_unref(e->enumerator);
                free(e);
                return fail_errno(-ENOMEM);
        }

        e->n_ref = 1;
        e->udev = udev;
        return e;
}

struct udev_enumerate *udev_enumerate_ref(struct udev_enumerate *udev_enumerate) {
        if (!udev_enumerate)
                return NULL;
        udev_enumerate->n_ref++;
        return udev_enumerate;
}

struct udev_enumerate *udev_enumerate_unref(struct udev_enumerate *udev_enumerate) {
        size_t i;

        if (!udev_enumerate)
                return NULL;
        if (--udev_enumerate->n_ref > 0)
                return NULL;

        libudev_list_free(udev_enumerate->devices);
        sd_device_enumerator_unref(udev_enumerate->enumerator);
        for (i = 0; i < udev_enumerate->n_added; i++)
                free(udev_enumerate->added[i]);
        free(udev_enumerate->added);
        free(udev_enumerate);
        return NULL;
}

struct udev *udev_enumerate_get_udev(struct udev_enumerate *udev_enumerate) {
        if (!udev_enumerate)
                return fail_errno(-EINVAL);
        return udev_enumerate->udev;
}

/* --- matches: each one invalidates a previous scan, as upstream's do --- */

static int match_done(struct udev_enumerate *e, int r) {
        if (r < 0)
                return r;
        e->scanned = SCAN_NONE;
        return 0;
}

int udev_enumerate_add_match_subsystem(struct udev_enumerate *udev_enumerate, const char *subsystem) {
        if (!udev_enumerate)
                return -EINVAL;
        if (!subsystem)
                return 0;
        return match_done(udev_enumerate,
                          sd_device_enumerator_add_match_subsystem(udev_enumerate->enumerator, subsystem, 1));
}

int udev_enumerate_add_nomatch_subsystem(struct udev_enumerate *udev_enumerate, const char *subsystem) {
        if (!udev_enumerate)
                return -EINVAL;
        if (!subsystem)
                return 0;
        return match_done(udev_enumerate,
                          sd_device_enumerator_add_match_subsystem(udev_enumerate->enumerator, subsystem, 0));
}

int udev_enumerate_add_match_sysattr(struct udev_enumerate *udev_enumerate, const char *sysattr, const char *value) {
        if (!udev_enumerate)
                return -EINVAL;
        if (!sysattr)
                return 0;
        return match_done(udev_enumerate,
                          sd_device_enumerator_add_match_sysattr(udev_enumerate->enumerator, sysattr, value, 1));
}

int udev_enumerate_add_nomatch_sysattr(struct udev_enumerate *udev_enumerate, const char *sysattr, const char *value) {
        if (!udev_enumerate)
                return -EINVAL;
        if (!sysattr)
                return 0;
        return match_done(udev_enumerate,
                          sd_device_enumerator_add_match_sysattr(udev_enumerate->enumerator, sysattr, value, 0));
}

int udev_enumerate_add_match_property(struct udev_enumerate *udev_enumerate, const char *property, const char *value) {
        if (!udev_enumerate)
                return -EINVAL;
        if (!property)
                return 0;
        return match_done(udev_enumerate,
                          sd_device_enumerator_add_match_property(udev_enumerate->enumerator, property, value));
}

int udev_enumerate_add_match_sysname(struct udev_enumerate *udev_enumerate, const char *sysname) {
        if (!udev_enumerate)
                return -EINVAL;
        if (!sysname)
                return 0;
        return match_done(udev_enumerate, sd_device_enumerator_add_match_sysname(udev_enumerate->enumerator, sysname));
}

int udev_enumerate_add_match_tag(struct udev_enumerate *udev_enumerate, const char *tag) {
        if (!udev_enumerate)
                return -EINVAL;
        if (!tag)
                return 0;
        return match_done(udev_enumerate, sd_device_enumerator_add_match_tag(udev_enumerate->enumerator, tag));
}

int udev_enumerate_add_match_parent(struct udev_enumerate *udev_enumerate, struct udev_device *parent) {
        if (!udev_enumerate)
                return -EINVAL;
        if (!parent)
                return 0;
        return match_done(udev_enumerate,
                          sd_device_enumerator_add_match_parent(udev_enumerate->enumerator,
                                                                libudev_device_get_sd_device(parent)));
}

int udev_enumerate_add_match_is_initialized(struct udev_enumerate *udev_enumerate) {
        if (!udev_enumerate)
                return -EINVAL;
        /* Every device here is initialized (sd_device_get_is_initialized()
         * says why), so the filter admits everything and changes nothing. */
        return 0;
}

int udev_enumerate_add_syspath(struct udev_enumerate *udev_enumerate, const char *syspath) {
        sd_device *device = NULL;
        const char *canonical;
        char **n, *dup;
        int r;

        if (!udev_enumerate)
                return -EINVAL;
        if (!syspath)
                return 0;

        r = sd_device_new_from_syspath(&device, syspath);
        if (r < 0)
                return r;
        r = sd_device_get_syspath(device, &canonical);
        if (r < 0) {
                sd_device_unref(device);
                return r;
        }
        dup = strdup(canonical);
        sd_device_unref(device);
        if (!dup)
                return -ENOMEM;

        n = realloc(udev_enumerate->added, (udev_enumerate->n_added + 1) * sizeof(*n));
        if (!n) {
                free(dup);
                return -ENOMEM;
        }
        udev_enumerate->added = n;
        udev_enumerate->added[udev_enumerate->n_added++] = dup;
        udev_enumerate->scanned = SCAN_NONE;
        return 0;
}

/* --- scanning --- */

static int scan(struct udev_enumerate *e, enum scan_kind kind) {
        sd_device *d;
        size_t i;

        libudev_list_clear(e->devices);

        for (d = kind == SCAN_DEVICES ? sd_device_enumerator_get_device_first(e->enumerator)
                                      : sd_device_enumerator_get_subsystem_first(e->enumerator);
             d;
             d = kind == SCAN_DEVICES ? sd_device_enumerator_get_device_next(e->enumerator)
                                      : sd_device_enumerator_get_subsystem_next(e->enumerator)) {
                const char *syspath;
                int r;

                r = sd_device_get_syspath(d, &syspath);
                if (r < 0)
                        return r;
                if (!libudev_list_add(e->devices, syspath, NULL))
                        return -ENOMEM;
        }

        for (i = 0; i < e->n_added; i++) {
                struct udev_list_entry *le;
                bool present = false;

                for (le = libudev_list_first(e->devices); le; le = udev_list_entry_get_next(le))
                        if (strcmp(udev_list_entry_get_name(le), e->added[i]) == 0) {
                                present = true;
                                break;
                        }
                if (!present && !libudev_list_add(e->devices, e->added[i], NULL))
                        return -ENOMEM;
        }

        e->scanned = kind;
        return 0;
}

int udev_enumerate_scan_devices(struct udev_enumerate *udev_enumerate) {
        if (!udev_enumerate)
                return -EINVAL;
        return scan(udev_enumerate, SCAN_DEVICES);
}

int udev_enumerate_scan_subsystems(struct udev_enumerate *udev_enumerate) {
        if (!udev_enumerate)
                return -EINVAL;
        return scan(udev_enumerate, SCAN_SUBSYSTEMS);
}

struct udev_list_entry *udev_enumerate_get_list_entry(struct udev_enumerate *udev_enumerate) {
        struct udev_list_entry *e;

        if (!udev_enumerate)
                return fail_errno(-EINVAL);

        if (udev_enumerate->scanned == SCAN_NONE) {
                int r = scan(udev_enumerate, SCAN_DEVICES);

                if (r < 0)
                        return fail_errno(r);
        }

        e = libudev_list_first(udev_enumerate->devices);
        if (!e)
                return fail_errno(-ENODATA);
        return e;
}
