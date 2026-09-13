/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Private helpers shared across libudev-*.c. Never installed; nothing here
 * is part of the ABI, and none of it is named udev_* so the version-script
 * generator's leak check keeps it behind `local: *`.
 *
 * Only public sd-device entry points are reachable from here: the shared
 * object links libsystemd.so.0, not the compat archive, so the wrapper
 * stays as thin as upstream's own libudev is over libsystemd-shared.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "libudev.h"
#include "sd-device.h"

struct udev {
        unsigned n_ref;
        void *userdata;
        int log_priority;
};

/*
 * A name/value list handed out entry by entry. `unique` lists (properties,
 * tags, sysattrs, devlinks, hwdb properties) replace on duplicate name and
 * come out sorted by name; a non-unique list (the enumeration result) keeps
 * insertion order. Entries stay valid until the next clear/free of the
 * list, which every regenerating getter does before rebuilding.
 */
struct udev_list;

struct udev_list *libudev_list_new(bool unique);
void libudev_list_free(struct udev_list *list);
void libudev_list_clear(struct udev_list *list);
struct udev_list_entry *libudev_list_add(struct udev_list *list, const char *name, const char *value);
struct udev_list_entry *libudev_list_first(struct udev_list *list);
size_t libudev_list_size(struct udev_list *list);
const char *libudev_list_lookup(struct udev_list *list, const char *name);

/* Wraps `device`, taking a reference on it. NULL with errno on OOM. */
struct udev_device *libudev_device_new(struct udev *udev, sd_device *device);
sd_device *libudev_device_get_sd_device(struct udev_device *udev_device);
