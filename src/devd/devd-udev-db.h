/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The udev on-disk database, /run/udev/data/<device-id>, written for the one
 * family of properties devd computes itself: devd-input-id.c's ID_INPUT*.
 *
 * The format is an interface, not code: one record per line, a type letter, a
 * colon and a value. devd writes exactly three of upstream's record types, in
 * the order upstream's own writer (device_update_db(), device-private.c:865 at
 * systemd 041e70d7) emits them -- `I:` the CLOCK_MONOTONIC usec the device was
 * processed at, `E:KEY=VALUE` once per property, `V:` the database format
 * version last. Nothing here is copied from that LGPL-2.1-or-later file; the
 * line grammar is what its reader (device_read_db_internal_filename(),
 * sd-device.c:1817) accepts, reimplemented from the format alone, which is the
 * same policy sd-device.h already states for the whole compat layer.
 *
 * Why a real file rather than a devd-private channel: every consumer that
 * wants ID_INPUT_* -- Xorg's config/udev, libinput, anything built on libudev
 * -- reads it through sd_device, and the compat layer's sd_device overlays
 * this file onto the uevent properties (src/compat/libsystemd/device-db.c)
 * exactly where upstream does. One writer, one reader, the upstream path and
 * upstream filename between them, and no consumer change.
 *
 * Deliberately absent, every one of them a record type devd has nothing to put
 * in: `S:` (devlinks -- the compat layer scans /dev for those), `L:` (link
 * priority), `G:`/`Q:` (tags; devd has no TAG+=), `W:` (watch). And never any
 * of /run/udev/control, /run/udev/queue or /run/udev/tags/: software takes
 * `control` to mean a udevd is running, and libudev-queue.c answers that
 * question from it on purpose.
 */

#pragma once

#include <stddef.h>

#include "../util.h"

typedef struct DevdRuleDevice DevdRuleDevice;

#define DEVD_UDEV_DB_ROOT "/run/udev/data"

/* Upstream's LATEST_UDEV_DATABASE_VERSION; what the closing `V:` line says. */
#define DEVD_UDEV_DB_VERSION 1

/* "c<major>:<minor>", "n<ifindex>" or "+<subsystem>:<sysname>". The last is
 * the long one, and DEVD_SUBSYSTEM_MAX + DEVD_NAME_MAX fits well inside. */
#define DEVD_UDEV_DB_ID_MAX 128

/*
 * The device-id grammar the database is keyed by -- the filename under
 * db_root. The same three forms, in the same order of preference, as upstream
 * sd_device_get_device_id() (sd-device.c:1753) and pico's own
 * device_format_id(): a devnum when MAJOR and MINOR both parse ('b' for the
 * block subsystem, 'c' otherwise), else a positive IFINDEX, else subsystem and
 * sysname. Writer and reader have to agree on this byte for byte, or the file
 * is written under a name nobody looks up -- event3 is c13:67 on both sides,
 * input3 is +input:input3.
 *
 * Built from the device's property table only, which is what makes it work on
 * a remove event, after sysfs has already dropped the directory. 0, -ENOENT
 * when none of the three forms applies, or -ENAMETOOLONG.
 */
int devd_udev_db_id(const DevdRuleDevice *dev, char *ret, size_t size);

/*
 * Replace <db_root>/<id> with `n` KEY=VALUE properties, atomically: a fixed
 * temporary name in the same directory, then rename(2). db_root and its
 * parents are created as needed -- /run/udev does not exist on a pico image
 * until devd makes it.
 *
 * `usec_initialized` becomes the `I:` line; 0 or USEC_INFINITY leaves it out.
 * n == 0 deletes the file instead of writing an empty one (a stated divergence
 * from upstream, which keeps an empty file for a device with a devnum --
 * nothing pico serves can observe the difference, see
 * sd_device_get_is_initialized()).
 *
 * -EINVAL for an id that could name another file (empty, a '/', a leading
 * '.'), a key that is empty or carries '=' or a newline, or a value that
 * carries a newline: any of those would read back as a different record.
 * Otherwise 0 or -errno; a short or failed write leaves no file behind and
 * the previous one, if any, untouched.
 */
int devd_udev_db_write(
                const char *db_root,
                const char *id,
                usec_t usec_initialized,
                const char * const *keys,
                const char * const *values,
                size_t n);

/* Remove <db_root>/<id>. An absent file is success. 0, -EINVAL for an unsafe
 * id (same rule as above), or -errno. */
int devd_udev_db_delete(const char *db_root, const char *id);
