/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * From an fstab source to a device node: UUID=, LABEL=, PARTUUID= and
 * PARTLABEL=, and a bounded wait for a device that is not there yet.
 *
 * Upstream resolves these through udev's /dev/disk/by-* links. None exist when
 * the boot-time fstab pass runs: devd, which makes them, is a supervised
 * service the manager has not started yet, and it only ever links partitions
 * of GPT disks, and only ext filesystems by UUID and label. So PID 1 resolves
 * them itself, the way the links would have: it walks the block devices the
 * kernel lists in sysfs and reads each one.
 *
 *  - PARTUUID=/PARTLABEL= come from the GPT partition entries of every disk
 *    (gpt-scan.c), matched back to the partition device by number through
 *    sysfs, never by pasting a number onto a disk name.
 *  - UUID=/LABEL= come from the filesystem or swap signature on every
 *    partition, and on every whole disk that has no partitions (fsid.h). The
 *    line's type field picks the one reader to use; "auto" tries them all.
 *
 * Comparison is exact, byte for byte, as a by-* link name lookup is. When two
 * devices carry the same identifier -- a cloned card, say -- the first in
 * sysfs name order wins and the duplicate is logged, which is at least
 * deterministic where upstream's answer depends on uevent timing.
 *
 * A source spelled as one of those links, /dev/disk/by-uuid/..., is resolved
 * as the tag it names (udev's \xNN escapes undone), for the same reason: the
 * link will not exist yet.
 *
 * Only the kernel names udev would make those links for are read (the
 * allowlist in systemd's 60-persistent-storage.rules, plus device-mapper and
 * md): not ram disks, and not MTD flash through mtdblock, which devd leaves
 * alone too -- raw NAND is slow to read and carries no filesystem these
 * readers know. Neither is a device with nothing behind it (size 0: an
 * unattached loop device, an empty card reader).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "fsid.h"
#include "fstab.h"
#include "util.h"

typedef enum FstabTag {
        FSTAB_TAG_NONE, /* a path, or anything else that is not a tag */
        FSTAB_TAG_UUID,
        FSTAB_TAG_LABEL,
        FSTAB_TAG_PARTUUID,
        FSTAB_TAG_PARTLABEL,
        _FSTAB_TAG_MAX,
} FstabTag;

/* "UUID", "LABEL", ...; NULL for FSTAB_TAG_NONE. */
const char *fstab_tag_to_string(FstabTag t);

/*
 * What `what` names. For a tag, or a /dev/disk/by-{uuid,label,partuuid,
 * partlabel}/ path, the identifier is copied into `value` (link escapes
 * undone) and the tag returned; FSTAB_TAG_NONE otherwise, `value` untouched.
 * A tag with an empty value is not one.
 */
FstabTag fstab_source_tag(const char *what, char *value, size_t size);

/* Where to look. NULL members mean "/sys" and "/dev". `scans`, when set,
 * counts the passes that actually read devices; tests. */
typedef struct FstabResolver {
        const char *sys_root;
        const char *dev_root;
        unsigned *scans;
} FstabResolver;

/*
 * Find the device carrying `tag`=`value`, with `hint` choosing the identity
 * reader for UUID=/LABEL= (ignored for the partition tags).
 *
 * 1 with the node in `ret`, 0 when no device carries it (yet), -EOPNOTSUPP
 * when `hint` names a type no reader handles, -EINVAL for a bad tag, or
 * -errno when sysfs itself cannot be listed.
 */
int fstab_resolve(const FstabResolver *r, FstabTag tag, const char *value, PicoFsKind hint, char *ret, size_t size);

/* The device wait's bounds: a short default, since PID 1 waits serially and
 * a missing card must not cost the boot a minute; and a ceiling, since PID 1
 * never waits forever whatever fstab says. */
#define FSTAB_DEVICE_TIMEOUT_DEFAULT (5 * USEC_PER_SEC)
#define FSTAB_DEVICE_TIMEOUT_MAX (90 * USEC_PER_SEC)

/*
 * How long to wait for `o`'s device: `dflt` without x-systemd.device-timeout=;
 * the given time within the ceiling; the ceiling for 0 and "infinity" --
 * which upstream both treat as "wait forever" -- and for anything longer.
 * *ret_clamped says the line asked for more than it gets.
 */
usec_t fstab_device_timeout(const FstabOptions *o, usec_t dflt, bool *ret_clamped);

/* Whether a source needs a device to appear before it can be used: a tag, or
 * a path under /dev. tmpfs, proc, bind sources and swap files do not. */
bool fstab_source_needs_device(const char *what);

/* The poll between looks, and the test seam that sees each one. */
#define FSTAB_DEVICE_POLL (100 * USEC_PER_MSEC)

typedef void (*fstab_poll_hook_t)(void *userdata, unsigned attempt);

/*
 * Resolve `what` -- a tag, a by-* link, or a plain path -- waiting up to
 * `timeout` for it to appear: re-stat()ed every FSTAB_DEVICE_POLL, or for a
 * tag re-resolved whenever the set of block devices (names, partitions, media
 * present) has changed since the last look. `hook`, when given, is called
 * before every look but the first.
 *
 * 1 with the node in `ret`, 0 when the time ran out, or a negative error from
 * fstab_resolve() that no amount of waiting would change.
 */
int fstab_wait_device(
                const FstabResolver *r,
                const char *what,
                PicoFsKind hint,
                usec_t timeout,
                fstab_poll_hook_t hook,
                void *userdata,
                char *ret,
                size_t size);
