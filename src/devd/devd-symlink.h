/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The /dev/disk/by-* symlink families and their lifecycle (plans/31, Part 2,
 * "Persistent symlinks").
 *
 * Five families, three sources, one lifecycle:
 *
 *   by-partuuid, by-partlabel   the GPT entry gpt-scan.c already parsed
 *   by-uuid, by-label           the ext superblock devd-probe.c reads
 *   by-id                       the sysfs bus walk devd-probe.c does
 *
 * The lifecycle is why this belongs to a daemon and not to PID 1's boot-time
 * scan. Creating links at boot is the easy third of it; the other two are
 * removing them when the card is pulled, and reconciling at coldplug so links
 * left behind by an unclean stop do not outlive the device they name. A
 * boot-only writer has no remove half at all, and /dev/disk/by-uuid slowly
 * fills with links to devices that are not there.
 *
 * Removal is deliberately done by reading the links rather than by remembering
 * what was written. devd can be restarted, killed, or started after the device
 * was already there, and in every one of those cases its memory of what it
 * created is empty while the links are still on disk. What is on disk is
 * therefore the authoritative record, and both remove and reconcile work from
 * it -- which also makes reconcile a plain special case of remove rather than a
 * second mechanism.
 *
 * `dev_root` is a parameter everywhere for the same reason devd-probe.c takes a
 * sys_root: creating and unlinking things under the test host's real /dev is
 * not a test anyone can run twice.
 */

#pragma once

#include <stddef.h>

#include "../gpt-scan.h"
#include "devd-probe.h"

/* Everything the five families need about one partition. An empty string means
 * "this family has no value for this device", and no link is made. */
typedef struct DevdLinks {
        char partuuid[GPT_GUID_STRING_MAX];
        char partlabel[GPT_PARTITION_NAME_MAX];
        char fsuuid[DEVD_FS_UUID_MAX];
        char fslabel[DEVD_FS_LABEL_MAX];
        char id[DEVD_ID_MAX]; /* already carries its -partN suffix */
} DevdLinks;

/*
 * udev's blkid_encode_string(): bytes outside [0-9A-Za-z#+-.:=@_] become
 * "\xNN". The same whitelist devd_sanitize() uses, escaping rather than
 * substituting -- because a label is being reproduced here, not named, and two
 * labels differing only in a space must not collapse onto one link.
 *
 * A '/' in a filesystem label is the case that makes this mandatory rather than
 * cosmetic: unescaped it would turn one link name into a path.
 *
 * Returns the length written, or 0 if nothing fit.
 */
size_t devd_symlink_escape(const char *in, char *out, size_t size);

/*
 * Create every family link `l` has a value for, pointing at <dev_root>/<devname>
 * as a relative "../../<devname>" -- the same relative form udev writes, so the
 * links stay correct if /dev is ever bind-mounted somewhere else.
 *
 * Replaces an existing link of the same name rather than failing on it: the
 * same UUID appearing on a new device means the old link is wrong, and leaving
 * it would be the one outcome worse than either alternative. Returns 0, or
 * -errno for a failure that stopped it creating any of them.
 */
int devd_symlink_create(const char *dev_root, const char *devname, const DevdLinks *l);

/*
 * Remove every by-* link pointing at `devname`, whatever created it. Returns
 * the number removed, or -errno.
 */
int devd_symlink_remove(const char *dev_root, const char *devname);

/*
 * Remove every by-* link whose target is not there. Called once at coldplug,
 * before anything is created, so a stale link from an unclean stop is gone
 * before the walk starts rather than being overwritten only if the same device
 * happens to come back. Returns the number removed, or -errno.
 */
int devd_symlink_reconcile(const char *dev_root);
