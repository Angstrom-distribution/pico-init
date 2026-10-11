/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The /dev/disk/by-* symlink families and their lifecycle.
 *
 * Five families, three sources, one lifecycle:
 *
 *   by-partuuid, by-partlabel   the GPT entry gpt-scan.c already parsed
 *   by-uuid, by-label           the ext superblock ext-super.c reads
 *   by-id                       the sysfs bus walk devd-probe.c does
 *
 * Links are created when a device appears, removed when it goes, and
 * reconciled at coldplug so links left by an unclean stop do not outlive their
 * device.
 *
 * Removal reads the links on disk rather than remembering what was written:
 * devd may have been restarted or started after the device was already there,
 * so its memory is empty while the links are not. Reconcile is therefore a
 * special case of remove.
 *
 * `dev_root` is a parameter everywhere so tests can use a fixture directory
 * instead of the real /dev.
 */

#pragma once

#include <stddef.h>

#include "../ext-super.h"
#include "../gpt-scan.h"
#include "devd-probe.h"

/* Everything the five families need about one partition. An empty string means
 * "this family has no value for this device", and no link is made. */
typedef struct DevdLinks {
        char partuuid[GPT_GUID_STRING_MAX];
        char partlabel[GPT_PARTITION_NAME_MAX];
        char fsuuid[EXT_FS_UUID_MAX];
        char fslabel[EXT_FS_LABEL_MAX];
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

/*
 * The same three operations for a link a SYMLINK+= rule named, where the
 * path is whatever the rule said rather than one of the five known families.
 *
 * `link` is relative to `dev_root` and may name directories that do not exist
 * yet -- `serial/by-id/usb-FTDI_...` is the case this exists for. It may not
 * contain a `..` component or start with a slash: a rules file is data, devd
 * reads it as root, and a symlink name is the one field in it that turns into a
 * path.
 *
 * The relative target is computed from the link's own depth, so a link two
 * directories down points at `../../<devname>` -- the same relative form the
 * by-* families use, and for the same reason.
 */
int devd_symlink_create_named(const char *dev_root, const char *devname, const char *link);

/* Remove one such link, and any directory it leaves empty below dev_root. 0,
 * or -errno; a link that is not there is not an error. */
int devd_symlink_remove_named(const char *dev_root, const char *link);

/*
 * Remove every dangling symlink under <dev_root>/<subdir>, recursively.
 *
 * The rule-created half of what devd_symlink_reconcile() does for the by-*
 * families, and needed for the same reason: devd can be stopped while a device
 * is present and started after it is gone, and in that window its in-memory
 * record of what it created is empty while the links are still on disk.
 * Returns the number removed, or -errno.
 */
int devd_symlink_sweep_dangling(const char *dev_root, const char *subdir);
