/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Removable-media mount policy (plans/31, Part 2, Option A).
 *
 * A plain C function, deliberately, and that stays true once the H2 rule engine
 * exists: this needs the debounce state, the gpt-scan.c link and the
 * removable-versus-DPS distinction, none of which fit a stateless match line.
 * Rules trigger tools; for storage, this is the tool.
 *
 * The policy is not DPS, and the difference is the whole reason both exist.
 * PID 1's dps_scan() is scoped to the boot disk precisely so a card someone
 * plugged in cannot get its swap-typed partition swapped onto or its root-typed
 * partition adopted as anything. This is the other half: partitions on disks
 * that are NOT the boot disk, of a data type only, mounted somewhere clearly
 * marked as removable and nowhere else. The two share gpt-scan.c as a parser
 * and share nothing as policy, and the boot-disk exclusion here is what keeps
 * them from ever meeting -- without it the root partition would come up
 * mounted a second time under /media.
 *
 * v1 scope, as signed off in the plan: GPT-prepared media only, ext-family
 * filesystems only. An MBR card or a FAT volume is recognised as "not something
 * devd mounts" and logged once, not half-handled.
 *
 * The known stall: mount(2) on bad media can block for seconds inside the epoll
 * loop, and while it does, devd is deaf. The plan named forking or accepting it
 * as the two honest answers; v1 accepts it, and this is where that is written
 * down. It is bounded in practice by the boot-disk exclusion (the one device
 * guaranteed present is never mounted here) and by there being at most a
 * handful of slots on any pico board.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "../gpt-scan.h"

/*
 * The two type GUIDs devd will mount.
 *
 * 0fc63daf-8483-4772-8e79-3d69d8477de4 is the Discoverable Partitions Spec's
 * "Linux filesystem data", what this project's own mkfs-time tooling stamps.
 * ebd0a0a2-b9e5-4433-87c0-68b6b72699c7 is "Microsoft basic data", which is what
 * virtually every card partitioned by anything else carries. Root, swap, ESP
 * and the rest are absent on purpose: mounting a root-typed partition off a
 * card under /media is exactly the surprise the DPS cross-check exists to
 * prevent, and it would be no less surprising for coming from here.
 */
extern const GptGuid devd_type_linux_data;
extern const GptGuid devd_type_basic_data;

bool devd_media_is_data_type(const GptGuid *type);

/*
 * The mount point for a partition: <media_root>/<partlabel>, with the label
 * reduced to one safe path component -- and <media_root>/<devname> when there
 * is no usable label, so an unlabelled card still mounts somewhere predictable
 * rather than not at all.
 *
 * Separate from the mount itself so the naming rule can be tested without root:
 * this is the half that decides where a card shows up, which is the part a
 * person notices. Returns 0 or -errno.
 */
int devd_media_mount_point(
                const char *media_root, const char *partlabel, const char *devname, char *ret, size_t size);

/*
 * Mount `node` at its mount point, creating the directory. `read_only` comes
 * from the GPT entry's read-only attribute bit.
 *
 * A device `mountinfo` (NULL: /proc/self/mountinfo) shows mounted anywhere
 * else is not mounted a second time: PID 1's boot-time fstab pass mounts
 * non-boot-disk partitions too, and so may an administrator. One already at
 * this very mount point is devd's own from before a restart, and is adopted.
 *
 * Returns 1 mounted (with *ret_dir set), 0 when there was no filesystem devd
 * mounts on it or it is mounted elsewhere, or -errno -- including when
 * `mountinfo` cannot be read, since guessing "not mounted" could stack a
 * second mount. Already-mounted (-EBUSY from the kernel) is reported as 1, not
 * as a failure: the outcome asked for is the outcome there is.
 */
int devd_media_mount(
                const char *media_root,
                const char *mountinfo,
                const char *node,
                const char *partlabel,
                const char *devname,
                bool read_only,
                char *ret_dir,
                size_t size);

/*
 * Unmount `dir` and remove it again, so a pulled card leaves nothing behind
 * under /media. Takes the directory rather than recomputing it from the label:
 * by the time a card is gone, its partition table is gone with it, and the only
 * record of where it was mounted is the one devd kept.
 *
 * Lazy, via MNT_DETACH: the card is already gone by the time this runs, a
 * process still holding a file on it will never finish, and a plain umount(2)
 * would fail forever and leak the mount. Returns 0, or -errno.
 */
int devd_media_unmount(const char *dir);
