/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Reading the GPT partition table, and the one thing PID 1 does with it.
 *
 * Nothing else on a pico image can answer "what is this partition". The kernel's
 * own GPT parser (block/partitions/efi.c) creates the partition block devices
 * and stops there -- the partition type GUID is never surfaced in sysfs, and the
 * property real systemd's gpt-auto generator reads (ID_PART_ENTRY_TYPE) is
 * populated by udev's own GPT probe. These images run devtmpfs-only with no
 * device manager at all, so reading the table here is not a dependency-avoidance
 * preference: it is the only mechanism that can work.
 *
 * The format makes that cheap. A protective MBR at LBA 0 which nothing here
 * looks at, a fixed-layout 92-byte header at LBA 1 behind an "EFI PART" magic,
 * and a flat array of fixed-size entries -- no per-filesystem superblock zoo,
 * no probe ladder. Everything below is offset arithmetic over two read buffers.
 *
 * Two halves live in this file, and the seam between them is deliberate:
 *
 *  - gpt_scan() and its helpers are the parser, and are the reusable half. The
 *    hotplug daemon this project has scoped but not built (plans/31, Part 2)
 *    is the second consumer, for removable-media policy and for the
 *    /dev/disk/by-partuuid|by-partlabel families that come out of the same
 *    entry this already reads.
 *  - dps_scan() is PID 1's own boot-time consumer: find the boot disk, find the
 *    Discoverable-Partitions-Spec swap partitions on it, swapon() them. When
 *    that second consumer arrives, this is the half that stays behind.
 *
 * Everything here is best-effort in mount-setup.c's sense. A disk with no GPT,
 * a corrupt header, an unreadable device: all of them are a boot that continues
 * without swap, never a boot that stops. The spec says as much itself -- DPS
 * "has no effect on non-GPT systems" -- and a board that reaches a console is
 * worth more than one that is right about swap.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * A GPT GUID exactly as it sits on disk: mixed-endian, the first three fields
 * little-endian and the last two big-endian. Kept as raw bytes rather than
 * decoded fields because every use here is a comparison or a print, and
 * decoding would only add a place for the byte order to be got wrong twice.
 */
typedef struct GptGuid {
        uint8_t bytes[16];
} GptGuid;

/* "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" plus its NUL. */
#define GPT_GUID_STRING_MAX 37

/*
 * The Discoverable Partitions Specification's Linux swap type,
 * 0657fd6d-a4ab-43c4-84e5-0933c84b4f4f (uapi-group.org). Architecture
 * independent, unlike the root GUIDs -- there is one swap type for every
 * machine this project will ever build.
 */
extern const GptGuid gpt_type_linux_swap;

/*
 * Partition attribute flags, from the type-specific half (bits 48-63) of the
 * entry's attribute field. Both are DPS-defined rather than pico inventions.
 *
 * NO_AUTO is honoured by gpt_scan() itself, not left to callers -- see below.
 * READ_ONLY is parsed and reported and nothing more: it is meaningful for the
 * filesystem partitions a future Mount consumer would care about, and for swap
 * it only predicts the swapon() failure that would then be logged anyway.
 */
#define GPT_ATTR_READ_ONLY (UINT64_C(1) << 60)
#define GPT_ATTR_NO_AUTO (UINT64_C(1) << 63)

typedef struct GptPartition {
        /*
         * 1-based index of the entry in the array, which is also the number
         * the kernel gives the partition device -- vda2 is entry 2. Used to
         * find the device node, never to construct its name: /dev/vda2 and
         * /dev/mmcblk0p2 are the same partition number under two naming rules,
         * so the name comes from sysfs and only the number is matched.
         */
        unsigned nr;

        GptGuid type;
        GptGuid uuid; /* the unique partition GUID: udev's PARTUUID */

        uint64_t first_lba;
        uint64_t last_lba;
        uint64_t attributes;
} GptPartition;

/*
 * Scan `device` for partitions whose type GUID is `type`.
 *
 * On success *ret is a malloc'd array of *ret_n entries in table order, which
 * the caller frees; *ret_n may be 0, in which case *ret is NULL.
 *
 * Returns 1 when a valid GPT was read, 0 when there is no usable partition
 * table there at all (no magic, a bad CRC, a header claiming something
 * impossible -- all logged, none of them an error), or -errno when the device
 * itself could not be read or memory ran out.
 *
 * Entries carrying GPT_ATTR_NO_AUTO are dropped rather than returned. The spec
 * requires a matching partition to be skipped when that bit is set, and every
 * consumer of a type-GUID search is by definition an automatic one; a future
 * enumerate-everything caller (partition symlinks, say) wants its own entry
 * point rather than a flag here.
 */
int gpt_scan(const char *device, const GptGuid *type, GptPartition **ret, size_t *ret_n);

/* Format `guid` into `buf` in the canonical 8-4-4-4-12 spelling. Returns buf. */
char *gpt_guid_to_string(const GptGuid *guid, char buf[static GPT_GUID_STRING_MAX]);

/*
 * CRC-32 (the reflected IEEE 802.3 one the GPT header and entry array are
 * checksummed with). Exposed because the header's own integrity check is the
 * only thing standing between a corrupt table and a swapon() of the wrong
 * blocks, and a checksum implementation nothing can test is worth very little.
 */
uint32_t gpt_crc32(const void *data, size_t n);

/*
 * The whole-disk device backing the mounted root filesystem, read out of
 * `mountinfo` (/proc/self/mountinfo in production; a fixture in tests).
 *
 * `ret_node` gets the device node path ("/dev/vda"), `ret_sysfs` the sysfs
 * directory of that disk ("/sys/devices/.../block/vda"), which is what turns a
 * partition number back into a device node. Either may be NULL.
 *
 * Returns 0, or -errno -- notably -ENOENT when the root filesystem is not on a
 * block device at all, which is an ordinary answer on an initramfs.
 */
int gpt_boot_disk(const char *mountinfo, char *ret_node, size_t node_size, char *ret_sysfs, size_t sysfs_size);

/*
 * Discoverable Partitions: activate the swap partitions of the boot disk.
 *
 * Called from main() after mount_setup() and dev_setup(), which is what makes
 * the three things this needs -- /proc for the mountinfo, /sys for the block
 * topology, /dev for the node to swapon() -- exist by the time it runs.
 *
 * Deliberately a plain function and not a unit type. The whole runtime action
 * is one swapon(2) per partition, so a Swap unit would buy only picoctl
 * visibility into it; that is a real thing to want later and a poor reason to
 * grow a fourth unit type now (plans/31, Slice B).
 *
 * Restricted to the boot disk on purpose, following upstream's own generator: a
 * removable card carrying its own swap-typed partition must not be swapped onto
 * just because it was plugged in.
 *
 * Returns the number of partitions activated (possibly 0), or -errno for a
 * failure worth a line in the log. A root filesystem with no block device under
 * it is not one of those -- that is an initramfs, and it returns 0.
 */
int dps_scan(void);
