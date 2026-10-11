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
 * Two halves live in this file:
 *
 *  - gpt_scan()/gpt_scan_all() and their helpers are the parser, shared with
 *    devd (removable-media policy and the /dev/disk/by-partuuid|by-partlabel
 *    links come out of the same entries) and fstab-resolve.c.
 *  - dps_scan() is PID 1's own boot-time consumer: find the boot disk, find the
 *    Discoverable-Partitions-Spec swap partitions on it, swapon() them.
 *
 * Everything here is best-effort in mount-setup.c's sense. A disk with no GPT,
 * a corrupt header, an unreadable device: all of them are a boot that continues
 * without swap, never a boot that stops. The spec says as much itself -- DPS
 * "has no effect on non-GPT systems" -- and a board that reaches a console is
 * worth more than one that is right about swap.
 */

#pragma once

#include <stdbool.h>
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
 * A partition name (udev's PARTLABEL) decoded to UTF-8, plus its NUL. The name
 * field is the last 72 bytes of a 128-byte entry, so 36 UTF-16 code units; the
 * worst case is 36 non-surrogate code points at three UTF-8 bytes each.
 */
#define GPT_PARTITION_NAME_MAX 109

/*
 * The Discoverable Partitions Specification's Linux swap type,
 * 0657fd6d-a4ab-43c4-84e5-0933c84b4f4f (uapi-group.org). Architecture
 * independent, unlike the root GUIDs.
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

        /*
         * The entry's UTF-16LE name, decoded to UTF-8; "" when the partition
         * has none. Inline rather than a pointer so a GptPartition array stays
         * one allocation the caller frees with one free() -- the same reason
         * every other field here is by value.
         */
        char name[GPT_PARTITION_NAME_MAX];
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

/*
 * The entry point the comment above promises: every used entry of `device`'s
 * table, whatever its type, no-auto ones included and flagged rather than
 * dropped. Same return convention and same ownership as gpt_scan().
 *
 * devd wants this and gpt_scan() does not fit it. A hotplug daemon has to name
 * every partition it sees (by-partuuid, by-partlabel) before it decides what to
 * do with any of them, and it has to see a no-auto partition in order to
 * decide not to mount it -- a search that silently drops entries can only
 * answer questions about one type at a time.
 */
int gpt_scan_all(const char *device, GptPartition **ret, size_t *ret_n);

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
 * Everything the mounted root filesystem's own mountinfo line can say about
 * where it lives and how it is mounted, read out of `mountinfo`
 * (/proc/self/mountinfo in production; a fixture in tests).
 *
 * Every out-parameter is optional, so a caller asks for exactly the answers it
 * has a use for:
 *
 *  - `ret_node`   the containing DISK's device node ("/dev/vda"). Swap
 *                 discovery and devd's boot-disk policy both want the disk,
 *                 because what they go on to read is its partition table.
 *  - `ret_sysfs`  the sysfs directory of that disk
 *                 ("/sys/devices/.../block/vda"), which is what turns a
 *                 partition number back into a device node.
 *  - `ret_part_node`  the PARTITION's own node ("/dev/vda1") -- the block
 *                 device the root filesystem is actually on. A filesystem
 *                 checker has to be pointed at this and never at the disk.
 *                 Equal to `ret_node` when root is on a whole unpartitioned
 *                 device, which is the right answer for the same reason.
 *  - `ret_read_only`  whether root carries the "ro" mount option right now.
 *                 Set from the mountinfo line as soon as one is found, so it is
 *                 still filled in when the function goes on to return -ENOENT
 *                 for a root with no block device under it.
 *
 * Returns 0, or -errno -- notably -ENOENT when there is no "/" line at all or
 * when the root filesystem is not on a block device, which is an ordinary
 * answer on an initramfs.
 */
int gpt_boot_root(
                const char *mountinfo,
                char *ret_node,
                size_t node_size,
                char *ret_sysfs,
                size_t sysfs_size,
                char *ret_part_node,
                size_t part_size,
                bool *ret_read_only);

/*
 * The disk half of the above, which is what every caller predating the root
 * check wants: gpt_boot_root() with the partition node and the read-only flag
 * left unasked for. Kept as its own entry point rather than open-coded at those
 * call sites so that "the boot disk" stays one named idea.
 */
int gpt_boot_disk(const char *mountinfo, char *ret_node, size_t node_size, char *ret_sysfs, size_t sysfs_size);

/*
 * Discoverable Partitions: activate the swap partitions of the boot disk.
 *
 * Called from main() after mount_setup() and dev_setup(), which is what makes
 * the three things this needs -- /proc for the mountinfo, /sys for the block
 * topology, /dev for the node to swapon() -- exist by the time it runs.
 *
 * A plain function and not a unit type: the whole runtime action is one
 * swapon(2) per partition, so a Swap unit would buy only picoctl visibility.
 *
 * Restricted to the boot disk on purpose, following upstream's own generator: a
 * removable card carrying its own swap-typed partition must not be swapped onto
 * just because it was plugged in. And, like that generator, main() does not
 * call this at all when /etc/fstab has a swap line of its own.
 *
 * Returns the number of partitions activated (possibly 0), or -errno for a
 * failure worth a line in the log. A root filesystem with no block device under
 * it is not one of those -- that is an initramfs, and it returns 0.
 */
int dps_scan(void);
