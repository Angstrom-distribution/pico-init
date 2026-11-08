/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The DOS partition table's disk signature, for /dev/disk/by-partuuid on a
 * disk without a GPT.
 *
 * An MBR partition has no UUID of its own. The kernel makes one up from the
 * 32-bit disk signature at offset 440 and the partition number,
 * "%08x-%02x" (block/partitions/msdos.c), and that is what root=PARTUUID=
 * matches and what blkid reports, so the link has to be spelled the same
 * way. Everything else about the table -- where the partitions are, logical
 * ones in extended partitions -- the kernel has already worked out; devd takes
 * the partition numbers from sysfs and needs only the signature.
 *
 * The sector is trusted on the kernel's own terms: the 0x55aa magic, every
 * boot indicator 0x00 or 0x80 (a FAT boot sector also ends in 0x55aa), and no
 * GPT protective entry (type 0xee), which belongs to gpt-scan.c.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define DEVD_MBR_SECTOR_SIZE 512
#define DEVD_MBR_SIGNATURE_OFF 440
#define DEVD_MBR_TABLE_OFF 446
#define DEVD_MBR_ENTRY_SIZE 16
#define DEVD_MBR_ENTRIES 4
#define DEVD_MBR_MAGIC_OFF 510
#define DEVD_MBR_TYPE_GPT_PROTECTIVE 0xeeu

/* "12345678-05" plus its NUL, with room for a three-digit partition number. */
#define DEVD_MBR_PARTUUID_MAX 13

/*
 * Decode a sector that has already been read. 1 with *ret set when it is a
 * DOS partition table, 0 when it is not, -EINVAL for a buffer shorter than a
 * sector.
 */
int devd_mbr_decode(const uint8_t *sector, size_t n, uint32_t *ret);

/* The same, reading sector 0 of `device` first. 1/0, or -errno when it
 * cannot be opened or read; a device shorter than a sector is 0. */
int devd_mbr_read(const char *device, uint32_t *ret);

/* The kernel's PARTUUID for partition `nr` of a disk with `signature`.
 * 0, or -ENAMETOOLONG when `size` is too small. */
int devd_mbr_partuuid(uint32_t signature, unsigned nr, char *ret, size_t size);
