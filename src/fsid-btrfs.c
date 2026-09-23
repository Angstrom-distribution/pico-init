/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Btrfs: the primary superblock, 4 KiB at byte 65536, little-endian.
 *
 * "_BHRfS_M" at offset 0x40 of it is the magic. The superblock checksums
 * itself -- bytes 32 to 4095, into the first 32 bytes -- with an algorithm the
 * superblock names: CRC-32C for every filesystem made with defaults, xxhash64,
 * SHA-256 or BLAKE2b when mkfs.btrfs was asked for one. CRC-32C is verified,
 * as blkid verifies it. For the other three the magic and a non-zero sector
 * size are what is believed; blkid verifies xxhash64 and SHA-256 too and skips
 * BLAKE2b, and none of those three is worth carrying hash code into PID 1 for.
 * Zoned btrfs, whose superblock moves around its zone log, is not read.
 *
 * UUID is the filesystem's fsid (shared by every device of a multi-device
 * filesystem, which is what fstab names), in 8-4-4-4-12 form. LABEL is the
 * 256-byte label field, NUL-terminated.
 */

#include <errno.h>
#include <string.h>

#include "fsid.h"

#define BTRFS_SB_OFFSET 65536
#define BTRFS_SB_SIZE 4096

#define BTRFS_CSUM 0
#define BTRFS_CSUM_LEN 32
#define BTRFS_FSID 32
#define BTRFS_MAGIC_OFF 0x40
#define BTRFS_SECTORSIZE 144
#define BTRFS_CSUM_TYPE 196
#define BTRFS_LABEL 299
#define BTRFS_LABEL_LEN 256

#define BTRFS_CSUM_TYPE_CRC32C 0

int pico_fs_probe_btrfs(int fd, PicoFsId *ret) {
        static uint8_t sb[BTRFS_SB_SIZE];
        int r;

        r = pico_fs_read(fd, BTRFS_SB_OFFSET, sb, sizeof(sb));
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        if (memcmp(sb + BTRFS_MAGIC_OFF, "_BHRfS_M", 8) != 0)
                return 0;

        if (pico_le16(sb + BTRFS_CSUM_TYPE) == BTRFS_CSUM_TYPE_CRC32C) {
                uint32_t crc = ~pico_crc32c(~0U, sb + BTRFS_CSUM_LEN, sizeof(sb) - BTRFS_CSUM_LEN);

                if (crc != pico_le32(sb + BTRFS_CSUM))
                        return 0;
        }

        if (pico_le32(sb + BTRFS_SECTORSIZE) == 0)
                return 0;

        memset(ret, 0, sizeof(*ret));
        ret->kind = PICO_FS_BTRFS;
        pico_fs_uuid_format(sb + BTRFS_FSID, ret->uuid);
        pico_fs_label_set(ret->label, sizeof(ret->label), sb + BTRFS_LABEL, BTRFS_LABEL_LEN);
        return 1;
}
