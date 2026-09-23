/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * XFS: the primary superblock at byte 0 of the device, big-endian throughout.
 *
 * "XFSB" alone is four bytes anything could contain, so the geometry is
 * checked the way blkid checks it before the magic is believed: sector,
 * block and inode sizes each a power of two in range and agreeing with their
 * own log2 fields, the realtime extent size in range, and a data block count
 * that fits the allocation groups. A version 5 superblock is additionally
 * CRC-32C checksummed over its whole sector with the checksum field itself
 * zeroed, which is the check that settles it; version 4 has no checksum and
 * rests on the geometry.
 *
 * UUID is sb_uuid in the ordinary 8-4-4-4-12 form. LABEL is sb_fname, twelve
 * bytes, NUL-padded.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "fsid.h"

#define XFS_MAGIC "XFSB"

#define XFS_BLOCKSIZE 4
#define XFS_DBLOCKS 8
#define XFS_UUID 32
#define XFS_REXTSIZE 80
#define XFS_AGBLOCKS 84
#define XFS_AGCOUNT 88
#define XFS_VERSIONNUM 100
#define XFS_SECTSIZE 102
#define XFS_INODESIZE 104
#define XFS_FNAME 108
#define XFS_FNAME_LEN 12
#define XFS_BLOCKLOG 120
#define XFS_SECTLOG 121
#define XFS_INODELOG 122
#define XFS_INOPBLOG 123
#define XFS_IMAX_PCT 127
#define XFS_FEATURES2 200
#define XFS_CRC 224

/* Everything up to and including sb_crc; a sector is at least 512. */
#define XFS_SB_MIN 512

#define XFS_VERSION_MOREBITS 0x8000
#define XFS_VERSION2_CRC 0x00000100
#define XFS_MIN_AG_BLOCKS 64

static bool in_range(uint64_t v, uint64_t lo, uint64_t hi) {
        return v >= lo && v <= hi;
}

static bool valid_geometry(const uint8_t *sb) {
        uint32_t blocksize = pico_be32(sb + XFS_BLOCKSIZE);
        uint64_t dblocks = pico_be64(sb + XFS_DBLOCKS);
        uint32_t rextsize = pico_be32(sb + XFS_REXTSIZE);
        uint32_t agblocks = pico_be32(sb + XFS_AGBLOCKS);
        uint32_t agcount = pico_be32(sb + XFS_AGCOUNT);
        uint16_t sectsize = pico_be16(sb + XFS_SECTSIZE);
        uint16_t inodesize = pico_be16(sb + XFS_INODESIZE);
        unsigned blocklog = sb[XFS_BLOCKLOG], sectlog = sb[XFS_SECTLOG], inodelog = sb[XFS_INODELOG];
        uint64_t rext_bytes = (uint64_t) rextsize * blocksize;

        if (agcount == 0)
                return false;
        if (!in_range(sectlog, 9, 15) || sectsize != (1u << sectlog))
                return false;
        if (!in_range(blocklog, 9, 16) || blocksize != (1u << blocklog))
                return false;
        if (!in_range(inodelog, 8, 11) || inodesize != (1u << inodelog))
                return false;
        if (blocklog - inodelog != sb[XFS_INOPBLOG])
                return false;
        if (!in_range(rext_bytes, 4096, 1024 * 1024 * 1024))
                return false;
        if (sb[XFS_IMAX_PCT] > 100)
                return false;
        if (dblocks == 0 || dblocks > (uint64_t) agcount * agblocks ||
            dblocks < (uint64_t) (agcount - 1) * agblocks + XFS_MIN_AG_BLOCKS)
                return false;

        return true;
}

/* 1 when a v5 superblock's checksum holds (or the superblock is not v5), 0
 * when it does not, -errno. */
static int valid_crc(int fd, const uint8_t *sb) {
        uint16_t version = pico_be16(sb + XFS_VERSIONNUM);
        size_t sectsize = pico_be16(sb + XFS_SECTSIZE);
        static const uint8_t zero[4];
        uint8_t *buf;
        uint32_t crc;
        int r;

        if ((version & 0x0f) != 5)
                return 1;
        if (!(version & XFS_VERSION_MOREBITS) || !(pico_be32(sb + XFS_FEATURES2) & XFS_VERSION2_CRC))
                return 0;

        /* Already range-checked: 512 to 32 KiB. */
        buf = malloc(sectsize);
        if (!buf)
                return -ENOMEM;

        r = pico_fs_read(fd, 0, buf, sectsize);
        if (r < 0) {
                free(buf);
                return r == -ENODATA ? 0 : r;
        }

        crc = pico_crc32c(~0U, buf, XFS_CRC);
        crc = pico_crc32c(crc, zero, sizeof(zero));
        crc = ~pico_crc32c(crc, buf + XFS_CRC + 4, sectsize - XFS_CRC - 4);
        r = crc == pico_le32(buf + XFS_CRC);

        free(buf);
        return r;
}

int pico_fs_probe_xfs(int fd, PicoFsId *ret) {
        uint8_t sb[XFS_SB_MIN];
        int r;

        r = pico_fs_read(fd, 0, sb, sizeof(sb));
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        if (memcmp(sb, XFS_MAGIC, 4) != 0 || !valid_geometry(sb))
                return 0;

        r = valid_crc(fd, sb);
        if (r <= 0)
                return r;

        memset(ret, 0, sizeof(*ret));
        ret->kind = PICO_FS_XFS;
        pico_fs_uuid_format(sb + XFS_UUID, ret->uuid);
        pico_fs_label_set(ret->label, sizeof(ret->label), sb + XFS_FNAME, XFS_FNAME_LEN);
        return 1;
}
