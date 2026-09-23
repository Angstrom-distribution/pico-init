/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * exFAT: what SDXC cards over 32 GB ship formatted as.
 *
 * Identified the way blkid identifies it, all of it from Microsoft's published
 * exFAT specification: "EXFAT   " at byte 3 behind the EB 76 90 jump, the
 * 53-byte must-be-zero region that keeps it from reading as a FAT boot sector,
 * the geometry ranges section 3.1 gives (sector and cluster shifts, FAT and
 * cluster-heap placement, root directory cluster), and the boot-region
 * checksum: sector 11 is the checksum of sectors 0-10, excluding the three
 * bytes that change while mounted, repeated to fill the sector. The checksum is
 * what makes a stray "EXFAT   " string not a volume.
 *
 * UUID is the 32-bit volume serial number printed as FAT prints its own,
 * "1A2B-3C4D". LABEL is the Volume Label directory entry (type 0x83) in the
 * root directory, up to 11 UTF-16 characters, converted to UTF-8. The root
 * directory is a FAT cluster chain; blkid follows it for up to 256 MiB of
 * entries, which is far more reading than a boot-time lookup should risk on a
 * card, so this stops after 1 MiB of directory -- 32768 entries, where
 * formatting tools put the label within the first handful -- or at the
 * end-of-directory entry, whichever comes first.
 */

#include <errno.h>
#include <string.h>

#include "fsid.h"

#define EXFAT_SECTOR_MAX 4096
#define EXFAT_BOOT_SECTORS 12

#define EXFAT_JUMP 0
#define EXFAT_NAME 3
#define EXFAT_ZERO 11
#define EXFAT_ZERO_LEN 53
#define EXFAT_FAT_OFFSET 80
#define EXFAT_FAT_LENGTH 84
#define EXFAT_HEAP_OFFSET 88
#define EXFAT_CLUSTER_COUNT 92
#define EXFAT_ROOT_CLUSTER 96
#define EXFAT_SERIAL 100
#define EXFAT_VOLUME_FLAGS 106
#define EXFAT_SECTOR_SHIFT 108
#define EXFAT_CLUSTER_SHIFT 109
#define EXFAT_NUM_FATS 110
#define EXFAT_PERCENT_IN_USE 112
#define EXFAT_BOOT_SIG 510

#define EXFAT_ENTRY_SIZE 32
#define EXFAT_ENTRY_EOD 0x00
#define EXFAT_ENTRY_LABEL 0x83
#define EXFAT_LABEL_LEN_OFF 1
#define EXFAT_LABEL_NAME_OFF 2
#define EXFAT_LABEL_NAME_LEN 22

#define EXFAT_FIRST_CLUSTER 2
#define EXFAT_LAST_CLUSTER 0x0ffffff6u

#define EXFAT_DIR_SCAN_MAX (1024 * 1024)
#define EXFAT_DIR_WINDOW 4096

typedef struct ExfatGeometry {
        unsigned sector_shift;
        unsigned cluster_shift;
        uint64_t fat_offset;  /* sectors */
        uint64_t heap_offset; /* sectors */
} ExfatGeometry;

static uint32_t boot_checksum(const uint8_t *sectors, size_t sector_size) {
        uint32_t sum = 0;
        size_t i;

        for (i = 0; i < sector_size * 11; i++) {
                if (i == EXFAT_VOLUME_FLAGS || i == EXFAT_VOLUME_FLAGS + 1 || i == EXFAT_PERCENT_IN_USE)
                        continue;
                sum = ((sum & 1) ? 0x80000000u : 0) + (sum >> 1) + sectors[i];
        }

        return sum;
}

static int valid_boot_region(int fd, const uint8_t *bs, ExfatGeometry *g) {
        static uint8_t region[EXFAT_SECTOR_MAX * EXFAT_BOOT_SECTORS];
        uint64_t fat_offset, fat_length, heap_offset, root, count;
        unsigned nfats = bs[EXFAT_NUM_FATS];
        size_t sector_size, i;
        uint32_t sum;
        int r;

        if (pico_le16(bs + EXFAT_BOOT_SIG) != 0xaa55)
                return 0;
        if (memcmp(bs + EXFAT_JUMP, "\xeb\x76\x90", 3) != 0)
                return 0;
        if (!pico_fs_bytes_zero(bs + EXFAT_ZERO, EXFAT_ZERO_LEN))
                return 0;
        if (nfats < 1 || nfats > 2)
                return 0;

        g->sector_shift = bs[EXFAT_SECTOR_SHIFT];
        g->cluster_shift = bs[EXFAT_CLUSTER_SHIFT];
        if (g->sector_shift < 9 || g->sector_shift > 12)
                return 0;
        if (g->cluster_shift > 25 - g->sector_shift)
                return 0;

        fat_offset = pico_le32(bs + EXFAT_FAT_OFFSET);
        fat_length = pico_le32(bs + EXFAT_FAT_LENGTH);
        heap_offset = pico_le32(bs + EXFAT_HEAP_OFFSET);
        count = pico_le32(bs + EXFAT_CLUSTER_COUNT);
        root = pico_le32(bs + EXFAT_ROOT_CLUSTER);

        /* 64-bit, so none of these sums can wrap: the FATs sit between the
         * boot regions and the cluster heap, the heap starts below 2^31
         * sectors, and the root directory is a real cluster. */
        if (fat_offset < 24 || heap_offset < fat_length * nfats ||
            fat_offset > heap_offset - fat_length * nfats)
                return 0;
        if (heap_offset < fat_offset + fat_length * nfats || heap_offset > (UINT64_C(1) << 31))
                return 0;
        if (root < EXFAT_FIRST_CLUSTER || root > count + 1)
                return 0;

        g->fat_offset = fat_offset;
        g->heap_offset = heap_offset;

        sector_size = (size_t) 1 << g->sector_shift;
        r = pico_fs_read(fd, 0, region, sector_size * EXFAT_BOOT_SECTORS);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        sum = boot_checksum(region, sector_size);
        for (i = 0; i < sector_size / 4; i++)
                if (pico_le32(region + sector_size * 11 + i * 4) != sum)
                        return 0;

        return 1;
}

static uint64_t cluster_offset(const ExfatGeometry *g, uint32_t cluster) {
        return (g->heap_offset + ((uint64_t) (cluster - EXFAT_FIRST_CLUSTER) << g->cluster_shift))
                        << g->sector_shift;
}

/* 1 with the label copied out, 0 for none, -errno. */
static int find_label(int fd, const uint8_t *bs, const ExfatGeometry *g, char *label, size_t size) {
        uint64_t cluster_size = (uint64_t) 1 << (g->sector_shift + g->cluster_shift);
        uint32_t cluster = pico_le32(bs + EXFAT_ROOT_CLUSTER);
        uint8_t buf[EXFAT_DIR_WINDOW];
        uint64_t scanned = 0, in_cluster = 0;
        int r;

        while (scanned < EXFAT_DIR_SCAN_MAX) {
                uint64_t n = cluster_size - in_cluster;

                if (n > sizeof(buf))
                        n = sizeof(buf);

                r = pico_fs_read(fd, cluster_offset(g, cluster) + in_cluster, buf, (size_t) n);
                if (r == -ENODATA)
                        return 0;
                if (r < 0)
                        return r;

                for (size_t i = 0; i < n; i += EXFAT_ENTRY_SIZE) {
                        const uint8_t *e = buf + i;

                        if (e[0] == EXFAT_ENTRY_EOD)
                                return 0;

                        if (e[0] == EXFAT_ENTRY_LABEL) {
                                size_t len = (size_t) e[EXFAT_LABEL_LEN_OFF] * 2;

                                if (len > EXFAT_LABEL_NAME_LEN)
                                        len = EXFAT_LABEL_NAME_LEN;
                                pico_fs_label_set_utf16le(label, size, e + EXFAT_LABEL_NAME_OFF, len);
                                return 1;
                        }
                }

                scanned += n;
                in_cluster += n;

                if (in_cluster == cluster_size) {
                        uint8_t next[4];

                        r = pico_fs_read(fd, (g->fat_offset << g->sector_shift) + (uint64_t) cluster * 4, next, 4);
                        if (r == -ENODATA)
                                return 0;
                        if (r < 0)
                                return r;

                        cluster = pico_le32(next);
                        if (cluster < EXFAT_FIRST_CLUSTER || cluster > EXFAT_LAST_CLUSTER)
                                return 0;
                        in_cluster = 0;
                }
        }

        return 0;
}

int pico_fs_probe_exfat(int fd, PicoFsId *ret) {
        char label[PICO_FS_LABEL_MAX] = "";
        ExfatGeometry g;
        uint8_t bs[512];
        int r;

        r = pico_fs_read(fd, 0, bs, sizeof(bs));
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        if (memcmp(bs + EXFAT_NAME, "EXFAT   ", 8) != 0)
                return 0;

        r = valid_boot_region(fd, bs, &g);
        if (r <= 0)
                return r;

        r = find_label(fd, bs, &g, label, sizeof(label));
        if (r < 0)
                return r;

        memset(ret, 0, sizeof(*ret));
        ret->kind = PICO_FS_EXFAT;
        memcpy(ret->label, label, sizeof(ret->label));

        pico_fs_serial32_format(bs + EXFAT_SERIAL, ret->uuid);

        return 1;
}
