/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The FAT reader, against FAT12, FAT16 and FAT32 volumes built byte by byte:
 * a boot sector with the geometry mkfs.fat writes for each width, and just
 * enough of the root directory (and, for FAT32, of the FAT and the FSInfo
 * sector) to carry what blkid reads. The images are sparse files, so the
 * 40 MiB FAT32 geometry costs a few sectors of disk.
 *
 * The checks that matter most are the ones that pin blkid's choices: the
 * label comes from the root directory, not the boot sector; the serial is
 * printed upper-case, high half first; and the boot-parameter-block rules
 * reject the non-FAT volumes that share FAT's jump byte and boot signature.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fsid.h"
#include "test-util.h"

static char *dir;
static const uint8_t serial[4] = { 0x4d, 0x3c, 0x2b, 0x1a };

static void put16(uint8_t *p, uint16_t v) {
        p[0] = (uint8_t) v;
        p[1] = (uint8_t) (v >> 8);
}

static void put32(uint8_t *p, uint32_t v) {
        put16(p, (uint16_t) v);
        put16(p + 2, (uint16_t) (v >> 16));
}

static int img_new(uint64_t size) {
        char path[PATH_MAX];
        int fd;

        snprintf(path, sizeof(path), "%s/img", dir);
        fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT(ftruncate(fd, (off_t) size), 0);
        return fd;
}

static void img_put(int fd, uint64_t off, const void *p, size_t n) {
        ASSERT_EQ_INT(pwrite(fd, p, n, (off_t) off), (ssize_t) n);
}

typedef struct Geometry {
        uint16_t sector_size;
        uint8_t cluster_sectors;
        uint16_t reserved;
        uint8_t fats;
        uint16_t root_entries;
        uint32_t sectors;
        uint8_t media;
        uint16_t fat16_size;
        uint32_t fat32_size;
} Geometry;

static void boot_sector(uint8_t bs[512], const Geometry *g) {
        memset(bs, 0, 512);
        bs[0] = 0xeb;
        bs[1] = 0x3c;
        bs[2] = 0x90;
        memcpy(bs + 3, "mkfs.fat", 8);
        put16(bs + 0x0b, g->sector_size);
        bs[0x0d] = g->cluster_sectors;
        put16(bs + 0x0e, g->reserved);
        bs[0x10] = g->fats;
        put16(bs + 0x11, g->root_entries);
        if (g->sectors < 65536)
                put16(bs + 0x13, (uint16_t) g->sectors);
        else
                put32(bs + 0x20, g->sectors);
        bs[0x15] = g->media;
        put16(bs + 0x16, g->fat16_size);
        bs[0x1fe] = 0x55;
        bs[0x1ff] = 0xaa;
}

/* The FAT12/16 extended boot record. */
static void ebr16(uint8_t bs[512], uint8_t sig, const char *type) {
        bs[0x26] = sig;
        memcpy(bs + 0x27, serial, 4);
        memcpy(bs + 0x2b, "BOOTSECTOR ", 11);
        memcpy(bs + 0x36, type, 8);
}

static void dirent(uint8_t e[32], const char *name, uint8_t attr, uint16_t cluster) {
        memset(e, 0, 32);
        memcpy(e, name, 11);
        e[11] = attr;
        put16(e + 26, cluster);
}

/* FAT16, 32 MiB: 16343 clusters of 2 KiB. */
static const Geometry fat16 = {
        .sector_size = 512,
        .cluster_sectors = 4,
        .reserved = 1,
        .fats = 2,
        .root_entries = 512,
        .sectors = 65536,
        .media = 0xf8,
        .fat16_size = 64,
};
#define FAT16_ROOT ((1 + 2 * 64) * 512)

static int fat16_image(uint8_t sig, uint8_t (*entries)[32], size_t n) {
        uint8_t bs[512];
        int fd = img_new(32u << 20);

        boot_sector(bs, &fat16);
        ebr16(bs, sig, "FAT16   ");
        img_put(fd, 0, bs, sizeof(bs));
        if (n > 0)
                img_put(fd, FAT16_ROOT, entries, n * 32);
        return fd;
}

static void test_fat16(void) {
        uint8_t e[5][32];
        PicoFsId id;
        int fd;

        /* A long-name fragment, a file, a deleted label, then the label: only
         * the last is the volume label. */
        dirent(e[0], "\x41p\0i\0c\0o\0\0\0", 0x0f, 0);
        dirent(e[1], "README  TXT", 0x20, 5);
        dirent(e[2], "\xe5OLD LABEL ", 0x08, 0);
        dirent(e[3], "PICO VFAT  ", 0x08, 0);
        fd = fat16_image(0x29, e, 4);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_VFAT);
        ASSERT_STREQ(id.uuid, "1A2B-3C4D");
        ASSERT_STREQ(id.label, "PICO VFAT");

        /* Through the dispatcher, by fstab type and by "auto". */
        ASSERT_EQ_INT(pico_fs_probe_fd(fd, PICO_FS_NONE, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_VFAT);
        ASSERT_EQ_INT(pico_fs_probe_fd(fd, pico_fs_kind_from_type("vfat"), &id), 1);
        ASSERT_EQ_INT(pico_fs_probe_fd(fd, pico_fs_kind_from_type("msdos"), &id), 1);
        ASSERT_EQ_INT(pico_fs_probe_fd(fd, PICO_FS_SWAP, &id), 0);
        ASSERT_STREQ(pico_fs_kind_to_string(PICO_FS_VFAT), "vfat");
        close(fd);

        /* No label entry: no LABEL, whatever the boot sector's copy says. */
        fd = fat16_image(0x29, e, 2);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "");
        ASSERT_STREQ(id.uuid, "1A2B-3C4D");
        close(fd);

        /* 0x28 is the short extended record: a serial, no label field. Any
         * other value means neither is there. */
        fd = fat16_image(0x28, e, 4);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        ASSERT_STREQ(id.uuid, "1A2B-3C4D");
        close(fd);
        fd = fat16_image(0x00, e, 4);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        ASSERT_STREQ(id.uuid, "");
        ASSERT_STREQ(id.label, "PICO VFAT");
        close(fd);

        /* A label whose first byte really is 0xE5 is stored as 0x05. */
        dirent(e[0],
               "\x05"
               "CLAIR     ",
               0x08,
               0);
        fd = fat16_image(0x29, e, 1);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        ASSERT_STREQ(id.label,
                     "\xe5"
                     "CLAIR");
        close(fd);

        /* Nothing after the end-of-directory marker is an entry. */
        memset(e[0], 0, 32);
        dirent(e[1], "HIDDEN     ", 0x08, 0);
        fd = fat16_image(0x29, e, 2);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "");
        close(fd);

        /* A directory, a volume-label-flagged file with a cluster, and a
         * label-flagged directory are none of them the label. */
        dirent(e[0], "SUBDIR     ", 0x10, 0);
        dirent(e[1], "WITHDATA   ", 0x08, 9);
        dirent(e[2], "LABELDIR   ", 0x18, 0);
        dirent(e[3], "REAL       ", 0x28, 0); /* archive bit set too */
        fd = fat16_image(0x29, e, 4);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "REAL");
        close(fd);
}

/* A 1.44 MB floppy's FAT12, found only by its jump byte and boot signature. */
static void test_fat12(void) {
        static const Geometry g = {
                .sector_size = 512,
                .cluster_sectors = 1,
                .reserved = 1,
                .fats = 2,
                .root_entries = 224,
                .sectors = 2880,
                .media = 0xf0,
                .fat16_size = 9,
        };
        uint8_t bs[512], e[32];
        PicoFsId id;
        int fd;

        fd = img_new(2880 * 512);
        boot_sector(bs, &g);
        img_put(fd, 0, bs, sizeof(bs));
        dirent(e, "FLOPPY     ", 0x08, 0);
        img_put(fd, (1 + 18) * 512, e, sizeof(e));

        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "FLOPPY");
        ASSERT_STREQ(id.uuid, "");

        /* On a weak signature the boot signature is required. */
        bs[0x1ff] = 0;
        img_put(fd, 0, bs, sizeof(bs));
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 0);

        /* And an OS/2 pseudo boot sector on a JFS volume is not FAT. */
        bs[0x1ff] = 0xaa;
        memcpy(bs + 0x36, "JFS     ", 8);
        img_put(fd, 0, bs, sizeof(bs));
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 0);
        close(fd);
}

/* FAT32, 40 MiB, 512-byte clusters: the root directory spills into a second
 * cluster, which is where the label is. */
static const Geometry fat32 = {
        .sector_size = 512,
        .cluster_sectors = 1,
        .reserved = 32,
        .fats = 2,
        .root_entries = 0,
        .sectors = 81920,
        .media = 0xf8,
        .fat16_size = 0,
        .fat32_size = 640,
};
#define FAT32_DATA ((32 + 2 * 640) * 512)
#define FAT32_FAT (32 * 512)

static int fat32_image(const char *fsinfo1, uint32_t second_cluster) {
        uint8_t bs[512], e[16][32], fat[4];
        int fd = img_new(40u << 20);

        boot_sector(bs, &fat32);
        put32(bs + 0x24, fat32.fat32_size);
        put32(bs + 0x2c, 2);
        put16(bs + 0x30, 1);
        bs[0x42] = 0x29;
        memcpy(bs + 0x43, serial, 4);
        memcpy(bs + 0x47, "BOOTSECTOR ", 11);
        memcpy(bs + 0x52, "FAT32   ", 8);
        img_put(fd, 0, bs, sizeof(bs));

        img_put(fd, 512, fsinfo1, 4);
        img_put(fd, 512 + 484, "rrAa", 4);

        /* Cluster 2: sixteen files, no end marker, so the scan must follow
         * the chain; FAT[2] names the next cluster. */
        for (int i = 0; i < 16; i++) {
                char name[12];

                snprintf(name, sizeof(name), "FILE%02d  BIN", i);
                dirent(e[i], name, 0x20, (uint16_t) (100 + i));
        }
        img_put(fd, FAT32_DATA, e, sizeof(e));

        put32(fat, second_cluster);
        img_put(fd, FAT32_FAT + 2 * 4, fat, 4);

        dirent(e[0], "PICO FAT32 ", 0x08, 0);
        img_put(fd, FAT32_DATA + (uint64_t) (7 - 2) * 512, e[0], 32);
        return fd;
}

static void test_fat32(void) {
        PicoFsId id;
        int fd;

        fd = fat32_image("RRaA", 7);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        ASSERT_STREQ(id.uuid, "1A2B-3C4D");
        ASSERT_STREQ(id.label, "PICO FAT32");
        ASSERT_EQ_INT(pico_fs_probe_fd(fd, PICO_FS_NONE, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_VFAT);
        close(fd);

        /* The high nibble of a FAT32 entry is reserved and masked off. */
        fd = fat32_image("RRaA", 0xf0000007);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "PICO FAT32");
        close(fd);

        /* A chain that loops on itself ends after the bounded walk: still
         * FAT, just unlabelled. */
        fd = fat32_image("RRaA", 2);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "");
        close(fd);

        /* An FSInfo sector that is neither signed nor blank is not FAT32. */
        fd = fat32_image("XXXX", 7);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 0);
        close(fd);
        fd = fat32_image("\0\0\0\0", 7);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 1);
        close(fd);
}

/* One field at a time turned into something mkfs.fat never writes. */
static void test_rejections(void) {
        static const struct {
                size_t off;
                uint8_t value;
        } breaks[] = {
                { 0x10,    0 }, /* no FATs: what exFAT and NTFS have */
                { 0x0e,    0 }, /* no reserved sectors (low byte; high is 0) */
                { 0x15, 0x00 }, /* media byte */
                { 0x0d,    3 }, /* cluster size not a power of two */
                { 0x0c,    1 }, /* sector size 256 */
                { 0x0b, 0x01 }, /* sector size 513 */
        };
        uint8_t bs[512], e[1][32];
        PicoFsId id;
        int fd;

        dirent(e[0], "X          ", 0x08, 0);

        for (size_t i = 0; i < sizeof(breaks) / sizeof(breaks[0]); i++) {
                fd = fat16_image(0x29, e, 1);
                ASSERT_EQ_INT(pread(fd, bs, sizeof(bs), 0), (ssize_t) sizeof(bs));
                bs[breaks[i].off] = breaks[i].value;
                img_put(fd, 0, bs, sizeof(bs));
                if (pico_fs_probe_vfat(fd, &id) != 0) {
                        fprintf(stderr, "break %zu accepted\n", i);
                        ASSERT_TRUE(false);
                }
                close(fd);
        }

        /* Too many clusters for the FAT width the geometry implies: FAT16
         * geometry claiming 2^32-1 sectors. */
        fd = fat16_image(0x29, e, 1);
        ASSERT_EQ_INT(pread(fd, bs, sizeof(bs), 0), (ssize_t) sizeof(bs));
        put32(bs + 0x20, 0xffffffffu);
        img_put(fd, 0, bs, sizeof(bs));
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 0);

        close(fd);

        /* A BitLocker volume's FAT-shaped boot sector. */
        fd = fat16_image(0x29, e, 1);
        ASSERT_EQ_INT(pread(fd, bs, sizeof(bs), 0), (ssize_t) sizeof(bs));
        memcpy(bs + 3, "-FVE-FS-", 8);
        img_put(fd, 0, bs, sizeof(bs));
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 0);
        close(fd);

        /* An NTFS boot sector: same jump byte and boot signature, no FATs. */
        fd = img_new(1u << 20);
        memset(bs, 0, sizeof(bs));
        memcpy(bs, "\xeb\x52\x90NTFS    ", 11);
        put16(bs + 0x0b, 512);
        bs[0x0d] = 8;
        bs[0x15] = 0xf8;
        bs[0x1fe] = 0x55;
        bs[0x1ff] = 0xaa;
        img_put(fd, 0, bs, sizeof(bs));
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 0);
        close(fd);

        /* Nothing at all, and too short for a boot sector. */
        fd = img_new(1u << 20);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 0);
        close(fd);
        fd = img_new(100);
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 0);
        close(fd);
}

int main(void) {
        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        test_fat16();
        test_fat12();
        test_fat32();
        test_rejections();

        test_rm_rf(dir);
        free(dir);
        printf("test-fsid-vfat: all checks passed\n");
        return 0;
}
