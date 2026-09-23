/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The XFS reader, against primary superblocks built byte by byte with the
 * geometry a default mkfs.xfs writes (4 KiB blocks, 512-byte sectors and
 * inodes, four allocation groups), in both the v5 layout with its CRC-32C
 * and the older unchecksummed v4 one.
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
static const uint8_t uuid[16] = { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
                                  0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 };

static void be16(uint8_t *p, uint16_t v) {
        p[0] = (uint8_t) (v >> 8);
        p[1] = (uint8_t) v;
}

static void be32(uint8_t *p, uint32_t v) {
        be16(p, (uint16_t) (v >> 16));
        be16(p + 2, (uint16_t) v);
}

static void be64(uint8_t *p, uint64_t v) {
        be32(p, (uint32_t) (v >> 32));
        be32(p + 4, (uint32_t) v);
}

static void superblock(uint8_t *sb, size_t sectsize, bool v5, const char *label) {
        unsigned sectlog = 0;

        while ((1u << sectlog) < sectsize)
                sectlog++;

        memset(sb, 0, sectsize);
        memcpy(sb, "XFSB", 4);
        be32(sb + 4, 4096);  /* blocksize */
        be64(sb + 8, 81920); /* dblocks: 4 AGs of 20480 */
        memcpy(sb + 32, uuid, 16);
        be32(sb + 80, 1);     /* rextsize, blocks */
        be32(sb + 84, 20480); /* agblocks */
        be32(sb + 88, 4);     /* agcount */
        be16(sb + 100, v5 ? 0xb4a5 : 0xb4b4);
        be16(sb + 102, (uint16_t) sectsize);
        be16(sb + 104, 512); /* inodesize */
        be16(sb + 106, 8);   /* inopblock */
        if (label)
                memcpy(sb + 108, label, strlen(label) > 12 ? 12 : strlen(label));
        sb[120] = 12; /* blocklog */
        sb[121] = (uint8_t) sectlog;
        sb[122] = 9; /* inodelog */
        sb[123] = 3; /* inopblog */
        sb[127] = 25;
        be32(sb + 200, v5 ? 0x18a : 0x8a); /* features2, CRC bit in v5 */
}

/* The v5 checksum, stored little-endian and inverted, over the sector with
 * the checksum field zeroed. */
static void seal(uint8_t *sb, size_t sectsize) {
        uint32_t crc;

        memset(sb + 224, 0, 4);
        crc = ~pico_crc32c(~0U, sb, sectsize);
        sb[224] = (uint8_t) crc;
        sb[225] = (uint8_t) (crc >> 8);
        sb[226] = (uint8_t) (crc >> 16);
        sb[227] = (uint8_t) (crc >> 24);
}

static int probe(const uint8_t *sb, size_t n, PicoFsKind hint, PicoFsId *id) {
        char path[PATH_MAX];
        int fd, r;

        snprintf(path, sizeof(path), "%s/img", dir);
        fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT(ftruncate(fd, 1 << 20), 0);
        ASSERT_EQ_INT(pwrite(fd, sb, n, 0), (ssize_t) n);
        r = hint == PICO_FS_XFS ? pico_fs_probe_xfs(fd, id) : pico_fs_probe_fd(fd, hint, id);
        close(fd);
        return r;
}

static void test_v5(void) {
        uint8_t sb[4096];
        PicoFsId id;

        superblock(sb, 512, true, "xfslbl");
        seal(sb, 512);
        ASSERT_EQ_INT(probe(sb, 512, PICO_FS_XFS, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_XFS);
        ASSERT_STREQ(id.uuid, "abcdef01-2345-6789-abcd-ef0123456789");
        ASSERT_STREQ(id.label, "xfslbl");

        ASSERT_EQ_INT(probe(sb, 512, PICO_FS_NONE, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_XFS);
        ASSERT_EQ_INT(pico_fs_kind_from_type("xfs"), PICO_FS_XFS);
        ASSERT_STREQ(pico_fs_kind_to_string(PICO_FS_XFS), "xfs");

        /* One bit anywhere in the sector breaks the checksum -- including
         * past the fields this reads, since the CRC covers the whole sector. */
        sb[400] ^= 1;
        ASSERT_EQ_INT(probe(sb, 512, PICO_FS_XFS, &id), 0);

        /* v5 without the CRC feature flag is not a real v5 superblock. */
        superblock(sb, 512, true, "x");
        be32(sb + 200, 0x8a);
        seal(sb, 512);
        ASSERT_EQ_INT(probe(sb, 512, PICO_FS_XFS, &id), 0);

        /* 4 KiB sectors: the checksum covers all 4096 bytes. */
        superblock(sb, 4096, true, "big sectors");
        seal(sb, 4096);
        ASSERT_EQ_INT(probe(sb, 4096, PICO_FS_XFS, &id), 1);
        ASSERT_STREQ(id.label, "big sectors");
        sb[4095] ^= 1;
        ASSERT_EQ_INT(probe(sb, 4096, PICO_FS_XFS, &id), 0);
}

static void test_v4(void) {
        uint8_t sb[512];
        PicoFsId id;

        /* No checksum to check; a twelve-byte label fills the field with no
         * NUL at all. */
        superblock(sb, 512, false, "TWELVECHARSX");
        ASSERT_EQ_INT(probe(sb, 512, PICO_FS_XFS, &id), 1);
        ASSERT_STREQ(id.label, "TWELVECHARSX");
        ASSERT_STREQ(id.uuid, "abcdef01-2345-6789-abcd-ef0123456789");

        superblock(sb, 512, false, NULL);
        ASSERT_EQ_INT(probe(sb, 512, PICO_FS_XFS, &id), 1);
        ASSERT_STREQ(id.label, "");
}

/* One geometry field at a time made impossible; v4, so no checksum masks it. */
static void test_geometry(void) {
        static const struct {
                size_t off;
                unsigned width;
                uint64_t value;
        } breaks[] = {
                {  88, 4,              0 }, /* no allocation groups */
                { 102, 2,           1024 }, /* sector size disagrees with its log */
                { 121, 1,             16 }, /* sector log too big */
                {   4, 4,         131072 }, /* block size too big */
                { 104, 2,            128 }, /* inode size too small */
                { 123, 1,              2 }, /* inodes-per-block log wrong */
                {  80, 4,              0 }, /* realtime extent of 0 bytes */
                { 127, 1,            101 }, /* inode space over 100% */
                {   8, 8,              0 }, /* no data blocks */
                {   8, 8,  4 * 20480 + 1 }, /* more blocks than the AGs hold */
                {   8, 8, 3 * 20480 + 63 }, /* last AG too small */
        };
        uint8_t sb[512];
        PicoFsId id;

        for (size_t i = 0; i < sizeof(breaks) / sizeof(breaks[0]); i++) {
                superblock(sb, 512, false, "x");
                switch (breaks[i].width) {
                case 1:
                        sb[breaks[i].off] = (uint8_t) breaks[i].value;
                        break;
                case 2:
                        be16(sb + breaks[i].off, (uint16_t) breaks[i].value);
                        break;
                case 4:
                        be32(sb + breaks[i].off, (uint32_t) breaks[i].value);
                        break;
                default:
                        be64(sb + breaks[i].off, breaks[i].value);
                }
                if (probe(sb, 512, PICO_FS_XFS, &id) != 0) {
                        fprintf(stderr, "break %zu accepted\n", i);
                        ASSERT_TRUE(false);
                }
        }

        /* The smallest last AG that is allowed. */
        superblock(sb, 512, false, "x");
        be64(sb + 8, 3 * 20480 + 64);
        ASSERT_EQ_INT(probe(sb, 512, PICO_FS_XFS, &id), 1);

        /* The magic on its own. */
        memset(sb, 0, sizeof(sb));
        memcpy(sb, "XFSB", 4);
        ASSERT_EQ_INT(probe(sb, 512, PICO_FS_XFS, &id), 0);
        ASSERT_EQ_INT(probe(sb, 512, PICO_FS_NONE, &id), 0);
}

int main(void) {
        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        test_v5();
        test_v4();
        test_geometry();

        test_rm_rf(dir);
        free(dir);
        printf("test-fsid-xfs: all checks passed\n");
        return 0;
}
