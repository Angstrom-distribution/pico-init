/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The btrfs reader, against primary superblocks built byte by byte at
 * 64 KiB, checksummed with CRC-32C as a default mkfs.btrfs checksums them.
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
static const uint8_t fsid[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

static void le32(uint8_t *p, uint32_t v) {
        for (int i = 0; i < 4; i++)
                p[i] = (uint8_t) (v >> (8 * i));
}

static void superblock(uint8_t sb[4096], const char *label, uint16_t csum_type) {
        memset(sb, 0, 4096);
        memcpy(sb + 32, fsid, 16);
        le32(sb + 48, 65536); /* bytenr: where this copy lives */
        memcpy(sb + 0x40, "_BHRfS_M", 8);
        le32(sb + 144, 4096);  /* sectorsize */
        le32(sb + 148, 16384); /* nodesize */
        sb[196] = (uint8_t) csum_type;
        /* dev_item.fsid repeats the filesystem's fsid; dev_item.uuid is this
         * device's own, which must not be what UUID reports. */
        memset(sb + 201 + 66, 0x77, 16);
        memcpy(sb + 201 + 82, fsid, 16);
        if (label)
                memcpy(sb + 299, label, strlen(label) > 256 ? 256 : strlen(label));
}

static void seal(uint8_t sb[4096]) {
        memset(sb, 0, 32);
        le32(sb, ~pico_crc32c(~0U, sb + 32, 4096 - 32));
}

static int probe(const uint8_t sb[4096], PicoFsKind hint, PicoFsId *id) {
        char path[PATH_MAX];
        int fd, r;

        snprintf(path, sizeof(path), "%s/img", dir);
        fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT(ftruncate(fd, 1 << 20), 0);
        ASSERT_EQ_INT(pwrite(fd, sb, 4096, 65536), 4096);
        r = hint == PICO_FS_BTRFS ? pico_fs_probe_btrfs(fd, id) : pico_fs_probe_fd(fd, hint, id);
        close(fd);
        return r;
}

static void test_btrfs(void) {
        uint8_t sb[4096];
        char longest[257];
        PicoFsId id;

        superblock(sb, "pico btrfs", 0);
        seal(sb);
        ASSERT_EQ_INT(probe(sb, PICO_FS_BTRFS, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_BTRFS);
        ASSERT_STREQ(id.uuid, "01234567-89ab-cdef-0123-456789abcdef");
        ASSERT_STREQ(id.label, "pico btrfs");

        ASSERT_EQ_INT(probe(sb, PICO_FS_NONE, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_BTRFS);
        ASSERT_EQ_INT(pico_fs_kind_from_type("btrfs"), PICO_FS_BTRFS);
        ASSERT_STREQ(pico_fs_kind_to_string(PICO_FS_BTRFS), "btrfs");

        /* The checksum covers the whole 4 KiB past the csum field. */
        sb[4000] ^= 1;
        ASSERT_EQ_INT(probe(sb, PICO_FS_BTRFS, &id), 0);
        ASSERT_EQ_INT(probe(sb, PICO_FS_NONE, &id), 0);

        /* A zero sector size makes the rest meaningless. */
        superblock(sb, "x", 0);
        memset(sb + 144, 0, 4);
        seal(sb);
        ASSERT_EQ_INT(probe(sb, PICO_FS_BTRFS, &id), 0);

        /* Unlabelled. */
        superblock(sb, NULL, 0);
        seal(sb);
        ASSERT_EQ_INT(probe(sb, PICO_FS_BTRFS, &id), 1);
        ASSERT_STREQ(id.label, "");

        /* The whole 256-byte field, no terminator. */
        memset(longest, 'L', 256);
        longest[256] = '\0';
        superblock(sb, longest, 0);
        seal(sb);
        ASSERT_EQ_INT(probe(sb, PICO_FS_BTRFS, &id), 1);
        ASSERT_EQ_INT(strlen(id.label), 256);

        /* A checksum type this does not verify (xxhash64): the magic and the
         * sector size are what is believed, and garbage in the csum field is
         * not a reason to reject. */
        superblock(sb, "xxhash", 1);
        memset(sb, 0xa5, 32);
        ASSERT_EQ_INT(probe(sb, PICO_FS_BTRFS, &id), 1);
        ASSERT_STREQ(id.label, "xxhash");

        /* No magic. */
        superblock(sb, "x", 0);
        sb[0x40] = '-';
        seal(sb);
        ASSERT_EQ_INT(probe(sb, PICO_FS_BTRFS, &id), 0);
}

int main(void) {
        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        test_btrfs();

        test_rm_rf(dir);
        free(dir);
        printf("test-fsid-btrfs: all checks passed\n");
        return 0;
}
