/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The MBR disk signature and the PARTUUID spelling built from it, against
 * sectors built byte by byte: the checks the kernel applies before trusting
 * a DOS table, and the "%08x-%02x" form root=PARTUUID= matches.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "devd-mbr.h"

/* A table with one Linux partition and signature 0x1234abcd. */
static void sector_init(uint8_t s[DEVD_MBR_SECTOR_SIZE]) {
        memset(s, 0, DEVD_MBR_SECTOR_SIZE);
        s[DEVD_MBR_SIGNATURE_OFF + 0] = 0xcd;
        s[DEVD_MBR_SIGNATURE_OFF + 1] = 0xab;
        s[DEVD_MBR_SIGNATURE_OFF + 2] = 0x34;
        s[DEVD_MBR_SIGNATURE_OFF + 3] = 0x12;
        s[DEVD_MBR_TABLE_OFF + 0] = 0x80; /* bootable */
        s[DEVD_MBR_TABLE_OFF + 4] = 0x83; /* Linux */
        s[DEVD_MBR_MAGIC_OFF] = 0x55;
        s[DEVD_MBR_MAGIC_OFF + 1] = 0xaa;
}

static void test_decode(void) {
        uint8_t s[DEVD_MBR_SECTOR_SIZE];
        uint32_t sig = 0;

        sector_init(s);
        ASSERT_EQ_INT(devd_mbr_decode(s, sizeof(s), &sig), 1);
        ASSERT_TRUE(sig == 0x1234abcdu);

        /* Shorter than a sector cannot say either way. */
        ASSERT_EQ_INT(devd_mbr_decode(s, sizeof(s) - 1, &sig), -EINVAL);

        sector_init(s);
        s[DEVD_MBR_MAGIC_OFF + 1] = 0x00;
        ASSERT_EQ_INT(devd_mbr_decode(s, sizeof(s), &sig), 0);

        /* A FAT boot sector ends in 0x55aa too; its bytes where the boot
         * indicators would be are not 0x00/0x80. */
        sector_init(s);
        s[DEVD_MBR_TABLE_OFF + 2 * DEVD_MBR_ENTRY_SIZE] = 0x12;
        ASSERT_EQ_INT(devd_mbr_decode(s, sizeof(s), &sig), 0);

        /* A protective MBR in front of a GPT is gpt-scan.c's. */
        sector_init(s);
        s[DEVD_MBR_TABLE_OFF + DEVD_MBR_ENTRY_SIZE + 4] = 0xee;
        ASSERT_EQ_INT(devd_mbr_decode(s, sizeof(s), &sig), 0);
}

static void test_partuuid(void) {
        char buf[DEVD_MBR_PARTUUID_MAX];

        ASSERT_EQ_INT(devd_mbr_partuuid(0x1234abcdu, 1, buf, sizeof(buf)), 0);
        ASSERT_STREQ(buf, "1234abcd-01");
        ASSERT_EQ_INT(devd_mbr_partuuid(0x0000beefu, 5, buf, sizeof(buf)), 0);
        ASSERT_STREQ(buf, "0000beef-05");
        ASSERT_EQ_INT(devd_mbr_partuuid(0xffffffffu, 0x1a, buf, sizeof(buf)), 0);
        ASSERT_STREQ(buf, "ffffffff-1a");
        ASSERT_EQ_INT(devd_mbr_partuuid(0x1234abcdu, 1, buf, 11), -ENAMETOOLONG);
}

static void test_read(const char *tmp) {
        uint8_t s[DEVD_MBR_SECTOR_SIZE];
        char path[PATH_MAX];
        uint32_t sig = 0;

        sector_init(s);
        (void) snprintf(path, sizeof(path), "%s/disk.img", tmp);
        ASSERT_EQ_INT(test_image_write(path, 1 << 20, s, sizeof(s), 0), 0);
        ASSERT_EQ_INT(devd_mbr_read(path, &sig), 1);
        ASSERT_TRUE(sig == 0x1234abcdu);

        /* A device that ends before the sector does is not a table. */
        ASSERT_EQ_INT(test_write_file(tmp, "short.img", "x"), 0);
        (void) snprintf(path, sizeof(path), "%s/short.img", tmp);
        ASSERT_EQ_INT(devd_mbr_read(path, &sig), 0);

        (void) snprintf(path, sizeof(path), "%s/absent.img", tmp);
        ASSERT_EQ_INT(devd_mbr_read(path, &sig), -ENOENT);
}

int main(void) {
        char *tmp = test_tmpdir_new();

        ASSERT_TRUE(tmp != NULL);

        test_decode();
        test_partuuid();
        test_read(tmp);

        test_rm_rf(tmp);
        free(tmp);
        return 0;
}
