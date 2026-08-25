/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The field extraction behind by-uuid, by-label and by-id.
 *
 * Two very different things get tested here because they answer the same
 * question -- "what is this device called" -- from two different places.
 *
 * The ext superblock half is built byte by byte, in test-gpt-scan.c's style and
 * for its reason: a checked-in binary blob is a fixture nobody can review. The
 * particular bytes are not invented, though. They reproduce a real
 * `mke2fs -t ext4 -U 12345678-90ab-cdef-1234-567890abcdef -L PICOTEST` image
 * whose superblock was read at those three offsets and cross-checked against
 * dumpe2fs before any of this code was written -- so the offsets under test are
 * a verified property of ext4, not a citation this test agrees with because it
 * was written from the same citation.
 *
 * The by-id half builds a sysfs tree in a temporary directory, because the real
 * one describes whatever is plugged into the machine running the test, which is
 * nothing predictable and on a build host is nothing at all. That is what
 * devd_probe_bus_id()'s sys_root parameter is for.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test-util.h"
#include "devd-probe.h"

/* --- the ext superblock --- */

/*
 * The bytes read out of the real image, at the three offsets this project's
 * plan cites and this milestone re-verified:
 *
 *   magic  @+56  : 0xef53
 *   uuid   @+104 : 1234567890abcdef1234567890abcdef
 *   label  @+120 : "PICOTEST" NUL-padded to 16
 */
static const uint8_t real_uuid[16] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
                                       0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };

static void build_super(uint8_t sb[DEVD_EXT_SUPER_SIZE], const uint8_t uuid[16], const char *label) {
        memset(sb, 0, DEVD_EXT_SUPER_SIZE);

        /* s_magic, little-endian like every other ext field. */
        sb[DEVD_EXT_MAGIC_OFF] = 0x53;
        sb[DEVD_EXT_MAGIC_OFF + 1] = 0xef;

        if (uuid)
                memcpy(sb + DEVD_EXT_UUID_OFF, uuid, 16);

        if (label)
                /* Not strncpy: a 16-character label has no terminator on disk,
                 * and the copy below must be able to produce that case. */
                memcpy(sb + DEVD_EXT_LABEL_OFF, label, strlen(label) > 16 ? 16 : strlen(label));
}

static void test_ext_super(void) {
        uint8_t sb[DEVD_EXT_SUPER_SIZE];
        DevdFsInfo fs;

        build_super(sb, real_uuid, "PICOTEST");
        ASSERT_EQ_INT(devd_probe_ext_super(sb, sizeof(sb), &fs), 1);
        ASSERT_STREQ(fs.uuid, "12345678-90ab-cdef-1234-567890abcdef");
        ASSERT_STREQ(fs.label, "PICOTEST");

        /* An unlabelled filesystem, which is the common case: a uuid and
         * nothing else, and no by-label link to make. */
        build_super(sb, real_uuid, NULL);
        ASSERT_EQ_INT(devd_probe_ext_super(sb, sizeof(sb), &fs), 1);
        ASSERT_STREQ(fs.label, "");
        ASSERT_STREQ(fs.uuid, "12345678-90ab-cdef-1234-567890abcdef");

        /* An all-zero uuid is "none", not a link called
         * 00000000-0000-0000-0000-000000000000 that every unformatted image
         * on the machine would collide on. */
        build_super(sb, NULL, "NOUUID");
        ASSERT_EQ_INT(devd_probe_ext_super(sb, sizeof(sb), &fs), 1);
        ASSERT_STREQ(fs.uuid, "");
        ASSERT_STREQ(fs.label, "NOUUID");

        /* A label filling the whole 16-byte field, with no terminator on disk.
         * Copying it with a string function would read into s_last_mounted. */
        build_super(sb, real_uuid, "SIXTEENCHARSLONG");
        ASSERT_EQ_INT(devd_probe_ext_super(sb, sizeof(sb), &fs), 1);
        ASSERT_STREQ(fs.label, "SIXTEENCHARSLONG");
        ASSERT_EQ_INT(strlen(fs.label), 16);

        /* No magic: not an ext filesystem, which is an answer rather than a
         * failure -- a FAT card gets exactly this. */
        memset(sb, 0, sizeof(sb));
        ASSERT_EQ_INT(devd_probe_ext_super(sb, sizeof(sb), &fs), 0);

        /* Magic in the right place but the wrong value. */
        build_super(sb, real_uuid, "X");
        sb[DEVD_EXT_MAGIC_OFF] = 0x54;
        ASSERT_EQ_INT(devd_probe_ext_super(sb, sizeof(sb), &fs), 0);

        /* A buffer too short to reach the label field cannot answer either
         * way, and says so rather than reading past its end. */
        build_super(sb, real_uuid, "PICOTEST");
        ASSERT_EQ_INT(devd_probe_ext_super(sb, DEVD_EXT_LABEL_OFF + 4, &fs), -EINVAL);
        ASSERT_EQ_INT(devd_probe_ext_super(NULL, sizeof(sb), &fs), -EINVAL);
}

/* The read path: a real file with a real superblock at byte 1024. */
static void test_ext_device(void) {
        uint8_t sb[DEVD_EXT_SUPER_SIZE];
        char *dir, path[PATH_MAX];
        DevdFsInfo fs;
        int fd;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        snprintf(path, sizeof(path), "%s/image", dir);

        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        ASSERT_TRUE(fd >= 0);

        /* The 1024 bytes before the superblock: a boot block on a real
         * filesystem, and never looked at here. */
        memset(sb, 0xa5, sizeof(sb));
        ASSERT_EQ_INT(write(fd, sb, DEVD_EXT_SUPER_OFFSET), DEVD_EXT_SUPER_OFFSET);

        build_super(sb, real_uuid, "PICOTEST");
        ASSERT_EQ_INT(write(fd, sb, sizeof(sb)), (ssize_t) sizeof(sb));
        ASSERT_EQ_INT(close(fd), 0);

        ASSERT_EQ_INT(devd_probe_ext(path, &fs), 1);
        ASSERT_STREQ(fs.uuid, "12345678-90ab-cdef-1234-567890abcdef");
        ASSERT_STREQ(fs.label, "PICOTEST");

        /* Shorter than a superblock: not a filesystem, and not an I/O error. */
        snprintf(path, sizeof(path), "%s/tiny", dir);
        ASSERT_EQ_INT(test_write_file(dir, "tiny", "not a filesystem"), 0);
        ASSERT_EQ_INT(devd_probe_ext(path, &fs), 0);

        snprintf(path, sizeof(path), "%s/absent", dir);
        ASSERT_EQ_INT(devd_probe_ext(path, &fs), -ENOENT);

        test_rm_rf(dir);
        free(dir);
}

/* --- the sanitizer --- */

static void test_sanitize(void) {
        char out[64];

        /* udev's replace_whitespace(): leading and trailing dropped, internal
         * runs collapsed to one underscore. */
        ASSERT_EQ_INT(devd_sanitize("  Generic  USB Reader ", out, sizeof(out)), 18);
        ASSERT_STREQ(out, "Generic_USB_Reader");

        /* replace_chars(): the whitelist survives, everything else becomes an
         * underscore -- including the '/' that would otherwise turn a link
         * name into a path. */
        ASSERT_EQ_INT(devd_sanitize("a/b", out, sizeof(out)), 3);
        ASSERT_STREQ(out, "a_b");
        ASSERT_EQ_INT(devd_sanitize("Kingston-DT#1.0:x=y@z_w+v", out, sizeof(out)), 25);
        ASSERT_STREQ(out, "Kingston-DT#1.0:x=y@z_w+v");

        /* Nothing but whitespace leaves nothing, which callers read as "no
         * identity" rather than as an empty component to concatenate. */
        ASSERT_EQ_INT(devd_sanitize("   ", out, sizeof(out)), 0);
        ASSERT_STREQ(out, "");
        ASSERT_EQ_INT(devd_sanitize("", out, sizeof(out)), 0);
        ASSERT_EQ_INT(devd_sanitize(NULL, out, sizeof(out)), 0);

        /* Truncation stays terminated and inside the buffer. */
        ASSERT_TRUE(devd_sanitize("abcdefghij", out, 5) == 4);
        ASSERT_STREQ(out, "abcd");
        ASSERT_EQ_INT(devd_sanitize("abc", out, 0), 0);
}

/* --- the sysfs by-id walk --- */

/* mkdir every component of `rel` under `root`. */
static void mkpath(const char *root, const char *rel) {
        char path[PATH_MAX];
        size_t n;

        n = (size_t) snprintf(path, sizeof(path), "%s/%s", root, rel);
        ASSERT_TRUE(n < sizeof(path));

        for (char *p = path + strlen(root) + 1; *p; p++) {
                if (*p != '/')
                        continue;

                *p = '\0';
                ASSERT_TRUE(mkdir(path, 0755) == 0 || errno == EEXIST);
                *p = '/';
        }

        ASSERT_TRUE(mkdir(path, 0755) == 0 || errno == EEXIST);
}

static void attr(const char *root, const char *rel, const char *name, const char *value) {
        char dir[PATH_MAX], content[256];

        ASSERT_TRUE((size_t) snprintf(dir, sizeof(dir), "%s/%s", root, rel) < sizeof(dir));
        ASSERT_TRUE((size_t) snprintf(content, sizeof(content), "%s\n", value) < sizeof(content));
        ASSERT_EQ_INT(test_write_file(dir, name, content), 0);
}

/*
 * A USB card reader, laid out the way a real one is: the block device six
 * levels below the usb_device that carries the descriptor strings, with a
 * scsi_device, a target, a host and the interface in between -- none of which
 * identify anything, which is the whole reason the walk exists.
 */
#define USB_DEV "devices/pci0000:00/0000:00:14.0/usb1/1-1"
#define USB_BLOCK USB_DEV "/1-1:1.0/host0/target0:0:0/0:0:0:0/block/sda"

static void test_usb_id(void) {
        char id[DEVD_ID_MAX], disk[PATH_MAX];
        char *root;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        mkpath(root, USB_BLOCK);
        attr(root, USB_DEV, "idVendor", "0bda");
        attr(root, USB_DEV, "idProduct", "0316");
        attr(root, USB_DEV, "manufacturer", "Generic");
        attr(root, USB_DEV, "product", "USB  Reader");
        attr(root, USB_DEV, "serial", "000000264001");

        ASSERT_TRUE((size_t) snprintf(disk, sizeof(disk), "%s/%s", root, USB_BLOCK) < sizeof(disk));
        ASSERT_EQ_INT(devd_probe_bus_id(root, disk, id, sizeof(id)), 1);

        /* The double space in the product string collapses to one underscore,
         * which is what makes this the same name udev would have written. */
        ASSERT_STREQ(id, "usb-Generic_USB_Reader_000000264001");

        test_rm_rf(root);
        free(root);
}

/* A stick with no serial: two components rather than three, and no attempt to
 * invent a third. */
static void test_usb_id_no_serial(void) {
        char id[DEVD_ID_MAX], disk[PATH_MAX];
        char *root;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        mkpath(root, USB_BLOCK);
        attr(root, USB_DEV, "idVendor", "0951");
        attr(root, USB_DEV, "idProduct", "1666");
        attr(root, USB_DEV, "manufacturer", "Kingston");
        attr(root, USB_DEV, "product", "DataTraveler 3.0");

        ASSERT_TRUE((size_t) snprintf(disk, sizeof(disk), "%s/%s", root, USB_BLOCK) < sizeof(disk));
        ASSERT_EQ_INT(devd_probe_bus_id(root, disk, id, sizeof(id)), 1);
        ASSERT_STREQ(id, "usb-Kingston_DataTraveler_3.0");

        test_rm_rf(root);
        free(root);
}

/*
 * The recorded v1 divergence, asserted rather than described: a USB device with
 * no descriptor strings at all gets no by-id link, where upstream's usb_id
 * builtin would fall back to hex vendor:product IDs.
 */
static void test_usb_id_no_strings(void) {
        char id[DEVD_ID_MAX], disk[PATH_MAX];
        char *root;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        mkpath(root, USB_BLOCK);
        attr(root, USB_DEV, "idVendor", "1234");
        attr(root, USB_DEV, "idProduct", "5678");

        ASSERT_TRUE((size_t) snprintf(disk, sizeof(disk), "%s/%s", root, USB_BLOCK) < sizeof(disk));
        ASSERT_EQ_INT(devd_probe_bus_id(root, disk, id, sizeof(id)), 0);
        ASSERT_STREQ(id, "");

        test_rm_rf(root);
        free(root);
}

/* MMC, which never needed a builtin even upstream: the card's CID-derived
 * name and serial are plain sysfs attributes one level above the block
 * device. */
#define MMC_CARD "devices/platform/soc/1c0f000.mmc/mmc_host/mmc0/mmc0:0001"
#define MMC_BLOCK MMC_CARD "/block/mmcblk0"

static void test_mmc_id(void) {
        char id[DEVD_ID_MAX], disk[PATH_MAX];
        char *root;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        mkpath(root, MMC_BLOCK);
        attr(root, MMC_CARD, "name", "SD32G");
        attr(root, MMC_CARD, "serial", "0x1b8c4e21");
        attr(root, MMC_CARD, "type", "SD");

        ASSERT_TRUE((size_t) snprintf(disk, sizeof(disk), "%s/%s", root, MMC_BLOCK) < sizeof(disk));
        ASSERT_EQ_INT(devd_probe_bus_id(root, disk, id, sizeof(id)), 1);
        ASSERT_STREQ(id, "mmc-SD32G_0x1b8c4e21");

        test_rm_rf(root);
        free(root);
}

/* Nothing on the chain identifies itself -- a virtual block device, say. The
 * walk stops at the root it was given rather than climbing out of the fixture
 * and into the host's own filesystem. */
static void test_no_identity(void) {
        char id[DEVD_ID_MAX], disk[PATH_MAX];
        char *root;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        mkpath(root, "devices/virtual/block/loop0");

        ASSERT_TRUE((size_t) snprintf(disk, sizeof(disk), "%s/devices/virtual/block/loop0", root) <
                    sizeof(disk));
        ASSERT_EQ_INT(devd_probe_bus_id(root, disk, id, sizeof(id)), 0);
        ASSERT_STREQ(id, "");

        /* A path that is not under the root at all is refused outright. */
        ASSERT_EQ_INT(devd_probe_bus_id(root, "/elsewhere/block/sda", id, sizeof(id)), -EINVAL);

        test_rm_rf(root);
        free(root);
}

int main(void) {
        test_ext_super();
        test_ext_device();
        test_sanitize();
        test_usb_id();
        test_usb_id_no_serial();
        test_usb_id_no_strings();
        test_mmc_id();
        test_no_identity();

        printf("test-devd-probe: all checks passed\n");
        return 0;
}
