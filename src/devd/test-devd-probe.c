/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The field extraction behind by-id, and the sanitizer in front of it.
 *
 * The by-id half builds a sysfs tree in a temporary directory, because the real
 * one describes whatever is plugged into the machine running the test, which is
 * nothing predictable and on a build host is nothing at all. That is what
 * devd_probe_bus_id()'s sys_root parameter is for.
 *
 * The ext superblock half of this probe lives outside devd now -- PID 1 reads
 * the same fields for its own root check -- and so do its tests: see
 * ../test-ext-super.c.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test-util.h"
#include "devd-probe.h"

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
        test_sanitize();
        test_usb_id();
        test_usb_id_no_serial();
        test_usb_id_no_strings();
        test_mmc_id();
        test_no_identity();

        printf("test-devd-probe: all checks passed\n");
        return 0;
}
