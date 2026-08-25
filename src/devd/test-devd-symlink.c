/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The /dev/disk/by-* lifecycle, against a real directory tree.
 *
 * A mock would prove nothing here. What is being tested is a set of symlinks on
 * a filesystem and three operations over them, and every interesting case is
 * about what is really on disk: a link left behind by a device that is gone, a
 * link whose target has been replaced, a label containing a character that
 * would otherwise turn one link name into a path. So each test builds a small
 * /dev of its own -- which is also the only honest way to run this at all,
 * since the alternative is creating and unlinking things under the test host's
 * real /dev.
 *
 * The reconcile case is the one that justifies devd being a daemon rather than
 * a boot-time pass. A writer that only ever creates links has no answer for
 * what happens after an unclean stop; this is that answer, and it is asserted
 * here rather than assumed.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test-util.h"
#include "devd-symlink.h"

/* A stand-in device node. A regular file is enough: everything under test
 * either readlink()s a symlink or stat()s a target. */
static void make_node(const char *dev_root, const char *name) {
        ASSERT_EQ_INT(test_write_file(dev_root, name, ""), 0);
}

/* Read one by-* link back. Returns false when it is not there at all. */
static bool read_link(const char *dev_root, const char *family, const char *name, char *ret, size_t size) {
        char path[PATH_MAX];
        ssize_t k;

        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/disk/%s/%s", dev_root, family, name) <
                    sizeof(path));

        k = readlink(path, ret, size - 1);
        if (k < 0)
                return false;

        ret[k] = '\0';
        return true;
}

static bool link_exists(const char *dev_root, const char *family, const char *name) {
        char target[PATH_MAX];

        return read_link(dev_root, family, name, target, sizeof(target));
}

static void test_escape(void) {
        char out[64];

        /* The whitelist passes through untouched, so the common case -- a
         * UUID -- is spelled exactly as blkid would spell it. */
        ASSERT_EQ_INT(devd_symlink_escape("12345678-90ab-cdef-1234-567890abcdef", out, sizeof(out)), 36);
        ASSERT_STREQ(out, "12345678-90ab-cdef-1234-567890abcdef");

        /* The case that makes escaping mandatory rather than cosmetic. */
        ASSERT_EQ_INT(devd_symlink_escape("a/b", out, sizeof(out)), 6);
        ASSERT_STREQ(out, "a\\x2fb");

        /* A space, which is what most real-world labels contain, and which
         * must survive as itself rather than collapsing the way the by-id
         * sanitizer collapses it -- two labels differing only in a space are
         * two labels. */
        ASSERT_EQ_INT(devd_symlink_escape("My Card", out, sizeof(out)), 10);
        ASSERT_STREQ(out, "My\\x20Card");

        ASSERT_EQ_INT(devd_symlink_escape("", out, sizeof(out)), 0);
        ASSERT_EQ_INT(devd_symlink_escape(NULL, out, sizeof(out)), 0);

        /* Truncation never splits an escape in half and never runs over. */
        ASSERT_TRUE(devd_symlink_escape("ab/cd", out, 6) == 2);
        ASSERT_STREQ(out, "ab");
}

static void fill(DevdLinks *l) {
        memset(l, 0, sizeof(*l));
        snprintf(l->partuuid, sizeof(l->partuuid), "5c2d1f7a-9b3e-4a11-8f42-6d7e0c9a1b23");
        snprintf(l->partlabel, sizeof(l->partlabel), "media");
        snprintf(l->fsuuid, sizeof(l->fsuuid), "12345678-90ab-cdef-1234-567890abcdef");
        snprintf(l->fslabel, sizeof(l->fslabel), "PICOTEST");
        snprintf(l->id, sizeof(l->id), "usb-Generic_USB_Reader_000000264001-part1");
}

static void test_create(void) {
        char target[PATH_MAX];
        DevdLinks l;
        char *dev;

        dev = test_tmpdir_new();
        ASSERT_TRUE(dev != NULL);
        make_node(dev, "sda1");

        fill(&l);
        ASSERT_EQ_INT(devd_symlink_create(dev, "sda1", &l), 0);

        /* All five families, and the relative target udev writes -- from
         * /dev/disk/by-uuid/x, "../../sda1" is /dev/sda1. */
        ASSERT_TRUE(read_link(
                        dev, "by-partuuid", "5c2d1f7a-9b3e-4a11-8f42-6d7e0c9a1b23", target, sizeof(target)));
        ASSERT_STREQ(target, "../../sda1");

        ASSERT_TRUE(link_exists(dev, "by-partlabel", "media"));
        ASSERT_TRUE(link_exists(dev, "by-uuid", "12345678-90ab-cdef-1234-567890abcdef"));
        ASSERT_TRUE(link_exists(dev, "by-label", "PICOTEST"));
        ASSERT_TRUE(link_exists(dev, "by-id", "usb-Generic_USB_Reader_000000264001-part1"));

        test_rm_rf(dev);
        free(dev);
}

/* An empty family value means "this device has no such name", and must make no
 * link at all rather than one called "". */
static void test_create_partial(void) {
        DevdLinks l;
        char *dev;

        dev = test_tmpdir_new();
        ASSERT_TRUE(dev != NULL);
        make_node(dev, "sda1");

        memset(&l, 0, sizeof(l));
        snprintf(l.partuuid, sizeof(l.partuuid), "5c2d1f7a-9b3e-4a11-8f42-6d7e0c9a1b23");

        ASSERT_EQ_INT(devd_symlink_create(dev, "sda1", &l), 0);
        ASSERT_TRUE(link_exists(dev, "by-partuuid", "5c2d1f7a-9b3e-4a11-8f42-6d7e0c9a1b23"));
        ASSERT_TRUE(!link_exists(dev, "by-label", ""));
        ASSERT_TRUE(!link_exists(dev, "by-uuid", ""));

        test_rm_rf(dev);
        free(dev);
}

/*
 * The same filesystem UUID turning up on a different device. The old link is
 * now wrong, and leaving it is the one outcome worse than either replacing or
 * refusing: a by-uuid link that resolves to the wrong disk.
 */
static void test_create_replaces(void) {
        char target[PATH_MAX];
        DevdLinks l;
        char *dev;

        dev = test_tmpdir_new();
        ASSERT_TRUE(dev != NULL);
        make_node(dev, "sda1");
        make_node(dev, "sdb1");

        memset(&l, 0, sizeof(l));
        snprintf(l.fsuuid, sizeof(l.fsuuid), "12345678-90ab-cdef-1234-567890abcdef");

        ASSERT_EQ_INT(devd_symlink_create(dev, "sda1", &l), 0);
        ASSERT_EQ_INT(devd_symlink_create(dev, "sdb1", &l), 0);

        ASSERT_TRUE(read_link(dev, "by-uuid", "12345678-90ab-cdef-1234-567890abcdef", target, sizeof(target)));
        ASSERT_STREQ(target, "../../sdb1");

        test_rm_rf(dev);
        free(dev);
}

/*
 * Removal works from what is on disk, not from what devd remembers -- which is
 * the whole point, since a restarted devd remembers nothing. Nothing here tells
 * devd_symlink_remove() which links it once created.
 */
static void test_remove(void) {
        DevdLinks l;
        char *dev;

        dev = test_tmpdir_new();
        ASSERT_TRUE(dev != NULL);
        make_node(dev, "sda1");
        make_node(dev, "sda2");

        fill(&l);
        ASSERT_EQ_INT(devd_symlink_create(dev, "sda1", &l), 0);

        memset(&l, 0, sizeof(l));
        snprintf(l.partlabel, sizeof(l.partlabel), "other");
        snprintf(l.fslabel, sizeof(l.fslabel), "SECOND");
        ASSERT_EQ_INT(devd_symlink_create(dev, "sda2", &l), 0);

        /* Five links for sda1, and not one of sda2's. */
        ASSERT_EQ_INT(devd_symlink_remove(dev, "sda1"), 5);

        ASSERT_TRUE(!link_exists(dev, "by-partuuid", "5c2d1f7a-9b3e-4a11-8f42-6d7e0c9a1b23"));
        ASSERT_TRUE(!link_exists(dev, "by-partlabel", "media"));
        ASSERT_TRUE(!link_exists(dev, "by-uuid", "12345678-90ab-cdef-1234-567890abcdef"));
        ASSERT_TRUE(!link_exists(dev, "by-label", "PICOTEST"));
        ASSERT_TRUE(!link_exists(dev, "by-id", "usb-Generic_USB_Reader_000000264001-part1"));

        ASSERT_TRUE(link_exists(dev, "by-partlabel", "other"));
        ASSERT_TRUE(link_exists(dev, "by-label", "SECOND"));

        /* Removing again, or removing a device that never had links, is zero
         * rather than an error: teardown should not need to know how far setup
         * got. */
        ASSERT_EQ_INT(devd_symlink_remove(dev, "sda1"), 0);
        ASSERT_EQ_INT(devd_symlink_remove(dev, "never-existed"), 0);

        test_rm_rf(dev);
        free(dev);
}

/*
 * Coldplug reconcile: devd is killed with a card in the slot, the card is
 * pulled while it is not running, and it starts again. Nothing generated a
 * remove event, so the only thing that can clear those links is noticing that
 * what they point at is not there.
 */
static void test_reconcile(void) {
        char path[PATH_MAX];
        DevdLinks l;
        char *dev;

        dev = test_tmpdir_new();
        ASSERT_TRUE(dev != NULL);
        make_node(dev, "sda1");
        make_node(dev, "mmcblk0p1");

        fill(&l);
        ASSERT_EQ_INT(devd_symlink_create(dev, "sda1", &l), 0);

        memset(&l, 0, sizeof(l));
        snprintf(l.partlabel, sizeof(l.partlabel), "onboard");
        snprintf(l.id, sizeof(l.id), "mmc-SD32G_0x1b8c4e21-part1");
        ASSERT_EQ_INT(devd_symlink_create(dev, "mmcblk0p1", &l), 0);

        /* The card goes away with devd not running. */
        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/sda1", dev) < sizeof(path));
        ASSERT_EQ_INT(unlink(path), 0);

        ASSERT_EQ_INT(devd_symlink_reconcile(dev), 5);

        ASSERT_TRUE(!link_exists(dev, "by-uuid", "12345678-90ab-cdef-1234-567890abcdef"));
        ASSERT_TRUE(!link_exists(dev, "by-id", "usb-Generic_USB_Reader_000000264001-part1"));

        /* The onboard card is still there and keeps its links: reconcile is
         * not "delete everything and start again". */
        ASSERT_TRUE(link_exists(dev, "by-partlabel", "onboard"));
        ASSERT_TRUE(link_exists(dev, "by-id", "mmc-SD32G_0x1b8c4e21-part1"));

        /* Idempotent: a second pass has nothing left to do. */
        ASSERT_EQ_INT(devd_symlink_reconcile(dev), 0);

        test_rm_rf(dev);
        free(dev);
}

/* A label with a '/' in it. Unescaped this would name a directory that does
 * not exist rather than a link, so the escape is what makes the link happen at
 * all -- and what makes it removable again afterwards. */
static void test_awkward_label(void) {
        char target[PATH_MAX];
        DevdLinks l;
        char *dev;

        dev = test_tmpdir_new();
        ASSERT_TRUE(dev != NULL);
        make_node(dev, "sda1");

        memset(&l, 0, sizeof(l));
        snprintf(l.fslabel, sizeof(l.fslabel), "A/B Card");

        ASSERT_EQ_INT(devd_symlink_create(dev, "sda1", &l), 0);
        ASSERT_TRUE(read_link(dev, "by-label", "A\\x2fB\\x20Card", target, sizeof(target)));
        ASSERT_STREQ(target, "../../sda1");

        ASSERT_EQ_INT(devd_symlink_remove(dev, "sda1"), 1);

        test_rm_rf(dev);
        free(dev);
}

/* Neither verb invents directories it was not given, and both tolerate a /dev
 * with no disk/ in it at all -- which is every first boot. */
static void test_missing_tree(void) {
        char *dev;

        dev = test_tmpdir_new();
        ASSERT_TRUE(dev != NULL);

        ASSERT_EQ_INT(devd_symlink_remove(dev, "sda1"), 0);
        ASSERT_EQ_INT(devd_symlink_reconcile(dev), 0);

        ASSERT_EQ_INT(devd_symlink_remove(NULL, "sda1"), -EINVAL);
        ASSERT_EQ_INT(devd_symlink_reconcile(NULL), -EINVAL);
        ASSERT_EQ_INT(devd_symlink_create(dev, "sda1", NULL), -EINVAL);

        test_rm_rf(dev);
        free(dev);
}

int main(void) {
        test_escape();
        test_create();
        test_create_partial();
        test_create_replaces();
        test_remove();
        test_reconcile();
        test_awkward_label();
        test_missing_tree();

        printf("test-devd-symlink: all checks passed\n");
        return 0;
}
