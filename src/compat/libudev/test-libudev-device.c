/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udev_device getters and list-entry iteration against a fixture /sys
 * and /dev: every scalar getter's value and its documented NULL/0 answer
 * for an absent field, the parent chain's child-owned lifetime, the
 * properties/sysattr/devlink/tag lists, sysattr write-through, the
 * environment-overlay constructor, the udev context, and
 * udev_util_encode_string(). Both libudev error conventions are pinned:
 * a NULL result with errno set for a real error, a plain NULL/0 with
 * errno untouched for "no such value".
 */

#include "libudev.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test-util.h"
#include "device-internal.h"

static char *g_sys, *g_dev;
static struct udev *g_udev;

static void mkpath(const char *base, const char *rel) {
        char partial[512] = { 0 };
        char rel_copy[256];
        char *seg, *saveptr;

        snprintf(rel_copy, sizeof(rel_copy), "%s", rel);
        for (seg = strtok_r(rel_copy, "/", &saveptr); seg; seg = strtok_r(NULL, "/", &saveptr)) {
                char next[512];

                /* GCC's format-truncation checker cannot see that these are short,
                 * controlled test fixture path segments -- it only sees three
                 * unbounded %s into a 512-byte buffer. Real risk is zero here. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
                snprintf(next, sizeof(next), "%s%s%s", partial, partial[0] ? "/" : "", seg);
#pragma GCC diagnostic pop
                ASSERT_EQ_INT(test_mkdir(base, next), 0);
                snprintf(partial, sizeof(partial), "%s", next);
        }
}

static void setup(void) {
        char sysroot[620];

        g_sys = test_tmpdir_new();
        g_dev = test_tmpdir_new();
        ASSERT_TRUE(g_sys != NULL && g_dev != NULL);
        snprintf(sysroot, sizeof(sysroot), "%s/sys", g_sys);
        device_set_sys_root_for_tests(sysroot);
        device_set_dev_root_for_tests(g_dev);

        /* platform/foo (driver foodrv, no node) -> foo/bar1 (block disk, node /dev/bar1) */
        mkpath(g_sys, "sys/devices/platform/foo/bar1");
        ASSERT_EQ_INT(test_write_file(g_sys, "sys/devices/platform/foo/uevent", "DRIVER=foodrv\n"), 0);
        ASSERT_EQ_INT(test_write_file(g_sys,
                                      "sys/devices/platform/foo/bar1/uevent",
                                      "MAJOR=8\nMINOR=1\nDEVNAME=bar1\nDEVTYPE=disk\nID_TEST=fixture\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(g_sys, "sys/devices/platform/foo/bar1/size", "2048\n"), 0);
        ASSERT_EQ_INT(test_write_file(g_sys, "sys/devices/platform/foo/bar1/ro", "0\n"), 0);
        mkpath(g_sys, "sys/bus/platform/drivers/foodrv");
        mkpath(g_sys, "sys/class/block");
        mkpath(g_sys, "sys/dev/block");
        ASSERT_EQ_INT(test_symlink(g_sys, "sys/devices/platform/foo/subsystem", "../../../bus/platform"), 0);
        ASSERT_EQ_INT(test_symlink(g_sys,
                                   "sys/devices/platform/foo/driver",
                                   "../../../bus/platform/drivers/foodrv"),
                      0);
        ASSERT_EQ_INT(test_symlink(g_sys, "sys/devices/platform/foo/bar1/subsystem", "../../../../class/block"),
                      0);
        ASSERT_EQ_INT(test_symlink(g_sys, "sys/class/block/bar1", "../../devices/platform/foo/bar1"), 0);
        ASSERT_EQ_INT(test_symlink(g_sys, "sys/dev/block/8:1", "../../devices/platform/foo/bar1"), 0);

        ASSERT_EQ_INT(test_write_file(g_dev, "bar1", ""), 0);
        mkpath(g_dev, "disk/by-label");
        ASSERT_EQ_INT(test_symlink(g_dev, "disk/by-label/fixture", "../../bar1"), 0);

        g_udev = udev_new();
        ASSERT_TRUE(g_udev != NULL);
}

static void teardown(void) {
        ASSERT_TRUE(udev_unref(g_udev) == NULL);
        test_rm_rf(g_sys);
        test_rm_rf(g_dev);
        free(g_sys);
        free(g_dev);
}

static struct udev_device *open_bar1(void) {
        char path[600];
        struct udev_device *d;

        snprintf(path, sizeof(path), "%s/sys/devices/platform/foo/bar1", g_sys);
        d = udev_device_new_from_syspath(g_udev, path);
        ASSERT_TRUE(d != NULL);
        return d;
}

static void test_scalar_getters(void) {
        struct udev_device *d, *parent, *again;
        char expect[600];

        setup();
        d = open_bar1();

        snprintf(expect, sizeof(expect), "%s/sys/devices/platform/foo/bar1", g_sys);
        ASSERT_STREQ(udev_device_get_syspath(d), expect);
        ASSERT_STREQ(udev_device_get_devpath(d), "/devices/platform/foo/bar1");
        ASSERT_STREQ(udev_device_get_sysname(d), "bar1");
        ASSERT_STREQ(udev_device_get_sysnum(d), "1");
        ASSERT_STREQ(udev_device_get_subsystem(d), "block");
        ASSERT_STREQ(udev_device_get_devtype(d), "disk");
        ASSERT_STREQ(udev_device_get_devnode(d), "/dev/bar1");
        ASSERT_EQ_INT(major(udev_device_get_devnum(d)), 8);
        ASSERT_EQ_INT(minor(udev_device_get_devnum(d)), 1);
        ASSERT_EQ_INT(udev_device_get_is_initialized(d), 1);
        ASSERT_STREQ(udev_device_get_property_value(d, "ID_TEST"), "fixture");
        ASSERT_STREQ(udev_device_get_property_value(d, "SUBSYSTEM"), "block");
        ASSERT_STREQ(udev_device_get_sysattr_value(d, "size"), "2048");

        /* "no such value" answers: NULL/0 with errno left alone */
        errno = 0;
        ASSERT_TRUE(udev_device_get_action(d) == NULL); /* not from a monitor */
        ASSERT_EQ_INT(udev_device_get_seqnum(d), 0);
        ASSERT_EQ_INT(udev_device_has_tag(d, "x"), 0);
        ASSERT_EQ_INT(udev_device_has_current_tag(d, "x"), 0);
        ASSERT_EQ_INT(errno, 0);
        ASSERT_TRUE(udev_device_get_driver(d) == NULL); /* no driver link on bar1: NULL + errno */
        ASSERT_EQ_INT(errno, ENOENT);
        errno = 0;
        ASSERT_EQ_INT(udev_device_get_usec_since_initialized(d), 0);
        ASSERT_EQ_INT(errno, ENODATA);

        /* a real error: NULL plus errno */
        errno = 0;
        ASSERT_TRUE(udev_device_get_property_value(d, "NOSUCH") == NULL);
        ASSERT_EQ_INT(errno, ENOENT);
        errno = 0;
        ASSERT_TRUE(udev_device_get_sysattr_value(d, "nosuch") == NULL);
        ASSERT_EQ_INT(errno, ENOENT);

        /* parent: driver-bearing, no node, no devtype; the same wrapper
         * comes back every time and dies with the child */
        parent = udev_device_get_parent(d);
        ASSERT_TRUE(parent != NULL);
        ASSERT_STREQ(udev_device_get_sysname(parent), "foo");
        ASSERT_STREQ(udev_device_get_driver(parent), "foodrv");
        ASSERT_STREQ(udev_device_get_subsystem(parent), "platform");
        ASSERT_TRUE(udev_device_get_devtype(parent) == NULL);
        ASSERT_TRUE(udev_device_get_sysnum(parent) == NULL);
        ASSERT_EQ_INT(udev_device_get_devnum(parent), makedev(0, 0));
        ASSERT_TRUE(udev_device_get_parent(d) == parent);
        ASSERT_TRUE(udev_device_get_parent(parent) == NULL); /* nothing above platform/foo */
        ASSERT_TRUE(udev_device_get_parent_with_subsystem_devtype(d, "platform", NULL) == parent);
        errno = 0;
        ASSERT_TRUE(udev_device_get_parent_with_subsystem_devtype(d, "usb", "usb_device") == NULL);
        ASSERT_EQ_INT(errno, ENOENT);

        /* the other constructors land on the same device */
        again = udev_device_new_from_devnum(g_udev, 'b', makedev(8, 1));
        ASSERT_TRUE(again != NULL);
        ASSERT_STREQ(udev_device_get_syspath(again), expect);
        udev_device_unref(again);
        again = udev_device_new_from_subsystem_sysname(g_udev, "block", "bar1");
        ASSERT_TRUE(again != NULL);
        ASSERT_STREQ(udev_device_get_syspath(again), expect);
        udev_device_unref(again);
        again = udev_device_new_from_device_id(g_udev, "b8:1");
        ASSERT_TRUE(again != NULL);
        ASSERT_STREQ(udev_device_get_syspath(again), expect);
        udev_device_unref(again);

        errno = 0;
        ASSERT_TRUE(udev_device_new_from_devnum(g_udev, 'c', makedev(8, 1)) == NULL);
        ASSERT_TRUE(errno != 0);
        errno = 0;
        ASSERT_TRUE(udev_device_new_from_syspath(g_udev, "/nonexistent/path") == NULL);
        ASSERT_TRUE(errno != 0);

        ASSERT_TRUE(udev_device_ref(d) == d);
        ASSERT_TRUE(udev_device_unref(d) == NULL);
        ASSERT_TRUE(udev_device_unref(d) == NULL);
        teardown();
}

static int count_entries(struct udev_list_entry *first, const char *must_have, const char *must_lack) {
        struct udev_list_entry *e;
        int n = 0, found = 0;

        udev_list_entry_foreach(e, first) {
                ASSERT_TRUE(udev_list_entry_get_name(e) != NULL);
                if (must_have && strcmp(udev_list_entry_get_name(e), must_have) == 0)
                        found = 1;
                if (must_lack)
                        ASSERT_TRUE(strcmp(udev_list_entry_get_name(e), must_lack) != 0);
                n++;
        }
        if (must_have)
                ASSERT_TRUE(found);
        return n;
}

static void test_lists(void) {
        struct udev_device *d;
        struct udev_list_entry *first, *e;
        const char *prev;

        setup();
        d = open_bar1();

        /* properties: keyed, sorted by name, searchable; the synthesized
         * keys sit beside the uevent ones */
        first = udev_device_get_properties_list_entry(d);
        ASSERT_TRUE(first != NULL);
        ASSERT_TRUE(count_entries(first, "ID_TEST", NULL) >= 6);
        e = udev_list_entry_get_by_name(first, "DEVNAME");
        ASSERT_TRUE(e != NULL);
        ASSERT_STREQ(udev_list_entry_get_value(e), "bar1");
        ASSERT_TRUE(udev_list_entry_get_by_name(first, "NOSUCH") == NULL);
        prev = NULL;
        udev_list_entry_foreach(e, first) {
                if (prev)
                        ASSERT_TRUE(strcmp(prev, udev_list_entry_get_name(e)) < 0);
                prev = udev_list_entry_get_name(e);
        }
        /* the list is cached: the same first entry comes back */
        ASSERT_TRUE(udev_device_get_properties_list_entry(d) == first);

        /* sysattrs: names only, values empty */
        first = udev_device_get_sysattr_list_entry(d);
        ASSERT_TRUE(first != NULL);
        ASSERT_TRUE(count_entries(first, "size", "subsystem") >= 3); /* regular files only, not the symlinks */
        e = udev_list_entry_get_by_name(first, "ro");
        ASSERT_TRUE(e != NULL);
        ASSERT_TRUE(udev_list_entry_get_value(e) == NULL);

        /* devlinks: the one symlink under the fixture /dev that targets bar1 */
        first = udev_device_get_devlinks_list_entry(d);
        ASSERT_TRUE(first != NULL);
        ASSERT_EQ_INT(count_entries(first, NULL, NULL), 1);
        ASSERT_TRUE(strstr(udev_list_entry_get_name(first), "disk/by-label/fixture") != NULL);

        /* tags: genuinely empty, both lists */
        ASSERT_TRUE(udev_device_get_tags_list_entry(d) == NULL);
        ASSERT_TRUE(udev_device_get_current_tags_list_entry(d) == NULL);

        /* sysattr write-through: the file and the cached value both change */
        ASSERT_EQ_INT(udev_device_set_sysattr_value(d, "ro", "1"), 0);
        ASSERT_STREQ(udev_device_get_sysattr_value(d, "ro"), "1");
        ASSERT_TRUE(udev_device_set_sysattr_value(d, "nosuch", "1") < 0);

        udev_device_unref(d);
        teardown();
}

static void test_from_environment(void) {
        struct udev_device *d;
        struct udev_list_entry *e;

        setup();

        errno = 0;
        unsetenv("DEVPATH");
        ASSERT_TRUE(udev_device_new_from_environment(g_udev) == NULL);
        ASSERT_EQ_INT(errno, EINVAL);

        /* The fixture root is not /sys, so this constructor's fixed /sys
         * prefix cannot reach it: only the rejection path is testable
         * here, the accept path is the same syspath constructor above. */
        setenv("DEVPATH", "/devices/nonexistent/fixture-only", 1);
        setenv("ACTION", "add", 1);
        errno = 0;
        d = udev_device_new_from_environment(g_udev);
        ASSERT_TRUE(d == NULL);
        ASSERT_TRUE(errno != 0);
        unsetenv("DEVPATH");
        unsetenv("ACTION");

        /* the udev context: refcount, userdata and the deprecated log knobs */
        ASSERT_TRUE(udev_get_userdata(g_udev) == NULL);
        udev_set_userdata(g_udev, &e);
        ASSERT_TRUE(udev_get_userdata(g_udev) == &e);
        ASSERT_TRUE(udev_ref(g_udev) == g_udev);
        ASSERT_TRUE(udev_unref(g_udev) == g_udev); /* one ref left: returns the context */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        udev_set_log_fn(g_udev, NULL);
        udev_set_log_priority(g_udev, 7);
        ASSERT_EQ_INT(udev_get_log_priority(g_udev), 7);
#pragma GCC diagnostic pop

        teardown();
}

static void test_encode_string(void) {
        char buf[64];

        ASSERT_EQ_INT(udev_util_encode_string("sda1", buf, sizeof(buf)), 0);
        ASSERT_STREQ(buf, "sda1");
        ASSERT_EQ_INT(udev_util_encode_string("a b/c", buf, sizeof(buf)), 0);
        ASSERT_STREQ(buf, "a\\x20b\\x2fc");
        ASSERT_EQ_INT(udev_util_encode_string("A-Z_0.9:=@#+", buf, sizeof(buf)), 0);
        ASSERT_STREQ(buf, "A-Z_0.9:=@#+");
        ASSERT_EQ_INT(udev_util_encode_string("caf\xc3\xa9", buf, sizeof(buf)), 0); /* valid UTF-8 passes */
        ASSERT_STREQ(buf, "caf\xc3\xa9");
        ASSERT_EQ_INT(udev_util_encode_string("x\xc3", buf, sizeof(buf)), 0); /* truncated sequence escaped */
        ASSERT_STREQ(buf, "x\\xc3");
        ASSERT_EQ_INT(udev_util_encode_string("", buf, sizeof(buf)), 0);
        ASSERT_STREQ(buf, "");
        ASSERT_TRUE(udev_util_encode_string("toolong", buf, 4) < 0);
        ASSERT_TRUE(udev_util_encode_string(" ", buf, 4) < 0); /* needs 4 + NUL */
        ASSERT_EQ_INT(udev_util_encode_string(" ", buf, 5), 0);
        ASSERT_TRUE(udev_util_encode_string(NULL, buf, sizeof(buf)) < 0);
}

int main(void) {
        test_scalar_getters();
        test_lists();
        test_from_environment();
        test_encode_string();

        printf("test-libudev-device: OK\n");
        return 0;
}
