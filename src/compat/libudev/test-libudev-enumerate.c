/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udev_enumerate round trip against the same fixture /sys
 * test-sd-device-enumerator.c uses: two devices on one bus, one nested
 * under a parent, plus the bus/class/module trees scan_subsystems() walks.
 * Every result comes back as a syspath list entry that is then re-opened
 * through udev_device_new_from_syspath(), which is the shape every real
 * consumer (libusb, bluez) drives this API in.
 */

#include "libudev.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../../test-util.h"
#include "device-internal.h"

static char *g_tmp;
static struct udev *g_udev;

static void setup(void) {
        char sysroot[620];

        g_tmp = test_tmpdir_new();
        ASSERT_TRUE(g_tmp != NULL);
        snprintf(sysroot, sizeof(sysroot), "%s/sys", g_tmp);
        device_set_sys_root_for_tests(sysroot);

        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys"), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/devices"), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/devices/platform"), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/devices/platform/parentX"), 0);
        ASSERT_EQ_INT(test_write_file(g_tmp, "sys/devices/platform/parentX/uevent", ""), 0);

        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/devices/platform/parentX/dev1"), 0);
        ASSERT_EQ_INT(test_write_file(g_tmp, "sys/devices/platform/parentX/dev1/uevent", "FOO=bar\n"), 0);
        ASSERT_EQ_INT(test_write_file(g_tmp, "sys/devices/platform/parentX/dev1/special", "yes\n"), 0);
        ASSERT_EQ_INT(test_symlink(g_tmp,
                                   "sys/devices/platform/parentX/dev1/subsystem",
                                   "../../../../bus/testbus"),
                      0);

        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/devices/platform/dev2"), 0);
        ASSERT_EQ_INT(test_write_file(g_tmp, "sys/devices/platform/dev2/uevent", ""), 0);
        ASSERT_EQ_INT(test_symlink(g_tmp, "sys/devices/platform/dev2/subsystem", "../../../bus/testbus"), 0);

        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/bus"), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/bus/testbus"), 0);
        ASSERT_EQ_INT(test_write_file(g_tmp, "sys/bus/testbus/uevent", ""), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/bus/testbus/devices"), 0);
        ASSERT_EQ_INT(test_symlink(g_tmp,
                                   "sys/bus/testbus/devices/dev1",
                                   "../../../devices/platform/parentX/dev1"),
                      0);
        ASSERT_EQ_INT(test_symlink(g_tmp, "sys/bus/testbus/devices/dev2", "../../../devices/platform/dev2"),
                      0);

        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/class"), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/class/net"), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/module"), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/module/foomod"), 0);

        g_udev = udev_new();
        ASSERT_TRUE(g_udev != NULL);
}

static void teardown(void) {
        ASSERT_TRUE(udev_unref(g_udev) == NULL);
        test_rm_rf(g_tmp);
        free(g_tmp);
}

/* Walks the result list, re-opens every entry as a device and checks its
 * sysname is one the caller expects; returns the entry count. */
static int count_and_check(struct udev_enumerate *e, const char *want_a, const char *want_b) {
        struct udev_list_entry *entry;
        int n = 0;

        udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(e)) {
                const char *syspath = udev_list_entry_get_name(entry);
                struct udev_device *d;
                const char *sysname;

                ASSERT_TRUE(syspath != NULL);
                ASSERT_TRUE(udev_list_entry_get_value(entry) == NULL);
                ASSERT_TRUE(strncmp(syspath, g_tmp, strlen(g_tmp)) == 0);

                d = udev_device_new_from_syspath(g_udev, syspath);
                ASSERT_TRUE(d != NULL);
                ASSERT_STREQ(udev_device_get_syspath(d), syspath);
                sysname = udev_device_get_sysname(d);
                ASSERT_TRUE(sysname != NULL);
                if (want_a || want_b)
                        ASSERT_TRUE((want_a && strcmp(sysname, want_a) == 0) ||
                                    (want_b && strcmp(sysname, want_b) == 0));
                ASSERT_TRUE(udev_device_get_udev(d) == g_udev);
                udev_device_unref(d);
                n++;
        }
        return n;
}

static void test_scan_devices_and_subsystem_match(void) {
        struct udev_enumerate *e;

        setup();

        e = udev_enumerate_new(g_udev);
        ASSERT_TRUE(e != NULL);
        ASSERT_TRUE(udev_enumerate_get_udev(e) == g_udev);
        ASSERT_TRUE(udev_enumerate_ref(e) == e);
        ASSERT_TRUE(udev_enumerate_unref(e) == NULL); /* one ref left */

        ASSERT_EQ_INT(udev_enumerate_scan_devices(e), 0);
        ASSERT_EQ_INT(count_and_check(e, NULL, NULL), 2);

        /* A NULL match argument is accepted and changes nothing. */
        ASSERT_EQ_INT(udev_enumerate_add_match_subsystem(e, NULL), 0);
        ASSERT_EQ_INT(udev_enumerate_add_match_subsystem(e, "testbus"), 0);
        ASSERT_EQ_INT(udev_enumerate_scan_devices(e), 0);
        ASSERT_EQ_INT(count_and_check(e, "dev1", "dev2"), 2);

        ASSERT_EQ_INT(udev_enumerate_add_nomatch_subsystem(e, "testbus"), 0);
        ASSERT_EQ_INT(udev_enumerate_scan_devices(e), 0);
        errno = 0;
        ASSERT_TRUE(udev_enumerate_get_list_entry(e) == NULL);
        ASSERT_EQ_INT(errno, ENODATA);

        ASSERT_TRUE(udev_enumerate_unref(e) == NULL);
        teardown();
}

static void test_property_sysname_sysattr_matches(void) {
        struct udev_enumerate *e;

        setup();

        e = udev_enumerate_new(g_udev);
        ASSERT_EQ_INT(udev_enumerate_add_match_sysname(e, "dev1"), 0);
        /* No explicit scan: get_list_entry() runs the device scan itself. */
        ASSERT_EQ_INT(count_and_check(e, "dev1", NULL), 1);
        udev_enumerate_unref(e);

        e = udev_enumerate_new(g_udev);
        ASSERT_EQ_INT(udev_enumerate_add_match_property(e, "FOO", "bar"), 0);
        ASSERT_EQ_INT(udev_enumerate_scan_devices(e), 0);
        ASSERT_EQ_INT(count_and_check(e, "dev1", NULL), 1);
        udev_enumerate_unref(e);

        e = udev_enumerate_new(g_udev);
        ASSERT_EQ_INT(udev_enumerate_add_match_sysattr(e, "special", "yes"), 0);
        ASSERT_EQ_INT(udev_enumerate_scan_devices(e), 0);
        ASSERT_EQ_INT(count_and_check(e, "dev1", NULL), 1);
        udev_enumerate_unref(e);

        e = udev_enumerate_new(g_udev);
        ASSERT_EQ_INT(udev_enumerate_add_nomatch_sysattr(e, "special", NULL), 0);
        ASSERT_EQ_INT(udev_enumerate_scan_devices(e), 0);
        ASSERT_EQ_INT(count_and_check(e, "dev2", NULL), 1);
        udev_enumerate_unref(e);

        e = udev_enumerate_new(g_udev);
        ASSERT_EQ_INT(udev_enumerate_add_match_tag(e, "anything"), 0); /* the tag set is always empty */
        ASSERT_EQ_INT(udev_enumerate_scan_devices(e), 0);
        ASSERT_TRUE(udev_enumerate_get_list_entry(e) == NULL);
        udev_enumerate_unref(e);

        e = udev_enumerate_new(g_udev);
        ASSERT_EQ_INT(udev_enumerate_add_match_is_initialized(e), 0); /* admits everything here */
        ASSERT_EQ_INT(udev_enumerate_scan_devices(e), 0);
        ASSERT_EQ_INT(count_and_check(e, "dev1", "dev2"), 2);
        udev_enumerate_unref(e);

        teardown();
}

static void test_parent_match_and_add_syspath(void) {
        struct udev_enumerate *e;
        struct udev_device *parent;
        char path[600];

        setup();

        snprintf(path, sizeof(path), "%s/sys/devices/platform/parentX", g_tmp);
        parent = udev_device_new_from_syspath(g_udev, path);
        ASSERT_TRUE(parent != NULL);

        e = udev_enumerate_new(g_udev);
        ASSERT_EQ_INT(udev_enumerate_add_match_parent(e, parent), 0);
        ASSERT_EQ_INT(udev_enumerate_scan_devices(e), 0);
        ASSERT_EQ_INT(count_and_check(e, "dev1", NULL), 1);

        /* add_syspath() joins the result even though the parent filter
         * excludes it; a duplicate of an already-listed device does not
         * double up; a non-device path is rejected. */
        snprintf(path, sizeof(path), "%s/sys/devices/platform/dev2", g_tmp);
        ASSERT_EQ_INT(udev_enumerate_add_syspath(e, path), 0);
        snprintf(path, sizeof(path), "%s/sys/devices/platform/parentX/dev1", g_tmp);
        ASSERT_EQ_INT(udev_enumerate_add_syspath(e, path), 0);
        snprintf(path, sizeof(path), "%s/sys/nosuch", g_tmp);
        ASSERT_TRUE(udev_enumerate_add_syspath(e, path) < 0);
        ASSERT_EQ_INT(udev_enumerate_scan_devices(e), 0);
        ASSERT_EQ_INT(count_and_check(e, "dev1", "dev2"), 2);

        udev_enumerate_unref(e);
        udev_device_unref(parent);
        teardown();
}

static void test_scan_subsystems(void) {
        struct udev_enumerate *e;
        struct udev_list_entry *entry;
        int n = 0, saw_testbus = 0;

        setup();

        e = udev_enumerate_new(g_udev);
        ASSERT_EQ_INT(udev_enumerate_scan_subsystems(e), 0);
        udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(e)) {
                const char *name = udev_list_entry_get_name(entry);

                if (strstr(name, "/bus/testbus"))
                        saw_testbus = 1;
                n++;
        }
        ASSERT_TRUE(saw_testbus);
        ASSERT_EQ_INT(n, 3); /* testbus (bus), net (class), foomod (module) */

        /* A device scan afterwards replaces the subsystem result. */
        ASSERT_EQ_INT(udev_enumerate_scan_devices(e), 0);
        ASSERT_EQ_INT(count_and_check(e, "dev1", "dev2"), 2);
        udev_enumerate_unref(e);

        teardown();
}

int main(void) {
        test_scan_devices_and_subsystem_match();
        test_property_sysname_sysattr_matches();
        test_parent_match_and_add_syspath();
        test_scan_subsystems();

        printf("test-libudev-enumerate: OK\n");
        return 0;
}
