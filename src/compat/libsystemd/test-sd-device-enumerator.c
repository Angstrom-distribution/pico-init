/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_device_enumerator against a small real /sys fixture: two devices on
 * one bus, one of them nested under a parent that itself has a uevent
 * file, plus the bus/class/module trees get_subsystem_first()/_next()
 * walks. Every match kind gets exercised against devices designed so a
 * wrong filter implementation would visibly include or exclude the wrong
 * one, not just "run without crashing".
 */

#include "sd-device.h"

#include <stdio.h>
#include <string.h>

#include "../../test-util.h"
#include "device-internal.h"

static char *g_tmp;

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
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/class/net"), 0); /* no uevent: real /sys/class/<x> has none */

        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/module"), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/module/foomod"), 0); /* no uevent either */
}

static void teardown(void) {
        test_rm_rf(g_tmp);
        free(g_tmp);
}

static int count_and_check(sd_device_enumerator *e, bool (*want)(const char *sysname)) {
        sd_device *d;
        int n = 0;
        const char *sysname;

        for (d = sd_device_enumerator_get_device_first(e); d; d = sd_device_enumerator_get_device_next(e)) {
                ASSERT_EQ_INT(sd_device_get_sysname(d, &sysname), 0);
                if (want)
                        ASSERT_TRUE(want(sysname));
                n++;
        }
        return n;
}

static bool is_dev1(const char *s) {
        return strcmp(s, "dev1") == 0;
}
static bool is_dev1_or_parentx(const char *s) {
        return strcmp(s, "dev1") == 0 || strcmp(s, "parentX") == 0;
}

static void test_unfiltered_and_subsystem_match(void) {
        sd_device_enumerator *e = NULL;

        setup();

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        ASSERT_EQ_INT(count_and_check(e, NULL), 2); /* dev1 + dev2, nothing else registered */

        /* The include list is OR'd: a device's single subsystem value can
         * equal any one member, so adding a second, non-matching name to
         * the list changes nothing about which devices already matched. */
        ASSERT_EQ_INT(sd_device_enumerator_add_match_subsystem(e, "testbus", 1), 0);
        ASSERT_EQ_INT(count_and_check(e, NULL), 2);

        ASSERT_EQ_INT(sd_device_enumerator_add_match_subsystem(e, "nosuchbus", 1), 0);
        ASSERT_EQ_INT(count_and_check(e, NULL), 2);

        /* Excluding the very subsystem the include list requires is the
         * real way to make this empty. */
        ASSERT_EQ_INT(sd_device_enumerator_add_match_subsystem(e, "testbus", 0), 0);
        ASSERT_EQ_INT(count_and_check(e, NULL), 0);

        sd_device_enumerator_unref(e);
        teardown();
}

static void test_sysname_and_property(void) {
        sd_device_enumerator *e = NULL;

        setup();

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_match_sysname(e, "dev1"), 0);
        ASSERT_EQ_INT(count_and_check(e, is_dev1), 1);
        sd_device_enumerator_unref(e);

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_match_property(e, "FOO", "bar"), 0);
        ASSERT_EQ_INT(count_and_check(e, is_dev1), 1); /* only dev1's uevent has FOO=bar */
        sd_device_enumerator_unref(e);

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_match_property_required(e, "NOSUCH", NULL), 0);
        ASSERT_EQ_INT(count_and_check(e, NULL), 0);
        sd_device_enumerator_unref(e);

        teardown();
}

static void test_sysattr_and_tag(void) {
        sd_device_enumerator *e = NULL;

        setup();

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_match_sysattr(e, "special", "yes", 1), 0);
        ASSERT_EQ_INT(count_and_check(e, is_dev1), 1);
        sd_device_enumerator_unref(e);

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_match_sysattr(e, "special", NULL, 0),
                      0);                           /* exclude anyone with it */
        ASSERT_EQ_INT(count_and_check(e, NULL), 1); /* dev2 survives, dev1 excluded */
        sd_device_enumerator_unref(e);

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_match_tag(e, "anything"), 0);
        ASSERT_EQ_INT(count_and_check(e, NULL), 0); /* the tag set is always empty */
        sd_device_enumerator_unref(e);

        teardown();
}

static void test_parent_and_all_parents(void) {
        sd_device_enumerator *e = NULL;
        sd_device *parent = NULL;
        char parentpath[600];

        setup();

        snprintf(parentpath, sizeof(parentpath), "%s/sys/devices/platform/parentX", g_tmp);
        ASSERT_EQ_INT(sd_device_new_from_syspath(&parent, parentpath), 0);

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_match_parent(e, parent), 0);
        ASSERT_EQ_INT(count_and_check(e, is_dev1), 1); /* dev2 is not under parentX */
        sd_device_enumerator_unref(e);

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_match_sysname(e, "dev1"), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_all_parents(e), 0);
        ASSERT_EQ_INT(count_and_check(e, is_dev1_or_parentx), 2); /* dev1 plus its real parent */
        sd_device_enumerator_unref(e);

        sd_device_unref(parent);
        teardown();
}

static bool is_grandparent_chain(const char *s) {
        return strcmp(s, "dev3") == 0 || strcmp(s, "dev4") == 0 || strcmp(s, "parentY") == 0 ||
                        strcmp(s, "grandparentG") == 0;
}

/* add_all_parents() over a two-level ancestor chain shared by two
 * devices: the walk (device-enumerator.c's enumerator_scan_devices())
 * must climb past the immediate parent to the grandparent, and the
 * dedup-by-syspath check must keep the shared parent and grandparent
 * to one entry each even though two children's walks both reach them. */
static void test_multi_level_parent_chain(void) {
        sd_device_enumerator *e = NULL;
        char *tmp = test_tmpdir_new();
        char sysroot[620];

        ASSERT_TRUE(tmp != NULL);
        snprintf(sysroot, sizeof(sysroot), "%s/sys", tmp);
        device_set_sys_root_for_tests(sysroot);

        ASSERT_EQ_INT(test_mkdir(tmp, "sys"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices/platform"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices/platform/grandparentG"), 0);
        ASSERT_EQ_INT(test_write_file(tmp, "sys/devices/platform/grandparentG/uevent", ""), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices/platform/grandparentG/parentY"), 0);
        ASSERT_EQ_INT(test_write_file(tmp, "sys/devices/platform/grandparentG/parentY/uevent", ""), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices/platform/grandparentG/parentY/dev3"), 0);
        ASSERT_EQ_INT(test_write_file(tmp, "sys/devices/platform/grandparentG/parentY/dev3/uevent", ""), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices/platform/grandparentG/parentY/dev4"), 0);
        ASSERT_EQ_INT(test_write_file(tmp, "sys/devices/platform/grandparentG/parentY/dev4/uevent", ""), 0);
        ASSERT_EQ_INT(test_symlink(tmp,
                                   "sys/devices/platform/grandparentG/parentY/dev3/subsystem",
                                   "../../../../../bus/testbus2"),
                      0);
        ASSERT_EQ_INT(test_symlink(tmp,
                                   "sys/devices/platform/grandparentG/parentY/dev4/subsystem",
                                   "../../../../../bus/testbus2"),
                      0);

        /* Enumeration walks /sys/bus/<x>/devices symlinks, not
         * /sys/devices directly (collect_device_candidates()), so dev3
         * and dev4 need their own bus registration -- a second bus,
         * kept separate from test_parent_and_all_parents()'s "testbus"
         * so this fixture is self-contained. */
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/bus"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/bus/testbus2"), 0);
        ASSERT_EQ_INT(test_write_file(tmp, "sys/bus/testbus2/uevent", ""), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/bus/testbus2/devices"), 0);
        ASSERT_EQ_INT(test_symlink(tmp,
                                   "sys/bus/testbus2/devices/dev3",
                                   "../../../devices/platform/grandparentG/parentY/dev3"),
                      0);
        ASSERT_EQ_INT(test_symlink(tmp,
                                   "sys/bus/testbus2/devices/dev4",
                                   "../../../devices/platform/grandparentG/parentY/dev4"),
                      0);

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_match_sysname(e, "dev3"), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_match_sysname(e, "dev4"), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_all_parents(e), 0);
        /* dev3 + dev4 + one parentY + one grandparentG, not five or six */
        ASSERT_EQ_INT(count_and_check(e, is_grandparent_chain), 4);
        sd_device_enumerator_unref(e);

        test_rm_rf(tmp);
        free(tmp);
}

static void test_subsystem_enumeration(void) {
        sd_device_enumerator *e = NULL;
        sd_device *d;
        int n = 0;
        bool saw_testbus = false;

        setup();

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        for (d = sd_device_enumerator_get_subsystem_first(e); d;
             d = sd_device_enumerator_get_subsystem_next(e)) {
                const char *sysname;
                ASSERT_EQ_INT(sd_device_get_sysname(d, &sysname), 0);
                if (strcmp(sysname, "testbus") == 0)
                        saw_testbus = true;
                n++;
        }
        ASSERT_TRUE(saw_testbus);
        ASSERT_EQ_INT(n, 3); /* testbus (bus), net (class), foomod (module) */
        sd_device_enumerator_unref(e);

        ASSERT_EQ_INT(sd_device_enumerator_new(&e), 0);
        ASSERT_EQ_INT(sd_device_enumerator_add_match_subsystem(e, "testbus", 1), 0);
        n = 0;
        for (d = sd_device_enumerator_get_subsystem_first(e); d;
             d = sd_device_enumerator_get_subsystem_next(e)) {
                const char *sysname;
                ASSERT_EQ_INT(sd_device_get_sysname(d, &sysname), 0);
                ASSERT_STREQ(sysname, "testbus");
                n++;
        }
        ASSERT_EQ_INT(n, 1);
        sd_device_enumerator_unref(e);

        teardown();
}

int main(void) {
        test_unfiltered_and_subsystem_match();
        test_sysname_and_property();
        test_sysattr_and_tag();
        test_parent_and_all_parents();
        test_multi_level_parent_chain();
        test_subsystem_enumeration();

        printf("test-sd-device-enumerator: OK\n");
        return 0;
}
