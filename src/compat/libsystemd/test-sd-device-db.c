/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The udev database overlay (device-db.c), against a fixture /sys and a
 * fixture database directory.
 *
 * The entry under test is the one devd writes for an input event node --
 * c<major>:<minor>, I:, E:ID_INPUT*, V: -- plus the records devd never
 * writes but a real file on a real system can hold, because the reader has
 * to be right about those too: an E: that replaces a uevent value, an E:
 * with an empty value that removes one, S:/G: lines it skips, malformed
 * lines it ignores, and an unterminated last line it drops.
 *
 * Every lookup that starts a test goes through the public API on a device
 * that has never built its property table. That is the recursion check:
 * device_read_db() runs inside device_ensure_properties() and has to find
 * the file without calling back into it, and a regression there is a stack
 * overflow on the first property lookup, not a failed assertion.
 */

#include "sd-device.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test-util.h"
#include "device-internal.h"

/* <tmp>/sys/devices/virtual/input/inputN/eventN, MAJOR=13 MINOR=<minor>,
 * subsystem -> <tmp>/sys/class/input. The eventN syspath goes in `ret`. */
static void make_event_node(const char *tmp, unsigned n, unsigned minor, char *ret, size_t size) {
        char rel[128], uevent[256], class_input[PATH_MAX];

        ASSERT_EQ_INT(test_mkdir(tmp, "sys"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/class"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/class/input"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices/virtual"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices/virtual/input"), 0);

        snprintf(rel, sizeof(rel), "sys/devices/virtual/input/input%u", n);
        ASSERT_EQ_INT(test_mkdir(tmp, rel), 0);
        snprintf(rel, sizeof(rel), "sys/devices/virtual/input/input%u/event%u", n, n);
        ASSERT_EQ_INT(test_mkdir(tmp, rel), 0);

        snprintf(rel, sizeof(rel), "sys/devices/virtual/input/input%u/event%u/uevent", n, n);
        snprintf(uevent,
                 sizeof(uevent),
                 "MAJOR=13\nMINOR=%u\nDEVNAME=input/event%u\nPICO_TEST_KEY=uevent\nPICO_TEST_GONE=here\n",
                 minor,
                 n);
        ASSERT_EQ_INT(test_write_file(tmp, rel, uevent), 0);

        snprintf(class_input, sizeof(class_input), "%s/sys/class/input", tmp);
        snprintf(rel, sizeof(rel), "sys/devices/virtual/input/input%u/event%u", n, n);
        {
                char dir[PATH_MAX];

                snprintf(dir, sizeof(dir), "%s/%s", tmp, rel);
                ASSERT_EQ_INT(test_symlink(dir, "subsystem", class_input), 0);
                ASSERT_TRUE((size_t) snprintf(ret, size, "%s", dir) < size);
        }
}

static void test_set_property(void) {
        sd_device *d = device_new_bare();

        ASSERT_TRUE(d != NULL);

        ASSERT_EQ_INT(device_add_property(d, "A", "1"), 0);
        ASSERT_EQ_INT(device_add_property(d, "B", "2"), 0);
        ASSERT_EQ_INT(device_add_property(d, "C", "3"), 0);

        /* Replace in place: same position, new value. */
        ASSERT_EQ_INT(device_set_property(d, "B", "x"), 0);
        ASSERT_EQ_INT(d->n_properties, 3);
        ASSERT_STREQ(d->properties[1].key, "B");
        ASSERT_STREQ(d->properties[1].value, "x");

        /* Empty removes, and the tail closes up behind it. */
        ASSERT_EQ_INT(device_set_property(d, "B", ""), 0);
        ASSERT_EQ_INT(d->n_properties, 2);
        ASSERT_STREQ(d->properties[0].key, "A");
        ASSERT_STREQ(d->properties[1].key, "C");

        ASSERT_EQ_INT(device_set_property(d, "A", NULL), 0);
        ASSERT_EQ_INT(d->n_properties, 1);
        ASSERT_STREQ(d->properties[0].key, "C");

        /* A new key appends; removing one that is not there is a no-op. */
        ASSERT_EQ_INT(device_set_property(d, "D", "4"), 0);
        ASSERT_EQ_INT(device_set_property(d, "E", ""), 0);
        ASSERT_EQ_INT(d->n_properties, 2);
        ASSERT_STREQ(d->properties[1].key, "D");
        ASSERT_STREQ(d->properties[1].value, "4");

        sd_device_unref(d);
}

static void test_overlay(void) {
        char *tmp = test_tmpdir_new();
        char sysroot[PATH_MAX], dbroot[PATH_MAX], syspath[PATH_MAX];
        sd_device *d = NULL;
        const char *key, *value;
        bool seen_touchscreen = false;
        uint64_t usec;

        ASSERT_TRUE(tmp != NULL);
        snprintf(sysroot, sizeof(sysroot), "%s/sys", tmp);
        snprintf(dbroot, sizeof(dbroot), "%s/db", tmp);
        device_set_sys_root_for_tests(sysroot);
        device_set_udev_db_root_for_tests(dbroot);

        make_event_node(tmp, 7, 71, syspath, sizeof(syspath));

        ASSERT_EQ_INT(test_mkdir(tmp, "db"), 0);
        ASSERT_EQ_INT(test_write_file(dbroot,
                                      "c13:71",
                                      "I:12345\n"
                                      "E:ID_INPUT=1\n"
                                      "E:ID_INPUT_TOUCHSCREEN=1\n"
                                      "E:PICO_TEST_KEY=db\n"
                                      "E:PICO_TEST_GONE=\n"
                                      "E:ID_INPUT_KEY=1\r"
                                      "S:input/by-path/platform-ts-event\n"
                                      "G:seat\n"
                                      "X\n"
                                      "Ebad\n"
                                      "E:NOEQUALS\n"
                                      "E:=novalue\n"
                                      "\n"
                                      "V:1\n"
                                      "E:ID_INPUT_KEYBOARD=1"),
                      0);

        ASSERT_EQ_INT(sd_device_new_from_syspath(&d, syspath), 0);

        /* The first lookup on a fresh device -- the recursion check. */
        ASSERT_EQ_INT(sd_device_get_property_value(d, "ID_INPUT_TOUCHSCREEN", &value), 0);
        ASSERT_STREQ(value, "1");

        ASSERT_EQ_INT(sd_device_get_property_value(d, "ID_INPUT", &value), 0);
        ASSERT_STREQ(value, "1");

        /* '\r' ends a record as well as '\n' does. */
        ASSERT_EQ_INT(sd_device_get_property_value(d, "ID_INPUT_KEY", &value), 0);
        ASSERT_STREQ(value, "1");

        /* E: replaces the uevent's value; an empty E: removes it. */
        ASSERT_EQ_INT(sd_device_get_property_value(d, "PICO_TEST_KEY", &value), 0);
        ASSERT_STREQ(value, "db");
        ASSERT_EQ_INT(sd_device_get_property_value(d, "PICO_TEST_GONE", &value), -ENOENT);

        /* The uevent's own keys are still there underneath. */
        ASSERT_EQ_INT(sd_device_get_property_value(d, "MAJOR", &value), 0);
        ASSERT_STREQ(value, "13");

        /* An unterminated last record is dropped; malformed ones are
         * ignored rather than half-applied. */
        ASSERT_EQ_INT(sd_device_get_property_value(d, "ID_INPUT_KEYBOARD", &value), -ENOENT);
        ASSERT_EQ_INT(sd_device_get_property_value(d, "NOEQUALS", &value), -ENOENT);
        ASSERT_EQ_INT(sd_device_get_property_value(d, "bad", &value), -ENOENT);

        for (key = sd_device_get_property_first(d, &value); key; key = sd_device_get_property_next(d, &value)) {
                if (strcmp(key, "ID_INPUT_TOUCHSCREEN") == 0) {
                        ASSERT_STREQ(value, "1");
                        seen_touchscreen = true;
                }
                ASSERT_TRUE(key[0] != '\0');
        }
        ASSERT_TRUE(seen_touchscreen);

        /* I: is the timestamp, and a property, as upstream makes it. */
        ASSERT_EQ_INT(sd_device_get_usec_initialized(d, &usec), 0);
        ASSERT_EQ_INT(usec, 12345);
        ASSERT_EQ_INT(sd_device_get_property_value(d, "USEC_INITIALIZED", &value), 0);
        ASSERT_STREQ(value, "12345");
        ASSERT_EQ_INT(sd_device_get_usec_since_initialized(d, &usec), 0);

        ASSERT_EQ_INT(d->database_version, 1);

        /* The id the file was found by is the id the device reports. */
        ASSERT_EQ_INT(sd_device_get_device_id(d, &value), 0);
        ASSERT_STREQ(value, "c13:71");

        ASSERT_EQ_INT(sd_device_get_is_initialized(d), 1);

        sd_device_unref(d);

        /* A monitor-received device never reads the file, even when it is
         * right there. Flagged before its first lookup, the way
         * device_set_monitor_properties() flags a real one. */
        ASSERT_EQ_INT(sd_device_new_from_syspath(&d, syspath), 0);
        d->from_monitor = true;
        ASSERT_EQ_INT(sd_device_get_property_value(d, "ID_INPUT_TOUCHSCREEN", &value), -ENOENT);
        ASSERT_EQ_INT(device_read_db(d), 0);
        ASSERT_TRUE(device_get_property_raw(d, "ID_INPUT_TOUCHSCREEN") == NULL);
        ASSERT_EQ_INT(sd_device_get_usec_initialized(d, &usec), -ENODATA);
        sd_device_unref(d);

        device_set_sys_root_for_tests(NULL);
        device_set_udev_db_root_for_tests(NULL);
        test_rm_rf(tmp);
        free(tmp);
}

static void test_no_entry(void) {
        char *tmp = test_tmpdir_new();
        char sysroot[PATH_MAX], dbroot[PATH_MAX], syspath[PATH_MAX];
        sd_device *d = NULL;
        const char *value;
        uint64_t usec;

        ASSERT_TRUE(tmp != NULL);
        snprintf(sysroot, sizeof(sysroot), "%s/sys", tmp);
        snprintf(dbroot, sizeof(dbroot), "%s/db", tmp);
        device_set_sys_root_for_tests(sysroot);

        /* A database directory that does not even exist: the state of every
         * pico image before devd has classified anything. */
        device_set_udev_db_root_for_tests(dbroot);

        make_event_node(tmp, 8, 72, syspath, sizeof(syspath));

        ASSERT_EQ_INT(sd_device_new_from_syspath(&d, syspath), 0);
        ASSERT_EQ_INT(sd_device_get_property_value(d, "MAJOR", &value), 0);
        ASSERT_STREQ(value, "13");
        ASSERT_EQ_INT(sd_device_get_property_value(d, "PICO_TEST_KEY", &value), 0);
        ASSERT_STREQ(value, "uevent");
        ASSERT_EQ_INT(sd_device_get_property_value(d, "ID_INPUT", &value), -ENOENT);

        ASSERT_EQ_INT(sd_device_get_usec_initialized(d, &usec), -ENODATA);
        ASSERT_EQ_INT(sd_device_get_usec_since_initialized(d, &usec), -ENODATA);
        ASSERT_EQ_INT(sd_device_get_is_initialized(d), 1);

        ASSERT_EQ_INT(sd_device_get_device_id(d, &value), 0);
        ASSERT_STREQ(value, "c13:72");

        sd_device_unref(d);

        device_set_sys_root_for_tests(NULL);
        device_set_udev_db_root_for_tests(NULL);
        ASSERT_STREQ(device_udev_db_root(), "/run/udev/data");

        test_rm_rf(tmp);
        free(tmp);
}

int main(void) {
        test_set_property();
        test_overlay();
        test_no_entry();

        printf("test-sd-device-db: OK\n");
        return 0;
}
