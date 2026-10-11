/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The property table: uevent-file parsing, iteration, the synthesized
 * keys, and the fields (ACTION/SEQNUM/SYNTH_UUID) that only ever come
 * from a monitor message. That last part is exercised via
 * device_new_from_devpath_bare() + device_add_property() directly --
 * device-internal.h functions, not the public API, since building a netlink
 * message just to test property parsing would test the socket, not the
 * parser.
 */

#include "sd-device.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../../test-util.h"
#include "device-internal.h"

static void test_uevent_file_and_properties(void) {
        char *tmp = test_tmpdir_new();
        char sysroot[620];
        char syspath[600];
        sd_device *d = NULL;
        const char *key, *value;
        int seen_major = 0, seen_devpath = 0;

        ASSERT_TRUE(tmp != NULL);
        snprintf(sysroot, sizeof(sysroot), "%s/sys", tmp);
        device_set_sys_root_for_tests(sysroot);

        ASSERT_EQ_INT(test_mkdir(tmp, "sys"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices/foo"), 0);
        ASSERT_EQ_INT(test_write_file(tmp,
                                      "sys/devices/foo/uevent",
                                      "MAJOR=8\nMINOR=0\nDEVNAME=sda\n\nGARBLED\n"),
                      0);

        snprintf(syspath, sizeof(syspath), "%s/sys/devices/foo", tmp);
        ASSERT_EQ_INT(sd_device_new_from_syspath(&d, syspath), 0);

        ASSERT_EQ_INT(sd_device_get_devname(d, &value), 0);
        ASSERT_STREQ(value, "/dev/sda"); /* relative DEVNAME gets /dev/ prefixed */

        for (key = sd_device_get_property_first(d, &value); key; key = sd_device_get_property_next(d, &value)) {
                if (strcmp(key, "MAJOR") == 0) {
                        ASSERT_STREQ(value, "8");
                        seen_major = 1;
                }
                if (strcmp(key, "DEVPATH") == 0) {
                        ASSERT_STREQ(value, "/devices/foo");
                        seen_devpath = 1;
                }
                ASSERT_TRUE(strcmp(key, "GARBLED") != 0); /* no '=': skipped */
        }
        ASSERT_TRUE(seen_major);
        ASSERT_TRUE(seen_devpath); /* synthesized even though the file never had it */

        ASSERT_EQ_INT(sd_device_get_property_value(d, "MAJOR", &value), 0);
        ASSERT_STREQ(value, "8");
        ASSERT_EQ_INT(sd_device_get_property_value(d, "NOSUCHKEY", &value), -ENOENT);
        ASSERT_EQ_INT(sd_device_get_property_value(NULL, "MAJOR", &value), -EINVAL);

        /* No DISKSEQ/IFINDEX/DEVTYPE in this uevent file. */
        {
                uint64_t diskseq;
                int ifindex;
                ASSERT_EQ_INT(sd_device_get_diskseq(d, &diskseq), -ENOENT);
                ASSERT_EQ_INT(sd_device_get_ifindex(d, &ifindex), -ENOENT);
                ASSERT_EQ_INT(sd_device_get_devtype(d, &value), -ENOENT);
        }

        /* No monitor/trigger fields on a constructed-from-disk device. */
        {
                sd_device_action_t action;
                uint64_t seqnum;
                sd_id128_t uuid;
                ASSERT_EQ_INT(sd_device_get_action(d, &action), -ENOENT);
                ASSERT_EQ_INT(sd_device_get_seqnum(d, &seqnum), -ENOENT);
                ASSERT_EQ_INT(sd_device_get_trigger_uuid(d, &uuid), -ENOENT);
        }

        /* The tag family: genuinely empty, always. */
        ASSERT_TRUE(sd_device_get_tag_first(d) == NULL);
        ASSERT_TRUE(sd_device_get_current_tag_first(d) == NULL);
        ASSERT_EQ_INT(sd_device_has_tag(d, "anything"), 0);
        ASSERT_EQ_INT(sd_device_has_tag(NULL, "anything"), -EINVAL);

        sd_device_unref(d);
        test_rm_rf(tmp);
        free(tmp);
}

/* A "monitor-shaped" device, built the way device-monitor.c's parser
 * builds one, without a real netlink message. */
static void test_monitor_fields(void) {
        sd_device *d = NULL;
        sd_device_action_t action;
        uint64_t seqnum;
        sd_id128_t uuid;
        const char *v;

        ASSERT_EQ_INT(device_new_from_devpath_bare(&d, "/devices/virtual/net/lo"), 0);
        d->from_monitor = true;
        d->action = SD_DEVICE_CHANGE;
        ASSERT_EQ_INT(device_add_property(d, "ACTION", "change"), 0);
        ASSERT_EQ_INT(device_add_property(d, "SEQNUM", "42"), 0);
        ASSERT_EQ_INT(device_add_property(d, "SUBSYSTEM", "net"), 0);
        d->has_seqnum = true;
        d->seqnum = 42;

        ASSERT_EQ_INT(sd_device_get_action(d, &action), 0);
        ASSERT_EQ_INT(action, SD_DEVICE_CHANGE);
        ASSERT_EQ_INT(sd_device_get_seqnum(d, &seqnum), 0);
        ASSERT_EQ_INT((long long) seqnum, 42);

        /* Not synthetic: no SYNTH_UUID was ever set. */
        ASSERT_EQ_INT(sd_device_get_trigger_uuid(d, &uuid), -ENOENT);

        /* Iteration shows ACTION/SEQNUM once ensure_properties() runs. */
        ASSERT_EQ_INT(sd_device_get_property_value(d, "ACTION", &v), 0);
        ASSERT_STREQ(v, "change");
        ASSERT_EQ_INT(sd_device_get_property_value(d, "SEQNUM", &v), 0);
        ASSERT_STREQ(v, "42");

        sd_device_unref(d);

        /* A real synthetic uuid round-trips through the same string form
         * device-monitor.c parses it out of. */
        ASSERT_EQ_INT(device_new_from_devpath_bare(&d, "/devices/virtual/net/lo"), 0);
        {
                sd_id128_t want;
                char uuidstr[37] = "12345678-90ab-cdef-1234-567890abcdef";
                ASSERT_EQ_INT(device_id128_from_uuid_string(uuidstr, &want), 0);
                d->has_synth_uuid = true;
                d->synth_uuid = want;
                ASSERT_EQ_INT(sd_device_get_trigger_uuid(d, &uuid), 0);
                ASSERT_TRUE(memcmp(&uuid, &want, sizeof(uuid)) == 0);
        }
        ASSERT_EQ_INT(device_id128_from_uuid_string("0", &uuid), -EINVAL); /* "no uuid" sentinel */
        ASSERT_EQ_INT(device_id128_from_uuid_string("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", &uuid), -EINVAL);

        sd_device_unref(d);
}

int main(void) {
        test_uevent_file_and_properties();
        test_monitor_fields();

        printf("test-sd-device-uevent: OK\n");
        return 0;
}
