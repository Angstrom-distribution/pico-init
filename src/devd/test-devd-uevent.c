/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The uevent parser, against real message bytes assembled here.
 *
 * A uevent is NUL-separated, so a fixture written as a C string literal would
 * be one field long and would prove nothing -- every message below is built the
 * way the kernel writes it, header line first and then NUL-terminated KEY=VALUE
 * pairs, and the parser is handed the byte count rather than a string.
 *
 * The rejections are the half that matters most. devd reacts to what this
 * parser returns by mounting filesystems and creating symlinks as root, and the
 * messages arrive on a socket any process can write to -- so the sender check,
 * the libudev-format rejection and the unterminated-buffer case are each
 * exercised rather than left to a board to discover.
 *
 * The socket itself (devd_uevent_open(), devd_uevent_recv()) is not covered
 * here, following the same split test-gpt-scan.c and test-dev-setup.c use:
 * subscribing to a kernel multicast group and receiving a real hotplug event
 * needs a real kernel and a real device, and is proven by a boot capture rather
 * than by a test that would have to plug something in.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../test-util.h"
#include "devd-uevent.h"

/* Concatenate NUL-terminated fields the way the kernel lays a message out.
 * Returns the total byte count, terminating NULs included. */
static size_t build(char *buf, size_t size, const char * const *fields) {
        size_t n = 0;

        for (size_t i = 0; fields[i]; i++) {
                size_t len = strlen(fields[i]);

                ASSERT_TRUE(n + len + 1 <= size);
                memcpy(buf + n, fields[i], len + 1);
                n += len + 1;
        }

        return n;
}

static void test_disk_add(void) {
        static const char * const fields[] = {
                "add@/devices/platform/soc/1c0f000.mmc/mmc_host/mmc0/mmc0:0001/block/mmcblk0",
                "ACTION=add",
                "DEVPATH=/devices/platform/soc/1c0f000.mmc/mmc_host/mmc0/mmc0:0001/block/mmcblk0",
                "SUBSYSTEM=block",
                "MAJOR=179",
                "MINOR=0",
                "DEVNAME=mmcblk0",
                "DEVTYPE=disk",
                "SEQNUM=1234",
                NULL,
        };

        char buf[DEVD_UEVENT_BUF_MAX];
        DevdUevent u;
        size_t n;

        n = build(buf, sizeof(buf), fields);

        ASSERT_EQ_INT(devd_uevent_parse(buf, n, &u), 0);
        ASSERT_EQ_INT(u.action, DEVD_ACTION_ADD);
        ASSERT_STREQ(u.subsystem, "block");
        ASSERT_STREQ(u.devname, "mmcblk0");
        ASSERT_STREQ(u.devtype, "disk");
        ASSERT_EQ_INT(u.major, 179);
        ASSERT_EQ_INT(u.minor, 0);
        ASSERT_TRUE(u.have_devno);
        ASSERT_EQ_INT(u.partn, 0);

        /* The devpath comes from the header line, not from the DEVPATH=
         * property -- see the parser's comment on believing a message that
         * disagrees with itself. */
        ASSERT_STREQ(u.devpath, "/devices/platform/soc/1c0f000.mmc/mmc_host/mmc0/mmc0:0001/block/mmcblk0");
}

static void test_partition_add(void) {
        static const char * const fields[] = {
                "add@/devices/platform/scsi/host0/target0:0:0/0:0:0:0/block/sda/sda2",
                "ACTION=add",
                "SUBSYSTEM=block",
                "MAJOR=8",
                "MINOR=2",
                "DEVNAME=sda2",
                "DEVTYPE=partition",
                "PARTN=2",
                NULL,
        };

        char buf[DEVD_UEVENT_BUF_MAX];
        DevdUevent u;
        size_t n;

        n = build(buf, sizeof(buf), fields);

        ASSERT_EQ_INT(devd_uevent_parse(buf, n, &u), 0);
        ASSERT_EQ_INT(u.action, DEVD_ACTION_ADD);
        ASSERT_STREQ(u.devtype, "partition");
        ASSERT_STREQ(u.devname, "sda2");
        ASSERT_EQ_INT(u.partn, 2);
        ASSERT_EQ_INT(u.minor, 2);
}

static void test_remove_and_other(void) {
        static const char * const removal[] = {
                "remove@/devices/platform/scsi/host0/target0:0:0/0:0:0:0/block/sda",
                "ACTION=remove",
                "SUBSYSTEM=block",
                "DEVNAME=sda",
                "DEVTYPE=disk",
                NULL,
        };

        /* A medium change on a card reader. Recognised, but not
         * classified as add or remove -- see devd-block.c on why v1 does not
         * act on it. */
        static const char * const change[] = {
                "change@/devices/platform/scsi/host0/target0:0:0/0:0:0:0/block/sda",
                "ACTION=change",
                "SUBSYSTEM=block",
                "DEVNAME=sda",
                "DEVTYPE=disk",
                NULL,
        };

        char buf[DEVD_UEVENT_BUF_MAX];
        DevdUevent u;

        ASSERT_EQ_INT(devd_uevent_parse(buf, build(buf, sizeof(buf), removal), &u), 0);
        ASSERT_EQ_INT(u.action, DEVD_ACTION_REMOVE);
        ASSERT_STREQ(u.devname, "sda");

        ASSERT_EQ_INT(devd_uevent_parse(buf, build(buf, sizeof(buf), change), &u), 0);
        ASSERT_EQ_INT(u.action, DEVD_ACTION_OTHER);

        /* An action devd has never heard of must land in OTHER too, not in
         * whichever branch happens to be last. */
        ASSERT_STREQ(devd_action_to_string(u.action), "other");
}

static void test_no_properties(void) {
        /* Legal and real: a subsystem-less device with a bare header line. */
        static const char * const fields[] = { "add@/devices/virtual/mem/null", NULL };

        char buf[DEVD_UEVENT_BUF_MAX];
        DevdUevent u;

        ASSERT_EQ_INT(devd_uevent_parse(buf, build(buf, sizeof(buf), fields), &u), 0);
        ASSERT_EQ_INT(u.action, DEVD_ACTION_ADD);
        ASSERT_STREQ(u.subsystem, "");
        ASSERT_STREQ(u.devname, "");
        ASSERT_TRUE(!u.have_devno);
}

static void test_rejections(void) {
        char buf[DEVD_UEVENT_BUF_MAX];
        DevdUevent u;
        size_t n;

        /* A libudev group-2 message. devd never subscribes to that group, so
         * this can only arrive from a process -- rejected by its own magic
         * rather than misparsed as a device called "libudev". */
        memcpy(buf, "libudev\0\xfe\xed\xca\xfe", 12);
        ASSERT_EQ_INT(devd_uevent_parse(buf, 12, &u), -EINVAL);

        /* No '@' in the header line. */
        n = build(buf, sizeof(buf), (const char * const[]){ "addslashdevices", "SUBSYSTEM=block", NULL });
        ASSERT_EQ_INT(devd_uevent_parse(buf, n, &u), -EINVAL);

        /* An '@' with nothing after it: an action naming no device. */
        n = build(buf, sizeof(buf), (const char * const[]){ "add@", NULL });
        ASSERT_EQ_INT(devd_uevent_parse(buf, n, &u), -EINVAL);

        /* ...and nothing before it. */
        n = build(buf, sizeof(buf), (const char * const[]){ "@/devices/x", NULL });
        ASSERT_EQ_INT(devd_uevent_parse(buf, n, &u), -EINVAL);

        /*
         * An unterminated buffer. This is the one that matters: every field
         * below the header is read as a C string, so a message whose last byte
         * is not a NUL would have the parser reading past what was received.
         * It is refused up front instead.
         */
        memcpy(buf, "add@/devices/x", 14);
        ASSERT_EQ_INT(devd_uevent_parse(buf, 14, &u), -EINVAL);

        /* A DEVPATH longer than the field it has to go in. Truncating it would
         * mean acting on a different device than the one named. */
        memset(buf, 'a', sizeof(buf));
        memcpy(buf, "add@/devices/", 13);
        buf[sizeof(buf) - 1] = '\0';
        ASSERT_EQ_INT(devd_uevent_parse(buf, sizeof(buf), &u), -EINVAL);

        ASSERT_EQ_INT(devd_uevent_parse(NULL, 4, &u), -EINVAL);
        ASSERT_EQ_INT(devd_uevent_parse("x", 0, &u), -EINVAL);
}

/*
 * The check that stops devd being a root-privilege reaction engine driven by
 * unprivileged input. Only the kernel is nl_pid 0, and only a multicast message
 * has a non-zero nl_groups -- a process aiming a forged uevent straight at
 * devd's socket gets its own pid in one and zero in the other, and fails both.
 */
static void test_sender_check(void) {
        ASSERT_TRUE(devd_uevent_sender_is_kernel(0, 1));
        ASSERT_TRUE(devd_uevent_sender_is_kernel(0, 2));

        /* A unicast send from a process: its own port id, no group. */
        ASSERT_TRUE(!devd_uevent_sender_is_kernel(4242, 0));

        /* A process that managed to bind port id 0 is still not multicasting. */
        ASSERT_TRUE(!devd_uevent_sender_is_kernel(0, 0));

        /* And a forged group number does not help without pid 0. */
        ASSERT_TRUE(!devd_uevent_sender_is_kernel(4242, 1));
}

int main(void) {
        test_disk_add();
        test_partition_add();
        test_remove_and_other();
        test_no_properties();
        test_rejections();
        test_sender_check();

        printf("test-devd-uevent: all checks passed\n");
        return 0;
}
