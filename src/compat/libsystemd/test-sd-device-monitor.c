/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_device_monitor: filter-matching logic tested as a pure function
 * against fixture devices (device_monitor_filter_matches(), an internal
 * hook), plus one end-to-end test: open a socket, trigger a uevent on the
 * loopback interface, and confirm sd_device_monitor_receive() decodes it.
 * Joining NETLINK_KOBJECT_UEVENT group 1 needs no CLONE_NEWNET/CLONE_NEWUSER,
 * so the test is not namespace-gated like test-netd-rtnl.c's.
 */

#include "sd-device.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../test-util.h"
#include "device-internal.h"

static void test_subsystem_devtype_filter(void) {
        sd_device_monitor *m = NULL;
        sd_device *net_dev = NULL, *other_dev = NULL;

        ASSERT_EQ_INT(sd_device_monitor_new(&m), 0);
        ASSERT_EQ_INT(sd_device_monitor_filter_add_match_subsystem_devtype(m, "net", NULL), 0);

        ASSERT_EQ_INT(device_new_from_devpath_bare(&net_dev, "/devices/virtual/net/lo"), 0);
        ASSERT_EQ_INT(device_add_property(net_dev, "SUBSYSTEM", "net"), 0);
        ASSERT_TRUE(device_monitor_filter_matches(m, net_dev));

        ASSERT_EQ_INT(device_new_from_devpath_bare(&other_dev, "/devices/virtual/tty/ttyS0"), 0);
        ASSERT_EQ_INT(device_add_property(other_dev, "SUBSYSTEM", "tty"), 0);
        ASSERT_TRUE(!device_monitor_filter_matches(m, other_dev));

        sd_device_unref(net_dev);
        sd_device_unref(other_dev);
        sd_device_monitor_unref(m);
}

static void test_tag_filter_always_empty(void) {
        sd_device_monitor *m = NULL;
        sd_device *dev = NULL;

        ASSERT_EQ_INT(sd_device_monitor_new(&m), 0);
        ASSERT_EQ_INT(sd_device_monitor_filter_add_match_tag(m, "anything"), 0);

        ASSERT_EQ_INT(device_new_from_devpath_bare(&dev, "/devices/virtual/net/lo"), 0);
        ASSERT_TRUE(!device_monitor_filter_matches(m, dev)); /* no event ever carries TAGS= */

        sd_device_unref(dev);
        sd_device_monitor_unref(m);
}

static void test_parent_filter(void) {
        sd_device_monitor *m = NULL;
        sd_device *parent = NULL, *child = NULL, *unrelated = NULL;

        device_set_sys_root_for_tests(NULL); /* real /sys: only used for its syspath string here */

        ASSERT_EQ_INT(device_new_from_devpath_bare(&parent, "/devices/pci0"), 0);
        ASSERT_EQ_INT(device_new_from_devpath_bare(&child, "/devices/pci0/eth0"), 0);
        ASSERT_EQ_INT(device_new_from_devpath_bare(&unrelated, "/devices/virtual/tty/ttyS0"), 0);

        ASSERT_EQ_INT(sd_device_monitor_new(&m), 0);
        ASSERT_EQ_INT(sd_device_monitor_filter_add_match_parent(m, parent, 1), 0);
        ASSERT_TRUE(device_monitor_filter_matches(m, child));
        ASSERT_TRUE(!device_monitor_filter_matches(m, unrelated));

        sd_device_unref(parent);
        sd_device_unref(child);
        sd_device_unref(unrelated);
        sd_device_monitor_unref(m);
}

static void test_filter_remove(void) {
        sd_device_monitor *m = NULL;
        sd_device *dev = NULL;

        ASSERT_EQ_INT(sd_device_monitor_new(&m), 0);
        ASSERT_EQ_INT(sd_device_monitor_filter_add_match_tag(m, "anything"), 0);
        ASSERT_EQ_INT(device_new_from_devpath_bare(&dev, "/devices/virtual/net/lo"), 0);
        ASSERT_TRUE(!device_monitor_filter_matches(m, dev));

        ASSERT_EQ_INT(sd_device_monitor_filter_remove(m), 0);
        ASSERT_TRUE(device_monitor_filter_matches(m, dev)); /* no filters left: everything passes */

        ASSERT_EQ_INT(sd_device_monitor_filter_update(m), 0); /* true_noop: just succeeds */

        sd_device_unref(dev);
        sd_device_monitor_unref(m);
}

static void test_description(void) {
        sd_device_monitor *m = NULL;
        const char *v;

        ASSERT_EQ_INT(sd_device_monitor_new(&m), 0);
        ASSERT_EQ_INT(sd_device_monitor_get_description(m, &v), 0);
        ASSERT_TRUE(v == NULL);

        ASSERT_EQ_INT(sd_device_monitor_set_description(m, "my monitor"), 0);
        ASSERT_EQ_INT(sd_device_monitor_get_description(m, &v), 0);
        ASSERT_STREQ(v, "my monitor");

        ASSERT_EQ_INT(sd_device_monitor_set_description(m, NULL), 0);
        ASSERT_EQ_INT(sd_device_monitor_get_description(m, &v), 0);
        ASSERT_TRUE(v == NULL);

        sd_device_monitor_unref(m);
}

static void test_deferred_event_family(void) {
        sd_device_monitor *m = NULL;

        ASSERT_EQ_INT(sd_device_monitor_new(&m), 0);
        ASSERT_EQ_INT(sd_device_monitor_attach_event(m, NULL), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_device_monitor_detach_event(m), -EOPNOTSUPP);
        ASSERT_TRUE(sd_device_monitor_get_event(m) == NULL);
        ASSERT_TRUE(sd_device_monitor_get_event_source(m) == NULL);
        ASSERT_EQ_INT(sd_device_monitor_start(m, NULL, NULL), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_device_monitor_stop(m), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_device_monitor_is_running(m), 0);

        sd_device_monitor_unref(m);
}

/* Triggers a "change" on loopback and checks the whole receive path (sender
 * credential check, header parse, property overlay, action decode) against
 * what the kernel sends. */
static void test_real_receive(void) {
        sd_device_monitor *m = NULL;
        sd_device *dev = NULL;
        pid_t child;
        int r, fd, status;

        r = sd_device_monitor_new(&m);
        if (r < 0) {
                printf("test-sd-device-monitor: SKIP real receive (sd_device_monitor_new: %d)\n", r);
                return;
        }
        ASSERT_EQ_INT(sd_device_monitor_get_events(m), POLLIN);
        {
                uint64_t timeout;
                ASSERT_EQ_INT(sd_device_monitor_get_timeout(m, &timeout), 0);
                ASSERT_EQ_INT((long long) timeout, (long long) UINT64_MAX);
        }
        ASSERT_TRUE(sd_device_monitor_get_fd(m) >= 0);
        ASSERT_EQ_INT(sd_device_monitor_set_receive_buffer_size(m, 1U << 20), 0);

        child = fork();
        ASSERT_TRUE(child >= 0);
        if (child == 0) {
                usleep(200000);
                fd = open("/sys/class/net/lo/uevent", O_WRONLY);
                if (fd >= 0) {
                        ssize_t ignored = write(fd, "change", 6);
                        (void) ignored;
                        close(fd);
                }
                _exit(0);
        }

        for (int attempts = 0;; attempts++) {
                ASSERT_TRUE(attempts < 500); /* bounded: never hang the suite on a missed event */

                r = sd_device_monitor_receive(m, &dev);
                if (r == -EAGAIN) {
                        usleep(20000);
                        continue;
                }
                ASSERT_EQ_INT(r, 0);

                {
                        sd_device_action_t action;
                        const char *sysname, *subsystem;

                        ASSERT_EQ_INT(sd_device_get_action(dev, &action), 0);
                        ASSERT_EQ_INT(sd_device_get_sysname(dev, &sysname), 0);
                        if (strcmp(sysname, "lo") != 0 || action != SD_DEVICE_CHANGE) {
                                sd_device_unref(dev);
                                continue; /* some other real event on this host's netlink bus */
                        }

                        ASSERT_EQ_INT(sd_device_get_subsystem(dev, &subsystem), 0);
                        ASSERT_STREQ(subsystem, "net");
                }

                sd_device_unref(dev);
                break;
        }

        waitpid(child, &status, 0);
        sd_device_monitor_unref(m);
}

int main(void) {
        test_subsystem_devtype_filter();
        test_tag_filter_always_empty();
        test_parent_filter();
        test_filter_remove();
        test_description();
        test_deferred_event_family();
        test_real_receive();

        printf("test-sd-device-monitor: OK\n");
        return 0;
}
