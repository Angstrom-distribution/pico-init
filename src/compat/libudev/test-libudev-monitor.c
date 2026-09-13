/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The interim udev_monitor contract, pinned because it is the piece most
 * easily gotten wrong by accident: udev_monitor_new_from_netlink() must
 * succeed with a real object (libusb_init() fails outright otherwise),
 * every call a consumer makes on it in the ordinary order -- filters,
 * enable_receiving, buffer size, get_fd, fcntl on the fd, poll, receive,
 * unref -- must return the success or the "nothing yet" answer, and the
 * fd must never become readable. Plus the queue and hwdb objects a
 * consumer may create alongside it. Linked against the built
 * libudev.so.1, so this exercises the installed shape.
 */

#include "libudev.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../../test-util.h"

static void test_monitor_never_delivers(void) {
        struct udev *udev = udev_new();
        struct udev_monitor *m;
        struct pollfd pfd;
        int fd, flags;

        ASSERT_TRUE(udev != NULL);

        /* the exact call sequence libusb's linux_udev.c makes in libusb_init() */
        m = udev_monitor_new_from_netlink(udev, "udev");
        ASSERT_TRUE(m != NULL);
        ASSERT_TRUE(udev_monitor_get_udev(m) == udev);
        ASSERT_EQ_INT(udev_monitor_filter_add_match_subsystem_devtype(m, "usb", "usb_device"), 0);
        ASSERT_EQ_INT(udev_monitor_enable_receiving(m), 0);
        fd = udev_monitor_get_fd(m);
        ASSERT_TRUE(fd >= 0);
        flags = fcntl(fd, F_GETFD);
        ASSERT_TRUE(flags >= 0);
        ASSERT_TRUE(flags & FD_CLOEXEC);
        flags = fcntl(fd, F_GETFL);
        ASSERT_TRUE(flags >= 0);
        ASSERT_EQ_INT(fcntl(fd, F_SETFL, flags | O_NONBLOCK), 0);

        /* the rest of the API on the same object */
        ASSERT_EQ_INT(udev_monitor_filter_add_match_subsystem_devtype(m, "net", NULL), 0);
        ASSERT_EQ_INT(udev_monitor_filter_add_match_tag(m, "seat"), 0);
        ASSERT_EQ_INT(udev_monitor_filter_update(m), 0);
        ASSERT_EQ_INT(udev_monitor_set_receive_buffer_size(m, 128 * 1024), 0);
        ASSERT_EQ_INT(udev_monitor_filter_remove(m), 0);
        ASSERT_EQ_INT(udev_monitor_filter_add_match_subsystem_devtype(m, NULL, NULL), -EINVAL);

        /* never readable: a bounded poll times out with no events */
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        ASSERT_EQ_INT(poll(&pfd, 1, 200), 0);
        ASSERT_EQ_INT(pfd.revents, 0);

        /* receive: the "nothing yet" answer, never a crash */
        errno = 0;
        ASSERT_TRUE(udev_monitor_receive_device(m) == NULL);
        ASSERT_EQ_INT(errno, EAGAIN);
        errno = 0;
        ASSERT_TRUE(udev_monitor_receive_device(m) == NULL);
        ASSERT_EQ_INT(errno, EAGAIN);

        ASSERT_TRUE(udev_monitor_ref(m) == m);
        ASSERT_TRUE(udev_monitor_unref(m) == NULL);
        ASSERT_TRUE(udev_monitor_unref(m) == NULL);
        ASSERT_TRUE(fcntl(fd, F_GETFD) < 0 && errno == EBADF); /* fd closed with the last ref */

        /* every accepted group name, and the one rejection real libudev has */
        m = udev_monitor_new_from_netlink(udev, "kernel");
        ASSERT_TRUE(m != NULL);
        udev_monitor_unref(m);
        m = udev_monitor_new_from_netlink(udev, NULL);
        ASSERT_TRUE(m != NULL);
        udev_monitor_unref(m);
        errno = 0;
        ASSERT_TRUE(udev_monitor_new_from_netlink(udev, "bogus") == NULL);
        ASSERT_EQ_INT(errno, EINVAL);

        ASSERT_EQ_INT(udev_monitor_get_fd(NULL), -EINVAL);
        ASSERT_EQ_INT(udev_monitor_enable_receiving(NULL), -EINVAL);
        ASSERT_TRUE(udev_monitor_receive_device(NULL) == NULL);

        udev_unref(udev);
}

static void test_queue_and_hwdb(void) {
        struct udev *udev = udev_new();
        struct udev_queue *q;

        q = udev_queue_new(udev);
        ASSERT_TRUE(q != NULL);
        ASSERT_TRUE(udev_queue_get_udev(q) == udev);
        /* no udevd, nothing queued -- the same answers real libudev gives
         * on a host where udevd is not running */
        ASSERT_EQ_INT(udev_queue_get_udev_is_active(q), access("/run/udev/control", F_OK) == 0);
        ASSERT_EQ_INT(udev_queue_get_queue_is_empty(q), access("/run/udev/queue", F_OK) != 0);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        ASSERT_EQ_INT(udev_queue_get_kernel_seqnum(q), 0);
        ASSERT_EQ_INT(udev_queue_get_udev_seqnum(q), 0);
        ASSERT_EQ_INT(udev_queue_get_seqnum_is_finished(q, 1), udev_queue_get_queue_is_empty(q));
        ASSERT_EQ_INT(udev_queue_get_seqnum_sequence_is_finished(q, 1, 2), udev_queue_get_queue_is_empty(q));
        errno = 0;
        ASSERT_TRUE(udev_queue_get_queued_list_entry(q) == NULL);
        ASSERT_EQ_INT(errno, ENODATA);
#pragma GCC diagnostic pop
        ASSERT_EQ_INT(udev_queue_flush(q), -EINVAL); /* no fd yet */
        if (access("/run/udev", F_OK) == 0) {
                int fd = udev_queue_get_fd(q);

                ASSERT_TRUE(fd >= 0);
                ASSERT_TRUE(udev_queue_get_fd(q) == fd);
                ASSERT_EQ_INT(udev_queue_flush(q), 0);
        } else
                ASSERT_EQ_INT(udev_queue_get_fd(q), -ENOENT);
        ASSERT_TRUE(udev_queue_ref(q) == q);
        ASSERT_TRUE(udev_queue_unref(q) == NULL);
        ASSERT_TRUE(udev_queue_unref(q) == NULL);

        /* no hwdb.bin ever exists here: NULL with ENOENT, as real libudev
         * reports on a host without one */
        errno = 0;
        ASSERT_TRUE(udev_hwdb_new(udev) == NULL);
        ASSERT_EQ_INT(errno, ENOENT);
        ASSERT_TRUE(udev_hwdb_ref(NULL) == NULL);
        ASSERT_TRUE(udev_hwdb_unref(NULL) == NULL);
        errno = 0;
        ASSERT_TRUE(udev_hwdb_get_properties_list_entry(NULL, "usb:v1D6Bp0002", 0) == NULL);
        ASSERT_EQ_INT(errno, EINVAL);

        udev_unref(udev);
}

int main(void) {
        test_monitor_never_delivers();
        test_queue_and_hwdb();

        printf("test-libudev-monitor: OK\n");
        return 0;
}
