/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udev_monitor, interim form: a real monitor object that never delivers
 * an event. Live uevent subscription through this API is roadmap work,
 * not a permanent limitation, and the interim shape is dictated by a real
 * consumer: libusb creates its monitor inside libusb_init(), and a NULL
 * from udev_monitor_new_from_netlink() fails initialisation outright --
 * no USB at all, not merely no hotplug. A monitor that succeeds and stays
 * silent is, to any correct consumer, a system on which nothing is ever
 * plugged in; the API carries no promise that events arrive.
 *
 * The fd is a NETLINK_KOBJECT_UEVENT socket with no group membership, so
 * the kernel never delivers to it and poll() never reports it readable,
 * while fcntl()/setsockopt() behave as consumers expect of a real one.
 * Turning this into the real thing is joining group 1 and receiving
 * through sd_device_monitor_receive(); no consumer-visible shape changes.
 */

#include "libudev.h"

#include <errno.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libudev-internal.h"

struct udev_monitor {
        struct udev *udev;
        unsigned n_ref;
        int fd;
};

static void *fail_errno(int e) {
        errno = e;
        return NULL;
}

struct udev_monitor *udev_monitor_new_from_netlink(struct udev *udev, const char *name) {
        struct udev_monitor *m;
        int fd;

        if (name && strcmp(name, "udev") != 0 && strcmp(name, "kernel") != 0)
                return fail_errno(EINVAL);

        fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
        if (fd < 0) {
                /* A kernel or sandbox without uevent netlink: an eventfd
                 * with a zero counter is equally never readable. */
                fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
                if (fd < 0)
                        return fail_errno(errno);
        }

        m = calloc(1, sizeof(*m));
        if (!m) {
                (void) close(fd);
                return fail_errno(ENOMEM);
        }
        m->n_ref = 1;
        m->udev = udev;
        m->fd = fd;
        return m;
}

struct udev_monitor *udev_monitor_ref(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return NULL;
        udev_monitor->n_ref++;
        return udev_monitor;
}

struct udev_monitor *udev_monitor_unref(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return NULL;
        if (--udev_monitor->n_ref > 0)
                return NULL;
        (void) close(udev_monitor->fd);
        free(udev_monitor);
        return NULL;
}

struct udev *udev_monitor_get_udev(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return NULL;
        return udev_monitor->udev;
}

int udev_monitor_get_fd(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return -EINVAL;
        return udev_monitor->fd;
}

int udev_monitor_enable_receiving(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return -EINVAL;
        return 0;
}

int udev_monitor_set_receive_buffer_size(struct udev_monitor *udev_monitor, int size) {
        if (!udev_monitor)
                return -EINVAL;

        if (setsockopt(udev_monitor->fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) == 0)
                return 0;
        if (setsockopt(udev_monitor->fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0)
                return 0;
        return errno == ENOTSOCK ? 0 : -errno;
}

struct udev_device *udev_monitor_receive_device(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return fail_errno(EINVAL);
        /* Nothing is ever queued: the same answer a real non-blocking
         * monitor gives between events. */
        return fail_errno(EAGAIN);
}

int udev_monitor_filter_add_match_subsystem_devtype(
                struct udev_monitor *udev_monitor, const char *subsystem, const char *devtype) {
        (void) devtype;
        if (!udev_monitor || !subsystem)
                return -EINVAL;
        return 0;
}

int udev_monitor_filter_add_match_tag(struct udev_monitor *udev_monitor, const char *tag) {
        if (!udev_monitor || !tag)
                return -EINVAL;
        return 0;
}

int udev_monitor_filter_update(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return -EINVAL;
        return 0;
}

int udev_monitor_filter_remove(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return -EINVAL;
        return 0;
}
