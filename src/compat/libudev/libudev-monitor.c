/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udev_monitor over sd_device_monitor: a thin wrapper, the same shape every
 * other libudev-*.c has over its sd-device counterpart. The real work --
 * the group-1 NETLINK_KOBJECT_UEVENT socket, bind, receive, and every
 * filter -- lives in sd_device_monitor_new()/_receive() et al.
 * (device-monitor.c); this file only translates libudev's calling
 * convention (NULL+errno, not a negative return) onto it and wraps a
 * received sd_device with libudev_device_new().
 *
 * "kernel" and "udev" are both wired to the same group-1 socket: nothing on
 * this image writes to group 2 (udev's own rebroadcast, which does not exist
 * without udevd), so a consumer asking for "udev" (libusb_init() does) gets the
 * only real uevent source rather than a permanently silent one.
 * test-libudev-monitor.c pins the two names as equivalent.
 *
 * NULL from udev_monitor_new_from_netlink() is a real failure (ENOMEM, or no
 * uevent netlink in this kernel/sandbox), not a fabricated fd: a consumer that
 * treats NULL as "no USB/hotplug at all" (libusb_init() does) should see that
 * only when it is true.
 */

#include "libudev.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "libudev-internal.h"

struct udev_monitor {
        struct udev *udev;
        unsigned n_ref;
        sd_device_monitor *monitor;
};

static void *fail_errno(int e) {
        errno = e;
        return NULL;
}

struct udev_monitor *udev_monitor_new_from_netlink(struct udev *udev, const char *name) {
        struct udev_monitor *m;
        sd_device_monitor *sdm;
        int r;

        if (name && strcmp(name, "udev") != 0 && strcmp(name, "kernel") != 0)
                return fail_errno(EINVAL);

        r = sd_device_monitor_new(&sdm);
        if (r < 0)
                return fail_errno(-r);

        m = calloc(1, sizeof(*m));
        if (!m) {
                sd_device_monitor_unref(sdm);
                return fail_errno(ENOMEM);
        }
        m->n_ref = 1;
        m->udev = udev;
        m->monitor = sdm;
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
        sd_device_monitor_unref(udev_monitor->monitor);
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
        return sd_device_monitor_get_fd(udev_monitor->monitor);
}

int udev_monitor_enable_receiving(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return -EINVAL;
        /* The socket is already bound and joined to group 1 by
         * sd_device_monitor_new(); there is no separate kernel BPF filter
         * install step here (device-monitor.c's own filter_update() is a
         * no-op for the same reason), so there is nothing left to enable. */
        return 0;
}

int udev_monitor_set_receive_buffer_size(struct udev_monitor *udev_monitor, int size) {
        if (!udev_monitor || size < 0)
                return -EINVAL;
        return sd_device_monitor_set_receive_buffer_size(udev_monitor->monitor, (size_t) size);
}

struct udev_device *udev_monitor_receive_device(struct udev_monitor *udev_monitor) {
        sd_device *dev = NULL;
        struct udev_device *wrapped;
        int r;

        if (!udev_monitor)
                return fail_errno(EINVAL);

        r = sd_device_monitor_receive(udev_monitor->monitor, &dev);
        if (r < 0)
                return fail_errno(-r);

        /* libudev_device_new() takes its own reference; drop the one
         * sd_device_monitor_receive() handed us either way. */
        wrapped = libudev_device_new(udev_monitor->udev, dev);
        sd_device_unref(dev);
        return wrapped;
}

int udev_monitor_filter_add_match_subsystem_devtype(
                struct udev_monitor *udev_monitor, const char *subsystem, const char *devtype) {
        if (!udev_monitor || !subsystem)
                return -EINVAL;
        return sd_device_monitor_filter_add_match_subsystem_devtype(udev_monitor->monitor, subsystem, devtype);
}

int udev_monitor_filter_add_match_tag(struct udev_monitor *udev_monitor, const char *tag) {
        if (!udev_monitor || !tag)
                return -EINVAL;
        return sd_device_monitor_filter_add_match_tag(udev_monitor->monitor, tag);
}

int udev_monitor_filter_update(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return -EINVAL;
        return sd_device_monitor_filter_update(udev_monitor->monitor);
}

int udev_monitor_filter_remove(struct udev_monitor *udev_monitor) {
        if (!udev_monitor)
                return -EINVAL;
        return sd_device_monitor_filter_remove(udev_monitor->monitor);
}
