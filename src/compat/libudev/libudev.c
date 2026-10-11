/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * struct udev: the library context. Upstream keeps nothing in it but a
 * refcount and the caller's userdata either; the three deprecated logging
 * entry points still exist because a binary built against real libudev may
 * reference them, and record the priority so a get after a set returns it.
 */

#include "libudev.h"

#include <errno.h>
#include <stdlib.h>
#include <syslog.h>

#include "libudev-internal.h"

struct udev *udev_new(void) {
        struct udev *udev = calloc(1, sizeof(*udev));

        if (!udev) {
                errno = ENOMEM;
                return NULL;
        }
        udev->n_ref = 1;
        udev->log_priority = LOG_INFO;
        return udev;
}

struct udev *udev_ref(struct udev *udev) {
        if (!udev)
                return NULL;
        udev->n_ref++;
        return udev;
}

/* Returns the context while references remain, NULL once freed -- the
 * one libudev unref that does not always return NULL, kept for binaries
 * that test the return value. */
struct udev *udev_unref(struct udev *udev) {
        if (!udev)
                return NULL;
        if (--udev->n_ref > 0)
                return udev;
        free(udev);
        return NULL;
}

void udev_set_log_fn(
                struct udev *udev,
                void (*log_fn)(struct udev *udev,
                               int priority,
                               const char *file,
                               int line,
                               const char *fn,
                               const char *format,
                               va_list args)) {
        (void) udev;
        (void) log_fn;
}

int udev_get_log_priority(struct udev *udev) {
        if (!udev)
                return LOG_INFO;
        return udev->log_priority;
}

void udev_set_log_priority(struct udev *udev, int priority) {
        if (!udev)
                return;
        udev->log_priority = priority;
}

void *udev_get_userdata(struct udev *udev) {
        if (!udev)
                return NULL;
        return udev->userdata;
}

void udev_set_userdata(struct udev *udev, void *userdata) {
        if (!udev)
                return;
        udev->userdata = userdata;
}
