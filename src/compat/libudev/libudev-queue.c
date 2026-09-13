/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udev_queue: upstream's own definition of these answers is the presence
 * of /run/udev/control (a udevd is running) and /run/udev/queue (events
 * are pending). devd creates neither, so a consumer asking gets the true
 * state -- no udevd, nothing queued -- which is also what real libudev
 * reports on any system where udevd is not running.
 */

#include "libudev.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "libudev-internal.h"

#define UDEV_RUN_DIR "/run/udev"
#define UDEV_CONTROL_PATH UDEV_RUN_DIR "/control"
#define UDEV_QUEUE_PATH UDEV_RUN_DIR "/queue"

struct udev_queue {
        struct udev *udev;
        unsigned n_ref;
        int fd;
};

struct udev_queue *udev_queue_new(struct udev *udev) {
        struct udev_queue *q = calloc(1, sizeof(*q));

        if (!q) {
                errno = ENOMEM;
                return NULL;
        }
        q->n_ref = 1;
        q->udev = udev;
        q->fd = -1;
        return q;
}

struct udev_queue *udev_queue_ref(struct udev_queue *udev_queue) {
        if (!udev_queue)
                return NULL;
        udev_queue->n_ref++;
        return udev_queue;
}

struct udev_queue *udev_queue_unref(struct udev_queue *udev_queue) {
        if (!udev_queue)
                return NULL;
        if (--udev_queue->n_ref > 0)
                return NULL;
        if (udev_queue->fd >= 0)
                (void) close(udev_queue->fd);
        free(udev_queue);
        return NULL;
}

struct udev *udev_queue_get_udev(struct udev_queue *udev_queue) {
        if (!udev_queue) {
                errno = EINVAL;
                return NULL;
        }
        return udev_queue->udev;
}

static int queue_is_empty(void) {
        if (access(UDEV_QUEUE_PATH, F_OK) >= 0)
                return 0;
        return errno == ENOENT ? 1 : -errno;
}

unsigned long long int udev_queue_get_kernel_seqnum(struct udev_queue *udev_queue) {
        (void) udev_queue;
        return 0;
}

unsigned long long int udev_queue_get_udev_seqnum(struct udev_queue *udev_queue) {
        (void) udev_queue;
        return 0;
}

int udev_queue_get_udev_is_active(struct udev_queue *udev_queue) {
        (void) udev_queue;
        return access(UDEV_CONTROL_PATH, F_OK) >= 0;
}

int udev_queue_get_queue_is_empty(struct udev_queue *udev_queue) {
        (void) udev_queue;
        return queue_is_empty() > 0;
}

int udev_queue_get_seqnum_sequence_is_finished(
                struct udev_queue *udev_queue, unsigned long long int start, unsigned long long int end) {
        (void) udev_queue;
        (void) start;
        (void) end;
        return queue_is_empty() > 0;
}

int udev_queue_get_seqnum_is_finished(struct udev_queue *udev_queue, unsigned long long int seqnum) {
        (void) udev_queue;
        (void) seqnum;
        return queue_is_empty() > 0;
}

struct udev_list_entry *udev_queue_get_queued_list_entry(struct udev_queue *udev_queue) {
        (void) udev_queue;
        errno = ENODATA;
        return NULL;
}

int udev_queue_get_fd(struct udev_queue *udev_queue) {
        int fd;

        if (!udev_queue)
                return -EINVAL;
        if (udev_queue->fd >= 0)
                return udev_queue->fd;

        fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
        if (fd < 0)
                return -errno;
        if (inotify_add_watch(fd, UDEV_RUN_DIR, IN_DELETE) < 0) {
                int e = errno;

                (void) close(fd);
                return -e;
        }

        udev_queue->fd = fd;
        return fd;
}

int udev_queue_flush(struct udev_queue *udev_queue) {
        if (!udev_queue)
                return -EINVAL;
        if (udev_queue->fd < 0)
                return -EINVAL;

        for (;;) {
                char buf[4096];
                ssize_t n = read(udev_queue->fd, buf, sizeof(buf));

                if (n < 0)
                        return errno == EAGAIN ? 0 : -errno;
                if (n == 0)
                        return 0;
        }
}
