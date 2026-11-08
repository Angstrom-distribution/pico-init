/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The state devd publishes so that `udevadm settle` can wait for it, and the
 * readers udevadm uses. Shared by devd-loop.c (writer) and udevadm.c (reader),
 * which is why it depends on nothing but libc.
 *
 * udevd answers "is the queue empty" through its control socket and
 * /run/udev/queue. devd has no control socket, and a flag file alone has a
 * hole: `udevadm trigger` returns as soon as the kernel has put the events in
 * devd's socket buffer, before devd has woken up to read them, so a settle
 * straight after it would see an empty queue and return early. The kernel's
 * own event counter closes that hole, as udev's settle did before it had a
 * control socket:
 *
 *  - <run_root>/seqnum holds a value of /sys/kernel/uevent_seqnum that devd
 *    read, then drained its socket, and then found itself idle: no settle
 *    window open, no RUN+= or modprobe child running. Every event with a
 *    number up to it has been handled.
 *  - settle reads /sys/kernel/uevent_seqnum once when it starts and waits
 *    until the published value reaches it. Events newer than settle itself
 *    are not waited for.
 *  - <udev_run_root>/queue exists while devd is busy and is removed when it
 *    publishes, which is upstream's own flag and what libudev's udev_queue
 *    and sd-device consumers read.
 *  - <run_root>/pid is devd's pid, for `udevadm control --exit`.
 *
 * Publishing the counter devd read rather than the last SEQNUM it handled is
 * what makes events devd never receives harmless: a device in another network
 * namespace, or events lost to a socket overrun, still advance the kernel
 * counter, and devd's next idle moment covers them.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define DEVD_RUN_ROOT "/run/devd"
#define DEVD_UDEV_RUN_ROOT "/run/udev"

#define DEVD_QUEUE_PID_FILE "pid"
#define DEVD_QUEUE_SEQNUM_FILE "seqnum"
#define DEVD_QUEUE_FLAG_FILE "queue"

/* Relative to the sysfs root. */
#define DEVD_KERNEL_SEQNUM_FILE "kernel/uevent_seqnum"

/*
 * One unsigned decimal number, optionally followed by a newline, from `path`.
 * 0 with *ret set, -ENOENT when the file is absent, -EINVAL when it holds
 * anything else, or -errno.
 */
int devd_queue_read_u64(const char *path, uint64_t *ret);

/*
 * Replace <dir>/<name> with `value` and a newline, atomically: a temporary
 * name in the same directory, then rename(2), so a reader never sees a torn
 * or empty file. `dir` is created (one level, 0755) if it is missing.
 * 0 or -errno.
 */
int devd_queue_write_u64(const char *dir, const char *name, uint64_t value);

/* Remove <dir>/<name>. An absent file is success. 0 or -errno. */
int devd_queue_remove(const char *dir, const char *name);

/* Create (empty) or remove <dir>/<name>, the busy flag. `dir` is created as
 * for devd_queue_write_u64(). 0 or -errno. */
int devd_queue_set_flag(const char *dir, const char *name, bool on);

/* Whether a published value covers everything up to `kernel_seqnum`. */
static inline bool devd_queue_covers(uint64_t published, uint64_t kernel_seqnum) {
        return published >= kernel_seqnum;
}
