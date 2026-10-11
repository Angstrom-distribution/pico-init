/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_device_trigger()/_with_uuid() (a write to <syspath>/uevent) and
 * sd_device_open() (a guarded open of the real devnode).
 *
 * sd_device_open()'s three checks -- st_rdev match, block/char shape
 * match, and the DISKSEQ ioctl compare -- all exist for the same reason:
 * a devnode can be reused for a different device between "we resolved
 * this path" and "we opened it" (unplug/replug, or a partition table
 * rewrite bumping DISKSEQ), and opening the wrong device silently is worse
 * than a slower, checked open.
 */

/* O_PATH is a glibc/kernel extension gated behind _GNU_SOURCE; -std=gnu17
 * alone does not imply it, so it must be defined first, before any header
 * pulls in features.h. */
#define _GNU_SOURCE

#include "sd-device.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include "device-internal.h"

int sd_device_trigger_with_uuid(sd_device *device, sd_device_action_t action, sd_id128_t *ret_uuid) {
        char path[PATH_MAX], payload[64];
        const char *action_str;
        sd_id128_t uuid = { 0 };
        int fd, r;
        size_t len;

        if (!device)
                return -EINVAL;

        action_str = device_action_to_string(action);
        if (!action_str)
                return -EINVAL;

        if ((size_t) snprintf(path, sizeof(path), "%s/uevent", device->syspath) >= sizeof(path))
                return -ENAMETOOLONG;

        if (ret_uuid) {
                char uuidstr[37];

                if (getrandom(uuid.bytes, sizeof(uuid.bytes), 0) != (ssize_t) sizeof(uuid.bytes))
                        return -errno;

                device_id128_to_uuid_string(uuid, uuidstr);
                len = (size_t) snprintf(payload, sizeof(payload), "%s %s", action_str, uuidstr);
        } else
                len = (size_t) snprintf(payload, sizeof(payload), "%s", action_str);

        fd = open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = write(fd, payload, len) == (ssize_t) len ? 0 : -errno;
        close(fd);
        if (r < 0)
                return r;

        if (ret_uuid)
                *ret_uuid = uuid;
        return 0;
}

int sd_device_trigger(sd_device *device, sd_device_action_t action) {
        return sd_device_trigger_with_uuid(device, action, NULL);
}

int sd_device_open(sd_device *device, int flags) {
        char devname_buf[PATH_MAX], procpath[64];
        const char *devname;
        const char *subsystem;
        dev_t devnum;
        uint64_t diskseq;
        struct stat st;
        int fd, real_fd, r;
        bool is_block;

        if (!device)
                return -EINVAL;

        if ((flags & O_NOFOLLOW) && !(flags & O_PATH))
                return -EINVAL;

        r = sd_device_get_devname(device, &devname);
        if (r == -ENOENT)
                return -ENOEXEC;
        if (r < 0)
                return r;
        (void) snprintf(devname_buf, sizeof(devname_buf), "%s", devname);

        r = sd_device_get_devnum(device, &devnum);
        if (r == -ENOENT)
                return -ENOEXEC;
        if (r < 0)
                return r;

        fd = open(devname_buf, O_CLOEXEC | O_NOFOLLOW | O_PATH);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        if (st.st_rdev != devnum) {
                close(fd);
                return -ENXIO;
        }

        is_block = sd_device_get_subsystem(device, &subsystem) >= 0 && strcmp(subsystem, "block") == 0;
        if (is_block ? !S_ISBLK(st.st_mode) : !S_ISCHR(st.st_mode)) {
                close(fd);
                return -ENXIO;
        }

        if (flags & O_PATH)
                return fd;

        (void) snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", fd);
        real_fd = open(procpath, flags);
        r = real_fd < 0 ? -errno : 0;
        close(fd);
        if (r < 0)
                return r;

        if (sd_device_get_diskseq(device, &diskseq) >= 0) {
                uint64_t got;

                if (ioctl(real_fd, BLKGETDISKSEQ, &got) < 0) {
                        if (errno != ENOTTY) {
                                r = -errno;
                                close(real_fd);
                                return r;
                        }
                        /* Not a block device, or an old kernel: nothing to
                         * compare against, same as real. */
                } else if (got != diskseq) {
                        close(real_fd);
                        return -ENXIO;
                }
        }

        return real_fd;
}
