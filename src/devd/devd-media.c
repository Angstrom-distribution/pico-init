/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Removable-media mounting. devd-media.h has the policy and the two things it
 * deliberately is not (DPS, and a rule).
 */

#include "devd-media.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../ext-super.h"
#include "../fstab-mount.h"
#include "../util.h"
#include "devd-probe.h"

/* On-disk byte order, like every other GUID in this project: first three
 * fields little-endian, last two big-endian. */
const GptGuid devd_type_linux_data = {
        { 0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4 }
};

const GptGuid devd_type_basic_data = {
        { 0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7 }
};

/*
 * Removable media, mounted by a daemon, with no idea what is on it. nosuid and
 * nodev are not hardening decoration here: without them, anyone able to hand
 * the machine a card can hand it a setuid-root binary and a device node.
 */
#define DEVD_MEDIA_FLAGS (MS_NOSUID | MS_NODEV)

bool devd_media_is_data_type(const GptGuid *type) {
        if (!type)
                return false;

        return memcmp(type, &devd_type_linux_data, sizeof(GptGuid)) == 0 ||
                        memcmp(type, &devd_type_basic_data, sizeof(GptGuid)) == 0;
}

int devd_media_mount_point(
                const char *media_root, const char *partlabel, const char *devname, char *ret, size_t size) {

        char name[NAME_MAX + 1];

        if (!media_root || !devname || !ret)
                return -EINVAL;

        /*
         * devd_sanitize() already removes '/' along with everything else
         * outside its whitelist, so what comes back is one path component by
         * construction. What it does not rule out is a component that is a
         * path *operator*: "." and ".." survive the whitelist untouched and
         * would name the media root itself and its parent.
         */
        if (devd_sanitize(partlabel, name, sizeof(name)) == 0 || strcmp(name, ".") == 0 ||
            strcmp(name, "..") == 0) {
                if (devd_sanitize(devname, name, sizeof(name)) == 0)
                        return -EINVAL;
        }

        if ((size_t) snprintf(ret, size, "%s/%s", media_root, name) >= size)
                return -ENAMETOOLONG;

        return 0;
}

int devd_media_mount(
                const char *media_root,
                const char *mountinfo,
                const char *node,
                const char *partlabel,
                const char *devname,
                bool read_only,
                char *ret_dir,
                size_t size) {

        char dir[PATH_MAX], where[PATH_MAX];
        PicoExtInfo fs;
        unsigned long flags = DEVD_MEDIA_FLAGS;
        int r;

        if (!media_root || !node || !devname)
                return -EINVAL;

        /*
         * Probe before mounting, not to choose between filesystem types -- v1
         * has one -- but so that "there is no ext filesystem here" is a
         * decision devd makes and logs, rather than a mount(2) failure it has
         * to guess the meaning of. A FAT card and an unreadable card both fail
         * mount(2) with the same errno; only one of them is worth a warning.
         */
        r = ext_super_read(node, &fs);
        if (r < 0)
                return r;

        if (r == 0) {
                pico_log(PICO_LOG_INFO, "devd: %s carries no ext filesystem, not mounting it", node);
                return 0;
        }

        r = devd_media_mount_point(media_root, partlabel, devname, dir, sizeof(dir));
        if (r < 0)
                return r;

        /*
         * Mounted anywhere already -- by PID 1's fstab pass, by hand -- is
         * left where it is: a second mount under /media would be a surprise
         * and would be pulled out from under its owner on eject. Mounted at
         * this very directory is devd's own mount from before a restart, and
         * is adopted. Unknown is not "not mounted".
         */
        r = fstab_device_mounted(mountinfo ? mountinfo : "/proc/self/mountinfo", node, where, sizeof(where));
        if (r < 0)
                return r;
        if (r > 0) {
                if (strcmp(where, dir) == 0) {
                        if (ret_dir && (size_t) snprintf(ret_dir, size, "%s", dir) >= size)
                                return -ENAMETOOLONG;
                        return 1;
                }

                pico_log(PICO_LOG_INFO, "devd: %s is already mounted on %s, not mounting it again", node, where);
                return 0;
        }

        if (mkdir(media_root, 0755) < 0 && errno != EEXIST)
                return -errno;

        if (mkdir(dir, 0755) < 0 && errno != EEXIST)
                return -errno;

        if (read_only)
                flags |= MS_RDONLY;

        if (mount(node, dir, "ext4", flags, NULL) < 0) {
                if (errno == EBUSY) {
                        /* Already mounted there. The state asked for is the
                         * state there is; saying so beats a spurious failure
                         * after a devd restart. */
                        if (ret_dir && (size_t) snprintf(ret_dir, size, "%s", dir) >= size)
                                return -ENAMETOOLONG;

                        return 1;
                }

                r = -errno;
                (void) rmdir(dir);
                return r;
        }

        if (ret_dir && (size_t) snprintf(ret_dir, size, "%s", dir) >= size)
                return -ENAMETOOLONG;

        pico_log(PICO_LOG_INFO,
                 "devd: mounted %s on %s%s%s%s",
                 node,
                 dir,
                 fs.label[0] ? " (label " : "",
                 fs.label[0] ? fs.label : "",
                 fs.label[0] ? ")" : "");

        return 1;
}

int devd_media_unmount(const char *dir) {
        if (!dir)
                return -EINVAL;

        if (umount2(dir, MNT_DETACH) < 0 && errno != EINVAL && errno != ENOENT)
                return -errno;

        /* EINVAL from umount2() means it was not a mount point, which after a
         * failed mount is exactly the state this leaves behind -- the rmdir is
         * still the right next step either way, and a non-empty directory
         * (something wrote to the mount point while nothing was mounted) is
         * left alone rather than emptied. */
        if (rmdir(dir) < 0 && errno != ENOENT && errno != ENOTEMPTY)
                return -errno;

        return 0;
}
