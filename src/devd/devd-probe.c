/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The ext superblock decode, the sysfs by-id walk, and the sanitizer both need.
 * devd-probe.h has the reasoning and the verified offsets.
 */

#include "devd-probe.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../util.h"

/* Where the label ends: the shortest buffer that can answer every question
 * this file asks of a superblock. */
#define DEVD_EXT_MIN_SUPER (DEVD_EXT_LABEL_OFF + 16)

/* How far up the sysfs chain the by-id walk will look. A USB block device sits
 * six levels under its usb_device; a bound stops a symlinked or malformed tree
 * from walking forever. */
#define DEVD_SYSFS_WALK_MAX 12

static bool bytes_all_zero(const uint8_t *p, size_t n) {
        for (size_t i = 0; i < n; i++)
                if (p[i])
                        return false;

        return true;
}

int devd_probe_ext_super(const uint8_t *sb, size_t n, DevdFsInfo *ret) {
        const uint8_t *u;
        size_t i;

        if (!sb || !ret || n < DEVD_EXT_MIN_SUPER)
                return -EINVAL;

        /* s_magic is little-endian, like every other ext field. */
        if (((uint32_t) sb[DEVD_EXT_MAGIC_OFF] | ((uint32_t) sb[DEVD_EXT_MAGIC_OFF + 1] << 8)) !=
            DEVD_EXT_MAGIC)
                return 0;

        memset(ret, 0, sizeof(*ret));

        /*
         * s_uuid is a plain big-endian UUID, unlike GPT's mixed-endian one --
         * printed straight through, which is why this does not reuse
         * gpt_guid_to_string(). Getting that wrong would produce a by-uuid link
         * no fstab or bootloader entry written by anything else would match.
         */
        u = sb + DEVD_EXT_UUID_OFF;
        if (!bytes_all_zero(u, 16))
                snprintf(ret->uuid,
                         sizeof(ret->uuid),
                         "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                         u[0],
                         u[1],
                         u[2],
                         u[3],
                         u[4],
                         u[5],
                         u[6],
                         u[7],
                         u[8],
                         u[9],
                         u[10],
                         u[11],
                         u[12],
                         u[13],
                         u[14],
                         u[15]);

        /* s_volume_name is 16 bytes and is NOT required to be terminated, so a
         * 16-character label has no NUL at all -- copying by length rather than
         * with strncpy() is the whole point. */
        for (i = 0; i < 16; i++) {
                if (sb[DEVD_EXT_LABEL_OFF + i] == '\0')
                        break;

                ret->label[i] = (char) sb[DEVD_EXT_LABEL_OFF + i];
        }

        ret->label[i] = '\0';

        return 1;
}

int devd_probe_ext(const char *device, DevdFsInfo *ret) {
        uint8_t sb[DEVD_EXT_SUPER_SIZE];
        size_t done = 0;
        int fd, r;

        if (!device || !ret)
                return -EINVAL;

        fd = open(device, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        while (done < sizeof(sb)) {
                ssize_t k = pread(fd, sb + done, sizeof(sb) - done, (off_t) (DEVD_EXT_SUPER_OFFSET + done));

                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        r = -errno;
                        goto done;
                }

                if (k == 0) {
                        /* Shorter than a superblock: not a filesystem devd can
                         * name, and not an I/O error either. */
                        r = 0;
                        goto done;
                }

                done += (size_t) k;
        }

        r = devd_probe_ext_super(sb, sizeof(sb), ret);

done:
        (void) close(fd);
        return r;
}

size_t devd_sanitize(const char *in, char *out, size_t size) {
        size_t n = 0;
        bool pending_space = false;

        if (!out || size == 0)
                return 0;

        out[0] = '\0';

        if (!in)
                return 0;

        for (; *in; in++) {
                unsigned char c = (unsigned char) *in;

                if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') {
                        /* Deferred rather than emitted: a run of whitespace
                         * becomes one underscore, and a run at the very end
                         * becomes nothing at all. */
                        if (n > 0)
                                pending_space = true;

                        continue;
                }

                if (pending_space) {
                        if (n + 1 >= size)
                                break;

                        out[n++] = '_';
                        pending_space = false;
                }

                if (n + 1 >= size)
                        break;

                if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    strchr("#+-.:=@_", (char) c))
                        out[n++] = (char) c;
                else
                        out[n++] = '_';
        }

        out[n] = '\0';
        return n;
}

/* Read a one-line sysfs attribute, trimmed. Returns 1 with *ret set, 0 when the
 * attribute is absent or empty, or -errno. */
static int attr_read(const char *dir, const char *name, char *ret, size_t size) {
        char path[PATH_MAX], buf[256];
        size_t len;
        FILE *f;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, name) >= sizeof(path))
                return -ENAMETOOLONG;

        f = fopen(path, "re");
        if (!f)
                return errno == ENOENT ? 0 : -errno;

        if (!fgets(buf, sizeof(buf), f)) {
                (void) fclose(f);
                return 0;
        }

        (void) fclose(f);

        len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
                buf[--len] = '\0';

        if (len == 0)
                return 0;

        return devd_sanitize(buf, ret, size) > 0 ? 1 : 0;
}

/* Append "sep" + "value" to a stem, or say it does not fit. */
static int stem_append(char *stem, size_t size, const char *sep, const char *value) {
        size_t have = strlen(stem);
        int len = snprintf(stem + have, size - have, "%s%s", sep, value);

        if (len < 0 || (size_t) len >= size - have)
                return -ENAMETOOLONG;

        return 0;
}

/* The usb_device level: idVendor and idProduct are what identify it as one. */
static int try_usb(const char *dir, char *ret, size_t size) {
        char field[DEVD_ID_MAX];
        bool any = false;
        int r;

        r = attr_read(dir, "idVendor", field, sizeof(field));
        if (r <= 0)
                return r;

        r = attr_read(dir, "idProduct", field, sizeof(field));
        if (r <= 0)
                return r;

        /*
         * From here this IS the usb device, so whatever it says is the answer
         * -- including "nothing", which is the recorded divergence from
         * usb_id's hex-ID fallback and not a reason to keep walking upwards
         * into the hub.
         */
        if ((size_t) snprintf(ret, size, "usb-") >= size)
                return -ENAMETOOLONG;

        r = attr_read(dir, "manufacturer", field, sizeof(field));
        if (r < 0)
                return r;
        if (r > 0) {
                if (stem_append(ret, size, "", field) < 0)
                        return -ENAMETOOLONG;

                any = true;
        }

        r = attr_read(dir, "product", field, sizeof(field));
        if (r < 0)
                return r;
        if (r > 0) {
                if (stem_append(ret, size, any ? "_" : "", field) < 0)
                        return -ENAMETOOLONG;

                any = true;
        }

        r = attr_read(dir, "serial", field, sizeof(field));
        if (r < 0)
                return r;
        if (r > 0) {
                if (stem_append(ret, size, any ? "_" : "", field) < 0)
                        return -ENAMETOOLONG;

                any = true;
        }

        if (!any) {
                ret[0] = '\0';
                return 0;
        }

        return 1;
}

/* The mmc card level: upstream's own rule keys off name and serial. */
static int try_mmc(const char *dir, char *ret, size_t size) {
        char name[DEVD_ID_MAX], serial[DEVD_ID_MAX];
        int r;

        r = attr_read(dir, "name", name, sizeof(name));
        if (r <= 0)
                return r;

        r = attr_read(dir, "serial", serial, sizeof(serial));
        if (r < 0)
                return r;

        if (r == 0) {
                if ((size_t) snprintf(ret, size, "mmc-%s", name) >= size)
                        return -ENAMETOOLONG;
        } else if ((size_t) snprintf(ret, size, "mmc-%s_%s", name, serial) >= size)
                return -ENAMETOOLONG;

        return 1;
}

int devd_probe_bus_id(const char *sys_root, const char *sysfs_disk, char *ret, size_t size) {
        char dir[PATH_MAX];
        size_t root_len;

        if (!sys_root || !sysfs_disk || !ret || size == 0)
                return -EINVAL;

        ret[0] = '\0';
        root_len = strlen(sys_root);

        if (strncmp(sysfs_disk, sys_root, root_len) != 0)
                return -EINVAL;

        if ((size_t) snprintf(dir, sizeof(dir), "%s", sysfs_disk) >= sizeof(dir))
                return -ENAMETOOLONG;

        for (unsigned depth = 0; depth < DEVD_SYSFS_WALK_MAX; depth++) {
                char *slash;
                int r;

                /*
                 * MMC first. A USB card reader has no `name`/`serial` pair and
                 * an MMC card has no idVendor, so the order is not a
                 * tie-break -- it is two disjoint tests written in one loop.
                 */
                r = try_mmc(dir, ret, size);
                if (r != 0)
                        return r;

                r = try_usb(dir, ret, size);
                if (r != 0)
                        return r;

                slash = strrchr(dir, '/');
                if (!slash)
                        break;

                *slash = '\0';

                /* Never above the root handed in: a walk that leaves sysfs is
                 * reading somebody else's filesystem, and in a test it would be
                 * reading the host's real /sys. */
                if (strlen(dir) <= root_len)
                        break;
        }

        ret[0] = '\0';
        return 0;
}
