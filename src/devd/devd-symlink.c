/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The by-* symlink families. devd-symlink.h has the lifecycle argument and why
 * removal reads the links rather than remembering them.
 */

#include "devd-symlink.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../util.h"

/* The families, in the order the links are created. Kept as a table because
 * create, remove and reconcile all walk exactly the same set, and three
 * hand-written lists is three places for a sixth family to be forgotten. */
static const char * const devd_link_dirs[] = {
        "by-partuuid", "by-partlabel", "by-uuid", "by-label", "by-id",
};

#define DEVD_LINK_DIR_COUNT (sizeof(devd_link_dirs) / sizeof(devd_link_dirs[0]))

size_t devd_symlink_escape(const char *in, char *out, size_t size) {
        size_t n = 0;

        if (!out || size == 0)
                return 0;

        out[0] = '\0';

        if (!in)
                return 0;

        for (; *in; in++) {
                unsigned char c = (unsigned char) *in;

                if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    strchr("#+-.:=@_", (char) c)) {
                        if (n + 1 >= size)
                                break;

                        out[n++] = (char) c;
                        continue;
                }

                if (n + 4 >= size)
                        break;

                /* Written by hand rather than with snprintf(): the four bytes
                 * are going into the middle of a buffer this function is
                 * already tracking the length of, and snprintf would want to
                 * terminate after each one. */
                out[n++] = '\\';
                out[n++] = 'x';
                out[n++] = "0123456789abcdef"[c >> 4];
                out[n++] = "0123456789abcdef"[c & 0x0f];
        }

        out[n] = '\0';
        return n;
}

/* mkdir <dev_root>/disk/<family>, parents included. 0 or -errno. */
static int link_dir(const char *dev_root, const char *family, char *ret, size_t size) {
        char disk[PATH_MAX];

        if ((size_t) snprintf(disk, sizeof(disk), "%s/disk", dev_root) >= sizeof(disk))
                return -ENAMETOOLONG;

        if ((size_t) snprintf(ret, size, "%s/%s", disk, family) >= size)
                return -ENAMETOOLONG;

        if (mkdir(disk, 0755) < 0 && errno != EEXIST)
                return -errno;

        if (mkdir(ret, 0755) < 0 && errno != EEXIST)
                return -errno;

        return 0;
}

/* The one link. Replaces whatever is there; see the header. 0 or -errno. */
static int link_make(const char *dev_root, const char *family, const char *value, const char *devname) {
        char dir[PATH_MAX], name[PATH_MAX], path[PATH_MAX], target[PATH_MAX];
        int r;

        if (!value || value[0] == '\0')
                return 0;

        if (devd_symlink_escape(value, name, sizeof(name)) == 0)
                return 0;

        r = link_dir(dev_root, family, dir, sizeof(dir));
        if (r < 0)
                return r;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, name) >= sizeof(path))
                return -ENAMETOOLONG;

        if ((size_t) snprintf(target, sizeof(target), "../../%s", devname) >= sizeof(target))
                return -ENAMETOOLONG;

        if (symlink(target, path) == 0)
                return 0;

        if (errno != EEXIST)
                return -errno;

        /* Replace. Not atomic, and deliberately not made so with a
         * rename(2) dance: the window is between two events devd itself
         * serialises, and an unlink that fails leaves the old link rather
         * than no link. */
        if (unlink(path) < 0 && errno != ENOENT)
                return -errno;

        if (symlink(target, path) < 0)
                return -errno;

        return 0;
}

int devd_symlink_create(const char *dev_root, const char *devname, const DevdLinks *l) {
        static const size_t n_values = 5;
        const char *family[5], *value[5];
        int r = 0;

        if (!dev_root || !devname || !l)
                return -EINVAL;

        family[0] = "by-partuuid";
        value[0] = l->partuuid;
        family[1] = "by-partlabel";
        value[1] = l->partlabel;
        family[2] = "by-uuid";
        value[2] = l->fsuuid;
        family[3] = "by-label";
        value[3] = l->fslabel;
        family[4] = "by-id";
        value[4] = l->id;

        for (size_t i = 0; i < n_values; i++) {
                int rr = link_make(dev_root, family[i], value[i], devname);

                if (rr < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "devd: %s/%s for %s: %s",
                                 family[i],
                                 value[i],
                                 devname,
                                 strerror(-rr));
                        r = rr;
                }
        }

        return r;
}

/*
 * Walk one family directory, calling `keep` on each entry's link target. An
 * entry `keep` says no to is unlinked. Returns the number removed or -errno.
 *
 * The two public verbs differ only in that predicate, which is the point: the
 * directory walk, the readlink, the basename and the unlink are the fiddly part
 * and exist once.
 */
typedef bool (*devd_link_keep_t)(const char *dev_root, const char *target_base, const void *userdata);

static int link_sweep(const char *dev_root, const char *family, devd_link_keep_t keep, const void *userdata) {
        char dir[PATH_MAX];
        struct dirent *e;
        int removed = 0;
        DIR *d;

        if ((size_t) snprintf(dir, sizeof(dir), "%s/disk/%s", dev_root, family) >= sizeof(dir))
                return -ENAMETOOLONG;

        d = opendir(dir);
        if (!d)
                return errno == ENOENT ? 0 : -errno;

        while ((e = readdir(d))) {
                char path[PATH_MAX], target[PATH_MAX];
                const char *base, *slash;
                ssize_t k;

                if (e->d_name[0] == '.')
                        continue;

                if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >= sizeof(path))
                        continue;

                k = readlink(path, target, sizeof(target) - 1);
                if (k < 0)
                        continue; /* not a symlink: not devd's to remove */

                target[k] = '\0';

                slash = strrchr(target, '/');
                base = slash ? slash + 1 : target;

                if (keep(dev_root, base, userdata))
                        continue;

                if (unlink(path) < 0) {
                        pico_log(PICO_LOG_WARNING, "devd: cannot remove %s: %s", path, strerror(errno));
                        continue;
                }

                removed++;
        }

        (void) closedir(d);
        return removed;
}

static bool keep_unless_named(const char *dev_root, const char *target_base, const void *userdata) {
        (void) dev_root;

        return strcmp(target_base, (const char *) userdata) != 0;
}

static bool keep_if_target_exists(const char *dev_root, const char *target_base, const void *userdata) {
        char node[PATH_MAX];
        struct stat st;

        (void) userdata;

        if ((size_t) snprintf(node, sizeof(node), "%s/%s", dev_root, target_base) >= sizeof(node))
                return true;

        return stat(node, &st) == 0;
}

/* Run one predicate across every family, summing what it removed. */
static int sweep_all(const char *dev_root, devd_link_keep_t keep, const void *userdata) {
        int removed = 0;

        for (size_t i = 0; i < DEVD_LINK_DIR_COUNT; i++) {
                int r = link_sweep(dev_root, devd_link_dirs[i], keep, userdata);

                if (r < 0)
                        return r;

                removed += r;
        }

        return removed;
}

int devd_symlink_remove(const char *dev_root, const char *devname) {
        if (!dev_root || !devname)
                return -EINVAL;

        return sweep_all(dev_root, keep_unless_named, devname);
}

int devd_symlink_reconcile(const char *dev_root) {
        if (!dev_root)
                return -EINVAL;

        return sweep_all(dev_root, keep_if_target_exists, NULL);
}
