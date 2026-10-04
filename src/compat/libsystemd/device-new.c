/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Refcounting, every sd_device_new_from_*() constructor, the parent walk,
 * and the two getters (syspath/devpath) that need nothing but the string
 * the constructor already stored.
 *
 * sd_device_new_from_syspath() is the constructor everything else in this
 * file funnels through (device_new_from_syspath_internal()): every other
 * sd_device_new_from_*() resolves its own argument down to a syspath and
 * calls it, which is also the real library's own shape. The one exception
 * is device_new_from_devpath_bare(), for device-monitor.c -- see its own
 * comment in device-internal.h for why a monitor-received device cannot
 * go through the disk-touching constructor.
 */

/* asprintf() is a glibc extension; -std=gnu17 alone does not imply
 * _GNU_SOURCE (see socket.c's own note), so this has to be explicit and
 * first, before any header pulls in features.h. */
#define _GNU_SOURCE

#include "sd-device.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "device-internal.h"

#define SYS_ROOT_DEFAULT "/sys"

static char sys_root_buf[PATH_MAX] = SYS_ROOT_DEFAULT;

const char *device_sys_root(void) {
        return sys_root_buf;
}

void device_set_sys_root_for_tests(const char *root) {
        if (!root)
                root = SYS_ROOT_DEFAULT;

        (void) snprintf(sys_root_buf, sizeof(sys_root_buf), "%s", root);
}

bool device_path_component_is_safe(const char *p) {
        const char *seg;

        if (!p || p[0] == '\0' || p[0] == '/')
                return false;

        for (seg = p; seg;) {
                const char *slash = strchr(seg, '/');
                size_t len = slash ? (size_t) (slash - seg) : strlen(seg);

                if (len == 0 || (len == 2 && seg[0] == '.' && seg[1] == '.'))
                        return false;

                seg = slash ? slash + 1 : NULL;
        }

        return true;
}

sd_device *device_new_bare(void) {
        sd_device *d = calloc(1, sizeof(*d));

        if (!d)
                return NULL;

        d->n_ref = 1;
        d->action = _SD_DEVICE_ACTION_INVALID;

        return d;
}

static void device_free(sd_device *d) {
        size_t i;

        if (!d)
                return;

        free(d->syspath);

        for (i = 0; i < d->n_properties; i++) {
                free(d->properties[i].key);
                free(d->properties[i].value);
        }
        free(d->properties);

        free(d->subsystem);
        free(d->driver);
        free(d->driver_subsystem);
        free(d->sysname);
        free(d->sysnum);
        free(d->device_id);
        free(d->devname);

        sd_device_unref(d->parent);

        for (i = 0; i < d->n_devlinks; i++)
                free(d->devlinks[i]);
        free(d->devlinks);

        for (i = 0; i < d->n_sysattr_names; i++)
                free(d->sysattr_names[i]);
        free(d->sysattr_names);

        for (i = 0; i < d->n_sysattr_cache; i++) {
                free(d->sysattr_cache[i].name);
                free(d->sysattr_cache[i].value);
        }
        free(d->sysattr_cache);

        for (i = 0; i < d->n_children; i++) {
                free(d->children[i].suffix);
                sd_device_unref(d->children[i].device);
        }
        free(d->children);

        free(d);
}

sd_device *sd_device_ref(sd_device *device) {
        if (!device)
                return NULL;

        device->n_ref++;
        return device;
}

sd_device *sd_device_unref(sd_device *device) {
        if (!device)
                return NULL;

        if (--device->n_ref == 0)
                device_free(device);

        return NULL;
}

/*
 * Which parts of the sysfs tree are ever a legitimate sd_device syspath.
 *
 * The design this file follows started from "must resolve under
 * <root>/devices/", which is true for every device reached via an alias
 * (/sys/class/<x>/<y>, /sys/bus/<x>/devices/<y>, since those are always
 * symlinks and realpath() has already chased them down to their canonical
 * <root>/devices/... target by this point) -- but checking it against a
 * real kernel's /sys turned up two real, common exceptions that rule
 * cannot see: a bus's driver directory (/sys/bus/<bus>/drivers/<drv>, which
 * genuinely has its own "uevent" file for triggering a rebind, and is what
 * sd_device_new_from_subsystem_sysname()'s "drivers" special case has to
 * resolve to) and a module directory (/sys/module/<name>), neither of
 * which lives under /devices at all. Both are real, separate sysfs
 * subtrees, not symlinks into one. The bare subsystem/class/module
 * directories themselves (no specific driver or device) are the third
 * exception, needed for sd_device_enumerator_get_subsystem_first()'s
 * pseudo-devices.
 */
static bool location_is_valid(const char *resolved, size_t rootlen) {
        const char *rel = resolved + rootlen; /* begins with '/' */
        const char *p, *slash;

        if (strncmp(rel, "/devices/", 9) == 0)
                return true;

        if (strncmp(rel, "/module/", 8) == 0 && rel[8] != '\0')
                return true;

        if (strncmp(rel, "/bus/", 5) == 0) {
                p = rel + 5;
                if (*p == '\0')
                        return false;

                slash = strchr(p, '/');
                if (!slash)
                        return true; /* bare "/bus/<x>" */

                if (strncmp(slash, "/drivers/", 9) == 0 && slash[9] != '\0' && !strchr(slash + 9, '/'))
                        return true; /* "/bus/<x>/drivers/<y>" */

                return false;
        }

        if (strncmp(rel, "/class/", 7) == 0) {
                p = rel + 7;
                if (*p == '\0' || strchr(p, '/'))
                        return false;
                return true; /* bare "/class/<x>" */
        }

        return false;
}

int device_new_from_syspath_internal(sd_device **ret, const char *syspath, bool relaxed) {
        char resolved[PATH_MAX], uevent_path[PATH_MAX], root_resolved[PATH_MAX];
        const char *root = device_sys_root();
        const char *canon_root;
        size_t rootlen;
        struct stat st;
        sd_device *d;

        if (!ret || !syspath || syspath[0] == '\0')
                return -EINVAL;

        if (!realpath(syspath, resolved))
                return errno == ENOENT ? -ENODEV : -errno;

        /* device_sys_root() can itself sit behind a symlink -- never true
         * for the real "/sys", but routine for a test fixture's tmpdir on
         * a host where /tmp (or some ancestor) is one. realpath(syspath,
         * ...) above already resolved through any such symlink, so
         * comparing it against the raw, un-resolved root mismatches for no
         * reason other than the two spellings of the same directory
         * differing -- confirmed by reproducing the exact failure with a
         * symlinked /tmp locally. Canonicalize root the same way; fall
         * back to the raw string only if it does not exist yet (only
         * possible mid-setup of a test fixture, and moot there since no
         * syspath under it could resolve to a real file either). */
        canon_root = realpath(root, root_resolved) ? root_resolved : root;
        rootlen = strlen(canon_root);

        if (strncmp(resolved, canon_root, rootlen) != 0 || resolved[rootlen] != '/')
                return -ENODEV;

        if (!location_is_valid(resolved, rootlen))
                return -ENODEV;

        if (!relaxed) {
                if ((size_t) snprintf(uevent_path, sizeof(uevent_path), "%s/uevent", resolved) >=
                    sizeof(uevent_path))
                        return -ENAMETOOLONG;

                if (stat(uevent_path, &st) < 0)
                        return errno == ENOENT ? -ENODEV : -errno;
        }

        d = device_new_bare();
        if (!d)
                return -ENOMEM;

        d->syspath = strdup(resolved);
        if (!d->syspath) {
                free(d);
                return -ENOMEM;
        }
        d->devpath = d->syspath + rootlen;
        d->no_uevent_file = relaxed;

        *ret = d;
        return 0;
}

int sd_device_new_from_syspath(sd_device **ret, const char *syspath) {
        return device_new_from_syspath_internal(ret, syspath, false);
}

int device_new_from_devpath_bare(sd_device **ret, const char *devpath) {
        sd_device *d;
        char *syspath;
        const char *root = device_sys_root();

        if (!ret || !devpath || devpath[0] != '/')
                return -EINVAL;

        if (asprintf(&syspath, "%s%s", root, devpath) < 0)
                return -ENOMEM;

        d = device_new_bare();
        if (!d) {
                free(syspath);
                return -ENOMEM;
        }

        d->syspath = syspath;
        d->devpath = d->syspath + strlen(root);
        d->no_uevent_file = true;

        *ret = d;
        return 0;
}

int sd_device_new_from_devnum(sd_device **ret, char type, dev_t devnum) {
        char path[PATH_MAX];
        sd_device *d = NULL;
        const char *want_block;
        int r;
        dev_t got;

        if (!ret || (type != 'b' && type != 'c'))
                return -EINVAL;

        if ((size_t) snprintf(
                            path,
                            sizeof(path),
                            "%s/dev/%s/%u:%u",
                            device_sys_root(),
                            type == 'b' ? "block" : "char",
                            major(devnum),
                            minor(devnum)) >= sizeof(path))
                return -ENAMETOOLONG;

        r = device_new_from_syspath_internal(&d, path, false);
        if (r < 0)
                return r;

        r = sd_device_get_devnum(d, &got);
        if (r < 0 || got != devnum) {
                sd_device_unref(d);
                return -ENXIO;
        }

        r = sd_device_get_subsystem(d, &want_block);
        if (type == 'b' ? (r < 0 || strcmp(want_block, "block") != 0) :
                          (r >= 0 && strcmp(want_block, "block") == 0)) {
                sd_device_unref(d);
                return -ENXIO;
        }

        *ret = d;
        return 0;
}

int sd_device_new_from_subsystem_sysname(sd_device **ret, const char *subsystem, const char *sysname) {
        char path[PATH_MAX];
        int r;

        if (!ret || !subsystem || !subsystem[0] || !sysname || !sysname[0] || strchr(sysname, '/'))
                return -EINVAL;

        if (strcmp(subsystem, "drivers") == 0) {
                const char *colon = strchr(sysname, ':');

                if (!colon || colon == sysname || colon[1] == '\0')
                        return -EINVAL;

                if ((size_t) snprintf(
                                    path,
                                    sizeof(path),
                                    "%s/bus/%.*s/drivers/%s",
                                    device_sys_root(),
                                    (int) (colon - sysname),
                                    sysname,
                                    colon + 1) >= sizeof(path))
                        return -ENAMETOOLONG;

                return device_new_from_syspath_internal(ret, path, false);
        }

        if ((size_t) snprintf(path, sizeof(path), "%s/bus/%s/devices/%s", device_sys_root(), subsystem, sysname) >=
            sizeof(path))
                return -ENAMETOOLONG;

        r = device_new_from_syspath_internal(ret, path, false);
        if (r != -ENODEV)
                return r;

        if ((size_t) snprintf(path, sizeof(path), "%s/class/%s/%s", device_sys_root(), subsystem, sysname) >=
            sizeof(path))
                return -ENAMETOOLONG;

        return device_new_from_syspath_internal(ret, path, false);
}

int sd_device_new_from_device_id(sd_device **ret, const char *id) {
        unsigned major_n, minor_n;
        int ifindex, consumed;

        if (!ret || !id || !id[0])
                return -EINVAL;

        switch (id[0]) {
        case 'b':
        case 'c':
                if (sscanf(id + 1, "%u:%u%n", &major_n, &minor_n, &consumed) != 2 || id[1 + consumed] != '\0')
                        return -EINVAL;
                return sd_device_new_from_devnum(ret, id[0], makedev(major_n, minor_n));
        case 'n':
                if (sscanf(id + 1, "%d%n", &ifindex, &consumed) != 1 || id[1 + consumed] != '\0')
                        return -EINVAL;
                return sd_device_new_from_ifindex(ret, ifindex);
        case '+': {
                const char *colon = strchr(id, ':');

                if (!colon || colon == id + 1 || colon[1] == '\0')
                        return -EINVAL;

                {
                        char subsystem[128];
                        size_t len = (size_t) (colon - (id + 1));

                        if (len >= sizeof(subsystem))
                                return -EINVAL;

                        memcpy(subsystem, id + 1, len);
                        subsystem[len] = '\0';

                        return sd_device_new_from_subsystem_sysname(ret, subsystem, colon + 1);
                }
        }
        default:
                return -EINVAL;
        }
}

int sd_device_new_from_stat_rdev(sd_device **ret, const struct stat *st) {
        char type;

        if (!ret || !st)
                return -EINVAL;

        if (S_ISBLK(st->st_mode))
                type = 'b';
        else if (S_ISCHR(st->st_mode))
                type = 'c';
        else
                return -ENOTTY;

        return sd_device_new_from_devnum(ret, type, st->st_rdev);
}

int sd_device_new_from_devname(sd_device **ret, const char *devname) {
        struct stat st;

        if (!ret || !devname || strncmp(devname, "/dev/", 5) != 0)
                return -EINVAL;

        if (stat(devname, &st) < 0)
                return -errno;

        return sd_device_new_from_stat_rdev(ret, &st);
}

int sd_device_new_from_path(sd_device **ret, const char *path) {
        if (!ret || !path)
                return -EINVAL;

        if (strncmp(path, "/dev/", 5) == 0)
                return sd_device_new_from_devname(ret, path);

        return sd_device_new_from_syspath(ret, path);
}

int sd_device_new_from_ifname(sd_device **ret, const char *ifname) {
        char path[PATH_MAX];
        sd_device *d = NULL;
        const char *interface;
        int r;

        if (!ret || !ifname || !ifname[0])
                return -EINVAL;

        if ((size_t) snprintf(path, sizeof(path), "%s/class/net/%s", device_sys_root(), ifname) >= sizeof(path))
                return -ENAMETOOLONG;

        r = device_new_from_syspath_internal(&d, path, false);
        if (r < 0)
                return r;

        /* Rename/alt-name race guard: if the uevent file names an
         * interface, it must be this one. Absent on some kernels, in which
         * case the sysfs-path match above is all there is to go on. */
        r = sd_device_get_property_value(d, "INTERFACE", &interface);
        if (r >= 0 && strcmp(interface, ifname) != 0) {
                sd_device_unref(d);
                return -ENODEV;
        }

        *ret = d;
        return 0;
}

int sd_device_new_from_ifindex(sd_device **ret, int ifindex) {
        char name[IF_NAMESIZE];
        sd_device *d = NULL;
        int r, got;

        if (!ret || ifindex <= 0)
                return -EINVAL;

        if (!if_indextoname((unsigned) ifindex, name))
                return -ENODEV;

        r = sd_device_new_from_ifname(&d, name);
        if (r < 0)
                return r;

        r = sd_device_get_ifindex(d, &got);
        if (r < 0 || got != ifindex) {
                sd_device_unref(d);
                return -ENODEV;
        }

        *ret = d;
        return 0;
}

int sd_device_new_child(sd_device **ret, sd_device *device, const char *suffix) {
        char path[PATH_MAX];

        if (!ret || !device || !device_path_component_is_safe(suffix))
                return -EINVAL;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", device->syspath, suffix) >= sizeof(path))
                return -ENAMETOOLONG;

        return device_new_from_syspath_internal(ret, path, false);
}

int sd_device_get_parent(sd_device *device, sd_device **ret) {
        char buf[PATH_MAX];
        const char *root;
        size_t rootlen, stop_len;

        if (!device)
                return -EINVAL;

        if (!device->parent_resolved) {
                root = device_sys_root();
                rootlen = strlen(root);
                /* "<root>/devices" itself is the top of the tree, never a device. */
                stop_len = rootlen + strlen("/devices");

                (void) snprintf(buf, sizeof(buf), "%s", device->syspath);

                device->parent_errno = -ENOENT;

                for (;;) {
                        char *slash = strrchr(buf, '/');
                        sd_device *cand = NULL;

                        if (!slash)
                                break;
                        *slash = '\0';

                        if (strlen(buf) <= stop_len)
                                break;

                        if (device_new_from_syspath_internal(&cand, buf, false) == 0) {
                                device->parent = cand;
                                device->parent_errno = 0;
                                break;
                        }
                }

                device->parent_resolved = true;
        }

        if (device->parent_errno < 0)
                return device->parent_errno;

        if (ret)
                *ret = device->parent;
        return 0;
}

int sd_device_get_parent_with_subsystem_devtype(
                sd_device *device, const char *subsystem, const char *devtype, sd_device **ret) {
        sd_device *cur;

        if (!device || !subsystem)
                return -EINVAL;

        cur = device;
        for (;;) {
                sd_device *parent;
                const char *s, *t;
                int r;

                r = sd_device_get_parent(cur, &parent);
                if (r < 0)
                        return r;

                cur = parent;

                if (sd_device_get_subsystem(cur, &s) < 0 || strcmp(s, subsystem) != 0)
                        continue;

                if (devtype) {
                        if (sd_device_get_devtype(cur, &t) < 0 || strcmp(t, devtype) != 0)
                                continue;
                }

                if (ret)
                        *ret = cur;
                return 0;
        }
}

int sd_device_get_syspath(sd_device *device, const char **ret) {
        if (!device)
                return -EINVAL;

        if (ret)
                *ret = device->syspath;
        return 0;
}

int sd_device_get_devpath(sd_device *device, const char **ret) {
        if (!device)
                return -EINVAL;

        if (ret)
                *ret = device->devpath;
        return 0;
}

/* MAJOR, MINOR, IFINDEX as the uevent prints them: digits only. Wider than
 * the result on purpose, so the range checks below mean something on a
 * 32-bit board too, where unsigned long and unsigned are the same width. */
static bool parse_full_ull(const char *s, unsigned long long *ret) {
        unsigned long long v;
        char *end;

        if (!s || s[0] < '0' || s[0] > '9')
                return false;

        errno = 0;
        v = strtoull(s, &end, 10);
        if (errno != 0 || *end != '\0')
                return false;

        *ret = v;
        return true;
}

int device_format_id(sd_device *d, char *buf, size_t size) {
        unsigned long long maj, min, ifindex;
        const char *subsystem = NULL, *sysname;
        int k;

        if (!d || !buf || size == 0)
                return -EINVAL;

        if (parse_full_ull(device_get_property_raw(d, "MAJOR"), &maj) &&
            parse_full_ull(device_get_property_raw(d, "MINOR"), &min) && maj <= UINT_MAX && min <= UINT_MAX) {
                /* Classify by subsystem when it resolves; a devnode's own
                 * type (block vs. char) is what matters, and "not resolvably
                 * block" defaults to the more general 'c' form -- the same
                 * lenient default sd_device_new_from_devnum() uses for a
                 * requested type of 'c'. */
                (void) sd_device_get_subsystem(d, &subsystem);
                k = snprintf(buf,
                             size,
                             "%c%u:%u",
                             subsystem && strcmp(subsystem, "block") == 0 ? 'b' : 'c',
                             (unsigned) maj,
                             (unsigned) min);
        } else if (parse_full_ull(device_get_property_raw(d, "IFINDEX"), &ifindex) && ifindex > 0 &&
                   ifindex <= INT_MAX)
                k = snprintf(buf, size, "n%d", (int) ifindex);
        else if (sd_device_get_subsystem(d, &subsystem) >= 0 && sd_device_get_sysname(d, &sysname) >= 0)
                k = snprintf(buf, size, "+%s:%s", subsystem, sysname);
        else
                return -ENOENT;

        if (k < 0 || (size_t) k >= size)
                return -ENAMETOOLONG;

        return 0;
}

int sd_device_get_device_id(sd_device *device, const char **ret) {
        char buf[256];
        int r;

        if (!device)
                return -EINVAL;

        if (!device->device_id_resolved) {
                /* Built first, its result deliberately ignored: a device whose
                 * properties cannot be read still has a subsystem and a
                 * sysname, and the last form of the id is built from those. */
                (void) device_ensure_properties(device);

                r = device_format_id(device, buf, sizeof(buf));
                if (r < 0)
                        device->device_id_errno = r;
                else {
                        device->device_id = strdup(buf);
                        device->device_id_errno = device->device_id ? 0 : -ENOMEM;
                }

                device->device_id_resolved = true;
        }

        if (device->device_id_errno < 0)
                return device->device_id_errno;

        if (ret)
                *ret = device->device_id;
        return 0;
}

int sd_device_get_is_initialized(sd_device *device) {
        if (!device)
                return -EINVAL;

        /*
         * Upstream answers this from the database: no /run/udev/data entry
         * means udevd has not processed the device yet. Pico has a database
         * now, but devd writes it for input devices only, so that rule would
         * call every disk, tty and network interface on the machine
         * uninitialized -- and a caller polling this in a loop would wait on
         * them forever. There is no initialization phase to be mid-way
         * through either: devtmpfs creates the node synchronously with the
         * add event. 1 is the true steady state for every device.
         */
        return 1;
}

int sd_device_get_usec_initialized(sd_device *device, uint64_t *ret) {
        if (!device || !ret)
                return -EINVAL;

        /* The database's I: record (device-db.c), which devd writes for the
         * devices it classifies. Every other device has none, and -ENODATA
         * is the real library's own code for "initialized but no
         * timestamp", so callers already handle it -- -EBUSY would claim
         * the device is not initialized at all. */
        (void) device_ensure_properties(device);

        if (device->usec_initialized == 0)
                return -ENODATA;

        *ret = device->usec_initialized;
        return 0;
}

int sd_device_get_usec_since_initialized(sd_device *device, uint64_t *ret) {
        struct timespec ts;
        uint64_t then, now;
        int r;

        if (!device || !ret)
                return -EINVAL;

        r = sd_device_get_usec_initialized(device, &then);
        if (r < 0)
                return r;

        /* CLOCK_MONOTONIC, because that is the clock devd writes I: in
         * (now_monotonic()), as upstream udevd does. */
        if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
                return -errno;

        now = (uint64_t) ts.tv_sec * UINT64_C(1000000) + (uint64_t) ts.tv_nsec / UINT64_C(1000);
        if (now < then)
                return -EIO;

        *ret = now - then;
        return 0;
}
