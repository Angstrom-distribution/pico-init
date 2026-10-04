/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * ID_PATH, scope-limited to the three subsystems a pico target actually
 * sees: pci, usb, platform -- a hand-written port of udev's
 * builtin_path_id() (udev-builtin-path_id.c) restricted to those branches,
 * same reasoning udev-builtin-path_id.c's own comment gives for
 * "supported_parent" refusal: a topology this function does not recognize
 * (a bare virtio-net NIC under qemu, say) gets no Path row at all, never a
 * guess -- matching real networkctl against the same hardware, which has
 * the identical refusal for virtio (it only ever sets a transport, never a
 * parent).
 *
 * Walks from the network device's own physical node (realpath() of its
 * "device" symlink, the same starting point netctl.c's own usb_device_dir()
 * uses) up toward "/sys" (or a fixture tree's own root, for
 * path_id_from_devpath() called directly -- see netctl-path.h), prepending
 * a segment for every pci/usb/platform ancestor it crosses and collapsing a
 * run of consecutive same-subsystem ancestors into one segment (nested USB
 * hub levels, a PCIe switch) -- see the worked examples in
 * test-netctl-path.c. "Prepending" while walking leaf-to-root is what
 * produces udev's own outermost-first ordering
 * ("pci-0000:0c:00.0-usb-0:2:1.0") without a second, root-to-leaf pass.
 *
 * Scope trim versus the full upstream algorithm: get_usb_revision()'s
 * "usbv<rev>-" prefix (fires only when the immediate parent is itself a hub,
 * per its own bDeviceProtocol check) is not implemented -- a pico target's
 * worked examples are all the no-revision case, and adding it needs a sysfs
 * read this function does not otherwise need. Noted here rather than
 * silently dropped.
 */

#include "netctl-path.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * The "subsystem" symlink's basename at one /sys/devices/... directory --
 * every component of that physical path is itself a device node with its
 * own such symlink, which is what makes a plain textual walk up the path
 * equivalent to sd_device_get_parent()'s own walk. NULL (not an empty
 * string) when the symlink is missing or unreadable, which is routine for a
 * directory with no "subsystem" of its own (e.g. a non-device component).
 */
static const char *path_id_classify(const char *devdir, char *buf, size_t bufsize) {
        char path[PATH_MAX + sizeof "/subsystem"], target[PATH_MAX];
        ssize_t len;
        const char *base;

        snprintf(path, sizeof path, "%s/subsystem", devdir);
        len = readlink(path, target, sizeof target - 1);
        if (len < 0)
                return NULL;
        target[len] = '\0';

        base = strrchr(target, '/');
        snprintf(buf, bufsize, "%s", base ? base + 1 : target);
        return buf;
}

/*
 * strlen()+memcpy() rather than snprintf("%s", ...): subsys/sysname/result
 * point into caller-controlled buffers (cur is PATH_MAX, result accumulates
 * across loop iterations) that GCC cannot prove stay short, so
 * -Wformat-truncation flags every %s join below at -O2. Clamped, not
 * checked: a path_id segment this function cannot fit just gets silently
 * truncated, which costs a vaguer Path row and nothing else -- same
 * reasoning as devd-match.c's iface_subsystem() and devd-run.c's
 * child_record().
 */
static void path_id_append(char *buf, size_t bufsize, size_t *len, const char *s) {
        size_t n = strlen(s);
        size_t room = bufsize - 1 - *len;

        if (n > room)
                n = room;
        memcpy(buf + *len, s, n);
        *len += n;
        buf[*len] = '\0';
}

bool path_id_from_devpath(const char *devpath_real, char *out, size_t bufsize) {
        char cur[PATH_MAX];
        char result[256] = "";
        char last_subsys[16] = "";
        bool found_any = false;

        snprintf(cur, sizeof cur, "%s", devpath_real);

        for (;;) {
                char subsysbuf[32];
                const char *subsys = path_id_classify(cur, subsysbuf, sizeof subsysbuf);
                char *slash;

                if (subsys &&
                    (strcmp(subsys, "pci") == 0 || strcmp(subsys, "usb") == 0 ||
                     strcmp(subsys, "platform") == 0)) {
                        if (strcmp(subsys, last_subsys) != 0) {
                                const char *sysname = strrchr(cur, '/');
                                char seg[160], merged[sizeof result];
                                size_t n;

                                sysname = sysname ? sysname + 1 : cur;

                                n = 0;
                                seg[0] = '\0';
                                if (strcmp(subsys, "usb") == 0) {
                                        /* Host number replaced with the
                                         * literal "0": topology, not host
                                         * numbering, is what is stable
                                         * (builtin_path_id()'s own
                                         * handle_usb() comment). */
                                        const char *dash = strchr(sysname, '-');

                                        path_id_append(seg, sizeof seg, &n, "usb-0:");
                                        path_id_append(seg, sizeof seg, &n, dash ? dash + 1 : sysname);
                                } else {
                                        path_id_append(seg, sizeof seg, &n, subsys);
                                        path_id_append(seg, sizeof seg, &n, "-");
                                        path_id_append(seg, sizeof seg, &n, sysname);
                                }

                                n = 0;
                                merged[0] = '\0';
                                path_id_append(merged, sizeof merged, &n, seg);
                                if (found_any)
                                        path_id_append(merged, sizeof merged, &n, "-");
                                path_id_append(merged, sizeof merged, &n, result);

                                n = 0;
                                result[0] = '\0';
                                path_id_append(result, sizeof result, &n, merged);

                                found_any = true;
                                snprintf(last_subsys, sizeof last_subsys, "%s", subsys);
                        }
                        /* else: consecutive same-subsystem ancestor, collapse. */
                } else
                        last_subsys[0] = '\0'; /* an unrelated ancestor breaks any run */

                slash = strrchr(cur, '/');
                if (!slash || slash == cur)
                        break;
                *slash = '\0';
        }

        if (!found_any)
                return false;

        snprintf(out, bufsize, "%s", result);
        return true;
}

bool iface_path_id(const char *ifname, char *out, size_t bufsize) {
        char devpath[PATH_MAX];
        char real[PATH_MAX];

        snprintf(devpath, sizeof devpath, "/sys/class/net/%s/device", ifname);
        if (!realpath(devpath, real))
                return false;

        return path_id_from_devpath(real, out, bufsize);
}
