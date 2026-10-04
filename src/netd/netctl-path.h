/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * ID_PATH for `networkctl status <iface>` -- a hand-written, scope-limited
 * port of udev's builtin_path_id() (pci/usb/platform only). Split out of
 * netctl.c into its own file/header purely for testability: it is pure
 * string/directory-walk logic with no sysfs *write* dependency and no
 * netlink dependency either, so test-netctl-path.c can drive it against a
 * hand-built fixture directory tree instead of the real /sys. See
 * netctl-path.c's own header for the algorithm itself.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

/*
 * The real entry point `networkctl status` uses: resolves
 * /sys/class/net/<ifname>/device and walks up from there. False (no row)
 * when the interface has no such device symlink, or when
 * path_id_from_devpath() below found no supported ancestor.
 */
bool iface_path_id(const char *ifname, char *out, size_t bufsize);

/*
 * The testable half: `devpath_real` is an already-resolved absolute
 * directory -- normally realpath()'d from /sys/class/net/<if>/device, but
 * test-netctl-path.c instead points this at a fixture tree it built itself,
 * since the algorithm from here on is pure path-string/readlink() work that
 * does not care whether the tree lives under /sys. False when no
 * pci/usb/platform ancestor was found anywhere in the walk (an unsupported
 * topology, e.g. a bare virtio-net device) -- never a guess.
 */
bool path_id_from_devpath(const char *devpath_real, char *out, size_t bufsize);
