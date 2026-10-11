/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The bus-level identity behind /dev/disk/by-id/, and the sanitizer in front of
 * it.
 *
 * Upstream gets this from two udev builtins, `blkid` and `usb_id`, neither of
 * which exists on a pico image:
 *
 *  - blkid: devd needs only the ext superblock, which is read by
 *    ../ext-super.h (shared with PID 1's root check).
 *  - usb_id is sysfs reads with a sanitizer on the front: idVendor/idProduct
 *    and the manufacturer/product/serial descriptor strings, run through
 *    replace_whitespace()/replace_chars(). MMC needs no builtin; upstream's
 *    rule reads ATTRS{name}/ATTRS{serial} straight from sysfs. Both buses are
 *    therefore a parent-directory walk and two file reads.
 *
 * Divergence: usb_id has a fallback ladder for devices with no descriptor
 * strings (hex vendor:product, interface class walks). devd has none; such a
 * device gets no by-id link.
 *
 * Every entry point takes its roots as parameters so test-devd-probe.c can
 * build a fixture sysfs tree.
 */

#pragma once

#include <stddef.h>

/*
 * "usb-Generic_USB_Reader_000000264001-part1" and friends.
 *
 * The stem is what a bus device identifies itself as; the full id adds a
 * "-partN" suffix. The stem buffer is strictly smaller so the concatenation
 * provably fits.
 */
#define DEVD_ID_STEM_MAX 128
#define DEVD_ID_MAX 160

/*
 * udev's replace_whitespace() followed by its replace_chars(), which is what
 * turns a descriptor string like "  Generic  USB Reader " into
 * "Generic_USB_Reader": leading and trailing whitespace dropped, internal runs
 * collapsed to one underscore, and anything outside [0-9A-Za-z#+-.:=@_]
 * replaced by an underscore.
 *
 * Writes at most `size` bytes including the NUL and returns the length written,
 * or 0 when there was nothing left after sanitizing -- which callers treat as
 * "no identity", not as an empty component to concatenate.
 */
size_t devd_sanitize(const char *in, char *out, size_t size);

/*
 * The by-id stem for the disk whose sysfs directory is `sysfs_disk`, e.g.
 * "usb-Generic_USB_Reader_000000264001" or "mmc-SD32G_0x1b8c4e21". The walk
 * goes up the parent chain from the block device looking for whichever bus
 * device carries the identifying attributes, exactly as ATTRS{} does.
 *
 * `sys_root` bounds that walk so it can neither escape sysfs nor, in a test,
 * escape the fixture. Returns 1 with *ret filled in, 0 when nothing on the
 * chain identifies itself (the named divergence above), or -errno.
 */
int devd_probe_bus_id(const char *sys_root, const char *sysfs_disk, char *ret, size_t size);
