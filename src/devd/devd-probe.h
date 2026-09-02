/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The bus-level identity behind /dev/disk/by-id/, and the sanitizer in front of
 * it.
 *
 * Upstream gets this from two udev builtins, `blkid` and `usb_id`, and neither
 * exists on a pico image. Reading what each actually does is what makes
 * replacing them cheap rather than a port:
 *
 *  - blkid is libblkid's whole per-filesystem superblock zoo, and devd needs
 *    exactly one entry from it -- the ext one. That half lives in
 *    ../ext-super.h, outside devd, because PID 1's root check reads the same
 *    superblock for its own reasons; devd is one of its two consumers rather
 *    than its owner.
 *  - usb_id looks like a builtin that would have to be ported, and reading it
 *    shows it is sysfs reads with a sanitizer on the front: idVendor/idProduct
 *    and the manufacturer/product/serial descriptor strings, run through
 *    replace_whitespace()/replace_chars(). MMC never needed a builtin at all --
 *    upstream's own rule reads ATTRS{name}/ATTRS{serial} straight out of sysfs.
 *    So both buses are a parent-directory walk and two file reads.
 *
 * The named v1 divergence, recorded rather than silent: usb_id has a fallback
 * ladder for devices with no descriptor strings (hex vendor:product, interface
 * class walks). devd has none -- such a device simply gets no by-id link.
 *
 * Every entry point here takes its roots as parameters. That is not test
 * scaffolding bolted on: it is what lets test-devd-probe.c build a sysfs tree
 * for a USB card reader that is not plugged into the machine running the test.
 */

#pragma once

#include <stddef.h>

/*
 * "usb-Generic_USB_Reader_000000264001-part1" and friends.
 *
 * Two sizes, not one. The stem is what a bus device identifies itself as; the
 * full id is that plus a "-partN" suffix. Keeping the stem's buffer strictly
 * smaller is what makes the concatenation provably fit -- otherwise the widest
 * stem plus the widest suffix is longer than the buffer it goes into, and the
 * compiler is right to say so.
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
