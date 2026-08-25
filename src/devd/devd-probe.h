/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * What devd knows about a partition beyond its GPT entry: the filesystem's own
 * UUID and label, and the bus-level identity behind /dev/disk/by-id/.
 *
 * Upstream gets all of this from two udev builtins, `blkid` and `usb_id`, and
 * neither exists on a pico image. Reading what each actually does is what makes
 * replacing them cheap rather than a port:
 *
 *  - blkid is libblkid's whole per-filesystem superblock zoo, and devd needs
 *    exactly one entry from it. Every filesystem this project ships on a pico
 *    image is ext4, and the three fields wanted sit at fixed offsets that have
 *    not moved since ext2: superblock at byte 1024 of the device, magic 0xEF53
 *    at +56, uuid[16] at +104, volume_name[16] at +120. Re-verified for this
 *    milestone against a real `mke2fs -t ext4 -U ... -L PICOTEST` image rather
 *    than taken from the plan's citation, because the offsets are load-bearing:
 *    dumpe2fs and the raw bytes at those three offsets agree exactly.
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
#include <stdint.h>

/* "12345678-90ab-cdef-1234-567890abcdef" plus its NUL. */
#define DEVD_FS_UUID_MAX 37

/* ext's s_volume_name is 16 bytes and need not be terminated. */
#define DEVD_FS_LABEL_MAX 17

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

/* The three verified offsets, and where the superblock itself lives. */
#define DEVD_EXT_SUPER_OFFSET 1024
#define DEVD_EXT_SUPER_SIZE 1024
#define DEVD_EXT_MAGIC_OFF 56
#define DEVD_EXT_UUID_OFF 104
#define DEVD_EXT_LABEL_OFF 120
#define DEVD_EXT_MAGIC 0xef53u

typedef struct DevdFsInfo {
        char uuid[DEVD_FS_UUID_MAX];   /* "" when the superblock carries none */
        char label[DEVD_FS_LABEL_MAX]; /* "" when the filesystem is unlabelled */
} DevdFsInfo;

/*
 * Decode an ext2/3/4 superblock that has already been read. Returns 1 when the
 * magic is there and *ret is filled in, 0 when it is not an ext filesystem, or
 * -EINVAL for a buffer too short to answer either way.
 *
 * Split from the read for the same reason gpt-scan.c pulls fields out of a
 * size-checked buffer by offset: the decode is the part worth testing against
 * bytes, and it is the part that must never read past what was really read.
 */
int devd_probe_ext_super(const uint8_t *sb, size_t n, DevdFsInfo *ret);

/* The same, reading the superblock off `device` first. Returns 1/0/-errno. */
int devd_probe_ext(const char *device, DevdFsInfo *ret);

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
