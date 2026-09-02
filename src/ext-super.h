/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The ext2/3/4 superblock, read at fixed offsets out of one buffer.
 *
 * Upstream gets all of this from libblkid's per-filesystem superblock zoo, and
 * neither libblkid nor anything else that could answer these questions exists on
 * a pico image. Every filesystem this project ships on such an image is ext4,
 * and everything wanted about one sits at offsets that have not moved since
 * ext2 -- so the whole "probe" is a 1024-byte pread() and a handful of
 * little-endian loads, in gpt-scan.c's style and for gpt-scan.c's reason: no
 * packed struct overlay, no assumption about the host's byte order, and no read
 * that can reach past the bytes that were really read.
 *
 * Two consumers, which is why this is here rather than under src/devd/:
 *
 *  - devd names a removable partition from its uuid and label, for
 *    /dev/disk/by-uuid and /dev/disk/by-label and its /media mount points.
 *  - PID 1's root check (root-check.h) reads the dirty-state fields off the
 *    root partition before deciding whether a filesystem checker is warranted
 *    at all -- the cheap gate that has to run in front of an expensive one.
 *
 * The offsets and bit values below are interface, not implementation: they are
 * what an on-disk ext4 filesystem IS, fixed by the format rather than by any
 * particular kernel. They were verified for this milestone against a real
 * `mke2fs -t ext4` image -- each field read raw and cross-checked against
 * dumpe2fs, and the two state-carrying ones (s_state, the RECOVER feature bit)
 * additionally toggled with debugfs and re-read, so the bit values are a
 * measured property of the format and not a citation this file agrees with
 * because it was written from the same citation. Linux's own
 * fs/ext4/ext4.h struct ext4_super_block is the reference they match.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* "12345678-90ab-cdef-1234-567890abcdef" plus its NUL. */
#define EXT_FS_UUID_MAX 37

/* s_volume_name is 16 bytes and need not be terminated. */
#define EXT_FS_LABEL_MAX 17

/* Where the superblock lives, and how much of it is worth reading. */
#define EXT_SUPER_OFFSET 1024
#define EXT_SUPER_SIZE 1024

/* The verified field offsets, hex as ext4.h spells them. */
#define EXT_SUPER_MAGIC_OFF 56            /* 0x38 s_magic */
#define EXT_SUPER_STATE_OFF 58            /* 0x3a s_state */
#define EXT_SUPER_FEATURE_COMPAT_OFF 92   /* 0x5c s_feature_compat */
#define EXT_SUPER_FEATURE_INCOMPAT_OFF 96 /* 0x60 s_feature_incompat */
#define EXT_SUPER_UUID_OFF 104            /* 0x68 s_uuid[16] */
#define EXT_SUPER_LABEL_OFF 120           /* 0x78 s_volume_name[16] */
#define EXT_SUPER_LAST_ORPHAN_OFF 232     /* 0xe8 s_last_orphan */

#define EXT_SUPER_MAGIC 0xef53u

/*
 * s_state. VALID_FS is set when the filesystem was cleanly unmounted and
 * cleared while it is mounted; ERROR_FS is the kernel's own record that it hit
 * an inconsistency; ORPHAN_FS says inodes were being deleted when it stopped.
 */
#define EXT_STATE_VALID_FS 0x0001u
#define EXT_STATE_ERROR_FS 0x0002u
#define EXT_STATE_ORPHAN_FS 0x0004u

/* s_feature_compat: whether there is a journal to replay at all. */
#define EXT_FEATURE_COMPAT_HAS_JOURNAL 0x00000004u

/* s_feature_incompat: the journal holds transactions nobody has replayed yet. */
#define EXT_FEATURE_INCOMPAT_RECOVER 0x00000004u

/*
 * Everything either consumer wants out of a superblock, decoded.
 *
 * The two strings are what devd names a device with; the four numbers are what
 * the root check decides on. One struct rather than two because they come out of
 * one 1024-byte read, and splitting them would mean reading the superblock
 * twice to answer two questions about the same filesystem.
 */
typedef struct PicoExtInfo {
        char uuid[EXT_FS_UUID_MAX];   /* "" when the superblock carries none */
        char label[EXT_FS_LABEL_MAX]; /* "" when the filesystem is unlabelled */

        uint16_t state;
        uint32_t feature_compat;
        uint32_t feature_incompat;
        uint32_t last_orphan; /* inode number of the head of the orphan list, 0 for none */
} PicoExtInfo;

/*
 * Decode a superblock that has already been read. Returns 1 when the magic is
 * there and *ret is filled in, 0 when this is not an ext filesystem, or -EINVAL
 * for a buffer too short to answer either way.
 *
 * Split from the read for the same reason gpt-scan.c pulls fields out of a
 * size-checked buffer by offset: the decode is the part worth testing against
 * bytes, and the part that must never read past what was really read.
 */
int ext_super_decode(const uint8_t *sb, size_t n, PicoExtInfo *ret);

/*
 * The same, reading the superblock off `device` first. Returns 1/0/-errno --
 * notably 0, not an error, for a device shorter than a superblock, which is not
 * a filesystem anyone can name and not an I/O failure either.
 */
int ext_super_read(const char *device, PicoExtInfo *ret);
