/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Filesystem identity: the UUID and LABEL a block device carries, read the way
 * blkid reads them, so that an fstab UUID=/LABEL= line written against blkid's
 * output resolves here to the same device.
 *
 * Upstream gets these from libblkid, whose value is its probe-chain engine:
 * a device of unknown content run past every known signature, with priority
 * and conflict rules for the ones that overlap. None of that is needed here.
 * The caller already knows what it is looking for -- fstab's own type field
 * names the format, and a line that says "auto" is answered by trying each
 * reader in a fixed order, first valid match wins -- so each format is one
 * narrow reader: find the magic, apply the same sanity checks blkid applies
 * before trusting it, and decode the two strings.
 *
 * What "the same as blkid" means, format by format, is in each reader's own
 * file. Two things hold for all of them, because they are what makes an
 * fstab value written from `blkid` output match:
 *
 *  - A UUID is formatted exactly as blkid formats it: the 8-4-4-4-12 form for
 *    the formats that carry a real UUID, and each format's own serial-number
 *    spelling ("1A2B-3C4D", a 16-digit hex number) for those that do not. An
 *    all-zero identifier is no identifier.
 *  - A label stops at its first NUL and loses trailing whitespace; UTF-16
 *    labels (exFAT, NTFS) are converted to UTF-8 first. Comparison is then an
 *    exact byte comparison, as upstream's /dev/disk/by-* lookup is.
 *
 * Every reader is handed an fd and reads what it needs at the offsets its
 * format fixes. Every length and offset that comes off the disk is
 * range-checked before it is used for a read, and every read is bounded: this
 * runs in PID 1, before anything else, on media someone may have handed the
 * machine. A device that ends early is "not this format", never an error.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum PicoFsKind {
        PICO_FS_NONE = 0, /* nothing recognised; as a hint: try every reader */
        PICO_FS_EXT,
        PICO_FS_SWAP,
        PICO_FS_VFAT,
        PICO_FS_EXFAT,
        PICO_FS_XFS,
        _PICO_FS_KIND_MAX, /* as a hint: a type none of the readers handles */
} PicoFsKind;

/* "12345678-90ab-cdef-1234-567890abcdef" plus its NUL. */
#define PICO_FS_UUID_MAX 37

/* The longest label any reader produces with room to spare: btrfs keeps 256
 * raw bytes, and a UTF-16 label grows by half again in UTF-8. */
#define PICO_FS_LABEL_MAX 512

typedef struct PicoFsId {
        PicoFsKind kind;
        char uuid[PICO_FS_UUID_MAX];   /* "" when the format or the device carries none */
        char label[PICO_FS_LABEL_MAX]; /* "" when unlabelled */
} PicoFsId;

/*
 * The kernel filesystem name for a kind -- what "auto" mounts it as and whose
 * fsck.<name> checks it. "ext4" for every ext revision: the ext4 driver and
 * e2fsck both serve all three. NULL for PICO_FS_NONE and out-of-range kinds.
 */
const char *pico_fs_kind_to_string(PicoFsKind k);

/*
 * The reader for an fstab type field. "auto" and NULL give PICO_FS_NONE (try
 * every reader); a type with no reader here gives _PICO_FS_KIND_MAX, which
 * pico_fs_probe() refuses rather than guessing at.
 */
PicoFsKind pico_fs_kind_from_type(const char *fstype);

/*
 * Identify `device`. With `hint` a real kind, only that reader runs; with
 * PICO_FS_NONE each reader runs in a fixed order and the first match wins.
 * Returns 1 with *ret filled in, 0 when nothing was recognised (*ret then says
 * PICO_FS_NONE), -EOPNOTSUPP for a hint no reader handles, or -errno when the
 * device could not be opened or read.
 */
int pico_fs_probe(const char *device, PicoFsKind hint, PicoFsId *ret);

/* The same, on an open fd. */
int pico_fs_probe_fd(int fd, PicoFsKind hint, PicoFsId *ret);

/*
 * The readers. Each returns 1 with *ret filled in (kind included) when the
 * device carries that format, 0 when it does not -- including a device too
 * short to hold it -- and -errno on a real read error. *ret is only written
 * on 1.
 */
int pico_fs_probe_ext(int fd, PicoFsId *ret);
int pico_fs_probe_swap(int fd, PicoFsId *ret);
int pico_fs_probe_vfat(int fd, PicoFsId *ret);
int pico_fs_probe_exfat(int fd, PicoFsId *ret);
int pico_fs_probe_xfs(int fd, PicoFsId *ret);

/* --- shared by the readers, and tested on their own --- */

/*
 * pread() exactly `n` bytes at `off`. 0, -ENODATA when the device ends first,
 * -EOVERFLOW for an offset the platform's off_t cannot express, or -errno.
 */
int pico_fs_read(int fd, uint64_t off, void *buf, size_t n);

static inline uint16_t pico_le16(const uint8_t *p) {
        return (uint16_t) ((uint16_t) p[0] | ((uint16_t) p[1] << 8));
}

static inline uint32_t pico_le32(const uint8_t *p) {
        return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static inline uint64_t pico_le64(const uint8_t *p) {
        return (uint64_t) pico_le32(p) | ((uint64_t) pico_le32(p + 4) << 32);
}

static inline uint16_t pico_be16(const uint8_t *p) {
        return (uint16_t) (((uint16_t) p[0] << 8) | (uint16_t) p[1]);
}

static inline uint32_t pico_be32(const uint8_t *p) {
        return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

static inline uint64_t pico_be64(const uint8_t *p) {
        return ((uint64_t) pico_be32(p) << 32) | (uint64_t) pico_be32(p + 4);
}

/* True for 0 as well as for any zero-filled field: "no identifier". */
bool pico_fs_bytes_zero(const uint8_t *p, size_t n);

/* A 16-byte UUID in byte order, lower-case 8-4-4-4-12; "" when all zero. */
void pico_fs_uuid_format(const uint8_t uuid[16], char ret[static PICO_FS_UUID_MAX]);

/*
 * A 32-bit FAT/exFAT volume serial, stored little-endian, as blkid prints it:
 * "1A2B-3C4D", upper case, high half first; "" when all zero.
 */
void pico_fs_serial32_format(const uint8_t serial[4], char ret[static PICO_FS_UUID_MAX]);

/*
 * An 8-bit label field of up to `n` bytes: stops at the first NUL, drops
 * trailing whitespace, and is always terminated. Bytes are copied as they are
 * -- a FAT label in a DOS code page stays in it, as blkid leaves it.
 */
void pico_fs_label_set(char *ret, size_t size, const uint8_t *raw, size_t n);

/*
 * A UTF-16LE label of `n` bytes, converted to UTF-8 the way util-linux's
 * ul_encode_to_utf8() converts it: stops at a NUL code unit, joins surrogate
 * pairs, passes an unpaired surrogate through as its own 3-byte sequence, and
 * stops rather than truncates a character when `ret` is full. Then trailing
 * whitespace is dropped, as for an 8-bit label.
 */
void pico_fs_label_set_utf16le(char *ret, size_t size, const uint8_t *raw, size_t n);

/*
 * CRC-32C (Castagnoli), bitwise, with no pre- or post-inversion so that a
 * caller can feed a buffer in pieces: pass ~0 in, invert what comes out. The
 * checksum XFS v5 and btrfs protect their superblocks with.
 */
uint32_t pico_crc32c(uint32_t crc, const void *buf, size_t n);
