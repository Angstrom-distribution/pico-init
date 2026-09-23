/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The reader table, the ext reader, and the helpers every reader shares.
 * fsid.h has the reasoning; each other format has a file of its own.
 */

#include "fsid.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "ext-super.h"

static const char * const kind_table[_PICO_FS_KIND_MAX] = {
        [PICO_FS_EXT] = "ext4",    [PICO_FS_SWAP] = "swap", [PICO_FS_VFAT] = "vfat",
        [PICO_FS_EXFAT] = "exfat", [PICO_FS_XFS] = "xfs",   [PICO_FS_BTRFS] = "btrfs",
};

const char *pico_fs_kind_to_string(PicoFsKind k) {
        if (k <= PICO_FS_NONE || k >= _PICO_FS_KIND_MAX)
                return NULL;
        return kind_table[k];
}

/* fstab type names, including the aliases the kernel and mount(8) accept for
 * the same on-disk format. */
static const struct {
        const char *type;
        PicoFsKind kind;
} type_table[] = {
        {    "ext2",   PICO_FS_EXT },
        {    "ext3",   PICO_FS_EXT },
        {    "ext4",   PICO_FS_EXT },
        { "ext4dev",   PICO_FS_EXT },
        {    "swap",  PICO_FS_SWAP },
        {    "vfat",  PICO_FS_VFAT },
        {   "msdos",  PICO_FS_VFAT },
        {   "exfat", PICO_FS_EXFAT },
        {     "xfs",   PICO_FS_XFS },
        {   "btrfs", PICO_FS_BTRFS },
};

PicoFsKind pico_fs_kind_from_type(const char *fstype) {
        size_t i;

        if (!fstype || strcmp(fstype, "auto") == 0)
                return PICO_FS_NONE;

        for (i = 0; i < sizeof(type_table) / sizeof(type_table[0]); i++)
                if (strcmp(fstype, type_table[i].type) == 0)
                        return type_table[i].kind;

        return _PICO_FS_KIND_MAX;
}

/*
 * The order "auto" tries the readers in. The formats with a strong,
 * checksummed or deep-offset signature go first; vfat, whose weakest accepted
 * signature is a single jump byte plus a plausible boot parameter block, goes
 * after exFAT and NTFS, which carry that same jump byte.
 */
static const struct {
        PicoFsKind kind;
        int (*probe)(int fd, PicoFsId *ret);
} probe_table[] = {
        {   PICO_FS_EXT,   pico_fs_probe_ext },
        {   PICO_FS_XFS,   pico_fs_probe_xfs },
        { PICO_FS_BTRFS, pico_fs_probe_btrfs },
        { PICO_FS_EXFAT, pico_fs_probe_exfat },
        {  PICO_FS_VFAT,  pico_fs_probe_vfat },
        {  PICO_FS_SWAP,  pico_fs_probe_swap },
};

int pico_fs_probe_fd(int fd, PicoFsKind hint, PicoFsId *ret) {
        size_t i;
        int r;

        if (fd < 0 || !ret)
                return -EINVAL;
        if (hint < PICO_FS_NONE || hint >= _PICO_FS_KIND_MAX)
                return -EOPNOTSUPP;

        memset(ret, 0, sizeof(*ret));

        for (i = 0; i < sizeof(probe_table) / sizeof(probe_table[0]); i++) {
                if (hint != PICO_FS_NONE && probe_table[i].kind != hint)
                        continue;

                r = probe_table[i].probe(fd, ret);
                if (r != 0)
                        return r;
        }

        memset(ret, 0, sizeof(*ret));
        return 0;
}

int pico_fs_probe(const char *device, PicoFsKind hint, PicoFsId *ret) {
        int fd, r;

        if (!device || !ret)
                return -EINVAL;
        if (hint < PICO_FS_NONE || hint >= _PICO_FS_KIND_MAX)
                return -EOPNOTSUPP;

        fd = open(device, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (fd < 0)
                return -errno;

        r = pico_fs_probe_fd(fd, hint, ret);
        (void) close(fd);
        return r;
}

/* ext-super.c is the decoder; this only puts its answer in the common shape
 * and trims the label the way blkid does, which ext-super.c does not. */
int pico_fs_probe_ext(int fd, PicoFsId *ret) {
        uint8_t sb[EXT_SUPER_SIZE];
        PicoExtInfo fs;
        int r;

        r = pico_fs_read(fd, EXT_SUPER_OFFSET, sb, sizeof(sb));
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        r = ext_super_decode(sb, sizeof(sb), &fs);
        if (r <= 0)
                return r == -EINVAL ? 0 : r;

        memset(ret, 0, sizeof(*ret));
        ret->kind = PICO_FS_EXT;
        memcpy(ret->uuid, fs.uuid, sizeof(ret->uuid));
        pico_fs_label_set(ret->label, sizeof(ret->label), (const uint8_t *) fs.label, strlen(fs.label));
        return 1;
}

int pico_fs_read(int fd, uint64_t off, void *buf, size_t n) {
        uint8_t *p = buf;
        size_t done = 0;

        /* off_t is signed, and 32 bits wide on a build without large-file
         * support: an offset it cannot hold is refused, never truncated
         * into a read of the wrong bytes. */
        uint64_t max = sizeof(off_t) >= 8 ? (uint64_t) INT64_MAX : (uint64_t) INT32_MAX;

        if (n > max || off > max - n)
                return -EOVERFLOW;

        while (done < n) {
                ssize_t k = pread(fd, p + done, n - done, (off_t) (off + done));

                if (k < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (k == 0)
                        return -ENODATA;

                done += (size_t) k;
        }

        return 0;
}

bool pico_fs_bytes_zero(const uint8_t *p, size_t n) {
        size_t i;

        for (i = 0; i < n; i++)
                if (p[i])
                        return false;
        return true;
}

void pico_fs_uuid_format(const uint8_t u[16], char ret[static PICO_FS_UUID_MAX]) {
        static const char hex[] = "0123456789abcdef";
        size_t i, o = 0;

        if (pico_fs_bytes_zero(u, 16)) {
                ret[0] = '\0';
                return;
        }

        for (i = 0; i < 16; i++) {
                if (i == 4 || i == 6 || i == 8 || i == 10)
                        ret[o++] = '-';
                ret[o++] = hex[u[i] >> 4];
                ret[o++] = hex[u[i] & 0xf];
        }
        ret[o] = '\0';
}

void pico_fs_serial32_format(const uint8_t s[4], char ret[static PICO_FS_UUID_MAX]) {
        static const char hex[] = "0123456789ABCDEF";
        size_t i, o = 0;

        if (pico_fs_bytes_zero(s, 4)) {
                ret[0] = '\0';
                return;
        }

        for (i = 4; i-- > 0;) {
                if (i == 1)
                        ret[o++] = '-';
                ret[o++] = hex[s[i] >> 4];
                ret[o++] = hex[s[i] & 0xf];
        }
        ret[o] = '\0';
}

/* isspace() in the C locale, spelled out: a label byte >= 0x80 is part of a
 * character, never whitespace, whatever locale PID 1 was started in. */
static bool is_space(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

static void rtrim(char *s) {
        size_t n = strlen(s);

        while (n > 0 && is_space(s[n - 1]))
                n--;
        s[n] = '\0';
}

void pico_fs_label_set(char *ret, size_t size, const uint8_t *raw, size_t n) {
        size_t i;

        if (size == 0)
                return;

        for (i = 0; i < n && i + 1 < size && raw[i] != '\0'; i++)
                ret[i] = (char) raw[i];
        ret[i] = '\0';

        rtrim(ret);
}

void pico_fs_label_set_utf16le(char *ret, size_t size, const uint8_t *raw, size_t n) {
        size_t i, j = 0;

        if (size == 0)
                return;

        for (i = 0; i + 2 <= n; i += 2) {
                uint32_t c = pico_le16(raw + i);

                if (c >= 0xd800 && c <= 0xdbff && i + 4 <= n) {
                        uint32_t lo = pico_le16(raw + i + 2);

                        if (lo >= 0xdc00 && lo <= 0xdfff) {
                                c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
                                i += 2;
                        }
                }

                if (c == 0)
                        break;

                if (c < 0x80) {
                        if (j + 1 >= size)
                                break;
                        ret[j++] = (char) c;
                } else if (c < 0x800) {
                        if (j + 2 >= size)
                                break;
                        ret[j++] = (char) (0xc0 | (c >> 6));
                        ret[j++] = (char) (0x80 | (c & 0x3f));
                } else if (c < 0x10000) {
                        if (j + 3 >= size)
                                break;
                        ret[j++] = (char) (0xe0 | (c >> 12));
                        ret[j++] = (char) (0x80 | ((c >> 6) & 0x3f));
                        ret[j++] = (char) (0x80 | (c & 0x3f));
                } else {
                        if (j + 4 >= size)
                                break;
                        ret[j++] = (char) (0xf0 | (c >> 18));
                        ret[j++] = (char) (0x80 | ((c >> 12) & 0x3f));
                        ret[j++] = (char) (0x80 | ((c >> 6) & 0x3f));
                        ret[j++] = (char) (0x80 | (c & 0x3f));
                }
        }

        ret[j] = '\0';
        rtrim(ret);
}

uint32_t pico_crc32c(uint32_t crc, const void *buf, size_t n) {
        const uint8_t *p = buf;
        size_t i;
        unsigned k;

        for (i = 0; i < n; i++) {
                crc ^= p[i];
                for (k = 0; k < 8; k++)
                        crc = (crc >> 1) ^ (0x82f63b78U * (crc & 1));
        }

        return crc;
}
