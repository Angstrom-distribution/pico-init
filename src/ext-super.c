/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The ext superblock decode and the read behind it. ext-super.h has the
 * reasoning, the two consumers, and the verified offsets.
 */

#include "ext-super.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * The shortest buffer that can answer every question this file asks of a
 * superblock. s_last_orphan is the field furthest out, so a buffer reaching it
 * reaches all of them -- and refusing anything shorter is what makes every
 * offset below provably inside the bytes that were really read.
 */
#define EXT_SUPER_MIN (EXT_SUPER_LAST_ORPHAN_OFF + 4)

static uint16_t ext_le16(const uint8_t *p) {
        return (uint16_t) ((uint16_t) p[0] | ((uint16_t) p[1] << 8));
}

static uint32_t ext_le32(const uint8_t *p) {
        return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static bool bytes_all_zero(const uint8_t *p, size_t n) {
        for (size_t i = 0; i < n; i++)
                if (p[i])
                        return false;

        return true;
}

int ext_super_decode(const uint8_t *sb, size_t n, PicoExtInfo *ret) {
        const uint8_t *u;
        size_t i;

        if (!sb || !ret || n < EXT_SUPER_MIN)
                return -EINVAL;

        /* s_magic is little-endian, like every other ext field. */
        if (ext_le16(sb + EXT_SUPER_MAGIC_OFF) != EXT_SUPER_MAGIC)
                return 0;

        memset(ret, 0, sizeof(*ret));

        /*
         * s_uuid is a plain big-endian UUID, unlike GPT's mixed-endian one --
         * printed straight through, which is why this does not reuse
         * gpt_guid_to_string(). Getting that wrong would produce a by-uuid link
         * no fstab or bootloader entry written by anything else would match.
         */
        u = sb + EXT_SUPER_UUID_OFF;
        if (!bytes_all_zero(u, 16))
                snprintf(ret->uuid,
                         sizeof(ret->uuid),
                         "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                         u[0],
                         u[1],
                         u[2],
                         u[3],
                         u[4],
                         u[5],
                         u[6],
                         u[7],
                         u[8],
                         u[9],
                         u[10],
                         u[11],
                         u[12],
                         u[13],
                         u[14],
                         u[15]);

        /* s_volume_name is 16 bytes and is NOT required to be terminated, so a
         * 16-character label has no NUL at all -- copying by length rather than
         * with strncpy() is the whole point. */
        for (i = 0; i < 16; i++) {
                if (sb[EXT_SUPER_LABEL_OFF + i] == '\0')
                        break;

                ret->label[i] = (char) sb[EXT_SUPER_LABEL_OFF + i];
        }

        ret->label[i] = '\0';

        ret->state = ext_le16(sb + EXT_SUPER_STATE_OFF);
        ret->feature_compat = ext_le32(sb + EXT_SUPER_FEATURE_COMPAT_OFF);
        ret->feature_incompat = ext_le32(sb + EXT_SUPER_FEATURE_INCOMPAT_OFF);
        ret->last_orphan = ext_le32(sb + EXT_SUPER_LAST_ORPHAN_OFF);

        return 1;
}

int ext_super_read(const char *device, PicoExtInfo *ret) {
        uint8_t sb[EXT_SUPER_SIZE];
        size_t done = 0;
        int fd, r;

        if (!device || !ret)
                return -EINVAL;

        fd = open(device, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        while (done < sizeof(sb)) {
                ssize_t k = pread(fd, sb + done, sizeof(sb) - done, (off_t) (EXT_SUPER_OFFSET + done));

                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        r = -errno;
                        goto done;
                }

                if (k == 0) {
                        /* Shorter than a superblock: not a filesystem anyone
                         * can name, and not an I/O error either. */
                        r = 0;
                        goto done;
                }

                done += (size_t) k;
        }

        r = ext_super_decode(sb, sizeof(sb), ret);

done:
        (void) close(fd);
        return r;
}
