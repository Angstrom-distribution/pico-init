/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Linux swap: the signature mkswap(8) writes and the kernel's swapon() checks.
 *
 * The magic sits in the last ten bytes of the first page, and the page size is
 * the one mkswap ran with, so it is looked for at the end of every page size a
 * Linux architecture has used (4 KiB to 64 KiB), as blkid does. "SWAPSPACE2"
 * is the v1 format with a 1 KiB boot area and then the header (the kernel's
 * union swap_header); "SWAP-SPACE" is the long-gone v0 format, which carries
 * no UUID or label and is recognised only so that it is not mistaken for
 * anything else.
 *
 * blkid's own acceptance rules, kept exactly: a v1 header needs version 1 in
 * either byte order and a non-zero page count; its UUID and label are only
 * believed when two padding words the format keeps zero are zero (mkswap has
 * always zeroed them, garbage there means the header is not really one); and
 * a TuxOnIce hibernation image, which keeps a valid-looking swap signature
 * behind its own magic at byte 0, is not swap.
 */

#include <errno.h>
#include <string.h>

#include "fsid.h"

#define SWAP_HEADER_OFF 1024
#define SWAP_VERSION_OFF 0
#define SWAP_LASTPAGE_OFF 4
#define SWAP_UUID_OFF 12
#define SWAP_LABEL_OFF 28
#define SWAP_LABEL_LEN 16
/* padding[32] and padding[33]: the padding array starts at 44. */
#define SWAP_SANITY_OFF (44 + 32 * 4)
#define SWAP_HEADER_LEN (SWAP_SANITY_OFF + 8)

#define SWAP_MAGIC_LEN 10

static const uint8_t toi_magic[8] = { 0xed, 0xc3, 0x02, 0xe9, 0x98, 0x56, 0xe5, 0x0c };

static const uint32_t page_sizes[] = { 4096, 8192, 16384, 32768, 65536 };

int pico_fs_probe_swap(int fd, PicoFsId *ret) {
        uint8_t magic[SWAP_MAGIC_LEN], hdr[SWAP_HEADER_LEN], head[sizeof(toi_magic)];
        bool v1 = false, found = false;
        size_t i;
        int r;

        for (i = 0; i < sizeof(page_sizes) / sizeof(page_sizes[0]) && !found; i++) {
                r = pico_fs_read(fd, page_sizes[i] - SWAP_MAGIC_LEN, magic, sizeof(magic));
                if (r == -ENODATA)
                        break; /* shorter than this page size, so shorter than every later one */
                if (r < 0)
                        return r;

                if (memcmp(magic, "SWAPSPACE2", SWAP_MAGIC_LEN) == 0)
                        found = v1 = true;
                else if (memcmp(magic, "SWAP-SPACE", SWAP_MAGIC_LEN) == 0)
                        found = true;
        }

        if (!found)
                return 0;

        r = pico_fs_read(fd, 0, head, sizeof(head));
        if (r < 0)
                return r == -ENODATA ? 0 : r;
        if (memcmp(head, toi_magic, sizeof(toi_magic)) == 0)
                return 0;

        if (!v1) {
                memset(ret, 0, sizeof(*ret));
                ret->kind = PICO_FS_SWAP;
                return 1;
        }

        r = pico_fs_read(fd, SWAP_HEADER_OFF, hdr, sizeof(hdr));
        if (r < 0)
                return r == -ENODATA ? 0 : r;

        /* The header is in the byte order of the machine that ran mkswap. */
        if (pico_le32(hdr + SWAP_VERSION_OFF) != 1 && pico_be32(hdr + SWAP_VERSION_OFF) != 1)
                return 0;
        if (pico_fs_bytes_zero(hdr + SWAP_LASTPAGE_OFF, 4))
                return 0;

        memset(ret, 0, sizeof(*ret));
        ret->kind = PICO_FS_SWAP;

        if (pico_fs_bytes_zero(hdr + SWAP_SANITY_OFF, 8)) {
                pico_fs_uuid_format(hdr + SWAP_UUID_OFF, ret->uuid);
                pico_fs_label_set(ret->label, sizeof(ret->label), hdr + SWAP_LABEL_OFF, SWAP_LABEL_LEN);
        }

        return 1;
}
