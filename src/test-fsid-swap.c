/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The swap signature reader, against swap areas built byte by byte in the
 * layout mkswap(8) writes: a 1 KiB boot area, the v1 header, and the
 * "SWAPSPACE2" magic in the last ten bytes of the first page. The header
 * offsets are the kernel's union swap_header.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fsid.h"
#include "test-util.h"

static const uint8_t uuid[16] = { 0x6f, 0x0e, 0x4c, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e,
                                  0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 };

static char *dir;

static void put32(uint8_t *p, uint32_t v, bool be) {
        for (int i = 0; i < 4; i++)
                p[be ? 3 - i : i] = (uint8_t) (v >> (8 * i));
}

/* One swap area of `size` bytes with its magic at the end of a `page`-sized
 * first page. */
static uint8_t *build(size_t size, uint32_t page, const char *magic, const char *label, bool be) {
        uint8_t *img = calloc(1, size);

        ASSERT_TRUE(img != NULL);
        memcpy(img + page - 10, magic, 10);

        put32(img + 1024, 1, be);       /* version */
        put32(img + 1024 + 4, 255, be); /* last_page */
        memcpy(img + 1024 + 12, uuid, 16);
        if (label)
                memcpy(img + 1024 + 28, label, strlen(label) > 16 ? 16 : strlen(label));
        return img;
}

static int probe(const uint8_t *img, size_t size, PicoFsKind hint, PicoFsId *id) {
        char path[PATH_MAX];
        int fd, r;

        snprintf(path, sizeof(path), "%s/img", dir);
        fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT(write(fd, img, size), (ssize_t) size);

        r = hint == PICO_FS_SWAP ? pico_fs_probe_swap(fd, id) : pico_fs_probe_fd(fd, hint, id);
        ASSERT_EQ_INT(close(fd), 0);
        return r;
}

static void test_v1(void) {
        uint8_t *img;
        PicoFsId id;

        img = build(40960, 4096, "SWAPSPACE2", "picoswap", false);
        ASSERT_EQ_INT(probe(img, 40960, PICO_FS_SWAP, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_SWAP);
        ASSERT_STREQ(id.uuid, "6f0e4c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6");
        ASSERT_STREQ(id.label, "picoswap");

        /* Through the dispatcher, both as "auto" and as fstab's "swap". */
        memset(&id, 0, sizeof(id));
        ASSERT_EQ_INT(probe(img, 40960, PICO_FS_NONE, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_SWAP);
        ASSERT_EQ_INT(pico_fs_kind_from_type("swap"), PICO_FS_SWAP);
        ASSERT_STREQ(pico_fs_kind_to_string(PICO_FS_SWAP), "swap");

        /* Asked for ext, a swap area is not one. */
        ASSERT_EQ_INT(probe(img, 40960, PICO_FS_EXT, &id), 0);
        free(img);

        /* A 16-byte label with no terminator, and trailing blanks trimmed. */
        img = build(40960, 4096, "SWAPSPACE2", "SIXTEEN_CHARS_XX", false);
        ASSERT_EQ_INT(probe(img, 40960, PICO_FS_SWAP, &id), 1);
        ASSERT_STREQ(id.label, "SIXTEEN_CHARS_XX");
        free(img);

        img = build(40960, 4096, "SWAPSPACE2", "swap  ", false);
        ASSERT_EQ_INT(probe(img, 40960, PICO_FS_SWAP, &id), 1);
        ASSERT_STREQ(id.label, "swap");
        free(img);

        /* No label and an all-zero UUID: a swap area with no identity. */
        img = build(40960, 4096, "SWAPSPACE2", NULL, false);
        memset(img + 1024 + 12, 0, 16);
        ASSERT_EQ_INT(probe(img, 40960, PICO_FS_SWAP, &id), 1);
        ASSERT_STREQ(id.uuid, "");
        ASSERT_STREQ(id.label, "");
        free(img);
}

static void test_page_sizes_and_order(void) {
        uint8_t *img;
        PicoFsId id;

        /* A 64 KiB-page mkswap (arm64/ppc64 with large pages). */
        img = build(10 * 65536, 65536, "SWAPSPACE2", "big", false);
        ASSERT_EQ_INT(probe(img, 10 * 65536, PICO_FS_SWAP, &id), 1);
        ASSERT_STREQ(id.label, "big");
        free(img);

        /* 16 KiB, header written by a big-endian machine. */
        img = build(10 * 16384, 16384, "SWAPSPACE2", "be", true);
        ASSERT_EQ_INT(probe(img, 10 * 16384, PICO_FS_SWAP, &id), 1);
        ASSERT_STREQ(id.label, "be");
        ASSERT_STREQ(id.uuid, "6f0e4c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6");
        free(img);

        /* Shorter than the page that would hold the magic: not swap. */
        img = build(4096, 4096, "SWAPSPACE2", "x", false);
        ASSERT_EQ_INT(probe(img, 4000, PICO_FS_SWAP, &id), 0);
        free(img);
}

static void test_rejections(void) {
        uint8_t *img;
        PicoFsId id;

        /* The v0 format: swap, but nothing to name it by. */
        img = build(40960, 4096, "SWAP-SPACE", "ignored", false);
        ASSERT_EQ_INT(probe(img, 40960, PICO_FS_SWAP, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_SWAP);
        ASSERT_STREQ(id.uuid, "");
        ASSERT_STREQ(id.label, "");
        free(img);

        /* Version 2 in either byte order is not a v1 header. */
        img = build(40960, 4096, "SWAPSPACE2", "x", false);
        put32(img + 1024, 2, false);
        ASSERT_EQ_INT(probe(img, 40960, PICO_FS_SWAP, &id), 0);
        free(img);

        /* A zero page count: mkswap never writes one. */
        img = build(40960, 4096, "SWAPSPACE2", "x", false);
        put32(img + 1024 + 4, 0, false);
        ASSERT_EQ_INT(probe(img, 40960, PICO_FS_SWAP, &id), 0);
        free(img);

        /* Garbage in the padding mkswap zeroes: still swap, but the UUID and
         * label beside it are not believed. */
        img = build(40960, 4096, "SWAPSPACE2", "x", false);
        img[1024 + 44 + 32 * 4 + 5] = 0x01;
        ASSERT_EQ_INT(probe(img, 40960, PICO_FS_SWAP, &id), 1);
        ASSERT_STREQ(id.uuid, "");
        ASSERT_STREQ(id.label, "");
        free(img);

        /* A TuxOnIce image behind its own magic is a hibernation image. */
        img = build(40960, 4096, "SWAPSPACE2", "x", false);
        memcpy(img, "\xed\xc3\x02\xe9\x98\x56\xe5\x0c", 8);
        ASSERT_EQ_INT(probe(img, 40960, PICO_FS_SWAP, &id), 0);
        free(img);

        /* No magic anywhere. */
        img = calloc(1, 65536);
        ASSERT_TRUE(img != NULL);
        ASSERT_EQ_INT(probe(img, 65536, PICO_FS_SWAP, &id), 0);
        ASSERT_EQ_INT(probe(img, 65536, PICO_FS_NONE, &id), 0);
        free(img);
}

int main(void) {
        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        test_v1();
        test_page_sizes_and_order();
        test_rejections();

        test_rm_rf(dir);
        free(dir);
        printf("test-fsid-swap: all checks passed\n");
        return 0;
}
