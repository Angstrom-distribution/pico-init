/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The NTFS reader, against volumes built byte by byte with mkntfs's default
 * layout: 512-byte sectors, 4 KiB clusters, 1 KiB MFT records (stored as the
 * negative "clusters per record" value 0xf6), the MFT at cluster 4, and a
 * $Volume record (MFT record 3) carrying $STANDARD_INFORMATION,
 * $VOLUME_NAME and $VOLUME_INFORMATION attributes in that order.
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

static char *dir;

#define MFT_OFF (4 * 4096)
#define RECORD 1024

static void put16(uint8_t *p, uint16_t v) {
        p[0] = (uint8_t) v;
        p[1] = (uint8_t) (v >> 8);
}

static void put32(uint8_t *p, uint32_t v) {
        put16(p, (uint16_t) v);
        put16(p + 2, (uint16_t) (v >> 16));
}

static void put64(uint8_t *p, uint64_t v) {
        put32(p, (uint32_t) v);
        put32(p + 4, (uint32_t) (v >> 32));
}

static void boot(uint8_t bs[512]) {
        memset(bs, 0, 512);
        memcpy(bs, "\xeb\x52\x90NTFS    ", 11);
        put16(bs + 11, 512);
        bs[13] = 8; /* 4 KiB clusters */
        bs[21] = 0xf8;
        put64(bs + 40, 32767); /* sectors: 16 MiB less one */
        put64(bs + 48, 4);     /* $MFT at cluster 4 */
        put64(bs + 56, 2047);  /* $MFTMirr */
        bs[64] = 0xf6;         /* 2^10-byte records */
        bs[68] = 1;            /* clusters per index record */
        put64(bs + 72, 0x35648c214a25205fULL);
        put16(bs + 510, 0xaa55);
}

/* A resident attribute header plus its value; returns its length. */
static uint32_t attr(uint8_t *a, uint32_t type, const void *value, uint32_t len) {
        uint32_t total = (24 + len + 7) & ~7u;

        memset(a, 0, total);
        put32(a, type);
        put32(a + 4, total);
        put32(a + 16, len);
        put16(a + 20, 24);
        if (value)
                memcpy(a + 24, value, len);
        return total;
}

/* $Volume with `name` (UTF-16LE, `len` bytes) as its $VOLUME_NAME, or no
 * name attribute at all when `name` is NULL. */
static void volume_record(uint8_t rec[RECORD], const void *name, uint32_t len) {
        uint32_t off = 56;

        memset(rec, 0, RECORD);
        memcpy(rec, "FILE", 4);
        put16(rec + 4, 48); /* update sequence array, never applied here */
        put16(rec + 6, 3);
        put16(rec + 20, (uint16_t) off);
        put32(rec + 24, 512);
        put32(rec + 28, RECORD);

        off += attr(rec + off, 0x10, NULL, 72);
        if (name)
                off += attr(rec + off, 0x60, name, len);
        off += attr(rec + off, 0x70, "\0\0\0\0\0\0\0\0\x03\x01\0\0", 12);
        put32(rec + off, 0xffffffffu);
}

static int image(const uint8_t bs[512], const uint8_t rec[RECORD], bool mft0) {
        char path[PATH_MAX];
        int fd;

        snprintf(path, sizeof(path), "%s/img", dir);
        fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT(ftruncate(fd, 16 << 20), 0);
        ASSERT_EQ_INT(pwrite(fd, bs, 512, 0), 512);
        if (mft0)
                ASSERT_EQ_INT(pwrite(fd, "FILE", 4, MFT_OFF), 4);
        ASSERT_EQ_INT(pwrite(fd, rec, RECORD, MFT_OFF + 3 * RECORD), RECORD);
        return fd;
}

static void test_ntfs(void) {
        static const char name[] = "P\0I\0C\0O\0 \0N\0T\0F\0S\0";
        uint8_t bs[512], rec[RECORD];
        PicoFsId id;
        int fd;

        boot(bs);
        volume_record(rec, name, sizeof(name) - 1);
        fd = image(bs, rec, true);
        ASSERT_EQ_INT(pico_fs_probe_ntfs(fd, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_NTFS);
        ASSERT_STREQ(id.uuid, "35648C214A25205F");
        ASSERT_STREQ(id.label, "PICO NTFS");

        ASSERT_EQ_INT(pico_fs_probe_fd(fd, PICO_FS_NONE, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_NTFS);
        ASSERT_EQ_INT(pico_fs_kind_from_type("ntfs3"), PICO_FS_NTFS);
        ASSERT_EQ_INT(pico_fs_kind_from_type("ntfs-3g"), PICO_FS_NTFS);
        ASSERT_STREQ(pico_fs_kind_to_string(PICO_FS_NTFS), "ntfs");

        /* NTFS shares FAT's jump byte and boot signature, and must not pass
         * for it. */
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 0);
        close(fd);

        /* "Tëst", converted to UTF-8. */
        volume_record(rec, "T\0\xeb\0s\0t\0", 8);
        fd = image(bs, rec, true);
        ASSERT_EQ_INT(pico_fs_probe_ntfs(fd, &id), 1);
        ASSERT_STREQ(id.label, "T\xc3\xabst");
        close(fd);

        /* No $VOLUME_NAME, and a zero serial: an NTFS volume with neither. */
        volume_record(rec, NULL, 0);
        put64(bs + 72, 0);
        fd = image(bs, rec, true);
        ASSERT_EQ_INT(pico_fs_probe_ntfs(fd, &id), 1);
        ASSERT_STREQ(id.label, "");
        ASSERT_STREQ(id.uuid, "");
        close(fd);

        /* A value claiming to run past the record is not read. */
        boot(bs);
        volume_record(rec, name, sizeof(name) - 1);
        put32(rec + 56 + 96 + 16, 5000);
        fd = image(bs, rec, true);
        ASSERT_EQ_INT(pico_fs_probe_ntfs(fd, &id), 1);
        ASSERT_STREQ(id.label, "");
        close(fd);

        /* A zero-length attribute ends the walk rather than spinning on it. */
        volume_record(rec, name, sizeof(name) - 1);
        put32(rec + 56 + 4, 0);
        fd = image(bs, rec, true);
        ASSERT_EQ_INT(pico_fs_probe_ntfs(fd, &id), 1);
        ASSERT_STREQ(id.label, "");
        close(fd);

        /* 64 KiB records, the largest accepted, as 0xf0. */
        boot(bs);
        bs[64] = 0xf0;
        {
                uint8_t *big = calloc(1, 65536);

                ASSERT_TRUE(big != NULL);
                volume_record(big, name, sizeof(name) - 1);
                put32(big + 28, 65536);
                fd = image(bs, big, true);
                ASSERT_EQ_INT(pwrite(fd, big, 65536, MFT_OFF + 3 * 65536), 65536);
                free(big);
        }
        ASSERT_EQ_INT(pico_fs_probe_ntfs(fd, &id), 1);
        ASSERT_STREQ(id.label, "PICO NTFS");
        close(fd);
}

static void test_rejections(void) {
        static const struct {
                size_t off;
                uint8_t value;
        } breaks[] = {
                { 11, 0x2c }, /* sector size 0x22c: not a power of two */
                { 12, 0x20 }, /* sector size 8 KiB */
                { 13,    3 }, /* sectors per cluster not a power of two */
                { 13, 0xf3 }, /* 2^13 sectors of 512: a 4 MiB cluster */
                { 16,    2 }, /* a FAT count */
                { 14,    1 }, /* reserved sectors */
                { 64,    3 }, /* clusters per record not a power of two */
                { 64, 0xe0 }, /* negative, outside 0xe1-0xf7 */
                { 64, 0xef }, /* 128 KiB records: past the 64 KiB cap */
                { 50, 0x01 }, /* $MFT beyond the end of the volume */
        };
        uint8_t bs[512], rec[RECORD];
        PicoFsId id;
        int fd;

        volume_record(rec, "X\0", 2);

        for (size_t i = 0; i < sizeof(breaks) / sizeof(breaks[0]); i++) {
                boot(bs);
                bs[breaks[i].off] = breaks[i].value;
                fd = image(bs, rec, true);
                if (pico_fs_probe_ntfs(fd, &id) != 0) {
                        fprintf(stderr, "break %zu accepted\n", i);
                        ASSERT_TRUE(false);
                }
                close(fd);
        }

        /* The two "FILE" records that must be there. */
        boot(bs);
        fd = image(bs, rec, false);
        ASSERT_EQ_INT(pico_fs_probe_ntfs(fd, &id), 0);
        close(fd);
        memcpy(rec, "BAAD", 4);
        fd = image(bs, rec, true);
        ASSERT_EQ_INT(pico_fs_probe_ntfs(fd, &id), 0);
        ASSERT_EQ_INT(pico_fs_probe_fd(fd, PICO_FS_NONE, &id), 0);
        close(fd);
}

int main(void) {
        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        test_ntfs();
        test_rejections();

        test_rm_rf(dir);
        free(dir);
        printf("test-fsid-ntfs: all checks passed\n");
        return 0;
}
