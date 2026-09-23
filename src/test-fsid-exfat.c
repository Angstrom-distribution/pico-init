/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The exFAT reader, against volumes built byte by byte to the exFAT
 * specification's layout: the main boot region (boot sector, eight extended
 * boot sectors, OEM and reserved sectors, and the checksum sector), one FAT,
 * and a root directory in the cluster heap. The checksum sector is computed
 * here with the specification's own formula, so an image that passes is one
 * a real exFAT driver would accept.
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

static void put16(uint8_t *p, uint16_t v) {
        p[0] = (uint8_t) v;
        p[1] = (uint8_t) (v >> 8);
}

static void put32(uint8_t *p, uint32_t v) {
        put16(p, (uint16_t) v);
        put16(p + 2, (uint16_t) (v >> 16));
}

typedef struct Volume {
        unsigned sector_shift;
        unsigned cluster_shift;
        uint32_t fat_offset;
        uint32_t fat_length;
        uint32_t heap_offset;
        uint32_t cluster_count;
        uint32_t root_cluster;
        uint8_t nfats;
} Volume;

static const Volume v512 = {
        .sector_shift = 9,
        .cluster_shift = 3,
        .fat_offset = 128,
        .fat_length = 8,
        .heap_offset = 256,
        .cluster_count = 1000,
        .root_cluster = 4,
        .nfats = 1,
};

static uint64_t sector(const Volume *v) {
        return (uint64_t) 1 << v->sector_shift;
}

static uint64_t cluster_off(const Volume *v, uint32_t c) {
        return ((uint64_t) v->heap_offset + ((uint64_t) (c - 2) << v->cluster_shift)) << v->sector_shift;
}

/* The specification's BootChecksum, over sectors 0-10 without VolumeFlags
 * and PercentInUse. */
static uint32_t spec_checksum(const uint8_t *region, size_t ss) {
        uint32_t sum = 0;

        for (size_t i = 0; i < ss * 11; i++) {
                if (i == 106 || i == 107 || i == 112)
                        continue;
                sum = ((sum & 1) ? 0x80000000u : 0) + (sum >> 1) + (uint32_t) region[i];
        }
        return sum;
}

/* Write the boot region, `patch` applied to the boot sector first (before
 * the checksum, unless `after` says to break the checksum instead). */
static int volume_new(const Volume *v, void (*patch)(uint8_t *bs), bool after) {
        size_t ss = (size_t) sector(v);
        uint8_t *region = calloc(12, ss);
        char path[PATH_MAX];
        uint32_t sum;
        int fd;

        ASSERT_TRUE(region != NULL);
        memcpy(region,
               "\xeb\x76\x90"
               "EXFAT   ",
               11);
        put32(region + 72, v->heap_offset + (v->cluster_count << v->cluster_shift)); /* VolumeLength (low) */
        put32(region + 80, v->fat_offset);
        put32(region + 84, v->fat_length);
        put32(region + 88, v->heap_offset);
        put32(region + 92, v->cluster_count);
        put32(region + 96, v->root_cluster);
        memcpy(region + 100, "\xcd\xab\x34\x12", 4);
        put16(region + 104, 0x0100);
        region[108] = (uint8_t) v->sector_shift;
        region[109] = (uint8_t) v->cluster_shift;
        region[110] = v->nfats;
        region[111] = 0x80;
        put16(region + 510, 0xaa55);

        if (patch && !after)
                patch(region);

        sum = spec_checksum(region, ss);
        for (size_t i = 0; i < ss / 4; i++)
                put32(region + 11 * ss + i * 4, sum);

        if (patch && after)
                patch(region);

        snprintf(path, sizeof(path), "%s/img", dir);
        fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT(ftruncate(fd, (off_t) cluster_off(v, v->cluster_count + 2)), 0);
        ASSERT_EQ_INT(pwrite(fd, region, 12 * ss, 0), (ssize_t) (12 * ss));
        free(region);
        return fd;
}

static void put_entry(int fd, uint64_t off, uint8_t type, const char *utf16, uint8_t len) {
        uint8_t e[32] = { 0 };

        e[0] = type;
        e[1] = len;
        if (utf16)
                memcpy(e + 2, utf16, (size_t) len * 2 > 22 ? 22 : (size_t) len * 2);
        ASSERT_EQ_INT(pwrite(fd, e, sizeof(e), (off_t) off), (ssize_t) sizeof(e));
}

static void set_fat(int fd, const Volume *v, uint32_t cluster, uint32_t next) {
        uint8_t b[4];

        put32(b, next);
        ASSERT_EQ_INT(pwrite(fd, b, 4, (off_t) ((uint64_t) v->fat_offset * sector(v) + cluster * 4)), 4);
}

#define PICO_UTF16 "P\0i\0c\0o\0E\0x\0F\0A\0T\0"

static void test_label_and_serial(void) {
        uint64_t root = cluster_off(&v512, 4);
        PicoFsId id;
        int fd;

        /* The allocation bitmap and up-case table entries come first, as
         * every formatter writes them; then the label. */
        fd = volume_new(&v512, NULL, false);
        put_entry(fd, root, 0x81, NULL, 0);
        put_entry(fd, root + 32, 0x82, NULL, 0);
        put_entry(fd, root + 64, 0x83, PICO_UTF16, 9);
        ASSERT_EQ_INT(pico_fs_probe_exfat(fd, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_EXFAT);
        ASSERT_STREQ(id.uuid, "1234-ABCD");
        ASSERT_STREQ(id.label, "PicoExFAT");

        ASSERT_EQ_INT(pico_fs_probe_fd(fd, PICO_FS_NONE, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_EXFAT);
        ASSERT_EQ_INT(pico_fs_probe_fd(fd, pico_fs_kind_from_type("exfat"), &id), 1);
        ASSERT_STREQ(pico_fs_kind_to_string(PICO_FS_EXFAT), "exfat");

        /* exFAT's boot sector must not pass for FAT: its BPB is zeroes. */
        ASSERT_EQ_INT(pico_fs_probe_vfat(fd, &id), 0);

        /* A length past the 11 characters the entry holds is clamped. */
        put_entry(fd, root + 64, 0x83, "L\0o\0n\0g\0e\0s\0t\0L\0a\0b\0l\0", 15);
        ASSERT_EQ_INT(pico_fs_probe_exfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "LongestLabl");

        /* Non-ASCII, converted to UTF-8: "Ünï". */
        put_entry(fd, root + 64, 0x83, "\xdc\x00n\0\xef\x00", 3);
        ASSERT_EQ_INT(pico_fs_probe_exfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "\xc3\x9cn\xc3\xaf");

        /* An unused label slot (type 0x03, the in-use bit clear) is not a
         * label, and the end-of-directory entry ends the search. */
        put_entry(fd, root + 64, 0x03, PICO_UTF16, 9);
        ASSERT_EQ_INT(pico_fs_probe_exfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "");
        put_entry(fd, root + 64, 0x00, NULL, 0);
        put_entry(fd, root + 96, 0x83, PICO_UTF16, 9);
        ASSERT_EQ_INT(pico_fs_probe_exfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "");
        close(fd);
}

/* The root directory fills its first cluster and continues in another. */
static void test_cluster_chain(void) {
        uint64_t root = cluster_off(&v512, 4);
        uint64_t csize = sector(&v512) << v512.cluster_shift;
        PicoFsId id;
        int fd;

        fd = volume_new(&v512, NULL, false);
        for (uint64_t off = 0; off < csize; off += 32)
                put_entry(fd, root + off, 0x85, NULL, 0);
        set_fat(fd, &v512, 4, 9);
        put_entry(fd, cluster_off(&v512, 9), 0x83, PICO_UTF16, 9);
        ASSERT_EQ_INT(pico_fs_probe_exfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "PicoExFAT");

        /* End of chain before any label. */
        set_fat(fd, &v512, 4, 0xffffffffu);
        ASSERT_EQ_INT(pico_fs_probe_exfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "");

        /* A chain that loops forever is cut off by the scan limit. */
        set_fat(fd, &v512, 4, 4);
        ASSERT_EQ_INT(pico_fs_probe_exfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "");
        close(fd);
}

/* 4 KiB sectors: the checksum then covers eleven 4 KiB sectors. */
static void test_4k_sectors(void) {
        static const Volume v4k = {
                .sector_shift = 12,
                .cluster_shift = 0,
                .fat_offset = 24,
                .fat_length = 1,
                .heap_offset = 32,
                .cluster_count = 100,
                .root_cluster = 2,
                .nfats = 2,
        };
        PicoFsId id;
        int fd;

        fd = volume_new(&v4k, NULL, false);
        put_entry(fd, cluster_off(&v4k, 2), 0x83, PICO_UTF16, 9);
        ASSERT_EQ_INT(pico_fs_probe_exfat(fd, &id), 1);
        ASSERT_STREQ(id.label, "PicoExFAT");
        close(fd);
}

static void flip_sector5(uint8_t *bs) {
        bs[5 * 512 + 17] ^= 0x40;
}
static void flip_flags(uint8_t *bs) {
        bs[106] = 0x02; /* VolumeDirty: excluded from the checksum */
        bs[112] = 42;   /* PercentInUse: likewise */
}
static void set_zero_region(uint8_t *bs) {
        bs[40] = 1;
}
static void set_fats3(uint8_t *bs) {
        bs[110] = 3;
}
static void set_shift8(uint8_t *bs) {
        bs[108] = 8;
}
static void set_root1(uint8_t *bs) {
        put32(bs + 96, 1);
}
static void set_fat_in_boot(uint8_t *bs) {
        put32(bs + 80, 12);
}
static void set_jump(uint8_t *bs) {
        bs[1] = 0x3c;
}
static void set_no_sig(uint8_t *bs) {
        bs[510] = 0;
}
static void set_zero_serial(uint8_t *bs) {
        memset(bs + 100, 0, 4);
}

static void test_rejections(void) {
        static const struct {
                void (*patch)(uint8_t *bs);
                bool after;
                int want;
        } cases[] = {
                {    flip_sector5,  true, 0 }, /* checksum no longer matches */
                {      flip_flags,  true, 1 }, /* ...but these bytes are not in it */
                { set_zero_region, false, 0 },
                {       set_fats3, false, 0 },
                {      set_shift8, false, 0 },
                {       set_root1, false, 0 },
                { set_fat_in_boot, false, 0 }, /* FAT inside the boot regions  */
                {        set_jump, false, 0 },
                {      set_no_sig, false, 0 },
        };
        PicoFsId id;
        int fd;

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                fd = volume_new(&v512, cases[i].patch, cases[i].after);
                if (pico_fs_probe_exfat(fd, &id) != cases[i].want) {
                        fprintf(stderr, "case %zu: want %d\n", i, cases[i].want);
                        ASSERT_TRUE(false);
                }
                close(fd);
        }

        fd = volume_new(&v512, set_zero_serial, false);
        ASSERT_EQ_INT(pico_fs_probe_exfat(fd, &id), 1);
        ASSERT_STREQ(id.uuid, "");
        close(fd);
}

int main(void) {
        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        test_label_and_serial();
        test_cluster_chain();
        test_4k_sectors();
        test_rejections();

        test_rm_rf(dir);
        free(dir);
        printf("test-fsid-exfat: all checks passed\n");
        return 0;
}
