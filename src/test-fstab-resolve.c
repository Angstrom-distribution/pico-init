/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * fstab source resolution against a fixture machine: a sysfs tree laid out
 * the way the kernel lays out block devices (partitions inside their disk's
 * directory, class/block symlinks to both), and image files standing in for
 * the /dev nodes, with a real GPT on one disk and real filesystem and swap
 * signatures on the partitions and whole disks.
 *
 * Then the device wait, driven through its poll hook so that a device
 * "arrives" on a chosen poll rather than after a guessed sleep.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fstab-resolve.h"
#include "gpt-scan.h"
#include "test-util.h"

static char root[PATH_MAX], sys[PATH_MAX + 8], dev[PATH_MAX + 8];

static const uint8_t uuid_x[16] = { 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33,
                                    0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
static const uint8_t uuid_y[16] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc,
                                    0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee };
static const uint8_t uuid_z[16] = { 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
                                    0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99 };
static const uint8_t no_uuid[16];
#define UUID_X "11111111-2222-3333-4444-555555555555"
#define UUID_Y "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
#define UUID_Z "99999999-9999-9999-9999-999999999999"

/* GPT partition GUIDs, on disk in mixed-endian order. */
static const GptGuid part_a = {
        { 0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 }
};
static const GptGuid part_b = {
        { 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }
};
#define PART_A "12345678-9abc-def0-1234-56789abcdef0"
#define PART_B "00000001-0002-0003-0400-000000000005"

static const GptGuid type_data = {
        { 0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4 }
};

static void le32(uint8_t *p, uint32_t v) {
        for (int i = 0; i < 4; i++)
                p[i] = (uint8_t) (v >> (8 * i));
}

static void le64(uint8_t *p, uint64_t v) {
        le32(p, (uint32_t) v);
        le32(p + 4, (uint32_t) (v >> 32));
}

static void node(char *buf, size_t size, const char *name) {
        ASSERT_TRUE((size_t) snprintf(buf, size, "%s/%s", dev, name) < size);
}

/* A 4 MiB disk with a three-entry GPT: rootfs, data, and "My Data". */
static void gpt_disk(const char *name) {
        static uint8_t disk[34 * 512];
        uint8_t *h = disk + 512, *e = disk + 1024;
        static const char * const names[] = { "rootfs", "data", "My Data" };
        const GptGuid *uuids[] = { &part_a, &part_b, &part_a };
        char path[PATH_MAX + 16];

        memset(disk, 0, sizeof(disk));
        for (int i = 0; i < 3; i++) {
                uint8_t *p = e + i * 128;

                memcpy(p, &type_data, 16);
                memcpy(p + 16, uuids[i], 16);
                /* The third reuses the first GUID's bytes with one changed,
                 * so no two partitions share a PARTUUID. */
                if (i == 2)
                        p[31] = 0x00;
                le64(p + 32, 34 + (uint64_t) i * 2000);
                le64(p + 40, 33 + (uint64_t) (i + 1) * 2000);
                for (size_t c = 0; names[i][c]; c++)
                        p[56 + c * 2] = (uint8_t) names[i][c];
        }

        memcpy(h, "EFI PART", 8);
        le32(h + 8, 0x00010000);
        le32(h + 12, 92);
        le64(h + 24, 1);
        le64(h + 32, 8191);
        le64(h + 40, 34);
        le64(h + 48, 8158);
        le64(h + 72, 2);
        le32(h + 80, 128);
        le32(h + 84, 128);
        le32(h + 88, gpt_crc32(e, 128 * 128));
        le32(h + 16, gpt_crc32(h, 92));

        node(path, sizeof(path), name);
        ASSERT_EQ_INT(test_image_write(path, 4 << 20, disk, sizeof(disk), 0), 0);
}

/* A v1 swap area, the whole of a disk with no partition table. */
static void swap_disk(const char *name, const char *label) {
        uint8_t page[4096] = { 0 };
        char path[PATH_MAX + 16];

        le32(page + 1024, 1);
        le32(page + 1028, 255);
        memcpy(page + 1036, uuid_z, 16);
        memcpy(page + 1052, label, strlen(label));
        memcpy(page + 4086, "SWAPSPACE2", 10);
        node(path, sizeof(path), name);
        ASSERT_EQ_INT(test_image_write(path, 1 << 20, page, sizeof(page), 0), 0);
}

static void ext_node(const char *name, const uint8_t uuid[16], const char *label) {
        char path[PATH_MAX + 16];

        node(path, sizeof(path), name);
        ASSERT_EQ_INT(test_ext_image(path, uuid, label), 0);
}

static void fixture(void) {
        char *d = test_tmpdir_new();

        ASSERT_TRUE(d != NULL);
        snprintf(root, sizeof(root), "%s", d);
        free(d);
        snprintf(sys, sizeof(sys), "%s/sys", root);
        snprintf(dev, sizeof(dev), "%s/dev", root);
        ASSERT_EQ_INT(test_mkdir(root, "dev"), 0);
        ASSERT_EQ_INT(test_mkdir(dev, "cciss"), 0);

        /* vda: GPT, three partitions. */
        ASSERT_EQ_INT(test_block_device(sys, "vda", NULL, 0, 8192), 0);
        ASSERT_EQ_INT(test_block_device(sys, "vda1", "vda", 1, 2000), 0);
        ASSERT_EQ_INT(test_block_device(sys, "vda2", "vda", 2, 2000), 0);
        ASSERT_EQ_INT(test_block_device(sys, "vda3", "vda", 3, 2000), 0);
        gpt_disk("vda");
        ext_node("vda1", uuid_x, "rootfs");
        ext_node("vda2", uuid_y, "DATA");
        ext_node("vda3", uuid_y, "my disk");

        /* vdb: no table the reader knows, one partition, carrying a clone
         * of vda1's filesystem. */
        ASSERT_EQ_INT(test_block_device(sys, "vdb", NULL, 0, 8192), 0);
        ASSERT_EQ_INT(test_block_device(sys, "vdb1", "vdb", 1, 2000), 0);
        ext_node("vdb", uuid_z, "whole-vdb");
        ext_node("vdb1", uuid_x, "clone");

        /* sda sorts before vda and has a partition 1 of its own: a
         * PARTUUID on vda's table must still name vda1, not sda1. */
        ASSERT_EQ_INT(test_block_device(sys, "sda", NULL, 0, 8192), 0);
        ASSERT_EQ_INT(test_block_device(sys, "sda1", "sda", 1, 2000), 0);
        ext_node("sda", no_uuid, NULL);
        ext_node("sda1", uuid_z, "sda-part");

        /* mmcblk0: a card with no partition table, swap across all of it. */
        ASSERT_EQ_INT(test_block_device(sys, "mmcblk0", NULL, 0, 2048), 0);
        swap_disk("mmcblk0", "picoswap");

        /* A ram disk: no by-* links upstream, so not read here either. */
        ASSERT_EQ_INT(test_block_device(sys, "ram0", NULL, 0, 8192), 0);
        ext_node("ram0", uuid_z, "ramfs");

        /* Nothing behind it, and MTD flash: neither is read. */
        ASSERT_EQ_INT(test_block_device(sys, "loop0", NULL, 0, 0), 0);
        ext_node("loop0", uuid_z, "loopfs");
        ASSERT_EQ_INT(test_block_device(sys, "mtdblock0", NULL, 0, 2048), 0);
        ext_node("mtdblock0", uuid_z, "flashfs");

        /* A kernel name with a '!', which devtmpfs turns into a directory. */
        ASSERT_EQ_INT(test_block_device(sys, "cciss!c0d0", NULL, 0, 2048), 0);
        ext_node("cciss/c0d0", uuid_z, "array");
}

static void test_source_tag(void) {
        char v[64];

        ASSERT_EQ_INT(fstab_source_tag("UUID=" UUID_X, v, sizeof(v)), FSTAB_TAG_UUID);
        ASSERT_STREQ(v, UUID_X);
        ASSERT_EQ_INT(fstab_source_tag("LABEL=my disk", v, sizeof(v)), FSTAB_TAG_LABEL);
        ASSERT_STREQ(v, "my disk");
        ASSERT_EQ_INT(fstab_source_tag("PARTUUID=" PART_A, v, sizeof(v)), FSTAB_TAG_PARTUUID);
        ASSERT_EQ_INT(fstab_source_tag("PARTLABEL=data", v, sizeof(v)), FSTAB_TAG_PARTLABEL);
        ASSERT_STREQ(v, "data");

        /* The by-* link spellings, udev's escapes undone. */
        ASSERT_EQ_INT(fstab_source_tag("/dev/disk/by-label/my\\x20disk", v, sizeof(v)), FSTAB_TAG_LABEL);
        ASSERT_STREQ(v, "my disk");
        ASSERT_EQ_INT(fstab_source_tag("/dev/disk/by-uuid/" UUID_X, v, sizeof(v)), FSTAB_TAG_UUID);
        ASSERT_EQ_INT(fstab_source_tag("/dev/disk/by-partlabel/a\\x2Fb", v, sizeof(v)), FSTAB_TAG_PARTLABEL);
        ASSERT_STREQ(v, "a/b");
        /* Not an escape: kept as written. */
        ASSERT_EQ_INT(fstab_source_tag("/dev/disk/by-label/x\\xzz", v, sizeof(v)), FSTAB_TAG_LABEL);
        ASSERT_STREQ(v, "x\\xzz");

        /* Not tags. */
        ASSERT_EQ_INT(fstab_source_tag("UUID=", v, sizeof(v)), FSTAB_TAG_NONE);
        ASSERT_EQ_INT(fstab_source_tag("uuid=abc", v, sizeof(v)), FSTAB_TAG_NONE);
        ASSERT_EQ_INT(fstab_source_tag("UUIDX=abc", v, sizeof(v)), FSTAB_TAG_NONE);
        ASSERT_EQ_INT(fstab_source_tag("/dev/sda1", v, sizeof(v)), FSTAB_TAG_NONE);
        ASSERT_EQ_INT(fstab_source_tag("/dev/disk/by-id/usb-x", v, sizeof(v)), FSTAB_TAG_NONE);
        ASSERT_EQ_INT(fstab_source_tag("/dev/disk/by-label/a/b", v, sizeof(v)), FSTAB_TAG_NONE);
        ASSERT_EQ_INT(fstab_source_tag("tmpfs", v, sizeof(v)), FSTAB_TAG_NONE);
        /* Too long for the buffer is not a truncated tag. */
        ASSERT_EQ_INT(fstab_source_tag("LABEL=0123456789", v, 8), FSTAB_TAG_NONE);

        ASSERT_STREQ(fstab_tag_to_string(FSTAB_TAG_PARTLABEL), "PARTLABEL");
        ASSERT_TRUE(fstab_tag_to_string(FSTAB_TAG_NONE) == NULL);

        ASSERT_TRUE(fstab_source_needs_device("UUID=" UUID_X));
        ASSERT_TRUE(fstab_source_needs_device("/dev/mmcblk0p2"));
        ASSERT_TRUE(fstab_source_needs_device("/dev/disk/by-label/x"));
        ASSERT_TRUE(!fstab_source_needs_device("tmpfs"));
        ASSERT_TRUE(!fstab_source_needs_device("/var/swapfile"));
        ASSERT_TRUE(!fstab_source_needs_device("/srv/export"));
        ASSERT_TRUE(!fstab_source_needs_device(NULL));
}

static void test_device_timeout(void) {
        FstabOptions o;
        bool clamped;

        ASSERT_EQ_INT(fstab_options_parse("defaults", &o), 0);
        ASSERT_EQ_INT(fstab_device_timeout(&o, 7, &clamped), 7);
        ASSERT_TRUE(!clamped);
        fstab_options_done(&o);

        ASSERT_EQ_INT(fstab_options_parse("x-systemd.device-timeout=30s", &o), 0);
        ASSERT_EQ_INT(fstab_device_timeout(&o, 7, &clamped), 30 * USEC_PER_SEC);
        ASSERT_TRUE(!clamped);
        fstab_options_done(&o);

        /* Upstream reads both 0 and infinity as "forever"; PID 1 never
         * waits forever. */
        ASSERT_EQ_INT(fstab_options_parse("x-systemd.device-timeout=0", &o), 0);
        ASSERT_EQ_INT(fstab_device_timeout(&o, 7, &clamped), FSTAB_DEVICE_TIMEOUT_MAX);
        ASSERT_TRUE(clamped);
        fstab_options_done(&o);
        ASSERT_EQ_INT(fstab_options_parse("x-systemd.device-timeout=infinity", &o), 0);
        ASSERT_EQ_INT(fstab_device_timeout(&o, 7, &clamped), FSTAB_DEVICE_TIMEOUT_MAX);
        ASSERT_TRUE(clamped);
        fstab_options_done(&o);
        ASSERT_EQ_INT(fstab_options_parse("x-systemd.device-timeout=10min", &o), 0);
        ASSERT_EQ_INT(fstab_device_timeout(&o, 7, &clamped), FSTAB_DEVICE_TIMEOUT_MAX);
        ASSERT_TRUE(clamped);
        fstab_options_done(&o);

        ASSERT_EQ_INT(fstab_device_timeout(NULL, 7, NULL), 7);
        ASSERT_TRUE(FSTAB_DEVICE_TIMEOUT_DEFAULT < FSTAB_DEVICE_TIMEOUT_MAX);
}

static void expect(FstabTag tag, const char *value, PicoFsKind hint, int want, const char *want_node) {
        FstabResolver r = { .sys_root = sys, .dev_root = dev };
        char got[PATH_MAX], path[PATH_MAX + 16];
        int k;

        k = fstab_resolve(&r, tag, value, hint, got, sizeof(got));
        if (k != want) {
                fprintf(stderr, "%s=%s: got %d, want %d\n", fstab_tag_to_string(tag), value, k, want);
                ASSERT_TRUE(false);
        }
        if (want_node) {
                node(path, sizeof(path), want_node);
                ASSERT_STREQ(got, path);
        }
}

static void test_resolve(void) {
        /* GPT partition entries, matched back to their partition by number. */
        expect(FSTAB_TAG_PARTUUID, PART_A, PICO_FS_NONE, 1, "vda1");
        expect(FSTAB_TAG_PARTUUID, PART_B, PICO_FS_NONE, 1, "vda2");
        expect(FSTAB_TAG_PARTLABEL, "data", PICO_FS_NONE, 1, "vda2");
        expect(FSTAB_TAG_PARTLABEL, "My Data", PICO_FS_NONE, 1, "vda3");
        /* Exact, as a link-name lookup is. */
        expect(FSTAB_TAG_PARTUUID, "12345678-9ABC-DEF0-1234-56789ABCDEF0", PICO_FS_NONE, 0, NULL);
        expect(FSTAB_TAG_PARTLABEL, "Data", PICO_FS_NONE, 0, NULL);

        /* Filesystem identity, by type and by "auto". A clone on vdb1 is
         * logged; vda1 comes first in name order and wins. */
        expect(FSTAB_TAG_UUID, UUID_X, PICO_FS_EXT, 1, "vda1");
        expect(FSTAB_TAG_UUID, UUID_X, PICO_FS_NONE, 1, "vda1");
        expect(FSTAB_TAG_LABEL, "clone", PICO_FS_NONE, 1, "vdb1");
        expect(FSTAB_TAG_LABEL, "DATA", PICO_FS_EXT, 1, "vda2");
        expect(FSTAB_TAG_LABEL, "my disk", PICO_FS_NONE, 1, "vda3");
        /* The wrong reader finds nothing: vda1 is ext, not FAT. */
        expect(FSTAB_TAG_UUID, UUID_X, PICO_FS_VFAT, 0, NULL);

        /* A whole disk with no partitions is read as a whole; one with
         * partitions is not, whatever its first sectors say. */
        expect(FSTAB_TAG_LABEL, "picoswap", PICO_FS_SWAP, 1, "mmcblk0");
        expect(FSTAB_TAG_UUID, UUID_Z, PICO_FS_SWAP, 1, "mmcblk0");
        expect(FSTAB_TAG_LABEL, "whole-vdb", PICO_FS_NONE, 0, NULL);

        /* Never read: nothing behind it, and MTD flash. */
        expect(FSTAB_TAG_LABEL, "loopfs", PICO_FS_NONE, 0, NULL);
        expect(FSTAB_TAG_LABEL, "flashfs", PICO_FS_NONE, 0, NULL);
        expect(FSTAB_TAG_LABEL, "ramfs", PICO_FS_NONE, 0, NULL);

        /* cciss!c0d0 is /dev/cciss/c0d0. */
        expect(FSTAB_TAG_LABEL, "array", PICO_FS_EXT, 1, "cciss/c0d0");

        /* A type no reader handles is refused up front, not searched for. */
        expect(FSTAB_TAG_UUID, UUID_X, _PICO_FS_KIND_MAX, -EOPNOTSUPP, NULL);
        expect(FSTAB_TAG_NONE, UUID_X, PICO_FS_NONE, -EINVAL, NULL);

        /* No sysfs at all is an error, not "not there yet". */
        {
                FstabResolver r = { .sys_root = "/nonexistent-sys", .dev_root = dev };
                char got[PATH_MAX];

                ASSERT_EQ_INT(fstab_resolve(&r, FSTAB_TAG_UUID, UUID_X, PICO_FS_NONE, got, sizeof(got)),
                              -ENOENT);
        }
}

/* --- the wait --- */

typedef struct Arrival {
        unsigned on_attempt;
        unsigned seen;
        void (*arrive)(void);
} Arrival;

static void hook(void *userdata, unsigned attempt) {
        Arrival *a = userdata;

        a->seen = attempt;
        if (attempt == a->on_attempt)
                a->arrive();
}

static void arrive_path(void) {
        char path[PATH_MAX + 16];

        node(path, sizeof(path), "late");
        ASSERT_EQ_INT(test_image_write(path, 4096, NULL, 0, 0), 0);
}

static void arrive_card(void) {
        ASSERT_EQ_INT(test_block_device(sys, "sdc", NULL, 0, 2048), 0);
        ext_node("sdc", uuid_y, "late card");
}

static void arrive_other(void) {
        ASSERT_EQ_INT(test_block_device(sys, "sdm", NULL, 0, 2048), 0);
        ext_node("sdm", uuid_y, "unrelated");
}

static void test_wait(void) {
        unsigned scans = 0;
        FstabResolver r = { .sys_root = sys, .dev_root = dev, .scans = &scans };
        char got[PATH_MAX], path[PATH_MAX + 16], what[PATH_MAX + 16];
        Arrival a = { 0 };
        usec_t t0;

        /* Present: found on the first look, no poll at all. */
        a.on_attempt = 99;
        a.arrive = arrive_path;
        ASSERT_EQ_INT(fstab_wait_device(
                                      &r, "LABEL=rootfs", PICO_FS_NONE, 5 * USEC_PER_SEC, hook, &a, got, sizeof(got)),
                      1);
        ASSERT_EQ_INT(a.seen, 0);

        /* A plain path that appears on the second poll. */
        node(what, sizeof(what), "late");
        a = (Arrival){ .on_attempt = 2, .arrive = arrive_path };
        ASSERT_EQ_INT(fstab_wait_device(&r, what, PICO_FS_NONE, 5 * USEC_PER_SEC, hook, &a, got, sizeof(got)),
                      1);
        ASSERT_STREQ(got, what);
        ASSERT_EQ_INT(a.seen, 2);

        /* A card that turns up on the first poll, found by label. */
        a = (Arrival){ .on_attempt = 1, .arrive = arrive_card };
        ASSERT_EQ_INT(fstab_wait_device(
                                      &r,
                                      "LABEL=late card",
                                      PICO_FS_EXT,
                                      5 * USEC_PER_SEC,
                                      hook,
                                      &a,
                                      got,
                                      sizeof(got)),
                      1);
        node(path, sizeof(path), "sdc");
        ASSERT_STREQ(got, path);

        /* Never there: the wait ends at its timeout, not before and not
         * long after -- and with nothing changing in sysfs, the devices are
         * read once, not once per poll. */
        a = (Arrival){ .on_attempt = 99, .arrive = arrive_path };
        scans = 0;
        t0 = now_monotonic();
        ASSERT_EQ_INT(fstab_wait_device(
                                      &r,
                                      "LABEL=never",
                                      PICO_FS_NONE,
                                      250 * USEC_PER_MSEC,
                                      hook,
                                      &a,
                                      got,
                                      sizeof(got)),
                      0);
        ASSERT_TRUE(now_monotonic() - t0 >= 250 * USEC_PER_MSEC);
        ASSERT_TRUE(now_monotonic() - t0 < 2 * USEC_PER_SEC);
        ASSERT_TRUE(a.seen >= 2);
        ASSERT_EQ_INT(scans, 1);

        /* A device arriving is a change, and gets a second read. */
        a = (Arrival){ .on_attempt = 1, .arrive = arrive_other };
        scans = 0;
        ASSERT_EQ_INT(fstab_wait_device(
                                      &r,
                                      "LABEL=never",
                                      PICO_FS_NONE,
                                      250 * USEC_PER_MSEC,
                                      hook,
                                      &a,
                                      got,
                                      sizeof(got)),
                      0);
        ASSERT_EQ_INT(scans, 2);

        /* A zero timeout is exactly one look. */
        a = (Arrival){ .on_attempt = 99, .arrive = arrive_path };
        ASSERT_EQ_INT(fstab_wait_device(&r, "/nonexistent/node", PICO_FS_NONE, 0, hook, &a, got, sizeof(got)),
                      0);
        ASSERT_EQ_INT(a.seen, 0);

        /* An error waiting cannot fix returns at once. */
        ASSERT_EQ_INT(fstab_wait_device(
                                      &r,
                                      "UUID=" UUID_X,
                                      _PICO_FS_KIND_MAX,
                                      5 * USEC_PER_SEC,
                                      NULL,
                                      NULL,
                                      got,
                                      sizeof(got)),
                      -EOPNOTSUPP);

        /* The by-* spelling waits for the tag, not for a link nobody makes. */
        ASSERT_EQ_INT(fstab_wait_device(
                                      &r,
                                      "/dev/disk/by-label/my\\x20disk",
                                      PICO_FS_NONE,
                                      0,
                                      NULL,
                                      NULL,
                                      got,
                                      sizeof(got)),
                      1);
        node(path, sizeof(path), "vda3");
        ASSERT_STREQ(got, path);
}

int main(void) {
        test_source_tag();
        test_device_timeout();

        fixture();
        test_resolve();
        test_wait();

        test_rm_rf(root);
        printf("test-fstab-resolve: all checks passed\n");
        return 0;
}
