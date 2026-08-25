/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Fixture-driven test for the GPT reader: real partition tables assembled byte
 * by byte here, written to a real file, read back through the real parser.
 *
 * Built rather than checked in, for the same reason test-status.c writes its
 * os-release files instead of shipping them: a binary blob in the tree is a
 * fixture nobody can review. Every offset the parser reads is an offset this
 * file writes, so the two agreeing is a statement about the format rather than
 * about a byte array somebody once captured -- and the CRC-32s the format
 * carries make a fixture that "looks right" but was assembled wrong fail here
 * rather than pass by accident.
 *
 * The corruption cases matter as much as the valid one. A partition table is
 * data off a disk, parsed by PID 1 as root before anything else runs, and every
 * length in it is a number the table itself supplies -- so a header claiming
 * four billion entries, an entry array pointed past the end of the device, and
 * a truncated header are all exercised deliberately here rather than left to a
 * board to discover.
 *
 * What is NOT covered, on purpose and following the same split as
 * test-dev-setup.c: swapon(2) itself, and the sysfs walk from a partition
 * number back to a device node. Both need a real kernel with a real block
 * device, so they are proven by a qemuarmv5 boot capture showing /proc/swaps
 * with the discovered partition in it, not by a unit test that would have to
 * mount something on the machine running it.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpt-scan.h"
#include "test-util.h"
#include "util.h"

/*
 * The fixture disk: 1 MiB, 512-byte blocks, header at LBA 1, a 128 x 128-byte
 * entry array at LBA 2. Exactly the layout wic writes for this project's own
 * qemuarmv5 image, which is what makes these tables representative rather than
 * merely legal.
 */
#define FIX_BS 512u
#define FIX_SIZE (1024u * 1024u)
#define FIX_ENTRY_LBA 2u
#define FIX_ENTRY_COUNT 128u
#define FIX_ENTRY_SIZE 128u

/* Header field offsets, spelled out again here rather than shared with the
 * parser: a test that imported the parser's own offsets could only prove it is
 * self-consistent. */
#define H_HEADER_SIZE 12u
#define H_HEADER_CRC 16u
#define H_MY_LBA 24u
#define H_ENTRY_LBA 72u
#define H_ENTRY_COUNT 80u
#define H_ENTRY_SIZE 84u
#define H_ARRAY_CRC 88u

/* 69dad710-2ce4-4e3c-b16c-21a1d49abed3 -- the Discoverable Partitions Spec's
 * root type for 32-bit ARM, which is what this project's own wks file stamps
 * onto the qemuarmv5 rootfs partition. Present here as the realistic neighbour
 * a swap search has to walk past. */
static const GptGuid type_root_arm = {
        { 0x10, 0xd7, 0xda, 0x69, 0xe4, 0x2c, 0x3c, 0x4e, 0xb1, 0x6c, 0x21, 0xa1, 0xd4, 0x9a, 0xbe, 0xd3 }
};

/* An arbitrary non-DPS type: 0fc63daf-8483-4772-8e79-3d69d8477de4, the generic
 * "Linux filesystem data" GUID. Nothing should ever match it here. */
static const GptGuid type_linux_data = {
        { 0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4 }
};

static const GptGuid uuid_root = {
        { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }
};

/* 5c2d1f7a-9b3e-4a11-8f42-6d7e0c9a1b23 in on-disk byte order, so the string
 * the parser prints for it can be asserted against something specific. */
static const GptGuid uuid_swap = {
        { 0x7a, 0x1f, 0x2d, 0x5c, 0x3e, 0x9b, 0x11, 0x4a, 0x8f, 0x42, 0x6d, 0x7e, 0x0c, 0x9a, 0x1b, 0x23 }
};

static void put_le32(uint8_t *p, uint32_t v) {
        p[0] = (uint8_t) v;
        p[1] = (uint8_t) (v >> 8);
        p[2] = (uint8_t) (v >> 16);
        p[3] = (uint8_t) (v >> 24);
}

static void put_le64(uint8_t *p, uint64_t v) {
        put_le32(p, (uint32_t) v);
        put_le32(p + 4, (uint32_t) (v >> 32));
}

static uint32_t get_le32(const uint8_t *p) {
        return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static uint8_t *header_of(uint8_t *disk) {
        return disk + FIX_BS;
}

static uint8_t *entries_of(uint8_t *disk) {
        return disk + FIX_ENTRY_LBA * FIX_BS;
}

/* A zeroed disk carrying only the protective MBR a real GPT disk starts with.
 * The parser ignores LBA 0 entirely; it is here so the fixtures are the shape
 * of a real disk rather than the subset the parser happens to look at. */
static uint8_t *disk_new(void) {
        uint8_t *disk = calloc(1, FIX_SIZE);

        ASSERT_TRUE(disk != NULL);

        disk[446 + 4] = 0xee; /* partition type 0xEE: "the whole disk is GPT" */
        disk[510] = 0x55;
        disk[511] = 0xaa;

        return disk;
}

static void header_write(uint8_t *disk) {
        uint8_t *h = header_of(disk);

        memset(h, 0, FIX_BS);
        memcpy(h, "EFI PART", 8);
        put_le32(h + 8, 0x00010000); /* revision 1.0 */
        put_le32(h + H_HEADER_SIZE, 92);
        put_le64(h + H_MY_LBA, 1);
        put_le64(h + 32, (FIX_SIZE / FIX_BS) - 1); /* alternate (backup) LBA */
        put_le64(h + 40, 34);                      /* first usable */
        put_le64(h + 48, (FIX_SIZE / FIX_BS) - 34);
        put_le64(h + H_ENTRY_LBA, FIX_ENTRY_LBA);
        put_le32(h + H_ENTRY_COUNT, FIX_ENTRY_COUNT);
        put_le32(h + H_ENTRY_SIZE, FIX_ENTRY_SIZE);
}

static void
                entry_write(uint8_t *disk,
                            unsigned nr,
                            const GptGuid *type,
                            const GptGuid *uuid,
                            uint64_t first_lba,
                            uint64_t last_lba,
                            uint64_t attributes) {
        uint8_t *e = entries_of(disk) + (nr - 1) * FIX_ENTRY_SIZE;

        memcpy(e, type, sizeof(GptGuid));
        memcpy(e + 16, uuid, sizeof(GptGuid));
        put_le64(e + 32, first_lba);
        put_le64(e + 40, last_lba);
        put_le64(e + 48, attributes);
}

/*
 * Write an entry's UTF-16LE name field, at offset 56 of the 128-byte entry.
 * ASCII only in the helper; the non-ASCII and surrogate cases below poke the
 * code units in directly, since that is the whole point of testing a decoder.
 */
static void entry_name_write(uint8_t *disk, unsigned nr, const char *name) {
        uint8_t *e = entries_of(disk) + (nr - 1) * FIX_ENTRY_SIZE;

        for (size_t i = 0; i < 36 && name[i]; i++)
                e[56 + i * 2] = (uint8_t) name[i];
}

/* Recompute the header's own checksum over its declared size, with the CRC
 * field zeroed -- the format's own rule, and the step every corruption case
 * below either repeats (to test something other than the CRC) or skips (to test
 * the CRC itself). */
static void header_crc_fix(uint8_t *disk) {
        uint8_t *h = header_of(disk);

        put_le32(h + H_HEADER_CRC, 0);
        put_le32(h + H_HEADER_CRC, gpt_crc32(h, get_le32(h + H_HEADER_SIZE)));
}

static void gpt_finalize(uint8_t *disk) {
        uint8_t *h = header_of(disk);

        put_le32(h + H_ARRAY_CRC, gpt_crc32(entries_of(disk), FIX_ENTRY_COUNT * FIX_ENTRY_SIZE));
        header_crc_fix(disk);
}

/* The two-partition table this project actually builds: DPS-typed root at
 * entry 1, DPS-typed swap at entry 2. */
static uint8_t *disk_root_and_swap(uint64_t swap_attributes) {
        uint8_t *disk = disk_new();

        header_write(disk);
        entry_write(disk, 1, &type_root_arm, &uuid_root, 34, 1900, 0);
        entry_write(disk, 2, &gpt_type_linux_swap, &uuid_swap, 1901, 2013, swap_attributes);
        gpt_finalize(disk);

        return disk;
}

/*
 * Write `size` bytes to <dir>/disk.img, storing its path in `path` and
 * returning the directory the caller removes. Binary, so test_write_file()'s
 * string interface is no use here.
 */
static char *disk_fixture(const uint8_t *disk, size_t size, char *path, size_t path_size) {
        char *dir = test_tmpdir_new();
        FILE *f;

        ASSERT_TRUE(dir != NULL);
        ASSERT_TRUE((size_t) snprintf(path, path_size, "%s/disk.img", dir) < path_size);

        f = fopen(path, "we");
        ASSERT_TRUE(f != NULL);
        ASSERT_EQ_INT(fwrite(disk, 1, size, f), size);
        ASSERT_EQ_INT(fclose(f), 0);

        return dir;
}

/* Run one scan over an in-memory disk image and hand back the result. */
static int scan_image(const uint8_t *disk, size_t size, const GptGuid *type, GptPartition **ret, size_t *ret_n) {
        char path[PATH_MAX];
        char *dir;
        int r;

        dir = disk_fixture(disk, size, path, sizeof(path));
        r = gpt_scan(path, type, ret, ret_n);
        test_rm_rf(dir);
        free(dir);

        return r;
}

/* The same, through the enumerate-everything entry point devd uses. */
static int scan_all_image(const uint8_t *disk, size_t size, GptPartition **ret, size_t *ret_n) {
        char path[PATH_MAX];
        char *dir;
        int r;

        dir = disk_fixture(disk, size, path, sizeof(path));
        r = gpt_scan_all(path, ret, ret_n);
        test_rm_rf(dir);
        free(dir);

        return r;
}

/* The common shape of every rejection case: a valid GPT is not found, no
 * entries come back, and nothing crashes getting there. */
static void assert_no_table(const uint8_t *disk, size_t size) {
        GptPartition *p = (GptPartition *) 0x1; /* poisoned: the parser must overwrite it */
        size_t n = 42;

        ASSERT_EQ_INT(scan_image(disk, size, &gpt_type_linux_swap, &p, &n), 0);
        ASSERT_TRUE(p == NULL);
        ASSERT_EQ_INT(n, 0);
}

/*
 * The valid two-partition table: the swap partition is found by type GUID
 * alone, with its entry number, extent, attributes and unique GUID intact --
 * and the root partition sitting next to it is not confused for it.
 */
static void test_valid_two_partitions(void) {
        char uuid[GPT_GUID_STRING_MAX];
        GptPartition *p = NULL;
        uint8_t *disk;
        size_t n = 0;

        disk = disk_root_and_swap(0);

        ASSERT_EQ_INT(scan_image(disk, FIX_SIZE, &gpt_type_linux_swap, &p, &n), 1);
        ASSERT_EQ_INT(n, 1);
        ASSERT_EQ_INT(p[0].nr, 2);
        ASSERT_EQ_INT(p[0].first_lba, 1901);
        ASSERT_EQ_INT(p[0].last_lba, 2013);
        ASSERT_EQ_INT(p[0].attributes, 0);
        ASSERT_TRUE(memcmp(&p[0].type, &gpt_type_linux_swap, sizeof(GptGuid)) == 0);
        ASSERT_STREQ(gpt_guid_to_string(&p[0].uuid, uuid), "5c2d1f7a-9b3e-4a11-8f42-6d7e0c9a1b23");
        free(p);

        /* the same table, searched for the other type it carries */
        p = NULL;
        n = 0;
        ASSERT_EQ_INT(scan_image(disk, FIX_SIZE, &type_root_arm, &p, &n), 1);
        ASSERT_EQ_INT(n, 1);
        ASSERT_EQ_INT(p[0].nr, 1);
        free(p);

        free(disk);
}

/* No "EFI PART" magic at all: a clean no-op, exactly as the spec requires of a
 * non-GPT system, and not an error. Three shapes of it. */
static void test_not_gpt(void) {
        uint8_t *disk = disk_new();

        /* a disk with nothing but its protective MBR */
        assert_no_table(disk, FIX_SIZE);

        /* something else entirely where the header would be */
        memcpy(header_of(disk), "this is not a partition table", 29);
        assert_no_table(disk, FIX_SIZE);

        /* and a device too short to hold a header at either block size */
        assert_no_table(disk, 100);

        free(disk);
}

/*
 * The no-auto bit (63). The partition matches on type and is skipped anyway,
 * which is the spec's own rule and the one attribute a minimal implementation
 * still has to honour -- an installer that left a swap-typed partition marked
 * no-auto meant it.
 */
static void test_no_auto_is_skipped(void) {
        GptPartition *p = (GptPartition *) 0x1;
        uint8_t *disk;
        size_t n = 42;

        disk = disk_root_and_swap(UINT64_C(1) << 63);

        /* a valid table -- it is the partition that is skipped, not the disk */
        ASSERT_EQ_INT(scan_image(disk, FIX_SIZE, &gpt_type_linux_swap, &p, &n), 1);
        ASSERT_TRUE(p == NULL);
        ASSERT_EQ_INT(n, 0);

        free(disk);

        /* read-only (bit 60) is reported rather than acted on, so the same
         * partition still comes back with the flag visible to the caller */
        disk = disk_root_and_swap(UINT64_C(1) << 60);
        p = NULL;
        n = 0;

        ASSERT_EQ_INT(scan_image(disk, FIX_SIZE, &gpt_type_linux_swap, &p, &n), 1);
        ASSERT_EQ_INT(n, 1);
        ASSERT_TRUE((p[0].attributes & GPT_ATTR_READ_ONLY) != 0);
        free(p);

        free(disk);
}

/* A perfectly valid table with nothing of the wanted type in it. */
static void test_unrelated_type_ignored(void) {
        GptPartition *p = (GptPartition *) 0x1;
        uint8_t *disk = disk_new();
        size_t n = 42;

        header_write(disk);
        entry_write(disk, 1, &type_root_arm, &uuid_root, 34, 1900, 0);
        entry_write(disk, 2, &type_linux_data, &uuid_swap, 1901, 2013, 0);
        gpt_finalize(disk);

        ASSERT_EQ_INT(scan_image(disk, FIX_SIZE, &gpt_type_linux_swap, &p, &n), 1);
        ASSERT_TRUE(p == NULL);
        ASSERT_EQ_INT(n, 0);

        free(disk);
}

/*
 * Corrupt and hostile headers, one field at a time. Each case starts from the
 * valid table and breaks exactly one thing, so a pass here says which check
 * caught it rather than merely that something did.
 *
 * Every case that is not itself about a checksum repairs the header CRC after
 * the mutation -- otherwise the CRC check would catch all of them first and the
 * range checks behind it would never be reached.
 */
static void test_corrupt_header(void) {
        uint8_t *disk;

        /* the header itself truncated away with the rest of the device */
        disk = disk_root_and_swap(0);
        assert_no_table(disk, FIX_BS + 40);
        free(disk);

        /* a flipped byte anywhere in the header, with the CRC left alone */
        disk = disk_root_and_swap(0);
        header_of(disk)[H_MY_LBA] ^= 0xff;
        assert_no_table(disk, FIX_SIZE);
        free(disk);

        /* a flipped byte in the entry array: the header checksums fine and the
         * array's own checksum is what catches it */
        disk = disk_root_and_swap(0);
        entries_of(disk)[200] ^= 0xff;
        assert_no_table(disk, FIX_SIZE);
        free(disk);

        /* a header that does not claim to be the primary one */
        disk = disk_root_and_swap(0);
        put_le64(header_of(disk) + H_MY_LBA, 2047);
        header_crc_fix(disk);
        assert_no_table(disk, FIX_SIZE);
        free(disk);

        /* a header smaller than the format's own 92 bytes... */
        disk = disk_root_and_swap(0);
        put_le32(header_of(disk) + H_HEADER_SIZE, 40);
        header_crc_fix(disk);
        assert_no_table(disk, FIX_SIZE);
        free(disk);

        /* ...and one bigger than the block it was read out of, which is the
         * case that would read past the buffer if it were not checked */
        disk = disk_root_and_swap(0);
        put_le32(header_of(disk) + H_HEADER_SIZE, 100000);
        header_crc_fix(disk);
        assert_no_table(disk, FIX_SIZE);
        free(disk);

        /* an entry size of zero: an infinite number of entries in no space */
        disk = disk_root_and_swap(0);
        put_le32(header_of(disk) + H_ENTRY_SIZE, 0);
        header_crc_fix(disk);
        assert_no_table(disk, FIX_SIZE);
        free(disk);

        /* an entry size that is not a multiple of 8, which the spec forbids */
        disk = disk_root_and_swap(0);
        put_le32(header_of(disk) + H_ENTRY_SIZE, 129);
        header_crc_fix(disk);
        assert_no_table(disk, FIX_SIZE);
        free(disk);

        /* four billion entries: the allocation this must never attempt */
        disk = disk_root_and_swap(0);
        put_le32(header_of(disk) + H_ENTRY_COUNT, 0xffffffffU);
        header_crc_fix(disk);
        assert_no_table(disk, FIX_SIZE);
        free(disk);

        /* an entry array starting at LBA 0, i.e. on top of the MBR */
        disk = disk_root_and_swap(0);
        put_le64(header_of(disk) + H_ENTRY_LBA, 0);
        header_crc_fix(disk);
        assert_no_table(disk, FIX_SIZE);
        free(disk);

        /* an entry array at an LBA whose byte offset overflows anything sane */
        disk = disk_root_and_swap(0);
        put_le64(header_of(disk) + H_ENTRY_LBA, UINT64_MAX);
        header_crc_fix(disk);
        assert_no_table(disk, FIX_SIZE);
        free(disk);

        /* and one pointed just past the end of a real device */
        disk = disk_root_and_swap(0);
        put_le64(header_of(disk) + H_ENTRY_LBA, FIX_SIZE / FIX_BS);
        header_crc_fix(disk);
        assert_no_table(disk, FIX_SIZE);
        free(disk);
}

/* A device that is not there is an error, unlike a device with no table on
 * it -- the two are genuinely different answers and the caller logs them
 * differently. */
static void test_missing_device(void) {
        GptPartition *p = NULL;
        size_t n = 0;

        ASSERT_EQ_INT(gpt_scan("/nonexistent/disk", &gpt_type_linux_swap, &p, &n), -ENOENT);
        ASSERT_EQ_INT(gpt_scan(NULL, &gpt_type_linux_swap, &p, &n), -EINVAL);
}

/*
 * The GUID printer, against the one constant whose spelling this whole feature
 * depends on. A byte order got backwards here would make every DPS match fail
 * silently, and the disk would simply appear to have no swap on it.
 */
static void test_guid_string(void) {
        char buf[GPT_GUID_STRING_MAX];

        ASSERT_STREQ(gpt_guid_to_string(&gpt_type_linux_swap, buf), "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f");
        ASSERT_STREQ(gpt_guid_to_string(&type_root_arm, buf), "69dad710-2ce4-4e3c-b16c-21a1d49abed3");
        ASSERT_STREQ(gpt_guid_to_string(&type_linux_data, buf), "0fc63daf-8483-4772-8e79-3d69d8477de4");
}

/* The standard CRC-32 check value: "123456789" hashes to 0xcbf43926 in every
 * published table for this polynomial. Everything else in this file rests on
 * this being right. */
static void test_crc32(void) {
        ASSERT_EQ_INT(gpt_crc32("123456789", 9), 0xcbf43926U);
        ASSERT_EQ_INT(gpt_crc32("", 0), 0U);
}

/* Write a mountinfo fixture and return the directory holding it. */
static char *mountinfo_fixture(const char *content, char *path, size_t path_size) {
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "mountinfo", content), 0);
        ASSERT_TRUE((size_t) snprintf(path, path_size, "%s/mountinfo", dir) < path_size);

        return dir;
}

static int boot_disk_of(const char *content, char *node, size_t node_size) {
        char path[PATH_MAX];
        char *dir;
        int r;

        dir = mountinfo_fixture(content, path, sizeof(path));
        r = gpt_boot_disk(path, node, node_size, NULL, 0);
        test_rm_rf(dir);
        free(dir);

        return r;
}

/* The first real entry under /sys/dev/block, or false if sysfs is not
 * available -- which it is not on every machine this suite might run on. */
static bool find_real_block_device(char *ret, size_t size) {
        struct dirent *e;
        bool found = false;
        DIR *d;

        d = opendir("/sys/dev/block");
        if (!d)
                return false;

        while ((e = readdir(d))) {
                if (e->d_name[0] == '.')
                        continue;

                found = (size_t) snprintf(ret, size, "%s", e->d_name) < size;
                break;
        }

        closedir(d);

        return found;
}

/*
 * Boot-disk identification, over the half of it that can be settled without a
 * particular kernel underneath: which mountinfo line is believed, and what
 * happens when the answer is not a block device.
 *
 * The other half -- resolving /sys/dev/block/<maj>:<min> through its parent
 * directory to the containing disk, and finding the partition's node again from
 * its number -- needs a real disk with real partitions, and is proven by the
 * qemuarmv5 boot capture instead.
 */
static void test_boot_disk(void) {
        char node[PATH_MAX], devno[64];

        /* no mount on "/" at all */
        ASSERT_EQ_INT(boot_disk_of("21 20 0:19 / /proc rw - proc proc rw\n", node, sizeof(node)), -ENOENT);

        /* a file that is not there */
        ASSERT_EQ_INT(gpt_boot_disk("/nonexistent/mountinfo", node, sizeof(node), NULL, 0), -ENOENT);

        /* major 0: a root filesystem with no block device under it, which is
         * what an initramfs looks like and is an ordinary answer */
        ASSERT_EQ_INT(boot_disk_of("1 1 0:2 / / rw - rootfs rootfs rw\n", node, sizeof(node)), -ENOENT);

        /* a device number nothing in sysfs answers to */
        ASSERT_EQ_INT(boot_disk_of("1 1 4095:4095 / / rw - ext4 /dev/nope rw\n", node, sizeof(node)), -ENOENT);

        /* a line too short to be a mountinfo line is skipped, not fatal, and
         * does not stop the real line after it from being read */
        ASSERT_EQ_INT(boot_disk_of("truncated\n1 1 0:2 / / rw - rootfs rootfs rw\n", node, sizeof(node)),
                      -ENOENT);

        /*
         * Last line wins. Two mounts on "/", the second one real: getting an
         * answer at all proves the second was the one believed, since the first
         * is the major-0 case that returns -ENOENT just above. Skipped where
         * there is no sysfs to point at.
         */
        if (find_real_block_device(devno, sizeof(devno))) {
                char mountinfo[256];

                snprintf(mountinfo,
                         sizeof(mountinfo),
                         "1 1 0:2 / / rw - rootfs rootfs rw\n"
                         "2 1 %s / / rw - ext4 /dev/real rw\n",
                         devno);

                ASSERT_EQ_INT(boot_disk_of(mountinfo, node, sizeof(node)), 0);
                ASSERT_TRUE(strncmp(node, "/dev/", 5) == 0);
        }
}

/*
 * gpt_scan_all(): every used entry, whatever its type, no-auto ones included
 * and flagged rather than dropped.
 *
 * The two differences from gpt_scan() are exactly what devd needs and exactly
 * what a type-filtered search cannot give it. It has to name every partition it
 * sees before deciding what to do with any of them, and it has to be able to
 * SEE a no-auto partition in order to deliberately not mount it -- an entry
 * silently dropped by the parser is one the daemon cannot decline.
 */
static void test_scan_all(void) {
        GptPartition *parts = NULL;
        size_t n = 0;
        uint8_t *disk;

        disk = disk_root_and_swap(GPT_ATTR_NO_AUTO);
        entry_name_write(disk, 1, "rootfs");
        entry_name_write(disk, 2, "swap");
        gpt_finalize(disk);

        ASSERT_EQ_INT(scan_all_image(disk, FIX_SIZE, &parts, &n), 1);
        ASSERT_EQ_INT(n, 2);

        ASSERT_EQ_INT(parts[0].nr, 1);
        ASSERT_STREQ(parts[0].name, "rootfs");
        ASSERT_EQ_INT(parts[0].attributes, 0);

        /* The no-auto partition gpt_scan() would have dropped, present with
         * the bit still set for the caller to act on. */
        ASSERT_EQ_INT(parts[1].nr, 2);
        ASSERT_STREQ(parts[1].name, "swap");
        ASSERT_TRUE((parts[1].attributes & GPT_ATTR_NO_AUTO) != 0);

        free(parts);
        free(disk);

        /* A disk with no table answers 0 here too, rather than differently
         * from gpt_scan() -- devd's "no GPT, leave it alone" path depends on
         * the two agreeing. */
        disk = disk_new();
        ASSERT_EQ_INT(scan_all_image(disk, FIX_SIZE, &parts, &n), 0);
        ASSERT_EQ_INT(n, 0);
        ASSERT_TRUE(parts == NULL);
        free(disk);
}

/*
 * The partition-name decoder, which is the field /dev/disk/by-partlabel and
 * /media/<partlabel> are both built out of.
 *
 * UTF-16LE in, UTF-8 out, and the interesting cases are all the ones a disk can
 * carry but a well-formed name cannot: a lone low surrogate, a high surrogate
 * with nothing after it, a name filling the field with no terminator. Every one
 * of those has to produce valid UTF-8 or nothing, because what comes out is
 * used as a path component.
 */
static void test_partition_name(void) {
        GptPartition *parts = NULL;
        uint8_t *disk, *e;
        size_t n = 0;

        disk = disk_root_and_swap(0);
        e = entries_of(disk);

        /* Entry 1: "Ångström" -- two-byte and three-byte UTF-8 output from
         * plain BMP code units, which is the ordinary non-ASCII case. */
        {
                static const uint16_t units[] = { 0x00c5, 'n', 'g', 's', 't', 'r', 0x00f6, 'm', 0 };

                for (size_t i = 0; units[i]; i++) {
                        e[56 + i * 2] = (uint8_t) (units[i] & 0xff);
                        e[56 + i * 2 + 1] = (uint8_t) (units[i] >> 8);
                }
        }

        /* Entry 2: a surrogate pair (U+1F4BE) followed by a lone low
         * surrogate, which must be dropped rather than emitted. */
        {
                static const uint16_t units[] = { 0xd83d, 0xdcbe, 0xdc00, 'x', 0 };
                uint8_t *e2 = e + FIX_ENTRY_SIZE;

                for (size_t i = 0; units[i]; i++) {
                        e2[56 + i * 2] = (uint8_t) (units[i] & 0xff);
                        e2[56 + i * 2 + 1] = (uint8_t) (units[i] >> 8);
                }
        }

        gpt_finalize(disk);

        ASSERT_EQ_INT(scan_all_image(disk, FIX_SIZE, &parts, &n), 1);
        ASSERT_EQ_INT(n, 2);
        ASSERT_STREQ(parts[0].name, "\xc3\x85ngstr\xc3\xb6m");
        ASSERT_STREQ(parts[1].name, "\xf0\x9f\x92\xbex");

        free(parts);
        free(disk);

        /* A name filling all 36 code units, with no terminator in the field --
         * legal on disk, and the case a decoder that trusts a NUL walks off
         * the end of. */
        disk = disk_root_and_swap(0);

        for (size_t i = 0; i < 36; i++)
                entries_of(disk)[56 + i * 2] = 'A';

        gpt_finalize(disk);

        ASSERT_EQ_INT(scan_all_image(disk, FIX_SIZE, &parts, &n), 1);
        ASSERT_EQ_INT(strlen(parts[0].name), 36);

        free(parts);
        free(disk);

        /* An unnamed partition is "", not a link name nobody asked for. */
        disk = disk_root_and_swap(0);
        ASSERT_EQ_INT(scan_all_image(disk, FIX_SIZE, &parts, &n), 1);
        ASSERT_STREQ(parts[0].name, "");
        free(parts);
        free(disk);
}

int main(void) {
        test_crc32();
        test_guid_string();
        test_valid_two_partitions();
        test_not_gpt();
        test_no_auto_is_skipped();
        test_unrelated_type_ignored();
        test_corrupt_header();
        test_missing_device();
        test_boot_disk();
        test_scan_all();
        test_partition_name();

        printf("test-gpt-scan: all checks passed\n");
        return 0;
}
