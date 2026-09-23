/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The shared half of the identity readers: the bounded read, the UUID and
 * label formatting every reader leans on, CRC-32C, the type table, and the
 * dispatcher, driven through the ext reader against an image file.
 *
 * The formatting checks pin blkid's own output shapes, because an fstab
 * UUID=/LABEL= value is copied from blkid and compared byte for byte.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ext-super.h"
#include "fsid.h"
#include "test-util.h"

static void test_uuid_format(void) {
        static const uint8_t u[16] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
                                       0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
        static const uint8_t zero[16] = { 0 };
        char s[PICO_FS_UUID_MAX];

        pico_fs_uuid_format(u, s);
        ASSERT_STREQ(s, "12345678-90ab-cdef-0123-456789abcdef");

        /* All-zero is "none", not a UUID every blank device would share. */
        pico_fs_uuid_format(zero, s);
        ASSERT_STREQ(s, "");

        ASSERT_TRUE(pico_fs_bytes_zero(zero, 16));
        ASSERT_TRUE(!pico_fs_bytes_zero(u, 16));
        ASSERT_TRUE(pico_fs_bytes_zero(u, 0));
}

static void test_label(void) {
        char s[PICO_FS_LABEL_MAX], tiny[4];

        /* Stops at NUL, drops trailing whitespace of every kind, keeps
         * leading and inner whitespace. */
        pico_fs_label_set(s, sizeof(s), (const uint8_t *) " MY DISK \t\r\n", 12);
        ASSERT_STREQ(s, " MY DISK");
        pico_fs_label_set(s, sizeof(s), (const uint8_t *) "AB\0CD", 5);
        ASSERT_STREQ(s, "AB");

        /* A FAT field is space-padded to 11 bytes with no NUL at all. */
        pico_fs_label_set(s, sizeof(s), (const uint8_t *) "BOOT       XXXX", 11);
        ASSERT_STREQ(s, "BOOT");

        /* A byte >= 0x80 is a code-page character, never whitespace, and is
         * passed through untouched -- 0xa0 is a space in Latin-1, not here. */
        pico_fs_label_set(s, sizeof(s), (const uint8_t *) "CAF\x82\xa0", 5);
        ASSERT_STREQ(s, "CAF\x82\xa0");

        pico_fs_label_set(s, sizeof(s), (const uint8_t *) "       ", 7);
        ASSERT_STREQ(s, "");

        /* Always terminated, even when the field is longer than the buffer. */
        pico_fs_label_set(tiny, sizeof(tiny), (const uint8_t *) "ABCDEFG", 7);
        ASSERT_STREQ(tiny, "ABC");
}

static void test_label_utf16(void) {
        char s[PICO_FS_LABEL_MAX], small[5];

        /* "Ab" then a NUL unit: stops there. */
        pico_fs_label_set_utf16le(s, sizeof(s), (const uint8_t *) "A\0b\0\0\0Z\0", 8);
        ASSERT_STREQ(s, "Ab");

        /* U+00E9 (2 bytes), U+20AC (3 bytes), U+1F600 as a surrogate pair
         * (4 bytes), trailing spaces trimmed. */
        {
                static const uint8_t in[] = { 0xe9, 0x00, 0xac, 0x20, 0x3d, 0xd8, 0x00, 0xde, 0x20, 0x00 };

                pico_fs_label_set_utf16le(s, sizeof(s), in, sizeof(in));
                ASSERT_STREQ(s, "\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80");
        }

        /* An unpaired high surrogate is passed through as its own 3-byte
         * sequence, as util-linux passes it; so is a lone low one. */
        {
                static const uint8_t in[] = { 0x00, 0xd8, 0x41, 0x00, 0x00, 0xdc };

                pico_fs_label_set_utf16le(s, sizeof(s), in, sizeof(in));
                ASSERT_STREQ(s,
                             "\xed\xa0\x80"
                             "A"
                             "\xed\xb0\x80");
        }

        /* An odd trailing byte is not half a character. */
        pico_fs_label_set_utf16le(s, sizeof(s), (const uint8_t *) "A\0B", 3);
        ASSERT_STREQ(s, "A");

        /* A full buffer stops before a character, never inside one. */
        {
                static const uint8_t in[] = { 'a', 0, 'b', 0, 0xac, 0x20 };

                pico_fs_label_set_utf16le(small, sizeof(small), in, sizeof(in));
                ASSERT_STREQ(small, "ab");
        }
}

static void test_crc32c(void) {
        /* The standard check value for CRC-32C over "123456789". */
        ASSERT_EQ_INT(~pico_crc32c(~0U, "123456789", 9), 0xe3069283U);

        /* Fed in pieces, the same answer. */
        ASSERT_EQ_INT(~pico_crc32c(pico_crc32c(~0U, "1234", 4), "56789", 5), 0xe3069283U);

        ASSERT_EQ_INT(~pico_crc32c(~0U, "", 0), 0);
}

static void test_endian(void) {
        static const uint8_t b[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

        ASSERT_EQ_INT(pico_le16(b), 0x0201);
        ASSERT_EQ_INT(pico_le32(b), 0x04030201U);
        ASSERT_TRUE(pico_le64(b) == UINT64_C(0x0807060504030201));
        ASSERT_EQ_INT(pico_be16(b), 0x0102);
        ASSERT_EQ_INT(pico_be32(b), 0x01020304U);
        ASSERT_TRUE(pico_be64(b) == UINT64_C(0x0102030405060708));
}

static void test_kinds(void) {
        ASSERT_EQ_INT(pico_fs_kind_from_type("ext2"), PICO_FS_EXT);
        ASSERT_EQ_INT(pico_fs_kind_from_type("ext3"), PICO_FS_EXT);
        ASSERT_EQ_INT(pico_fs_kind_from_type("ext4"), PICO_FS_EXT);
        ASSERT_EQ_INT(pico_fs_kind_from_type("auto"), PICO_FS_NONE);
        ASSERT_EQ_INT(pico_fs_kind_from_type(NULL), PICO_FS_NONE);
        ASSERT_EQ_INT(pico_fs_kind_from_type("f2fs"), _PICO_FS_KIND_MAX);
        ASSERT_EQ_INT(pico_fs_kind_from_type("EXT4"), _PICO_FS_KIND_MAX);

        ASSERT_STREQ(pico_fs_kind_to_string(PICO_FS_EXT), "ext4");

        /* Every reader has a name, and every name maps back to its reader. */
        for (int k = PICO_FS_NONE + 1; k < _PICO_FS_KIND_MAX; k++) {
                const char *name = pico_fs_kind_to_string((PicoFsKind) k);

                ASSERT_TRUE(name != NULL);
                ASSERT_EQ_INT(pico_fs_kind_from_type(name), k);
        }
        ASSERT_TRUE(pico_fs_kind_to_string(PICO_FS_NONE) == NULL);
        ASSERT_TRUE(pico_fs_kind_to_string(_PICO_FS_KIND_MAX) == NULL);
}

static char *write_image(const char *dir, const char *name, const uint8_t *data, size_t n, uint64_t at) {
        char *path;
        int fd;

        path = malloc(PATH_MAX);
        ASSERT_TRUE(path != NULL);
        snprintf(path, PATH_MAX, "%s/%s", dir, name);

        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT(pwrite(fd, data, n, (off_t) at), (ssize_t) n);
        ASSERT_EQ_INT(close(fd), 0);

        return path;
}

static void test_read_and_dispatch(void) {
        uint8_t sb[EXT_SUPER_SIZE], buf[8];
        char *dir, *path, *tiny;
        PicoFsId id;
        int fd;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        /* An ext superblock with a space-padded label, which the ext decoder
         * keeps and the common shape trims. */
        memset(sb, 0, sizeof(sb));
        sb[EXT_SUPER_MAGIC_OFF] = 0x53;
        sb[EXT_SUPER_MAGIC_OFF + 1] = 0xef;
        memcpy(sb + EXT_SUPER_UUID_OFF, "\x12\x34\x56\x78\x90\xab\xcd\xef\x12\x34\x56\x78\x90\xab\xcd\xef", 16);
        memcpy(sb + EXT_SUPER_LABEL_OFF, "rootfs  ", 8);
        path = write_image(dir, "ext", sb, sizeof(sb), EXT_SUPER_OFFSET);

        ASSERT_EQ_INT(pico_fs_probe(path, PICO_FS_NONE, &id), 1);
        ASSERT_EQ_INT(id.kind, PICO_FS_EXT);
        ASSERT_STREQ(id.uuid, "12345678-90ab-cdef-1234-567890abcdef");
        ASSERT_STREQ(id.label, "rootfs");

        ASSERT_EQ_INT(pico_fs_probe(path, PICO_FS_EXT, &id), 1);
        ASSERT_EQ_INT(pico_fs_probe(path, _PICO_FS_KIND_MAX, &id), -EOPNOTSUPP);

        /* pico_fs_read: whole reads, and a device that ends early says so. */
        fd = open(path, O_RDONLY | O_CLOEXEC);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT(pico_fs_read(fd, EXT_SUPER_OFFSET + EXT_SUPER_MAGIC_OFF, buf, 2), 0);
        ASSERT_EQ_INT(buf[0], 0x53);
        ASSERT_EQ_INT(pico_fs_read(fd, EXT_SUPER_OFFSET + EXT_SUPER_SIZE - 4, buf, 8), -ENODATA);
        ASSERT_EQ_INT(pico_fs_read(fd, UINT64_MAX - 2, buf, 8), -EOVERFLOW);
        ASSERT_EQ_INT(close(fd), 0);

        /* Nothing recognisable: 0, and the answer says "none". */
        {
                static const uint8_t junk[4096] = { 1 };

                tiny = write_image(dir, "junk", junk, sizeof(junk), 0);
                id.kind = PICO_FS_EXT;
                ASSERT_EQ_INT(pico_fs_probe(tiny, PICO_FS_NONE, &id), 0);
                ASSERT_EQ_INT(id.kind, PICO_FS_NONE);
                free(tiny);
        }

        /* Shorter than any superblock: not a filesystem, not an error. */
        tiny = write_image(dir, "tiny", (const uint8_t *) "x", 1, 0);
        ASSERT_EQ_INT(pico_fs_probe(tiny, PICO_FS_NONE, &id), 0);
        free(tiny);

        snprintf(path, PATH_MAX, "%s/absent", dir);
        ASSERT_EQ_INT(pico_fs_probe(path, PICO_FS_NONE, &id), -ENOENT);
        ASSERT_EQ_INT(pico_fs_probe(NULL, PICO_FS_NONE, &id), -EINVAL);

        free(path);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_uuid_format();
        test_label();
        test_label_utf16();
        test_crc32c();
        test_endian();
        test_kinds();
        test_read_and_dispatch();

        printf("test-fsid: all checks passed\n");
        return 0;
}
