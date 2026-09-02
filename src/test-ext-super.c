/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The ext superblock reader: superblocks built byte by byte here, decoded by the
 * real decoder.
 *
 * Built rather than checked in, in test-gpt-scan.c's style and for its reason: a
 * binary blob in the tree is a fixture nobody can review. The particular bytes
 * are not invented, though. They reproduce a real
 * `mke2fs -t ext4 -U 12345678-90ab-cdef-1234-567890abcdef -L PICOTEST` image
 * whose superblock was read raw at every offset below and cross-checked against
 * dumpe2fs, with the two state-carrying fields additionally toggled through
 * debugfs (`ssv state 2`, `features needs_recovery`) and re-read to pin their
 * bit values down. So what is under test is a verified property of ext4, not a
 * citation this test agrees with because it was written from the same citation.
 *
 * The dirty-state half matters more than the naming half, because it is the
 * gate in front of a filesystem checker on PID 1's own boot path: a
 * misread byte there is either a check that never runs on a damaged root or a
 * check that runs on every clean boot.
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
#include "test-util.h"

/*
 * The bytes read out of the real image:
 *
 *   magic  @+56  : 0xef53
 *   uuid   @+104 : 1234567890abcdef1234567890abcdef
 *   label  @+120 : "PICOTEST" NUL-padded to 16
 */
static const uint8_t real_uuid[16] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
                                       0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };

static void put_le16(uint8_t *p, uint16_t v) {
        p[0] = (uint8_t) v;
        p[1] = (uint8_t) (v >> 8);
}

static void put_le32(uint8_t *p, uint32_t v) {
        p[0] = (uint8_t) v;
        p[1] = (uint8_t) (v >> 8);
        p[2] = (uint8_t) (v >> 16);
        p[3] = (uint8_t) (v >> 24);
}

/*
 * A superblock the way mke2fs writes one: clean, journalled, nothing to
 * recover. The state fields are set here rather than left zero because "zero"
 * is itself a meaningful and alarming value for s_state -- VALID_FS clear -- and
 * a fixture that reached it by omission would make the clean case untestable.
 */
static void build_super(uint8_t sb[EXT_SUPER_SIZE], const uint8_t uuid[16], const char *label) {
        memset(sb, 0, EXT_SUPER_SIZE);

        /* s_magic, little-endian like every other ext field. */
        put_le16(sb + EXT_SUPER_MAGIC_OFF, (uint16_t) EXT_SUPER_MAGIC);

        put_le16(sb + EXT_SUPER_STATE_OFF, EXT_STATE_VALID_FS);
        put_le32(sb + EXT_SUPER_FEATURE_COMPAT_OFF, EXT_FEATURE_COMPAT_HAS_JOURNAL);

        if (uuid)
                memcpy(sb + EXT_SUPER_UUID_OFF, uuid, 16);

        if (label)
                /* Not strncpy: a 16-character label has no terminator on disk,
                 * and the copy below must be able to produce that case. */
                memcpy(sb + EXT_SUPER_LABEL_OFF, label, strlen(label) > 16 ? 16 : strlen(label));
}

/* --- naming: uuid and label --- */

static void test_ext_super(void) {
        uint8_t sb[EXT_SUPER_SIZE];
        PicoExtInfo fs;

        build_super(sb, real_uuid, "PICOTEST");
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 1);
        ASSERT_STREQ(fs.uuid, "12345678-90ab-cdef-1234-567890abcdef");
        ASSERT_STREQ(fs.label, "PICOTEST");

        /* An unlabelled filesystem, which is the common case: a uuid and
         * nothing else, and no by-label link to make. */
        build_super(sb, real_uuid, NULL);
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 1);
        ASSERT_STREQ(fs.label, "");
        ASSERT_STREQ(fs.uuid, "12345678-90ab-cdef-1234-567890abcdef");

        /* An all-zero uuid is "none", not a link called
         * 00000000-0000-0000-0000-000000000000 that every unformatted image
         * on the machine would collide on. */
        build_super(sb, NULL, "NOUUID");
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 1);
        ASSERT_STREQ(fs.uuid, "");
        ASSERT_STREQ(fs.label, "NOUUID");

        /* A label filling the whole 16-byte field, with no terminator on disk.
         * Copying it with a string function would read into s_last_mounted. */
        build_super(sb, real_uuid, "SIXTEENCHARSLONG");
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 1);
        ASSERT_STREQ(fs.label, "SIXTEENCHARSLONG");
        ASSERT_EQ_INT(strlen(fs.label), 16);

        /* No magic: not an ext filesystem, which is an answer rather than a
         * failure -- a FAT card gets exactly this. */
        memset(sb, 0, sizeof(sb));
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 0);

        /* Magic in the right place but the wrong value. */
        build_super(sb, real_uuid, "X");
        sb[EXT_SUPER_MAGIC_OFF] = 0x54;
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 0);

        /* A buffer too short to reach the last field this decodes cannot
         * answer either way, and says so rather than reading past its end. */
        build_super(sb, real_uuid, "PICOTEST");
        ASSERT_EQ_INT(ext_super_decode(sb, EXT_SUPER_LABEL_OFF + 4, &fs), -EINVAL);
        ASSERT_EQ_INT(ext_super_decode(sb, EXT_SUPER_LAST_ORPHAN_OFF + 3, &fs), -EINVAL);
        ASSERT_EQ_INT(ext_super_decode(sb, EXT_SUPER_LAST_ORPHAN_OFF + 4, &fs), 1);
        ASSERT_EQ_INT(ext_super_decode(NULL, sizeof(sb), &fs), -EINVAL);
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), NULL), -EINVAL);
}

/* --- dirty state: the gate in front of a checker --- */

static void test_ext_state(void) {
        uint8_t sb[EXT_SUPER_SIZE];
        PicoExtInfo fs;

        /* Cleanly unmounted: VALID_FS set, nothing else. */
        build_super(sb, real_uuid, "PICOTEST");
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 1);
        ASSERT_EQ_INT(fs.state, EXT_STATE_VALID_FS);
        ASSERT_EQ_INT(fs.feature_compat & EXT_FEATURE_COMPAT_HAS_JOURNAL, EXT_FEATURE_COMPAT_HAS_JOURNAL);
        ASSERT_EQ_INT(fs.feature_incompat & EXT_FEATURE_INCOMPAT_RECOVER, 0);
        ASSERT_EQ_INT(fs.last_orphan, 0);

        /* The kernel's own record that it hit an inconsistency. Note that
         * s_state is a bitfield: a filesystem can be both mounted-dirty and
         * errored, so this must not be an equality test anywhere. */
        build_super(sb, real_uuid, "PICOTEST");
        put_le16(sb + EXT_SUPER_STATE_OFF, EXT_STATE_ERROR_FS);
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 1);
        ASSERT_EQ_INT(fs.state & EXT_STATE_ERROR_FS, EXT_STATE_ERROR_FS);
        ASSERT_EQ_INT(fs.state & EXT_STATE_VALID_FS, 0);

        /* Errored but still marked valid -- what a running kernel leaves
         * behind after remounting a filesystem read-only on error. */
        build_super(sb, real_uuid, "PICOTEST");
        put_le16(sb + EXT_SUPER_STATE_OFF, EXT_STATE_VALID_FS | EXT_STATE_ERROR_FS);
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 1);
        ASSERT_EQ_INT(fs.state, EXT_STATE_VALID_FS | EXT_STATE_ERROR_FS);

        /* Orphan inodes were being deleted when it stopped. */
        build_super(sb, real_uuid, "PICOTEST");
        put_le16(sb + EXT_SUPER_STATE_OFF, EXT_STATE_ORPHAN_FS);
        put_le32(sb + EXT_SUPER_LAST_ORPHAN_OFF, 12345);
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 1);
        ASSERT_EQ_INT(fs.state & EXT_STATE_ORPHAN_FS, EXT_STATE_ORPHAN_FS);
        ASSERT_EQ_INT(fs.last_orphan, 12345);

        /* An unreplayed journal, which is a feature bit and not a state bit --
         * the one case where a checker is NOT the right answer. */
        build_super(sb, real_uuid, "PICOTEST");
        put_le32(sb + EXT_SUPER_FEATURE_INCOMPAT_OFF, EXT_FEATURE_INCOMPAT_RECOVER);
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 1);
        ASSERT_EQ_INT(fs.feature_incompat & EXT_FEATURE_INCOMPAT_RECOVER, EXT_FEATURE_INCOMPAT_RECOVER);

        /* A real image's feature words, byte for byte: the 0x3c/0x2c2 pair a
         * default `mke2fs -t ext4` writes, read back field by field. Wrong
         * offsets would land in s_first_ino or s_feature_ro_compat and this is
         * the assertion that would catch it. */
        build_super(sb, real_uuid, "PICOTEST");
        put_le32(sb + EXT_SUPER_FEATURE_COMPAT_OFF, 0x0000003cU);
        put_le32(sb + EXT_SUPER_FEATURE_INCOMPAT_OFF, 0x000002c2U);
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 1);
        ASSERT_EQ_INT(fs.feature_compat, 0x0000003cU);
        ASSERT_EQ_INT(fs.feature_incompat, 0x000002c2U);
        ASSERT_EQ_INT(fs.feature_incompat & EXT_FEATURE_INCOMPAT_RECOVER, 0);

        /* And the same image after `debugfs -w -R "features needs_recovery"`,
         * which moves exactly one bit. */
        put_le32(sb + EXT_SUPER_FEATURE_INCOMPAT_OFF, 0x000002c6U);
        ASSERT_EQ_INT(ext_super_decode(sb, sizeof(sb), &fs), 1);
        ASSERT_EQ_INT(fs.feature_incompat & EXT_FEATURE_INCOMPAT_RECOVER, EXT_FEATURE_INCOMPAT_RECOVER);
}

/* --- the read path: a real file with a real superblock at byte 1024 --- */

static void test_ext_device(void) {
        uint8_t sb[EXT_SUPER_SIZE];
        char *dir, path[PATH_MAX];
        PicoExtInfo fs;
        int fd;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        snprintf(path, sizeof(path), "%s/image", dir);

        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        ASSERT_TRUE(fd >= 0);

        /* The 1024 bytes before the superblock: a boot block on a real
         * filesystem, and never looked at here. */
        memset(sb, 0xa5, sizeof(sb));
        ASSERT_EQ_INT(write(fd, sb, EXT_SUPER_OFFSET), EXT_SUPER_OFFSET);

        build_super(sb, real_uuid, "PICOTEST");
        put_le16(sb + EXT_SUPER_STATE_OFF, EXT_STATE_ERROR_FS);
        ASSERT_EQ_INT(write(fd, sb, sizeof(sb)), (ssize_t) sizeof(sb));
        ASSERT_EQ_INT(close(fd), 0);

        ASSERT_EQ_INT(ext_super_read(path, &fs), 1);
        ASSERT_STREQ(fs.uuid, "12345678-90ab-cdef-1234-567890abcdef");
        ASSERT_STREQ(fs.label, "PICOTEST");

        /* The state survives the read, at the same offset, from a real file --
         * which is what says the 1024-byte skip and the decode agree. */
        ASSERT_EQ_INT(fs.state, EXT_STATE_ERROR_FS);

        /* Shorter than a superblock: not a filesystem, and not an I/O error. */
        snprintf(path, sizeof(path), "%s/tiny", dir);
        ASSERT_EQ_INT(test_write_file(dir, "tiny", "not a filesystem"), 0);
        ASSERT_EQ_INT(ext_super_read(path, &fs), 0);

        snprintf(path, sizeof(path), "%s/absent", dir);
        ASSERT_EQ_INT(ext_super_read(path, &fs), -ENOENT);

        ASSERT_EQ_INT(ext_super_read(NULL, &fs), -EINVAL);

        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_ext_super();
        test_ext_state();
        test_ext_device();

        printf("test-ext-super: all checks passed\n");
        return 0;
}
