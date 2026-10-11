/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * devd_media_mount_point()'s path-traversal guard, and devd_media_is_data_type()'s
 * GPT GUID matching -- the two pure-function halves of removable-media
 * mounting that do not need root or a real block device to exercise.
 *
 * The guard is the whole reason this file exists: devd_sanitize() (devd-
 * probe.c) keeps '.' in its whitelist, so PARTLABEL="." or PARTLABEL=".."
 * survives sanitizing untouched, and devd_media_mount_point() has to catch
 * that itself before handing the result to mkdir()/mount(). See
 * devd-media.c's own comment on the function for why.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "../test-util.h"
#include "devd-media.h"

#define MEDIA_ROOT "/media"

/* EFI System Partition type GUID (C12A7328-F81F-11D2-BA4B-00A0C93EC93B),
 * mixed-endian on disk like every other GUID here -- neither of
 * the two GUIDs devd mounts, to prove is_data_type() is a real comparison
 * rather than "anything with a GUID". */
static const GptGuid type_esp = {
        { 0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b }
};

static void test_is_data_type(void) {
        ASSERT_TRUE(devd_media_is_data_type(&devd_type_linux_data));
        ASSERT_TRUE(devd_media_is_data_type(&devd_type_basic_data));
        ASSERT_TRUE(!devd_media_is_data_type(&type_esp));
        ASSERT_TRUE(!devd_media_is_data_type(NULL));
}

/* An ordinary label sanitizes to itself and is used as-is. */
static void test_mount_point_ordinary_label(void) {
        char dir[PATH_MAX];

        ASSERT_EQ_INT(devd_media_mount_point(MEDIA_ROOT, "MY CARD", "mmcblk0p1", dir, sizeof(dir)), 0);
        ASSERT_STREQ(dir, MEDIA_ROOT "/MY_CARD");
}

/* The case this file exists for: a label of "." or ".." names the media
 * root itself or its parent and must fall back to the (trusted, kernel-
 * supplied) devname rather than being used. */
static void test_mount_point_dot_and_dotdot_fall_back(void) {
        char dir[PATH_MAX];

        ASSERT_EQ_INT(devd_media_mount_point(MEDIA_ROOT, ".", "sda1", dir, sizeof(dir)), 0);
        ASSERT_STREQ(dir, MEDIA_ROOT "/sda1");

        ASSERT_EQ_INT(devd_media_mount_point(MEDIA_ROOT, "..", "sda1", dir, sizeof(dir)), 0);
        ASSERT_STREQ(dir, MEDIA_ROOT "/sda1");

        /* A label that sanitizes down to "." (e.g. surrounded by characters
         * devd_sanitize() strips) hits the same guard by way of the sanitized
         * result, not the raw input. */
        ASSERT_EQ_INT(devd_media_mount_point(MEDIA_ROOT, " . ", "sda1", dir, sizeof(dir)), 0);
        ASSERT_STREQ(dir, MEDIA_ROOT "/sda1");
}

/* A label that sanitizes to nothing at all (whitespace only, or empty) is the
 * same "no usable label" case as "."/".." and takes the same fallback. */
static void test_mount_point_empty_label_falls_back(void) {
        char dir[PATH_MAX];

        ASSERT_EQ_INT(devd_media_mount_point(MEDIA_ROOT, "   ", "sda1", dir, sizeof(dir)), 0);
        ASSERT_STREQ(dir, MEDIA_ROOT "/sda1");

        ASSERT_EQ_INT(devd_media_mount_point(MEDIA_ROOT, "", "sda1", dir, sizeof(dir)), 0);
        ASSERT_STREQ(dir, MEDIA_ROOT "/sda1");

        ASSERT_EQ_INT(devd_media_mount_point(MEDIA_ROOT, NULL, "sda1", dir, sizeof(dir)), 0);
        ASSERT_STREQ(dir, MEDIA_ROOT "/sda1");
}

/* devname is trusted kernel input, so nothing here
 * exercises it sanitizing to "." -- a real DEVNAME uevent property is never
 * ".", only ever a device node name like "sda1" or "mmcblk0p1". What this
 * checks is only that an unusable devname (sanitizes to nothing) is reported
 * as an error rather than silently naming media_root itself. */
static void test_mount_point_unusable_devname_is_an_error(void) {
        char dir[PATH_MAX];

        ASSERT_EQ_INT(devd_media_mount_point(MEDIA_ROOT, ".", "", dir, sizeof(dir)), -EINVAL);
        ASSERT_EQ_INT(devd_media_mount_point(MEDIA_ROOT, NULL, "   ", dir, sizeof(dir)), -EINVAL);
}

static void test_mount_point_name_too_long(void) {
        char dir[8];

        ASSERT_EQ_INT(devd_media_mount_point(
                                      MEDIA_ROOT, "a-label-longer-than-the-buffer", "sda1", dir, sizeof(dir)),
                      -ENAMETOOLONG);
}

static void test_mount_point_invalid_args(void) {
        char dir[PATH_MAX];

        ASSERT_EQ_INT(devd_media_mount_point(NULL, "label", "sda1", dir, sizeof(dir)), -EINVAL);
        ASSERT_EQ_INT(devd_media_mount_point(MEDIA_ROOT, "label", NULL, dir, sizeof(dir)), -EINVAL);
        ASSERT_EQ_INT(devd_media_mount_point(MEDIA_ROOT, "label", "sda1", NULL, sizeof(dir)), -EINVAL);
}

/*
 * The double-mount guard, which decides before any mount(2) and so runs
 * unprivileged: a device mountinfo shows mounted elsewhere is left alone,
 * one at devd's own mount point is adopted, and an unreadable mountinfo is
 * an error rather than a guess.
 */
static void test_mount_skips_mounted_elsewhere(void) {
        static const uint8_t uuid[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        char *tmp, node[PATH_MAX], media[PATH_MAX], mi[PATH_MAX], content[PATH_MAX * 3], dir[PATH_MAX];

        tmp = test_tmpdir_new();
        ASSERT_TRUE(tmp != NULL);
        snprintf(node, sizeof(node), "%s/sdb1", tmp);
        snprintf(media, sizeof(media), "%s/media", tmp);
        snprintf(mi, sizeof(mi), "%s/mountinfo", tmp);
        ASSERT_EQ_INT(test_ext_image(node, uuid, "CARD"), 0);

        /* fstab put it on /data. */
        snprintf(content, sizeof(content), "40 1 0:99 / /data rw - ext4 %s rw\n", node);
        ASSERT_EQ_INT(test_write_file(tmp, "mountinfo", content), 0);
        dir[0] = '\0';
        ASSERT_EQ_INT(devd_media_mount(media, mi, node, "CARD", "sdb1", false, dir, sizeof(dir)), 0);
        ASSERT_STREQ(dir, "");
        ASSERT_TRUE(access(media, F_OK) < 0);

        /* devd put it on /media/CARD before it restarted. */
        snprintf(content, sizeof(content), "40 1 0:99 / %s/CARD rw - ext4 %s rw\n", media, node);
        ASSERT_EQ_INT(test_write_file(tmp, "mountinfo", content), 0);
        ASSERT_EQ_INT(devd_media_mount(media, mi, node, "CARD", "sdb1", false, dir, sizeof(dir)), 1);
        snprintf(content, sizeof(content), "%s/CARD", media);
        ASSERT_STREQ(dir, content);

        snprintf(mi, sizeof(mi), "%s/no-mountinfo", tmp);
        ASSERT_EQ_INT(devd_media_mount(media, mi, node, "CARD", "sdb1", false, dir, sizeof(dir)), -ENOENT);

        test_rm_rf(tmp);
        free(tmp);
}

int main(void) {
        test_is_data_type();
        test_mount_skips_mounted_elsewhere();
        test_mount_point_ordinary_label();
        test_mount_point_dot_and_dotdot_fall_back();
        test_mount_point_empty_label_falls_back();
        test_mount_point_unusable_devname_is_an_error();
        test_mount_point_name_too_long();
        test_mount_point_invalid_args();

        printf("test-devd-media: all checks passed\n");
        return 0;
}
