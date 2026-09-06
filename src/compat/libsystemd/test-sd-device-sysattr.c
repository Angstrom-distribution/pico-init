/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Sysattr read/write against a real fixture directory: the name iterator
 * (regular files only), value caching (including negative caching), the
 * three special symlink names, and path-safety on both the getter and
 * the setter.
 */

#include "sd-device.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "../../test-util.h"
#include "device-internal.h"

static char *g_tmp;
static char g_syspath[600];

static void setup(void) {
        char sysroot[620];

        g_tmp = test_tmpdir_new();
        ASSERT_TRUE(g_tmp != NULL);
        snprintf(sysroot, sizeof(sysroot), "%s/sys", g_tmp);
        device_set_sys_root_for_tests(sysroot);

        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys"), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/devices"), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/devices/foo"), 0);
        ASSERT_EQ_INT(test_write_file(g_tmp, "sys/devices/foo/uevent", ""), 0);
        ASSERT_EQ_INT(test_write_file(g_tmp, "sys/devices/foo/wakeup", "enabled\n"), 0);
        ASSERT_EQ_INT(test_mkdir(g_tmp, "sys/devices/foo/power"), 0); /* a real subdirectory, not an attr */
        ASSERT_EQ_INT(test_symlink(g_tmp, "sys/devices/foo/subsystem", "../../bus/plat"), 0);
        ASSERT_EQ_INT(test_symlink(g_tmp, "sys/devices/foo/driver", "../../bus/plat/drivers/foodrv"), 0);

        snprintf(g_syspath, sizeof(g_syspath), "%s/sys/devices/foo", g_tmp);
}

static void teardown(void) {
        test_rm_rf(g_tmp);
        free(g_tmp);
}

static void test_sysattr_read_write(void) {
        sd_device *d = NULL;
        const char *v, *name;
        size_t size;
        int n_names = 0, saw_wakeup = 0;

        setup();
        ASSERT_EQ_INT(sd_device_new_from_syspath(&d, g_syspath), 0);

        /* "wakeup" is a regular file: iterated AND readable. */
        for (name = sd_device_get_sysattr_first(d); name; name = sd_device_get_sysattr_next(d)) {
                n_names++;
                if (strcmp(name, "wakeup") == 0)
                        saw_wakeup = 1;
                /* "power" (a directory) and "subsystem"/"driver" (symlinks)
                 * must never appear here. */
                ASSERT_TRUE(strcmp(name, "power") != 0);
                ASSERT_TRUE(strcmp(name, "subsystem") != 0);
                ASSERT_TRUE(strcmp(name, "driver") != 0);
        }
        ASSERT_TRUE(saw_wakeup);
        ASSERT_TRUE(n_names >= 1);

        ASSERT_EQ_INT(sd_device_get_sysattr_value(d, "wakeup", &v), 0);
        ASSERT_STREQ(v, "enabled"); /* trailing newline chomped */
        ASSERT_EQ_INT(sd_device_get_sysattr_value_with_size(d, "wakeup", &v, &size), 0);
        ASSERT_EQ_INT((long long) size, 7);

        /* driver/subsystem/module read as their symlink's last component,
         * exactly like the real getters -- a real kernel's own driver and
         * module directories have no "subsystem" file to fall back to. */
        ASSERT_EQ_INT(sd_device_get_sysattr_value(d, "subsystem", &v), 0);
        ASSERT_STREQ(v, "plat");
        ASSERT_EQ_INT(sd_device_get_sysattr_value(d, "driver", &v), 0);
        ASSERT_STREQ(v, "foodrv");

        /* A directory attribute is -EISDIR, not a crash or a truncated read. */
        ASSERT_EQ_INT(sd_device_get_sysattr_value(d, "power", &v), -EISDIR);

        /* Missing attribute, and a cached negative result: change the file
         * on disk after the first (negative) lookup and confirm the cache,
         * not the disk, answers the second one. */
        ASSERT_EQ_INT(sd_device_get_sysattr_value(d, "missing", &v), -ENOENT);
        ASSERT_EQ_INT(test_write_file(g_tmp, "sys/devices/foo/missing", "now-exists\n"), 0);
        ASSERT_EQ_INT(sd_device_get_sysattr_value(d, "missing", &v), -ENOENT);

        /* Path escapes are rejected before any file is touched. */
        ASSERT_EQ_INT(sd_device_get_sysattr_value(d, "../escape", &v), -EINVAL);
        ASSERT_EQ_INT(sd_device_get_sysattr_value(d, "/absolute", &v), -EINVAL);

        /* set: no trailing newline in the caller's value gets one added;
         * NULL clears the cache without writing. */
        ASSERT_EQ_INT(sd_device_set_sysattr_value(d, "wakeup", "disabled"), 0);
        {
                char path[700], buf[64] = { 0 };
                FILE *f;
                snprintf(path, sizeof(path), "%s/wakeup", g_syspath);
                f = fopen(path, "re");
                ASSERT_TRUE(f != NULL);
                ASSERT_TRUE(fgets(buf, sizeof(buf), f) != NULL);
                fclose(f);
                ASSERT_STREQ(buf, "disabled\n");
        }
        ASSERT_EQ_INT(sd_device_get_sysattr_value(d, "wakeup", &v), 0);
        ASSERT_STREQ(v, "disabled"); /* cache invalidated by the write, re-read fresh */

        ASSERT_EQ_INT(sd_device_set_sysattr_value(d, "wakeup", NULL), 0); /* clears cache only */
        ASSERT_EQ_INT(sd_device_set_sysattr_value(d, "../escape", "x"), -EINVAL);

        ASSERT_EQ_INT(sd_device_set_sysattr_valuef(d, "wakeup", "%s-%d", "on", 1), 0);
        ASSERT_EQ_INT(sd_device_get_sysattr_value(d, "wakeup", &v), 0);
        ASSERT_STREQ(v, "on-1");

        sd_device_unref(d);
        teardown();
}

int main(void) {
        test_sysattr_read_write();

        printf("test-sd-device-sysattr: OK\n");
        return 0;
}
