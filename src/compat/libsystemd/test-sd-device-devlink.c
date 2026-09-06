/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_device_get_devlink_first()/_next() against a fixture /dev tree: real
 * symlinks under disk/by-uuid and serial/by-id, some pointing at this
 * device and some at a different one, proving the scan filters on target
 * rather than just listing everything it finds.
 */

#include "sd-device.h"

#include <stdio.h>
#include <string.h>

#include "../../test-util.h"
#include "device-internal.h"

int main(void) {
        char *sys_tmp = test_tmpdir_new();
        char *dev_tmp = test_tmpdir_new();
        char sysroot[620];
        sd_device *d = NULL;
        char syspath[600];
        const char *link;
        int n = 0, saw_uuid = 0, saw_serial = 0;

        ASSERT_TRUE(sys_tmp != NULL && dev_tmp != NULL);
        snprintf(sysroot, sizeof(sysroot), "%s/sys", sys_tmp);
        device_set_sys_root_for_tests(sysroot);
        device_set_dev_root_for_tests(dev_tmp);

        ASSERT_EQ_INT(test_mkdir(sys_tmp, "sys"), 0);
        ASSERT_EQ_INT(test_mkdir(sys_tmp, "sys/devices"), 0);
        ASSERT_EQ_INT(test_mkdir(sys_tmp, "sys/devices/foo"), 0);
        ASSERT_EQ_INT(test_write_file(sys_tmp, "sys/devices/foo/uevent", "MAJOR=8\nMINOR=1\nDEVNAME=sda1\n"),
                      0);

        ASSERT_EQ_INT(test_write_file(dev_tmp, "sda1", ""), 0);
        ASSERT_EQ_INT(test_write_file(dev_tmp, "sda2", ""), 0); /* a different device */

        ASSERT_EQ_INT(test_mkdir(dev_tmp, "disk"), 0);
        ASSERT_EQ_INT(test_mkdir(dev_tmp, "disk/by-uuid"), 0);
        ASSERT_EQ_INT(test_symlink(dev_tmp, "disk/by-uuid/1111-2222", "../../sda1"), 0);
        ASSERT_EQ_INT(test_symlink(dev_tmp, "disk/by-uuid/3333-4444", "../../sda2"), 0); /* not ours */

        ASSERT_EQ_INT(test_mkdir(dev_tmp, "serial"), 0);
        ASSERT_EQ_INT(test_mkdir(dev_tmp, "serial/by-id"), 0);
        ASSERT_EQ_INT(test_symlink(dev_tmp, "serial/by-id/usb-Foo", "../../sda1"), 0);

        snprintf(syspath, sizeof(syspath), "%s/sys/devices/foo", sys_tmp);
        ASSERT_EQ_INT(sd_device_new_from_syspath(&d, syspath), 0);

        for (link = sd_device_get_devlink_first(d); link; link = sd_device_get_devlink_next(d)) {
                n++;
                if (strstr(link, "by-uuid/1111-2222"))
                        saw_uuid = 1;
                if (strstr(link, "by-id/usb-Foo"))
                        saw_serial = 1;
                ASSERT_TRUE(strstr(link, "3333-4444") == NULL); /* points at sda2, must be excluded */
        }

        ASSERT_EQ_INT(n, 2);
        ASSERT_TRUE(saw_uuid);
        ASSERT_TRUE(saw_serial);

        sd_device_unref(d);
        test_rm_rf(sys_tmp);
        test_rm_rf(dev_tmp);
        free(sys_tmp);
        free(dev_tmp);

        printf("test-sd-device-devlink: OK\n");
        return 0;
}
