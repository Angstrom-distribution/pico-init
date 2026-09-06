/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * No hwdb.bin reader exists in this build: sd_hwdb_new() always -ENOENT,
 * sd_hwdb_new_from_path() always -EOPNOTSUPP, everything else -EINVAL or
 * a no-op, since no sd_hwdb object can ever exist.
 */

#include "sd-hwdb.h"

#include <errno.h>

#include "../../test-util.h"

int main(void) {
        sd_hwdb *hwdb = (sd_hwdb *) 0x1;
        const char *val = NULL;

        ASSERT_EQ_INT(sd_hwdb_new(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_hwdb_new(&hwdb), -ENOENT);
        ASSERT_TRUE(hwdb == (sd_hwdb *) 0x1); /* untouched */

        ASSERT_EQ_INT(sd_hwdb_new_from_path(NULL, &hwdb), -EINVAL);
        ASSERT_EQ_INT(sd_hwdb_new_from_path("/etc/udev/hwdb.bin", NULL), -EINVAL);
        ASSERT_EQ_INT(sd_hwdb_new_from_path("/etc/udev/hwdb.bin", &hwdb), -EOPNOTSUPP);

        ASSERT_EQ_INT(sd_hwdb_get(NULL, "usb:v1234p5678", "ID_VENDOR", &val), -EINVAL);
        ASSERT_TRUE(val == NULL);
        ASSERT_EQ_INT(sd_hwdb_seek(NULL, "usb:v1234p5678"), -EINVAL);
        ASSERT_EQ_INT(sd_hwdb_enumerate(NULL, &val, &val), -EINVAL);

        ASSERT_TRUE(sd_hwdb_ref(NULL) == NULL);
        ASSERT_TRUE(sd_hwdb_unref(NULL) == NULL);

        /* The FOREACH macro's loop body must simply never run. */
        {
                const char *key, *value;
                int ran = 0;

                SD_HWDB_FOREACH_PROPERTY(hwdb, "usb:v1234p5678", key, value) {
                        ran = 1;
                }
                ASSERT_EQ_INT(ran, 0);
        }

        printf("test-sd-hwdb: all checks passed\n");
        return 0;
}
