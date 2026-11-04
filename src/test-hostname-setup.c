/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Reading the hostname out of /etc/hostname. Applying it needs privilege and
 * changes the host, so only the parsing is run here.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hostname-setup.h"
#include "test-util.h"

static int read_from(const char *dir, const char *content, char *buf, size_t size) {
        char path[512];

        ASSERT_EQ_INT(test_write_file(dir, "hostname", content), 0);
        snprintf(path, sizeof path, "%s/hostname", dir);
        return hostname_read(path, buf, size);
}

static void test_read(const char *dir) {
        char buf[64];

        ASSERT_EQ_INT(read_from(dir, "h3900\n", buf, sizeof buf), 5);
        ASSERT_STREQ(buf, "h3900");
        ASSERT_EQ_INT(read_from(dir, "h3900", buf, sizeof buf), 5);
        ASSERT_STREQ(buf, "h3900");
        ASSERT_EQ_INT(read_from(dir, "h3900 \t\r\n", buf, sizeof buf), 5);
        ASSERT_STREQ(buf, "h3900");
        ASSERT_EQ_INT(read_from(dir, "first\nsecond\n", buf, sizeof buf), 5);
        ASSERT_STREQ(buf, "first");
}

static void test_nothing_to_apply(const char *dir) {
        char buf[64];
        char path[512];

        ASSERT_EQ_INT(read_from(dir, "", buf, sizeof buf), 0);
        ASSERT_EQ_INT(read_from(dir, "\n", buf, sizeof buf), 0);
        ASSERT_EQ_INT(read_from(dir, "  \n", buf, sizeof buf), 0);

        snprintf(path, sizeof path, "%s/absent", dir);
        ASSERT_EQ_INT(hostname_read(path, buf, sizeof buf), 0);
}

static void test_long_line_is_bounded(const char *dir) {
        char buf[8];

        ASSERT_EQ_INT(read_from(dir, "a-hostname-longer-than-the-buffer\n", buf, sizeof buf), 7);
        ASSERT_STREQ(buf, "a-hostn");
}

int main(void) {
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);

        test_read(dir);
        test_nothing_to_apply(dir);
        test_long_line_is_bounded(dir);

        test_rm_rf(dir);
        free(dir);

        printf("test-hostname-setup: all checks passed\n");
        return 0;
}
