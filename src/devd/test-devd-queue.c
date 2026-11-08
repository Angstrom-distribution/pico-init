/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The queue state files devd writes and udevadm reads, against a real
 * directory. Writer and reader are different programs, so what is checked is
 * the file itself: its exact content, that no temporary is left behind, and
 * that the reader refuses anything that is not one plain number.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../test-util.h"
#include "devd-queue.h"

static void read_file(const char *path, char *buf, size_t size) {
        FILE *f = fopen(path, "re");
        size_t n;

        ASSERT_TRUE(f != NULL);
        n = fread(buf, 1, size - 1, f);
        buf[n] = '\0';
        ASSERT_EQ_INT(fclose(f), 0);
}

static unsigned count_entries(const char *dir) {
        struct dirent *e;
        unsigned n = 0;
        DIR *dd = opendir(dir);

        ASSERT_TRUE(dd != NULL);
        while ((e = readdir(dd)))
                if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
                        n++;
        ASSERT_EQ_INT(closedir(dd), 0);
        return n;
}

static void test_write_read(const char *tmp) {
        char dir[PATH_MAX], path[PATH_MAX + 16], buf[64];
        uint64_t v = 0;

        /* The directory is created on first write, as /run/devd is. */
        (void) snprintf(dir, sizeof(dir), "%s/devd", tmp);
        (void) snprintf(path, sizeof(path), "%s/seqnum", dir);

        ASSERT_EQ_INT(devd_queue_write_u64(dir, "seqnum", 42), 0);
        read_file(path, buf, sizeof(buf));
        ASSERT_STREQ(buf, "42\n");
        ASSERT_EQ_INT(count_entries(dir), 1);

        ASSERT_EQ_INT(devd_queue_read_u64(path, &v), 0);
        ASSERT_EQ_INT(v, 42);

        /* Replaced, not appended to. */
        ASSERT_EQ_INT(devd_queue_write_u64(dir, "seqnum", 18446744073709551615ULL), 0);
        ASSERT_EQ_INT(devd_queue_read_u64(path, &v), 0);
        ASSERT_TRUE(v == 18446744073709551615ULL);
        ASSERT_EQ_INT(count_entries(dir), 1);

        ASSERT_EQ_INT(devd_queue_remove(dir, "seqnum"), 0);
        ASSERT_EQ_INT(devd_queue_read_u64(path, &v), -ENOENT);
        ASSERT_EQ_INT(devd_queue_remove(dir, "seqnum"), 0);
}

static void test_read_rejects(const char *tmp) {
        static const char * const bad[] = { "", "\n", "abc\n", " 12\n", "-1\n", "12x\n", "1 2\n", "+3\n" };
        char path[PATH_MAX];
        uint64_t v = 7;

        (void) snprintf(path, sizeof(path), "%s/value", tmp);

        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
                ASSERT_EQ_INT(test_write_file(tmp, "value", bad[i]), 0);
                ASSERT_EQ_INT(devd_queue_read_u64(path, &v), -EINVAL);
                ASSERT_EQ_INT(v, 7);
        }

        /* The kernel's own file ends in a newline; a hand-written one may not. */
        ASSERT_EQ_INT(test_write_file(tmp, "value", "1234"), 0);
        ASSERT_EQ_INT(devd_queue_read_u64(path, &v), 0);
        ASSERT_EQ_INT(v, 1234);

        ASSERT_EQ_INT(devd_queue_read_u64(NULL, &v), -EINVAL);
        ASSERT_EQ_INT(devd_queue_read_u64(path, NULL), -EINVAL);
}

static void test_flag(const char *tmp) {
        char dir[PATH_MAX], path[PATH_MAX + 16];

        (void) snprintf(dir, sizeof(dir), "%s/udev", tmp);
        (void) snprintf(path, sizeof(path), "%s/queue", dir);

        ASSERT_EQ_INT(devd_queue_set_flag(dir, "queue", true), 0);
        ASSERT_EQ_INT(access(path, F_OK), 0);

        /* Raising it twice is not an error: devd does not track the file. */
        ASSERT_EQ_INT(devd_queue_set_flag(dir, "queue", true), 0);

        ASSERT_EQ_INT(devd_queue_set_flag(dir, "queue", false), 0);
        ASSERT_TRUE(access(path, F_OK) < 0 && errno == ENOENT);
        ASSERT_EQ_INT(devd_queue_set_flag(dir, "queue", false), 0);
}

static void test_covers(void) {
        ASSERT_TRUE(devd_queue_covers(5, 5));
        ASSERT_TRUE(devd_queue_covers(6, 5));
        ASSERT_TRUE(!devd_queue_covers(4, 5));
        ASSERT_TRUE(devd_queue_covers(0, 0));
}

int main(void) {
        char *tmp = test_tmpdir_new();

        ASSERT_TRUE(tmp != NULL);

        test_write_read(tmp);
        test_read_rejects(tmp);
        test_flag(tmp);
        test_covers();

        test_rm_rf(tmp);
        free(tmp);
        return 0;
}
