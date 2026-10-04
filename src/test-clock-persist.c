/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * /etc/timestamp: the fourteen-digit parser and its inverse, the forward-only
 * decision (saved time, file mtime and epoch as floors, a bad candidate
 * ignored), restore with a fake clock setter, and the atomic, never-backwards
 * save. Nothing here touches the real clock.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "clock-persist.h"
#include "test-util.h"

#define T_2026_10_04_18_00_00 ((int64_t) 1791136800)
#define T_2026_10_04_19_00_00 ((int64_t) 1791140400)

static int64_t set_to;
static int set_calls;
static int set_result;

static int fake_set(int64_t sec) {
        set_to = sec;
        set_calls++;
        return set_result;
}

static char *slurp(const char *path, char *buf, size_t size) {
        FILE *f = fopen(path, "r");
        size_t n = 0;

        if (f) {
                n = fread(buf, 1, size - 1, f);
                fclose(f);
        }
        buf[n] = '\0';
        return buf;
}

static void test_parse_and_format(void) {
        int64_t sec;
        char text[CLOCK_PERSIST_TEXT_MAX];

        ASSERT_EQ_INT(clock_persist_parse("20261004180000", &sec), 0);
        ASSERT_TRUE(sec == T_2026_10_04_18_00_00);
        ASSERT_EQ_INT(clock_persist_parse("20261004180000\n", &sec), 0);
        ASSERT_TRUE(sec == T_2026_10_04_18_00_00);
        ASSERT_EQ_INT(clock_persist_parse("20180309123456", &sec), 0); /* the image's build-date file */

        ASSERT_EQ_INT(clock_persist_format(T_2026_10_04_19_00_00, text), 15);
        ASSERT_STREQ(text, "20261004190000\n");
        ASSERT_EQ_INT(clock_persist_parse(text, &sec), 0);
        ASSERT_TRUE(sec == T_2026_10_04_19_00_00);

        ASSERT_EQ_INT(clock_persist_parse("", &sec), -EINVAL);
        ASSERT_EQ_INT(clock_persist_parse("2026100418000", &sec), -EINVAL);   /* 13 digits */
        ASSERT_EQ_INT(clock_persist_parse("202610041800000", &sec), -EINVAL); /* 15 digits */
        ASSERT_EQ_INT(clock_persist_parse("2026-10-04 18:0", &sec), -EINVAL);
        ASSERT_EQ_INT(clock_persist_parse("20261004180000x", &sec), -EINVAL);
        ASSERT_EQ_INT(clock_persist_parse("20261304180000", &sec), -EINVAL); /* month 13 */
        ASSERT_EQ_INT(clock_persist_parse("20260231180000", &sec), -EINVAL); /* 31 February */
        ASSERT_EQ_INT(clock_persist_parse("20261004240000", &sec), -EINVAL); /* hour 24 */
        ASSERT_EQ_INT(clock_persist_parse("19690101000000", &sec), -EINVAL); /* before 1970 */
        ASSERT_EQ_INT(clock_persist_format(-1, text), -EINVAL);
}

static void test_decide(void) {
        const int64_t epoch = CLOCK_PERSIST_EPOCH_SEC;
        int64_t target = 0;

        /* The clock at 1970, nothing saved: the epoch is the floor. */
        ASSERT_TRUE(clock_persist_decide(0, 0, 23, &target));
        ASSERT_TRUE(target == epoch);

        /* The saved time beats the epoch, the mtime beats the saved time. */
        ASSERT_TRUE(clock_persist_decide(T_2026_10_04_18_00_00, 0, 23, &target));
        ASSERT_TRUE(target == T_2026_10_04_18_00_00);
        ASSERT_TRUE(clock_persist_decide(T_2026_10_04_18_00_00, T_2026_10_04_19_00_00, 23, &target));
        ASSERT_TRUE(target == T_2026_10_04_19_00_00);

        /* Never backwards: a clock already at or past the floor is left alone. */
        ASSERT_TRUE(!clock_persist_decide(T_2026_10_04_18_00_00, 0, T_2026_10_04_18_00_00, &target));
        ASSERT_TRUE(!clock_persist_decide(T_2026_10_04_18_00_00, 0, T_2026_10_04_19_00_00, &target));
        ASSERT_TRUE(!clock_persist_decide(0, 0, epoch, &target));

        /* A stale build-date file (2018) is below the epoch, so it changes nothing. */
        ASSERT_TRUE(clock_persist_decide(1520599496, 1520599496, 23, &target));
        ASSERT_TRUE(target == epoch);

        /* A candidate past the cap is a bad file, not a time. */
        ASSERT_TRUE(clock_persist_decide(CLOCK_PERSIST_MAX_SEC + 1, 0, 23, &target));
        ASSERT_TRUE(target == epoch);
        ASSERT_TRUE(clock_persist_decide(0, CLOCK_PERSIST_MAX_SEC + 1, 23, &target));
        ASSERT_TRUE(target == epoch);
        ASSERT_TRUE(clock_persist_decide(-5, -5, 23, &target));
        ASSERT_TRUE(target == epoch);
}

static void test_restore(void) {
        char *dir = test_tmpdir_new();
        char path[PATH_MAX];

        ASSERT_TRUE(dir != NULL);
        snprintf(path, sizeof(path), "%s/timestamp", dir);

        /* No file: the epoch still applies, once. */
        set_calls = 0;
        set_result = 0;
        ASSERT_EQ_INT(clock_persist_restore(path, 23, fake_set), 1);
        ASSERT_EQ_INT(set_calls, 1);
        ASSERT_TRUE(set_to == CLOCK_PERSIST_EPOCH_SEC);

        /* A valid file moves the clock to it (its mtime is "now" in real time, which is
         * far past any test value, so the mtime floor wins over the content here;
         * assert only that the result is at least the saved time). */
        ASSERT_EQ_INT(test_write_file(dir, "timestamp", "20261004180000\n"), 0);
        set_calls = 0;
        ASSERT_EQ_INT(clock_persist_restore(path, 23, fake_set), 1);
        ASSERT_TRUE(set_to >= T_2026_10_04_18_00_00);

        /* A garbled file is not an error: the epoch (and the mtime) still apply. */
        ASSERT_EQ_INT(test_write_file(dir, "timestamp", "garbage\n"), 0);
        set_calls = 0;
        ASSERT_EQ_INT(clock_persist_restore(path, 23, fake_set), 1);
        ASSERT_TRUE(set_to >= CLOCK_PERSIST_EPOCH_SEC);

        /* A clock already past every floor: nothing is set. */
        set_calls = 0;
        ASSERT_EQ_INT(clock_persist_restore(path, CLOCK_PERSIST_MAX_SEC, fake_set), 0);
        ASSERT_EQ_INT(set_calls, 0);

        /* The setter failing is reported. */
        set_result = -EPERM;
        ASSERT_EQ_INT(clock_persist_restore(path, 23, fake_set), -EPERM);

        test_rm_rf(dir);
        free(dir);
}

static void test_save(void) {
        char *dir = test_tmpdir_new();
        char path[PATH_MAX], tmp[PATH_MAX], buf[64];
        struct stat st;

        ASSERT_TRUE(dir != NULL);
        snprintf(path, sizeof(path), "%s/timestamp", dir);
        snprintf(tmp, sizeof(tmp), "%s/timestamp.tmp", dir);

        /* A clock that was never set (below the epoch) is not persisted. */
        ASSERT_EQ_INT(clock_persist_save(path, 23), 0);
        ASSERT_TRUE(stat(path, &st) < 0);

        /* First save creates the file, atomically (no temp file left). */
        ASSERT_EQ_INT(clock_persist_save(path, T_2026_10_04_18_00_00), 1);
        ASSERT_STREQ(slurp(path, buf, sizeof(buf)), "20261004180000\n");
        ASSERT_TRUE(stat(tmp, &st) < 0);

        /* A later time replaces it. */
        ASSERT_EQ_INT(clock_persist_save(path, T_2026_10_04_19_00_00), 1);
        ASSERT_STREQ(slurp(path, buf, sizeof(buf)), "20261004190000\n");

        /* An earlier or equal time never replaces a later one. */
        ASSERT_EQ_INT(clock_persist_save(path, T_2026_10_04_18_00_00), 0);
        ASSERT_EQ_INT(clock_persist_save(path, T_2026_10_04_19_00_00), 0);
        ASSERT_STREQ(slurp(path, buf, sizeof(buf)), "20261004190000\n");

        /* A garbled file is overwritten by a good time. */
        ASSERT_EQ_INT(test_write_file(dir, "timestamp", "garbage\n"), 0);
        ASSERT_EQ_INT(clock_persist_save(path, T_2026_10_04_18_00_00), 1);
        ASSERT_STREQ(slurp(path, buf, sizeof(buf)), "20261004180000\n");

        /* Past the cap is refused, not written. */
        ASSERT_EQ_INT(clock_persist_save(path, CLOCK_PERSIST_MAX_SEC + 1), 0);

        /* A directory that is not there is an error, not a crash. */
        snprintf(path, sizeof(path), "%s/missing/timestamp", dir);
        ASSERT_EQ_INT(clock_persist_save(path, T_2026_10_04_19_00_00), -ENOENT);

        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_parse_and_format();
        test_decide();
        test_restore();
        test_save();
        printf("test-clock-persist: all checks passed\n");
        return 0;
}
