/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The read side: sd_journal_open() over a fixture ring written in logd's
 * export format, then navigation, per-entry data, matches, unique/fields,
 * cutoffs/usage and the functions that always fail.
 *
 * Links libsystemd_compat alone, nothing from logd_core or pico_init_core:
 * that is what a shared libsystemd.so's consumers get.
 */

#include "sd-journal.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../logd/logd.h"
#include "../../test-util.h"

static char *g_dir;

static void set_env(void) {
        setenv("LOGD_RUNTIME_DIR", g_dir, 1);
}

/* The kernel's dashed boot ID, in the 32-hex form _BOOT_ID= carries. */
static void read_boot_id(char out[33]) {
        FILE *f;
        char buf[64];
        size_t n = 0;

        f = fopen("/proc/sys/kernel/random/boot_id", "re");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fgets(buf, sizeof(buf), f) != NULL);
        fclose(f);

        for (size_t i = 0; buf[i] != '\0' && n < 32; i++)
                if (buf[i] != '-')
                        out[n++] = buf[i];
        out[n] = '\0';
        ASSERT_EQ_INT((int) n, 32);
}

static uint64_t clock_usec(clockid_t id) {
        struct timespec ts;

        ASSERT_EQ_INT(clock_gettime(id, &ts), 0);
        return (uint64_t) ts.tv_sec * 1000000ULL + (uint64_t) ts.tv_nsec / 1000ULL;
}

/*
 * Three entries: two from "netd" (one info, one warning) and one from
 * "eudev" at err, as the bytes logd_writer_append() emits (writer-generated
 * clocks and _BOOT_ID first, the caller's fields in order, then a blank
 * line), written directly because logd-write.h's writer needs
 * pico_init_core. Clocks increase by one microsecond per entry for the
 * realtime/monotonic seek tests.
 *
 * The boot ID is this machine's real one: sd_journal_seek_monotonic_usec()/
 * seek_cursor() compare boot IDs against /proc/sys/kernel/random/boot_id
 * (journal_current_boot_id()), and with a fixed fake ID every such check
 * would see an unknown boot and report no data.
 */
static void build_fixture(void) {
        static const struct {
                const char *message, *priority, *identifier, *unit;
        } entries[] = {
                {      "netd started", "6",  "netd",  "netd.service" },
                {    "link down eth0", "4",  "netd",  "netd.service" },
                { "device add failed", "3", "eudev", "eudev.service" },
        };
        char boot_id[33];
        uint64_t realtime, monotonic;
        char content[1024];
        size_t off = 0;

        read_boot_id(boot_id);
        realtime = clock_usec(CLOCK_REALTIME);
        monotonic = clock_usec(CLOCK_MONOTONIC);

        for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
                int n = snprintf(
                                content + off,
                                sizeof(content) - off,
                                "__REALTIME_TIMESTAMP=%" PRIu64
                                "\n"
                                "__MONOTONIC_TIMESTAMP=%" PRIu64
                                "\n"
                                "_BOOT_ID=%s\n"
                                "MESSAGE=%s\n"
                                "PRIORITY=%s\n"
                                "SYSLOG_IDENTIFIER=%s\n"
                                "_SYSTEMD_UNIT=%s\n"
                                "\n",
                                realtime + i,
                                monotonic + i,
                                boot_id,
                                entries[i].message,
                                entries[i].priority,
                                entries[i].identifier,
                                entries[i].unit);

                ASSERT_TRUE(n > 0 && (size_t) n < sizeof(content) - off);
                off += (size_t) n;
        }

        ASSERT_EQ_INT(test_write_file(g_dir, LOGD_RING_ACTIVE_NAME, content), 0);
}

static void get_message(sd_journal *j, char *out, size_t out_sz) {
        const void *data;
        size_t len;

        ASSERT_EQ_INT(sd_journal_get_data(j, "MESSAGE", &data, &len), 0);
        ASSERT_TRUE(len > 8 && len - 8 < out_sz);
        memcpy(out, (const char *) data + 8, len - 8);
        out[len - 8] = '\0';
}

static void test_open_and_forward_walk(void) {
        sd_journal *j;
        char msg[128];

        set_env();
        ASSERT_EQ_INT(sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY), 0);

        ASSERT_EQ_INT(sd_journal_seek_head(j), 0);
        ASSERT_EQ_INT(sd_journal_next(j), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "netd started");

        ASSERT_EQ_INT(sd_journal_next(j), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "link down eth0");

        ASSERT_EQ_INT(sd_journal_next(j), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "device add failed");

        ASSERT_EQ_INT(sd_journal_next(j), 0); /* exhausted */
        ASSERT_EQ_INT(sd_journal_next(j), 0); /* stays exhausted */

        sd_journal_close(j);
}

static void test_backward_walk_and_step_one(void) {
        sd_journal *j;
        char msg[128];

        set_env();
        ASSERT_EQ_INT(sd_journal_open(&j, 0), 0);

        ASSERT_EQ_INT(sd_journal_seek_tail(j), 0);
        ASSERT_EQ_INT(sd_journal_previous(j), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "device add failed");

        ASSERT_EQ_INT(sd_journal_previous(j), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "link down eth0");

        /* step_one(advanced=1) from an ON_ENTRY state must move forward,
         * exactly like sd_journal_next(). */
        ASSERT_EQ_INT(sd_journal_step_one(j, 1), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "device add failed");

        /* step_one(advanced=0) from an ON_ENTRY state must move backward,
         * exactly like sd_journal_previous(). */
        ASSERT_EQ_INT(sd_journal_step_one(j, 0), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "link down eth0");

        ASSERT_EQ_INT(sd_journal_seek_head(j), 0);
        /* step_one() at BEFORE_HEAD always goes forward regardless of `advanced`. */
        ASSERT_EQ_INT(sd_journal_step_one(j, 0), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "netd started");

        sd_journal_close(j);
}

static void test_next_skip_previous_skip(void) {
        sd_journal *j;
        char msg[128];

        set_env();
        ASSERT_EQ_INT(sd_journal_open(&j, 0), 0);
        sd_journal_seek_head(j);

        ASSERT_EQ_INT(sd_journal_next_skip(j, 2), 2);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "link down eth0");

        /* Only one more entry exists: the skip count returned is clamped to
         * what was found, but as in upstream's real_journal_next_skip
         * ("if (r == 0) return c") the exhausting final sd_journal_next()
         * leaves the journal AFTER_TAIL. */
        ASSERT_EQ_INT(sd_journal_next_skip(j, 10), 1);

        ASSERT_EQ_INT(sd_journal_previous_skip(j, 100), 3); /* clamps to what's there */
        /* Same boundary rule applies backward: previous_skip() exhausting
         * itself leaves the journal BEFORE_HEAD. One more sd_journal_next()
         * is what a real caller would do next to actually land on entry 0. */
        ASSERT_EQ_INT(sd_journal_next(j), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "netd started");

        sd_journal_close(j);
}

static void test_add_match_filters(void) {
        sd_journal *j;
        char msg[128];

        set_env();
        ASSERT_EQ_INT(sd_journal_open(&j, 0), 0);

        ASSERT_EQ_INT(sd_journal_add_match(j, "SYSLOG_IDENTIFIER=eudev", strlen("SYSLOG_IDENTIFIER=eudev")),
                      0);
        sd_journal_seek_head(j);
        ASSERT_EQ_INT(sd_journal_next(j), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "device add failed");
        ASSERT_EQ_INT(sd_journal_next(j), 0); /* only one eudev entry */

        sd_journal_flush_matches(j);

        /* AND across distinct names, OR within one name: (ident==netd) AND
         * (PRIORITY==6 OR PRIORITY==4) matches both netd entries. */
        ASSERT_EQ_INT(sd_journal_add_match(j, "SYSLOG_IDENTIFIER=netd", strlen("SYSLOG_IDENTIFIER=netd")), 0);
        ASSERT_EQ_INT(sd_journal_add_match(j, "PRIORITY=6", strlen("PRIORITY=6")), 0);
        ASSERT_EQ_INT(sd_journal_add_match(j, "PRIORITY=4", strlen("PRIORITY=4")), 0);
        sd_journal_seek_head(j);
        ASSERT_EQ_INT(sd_journal_next(j), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "netd started");
        ASSERT_EQ_INT(sd_journal_next(j), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "link down eth0");
        ASSERT_EQ_INT(sd_journal_next(j), 0);

        /* add_match() rejects malformed data the same way upstream does. */
        ASSERT_EQ_INT(sd_journal_add_match(j, "noequals", strlen("noequals")), -EINVAL);
        ASSERT_EQ_INT(sd_journal_add_match(j, "=leadingeq", strlen("=leadingeq")), -EINVAL);
        ASSERT_EQ_INT(sd_journal_add_disjunction(j), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_journal_add_conjunction(j), -EOPNOTSUPP);

        sd_journal_close(j);
}

static void test_enumerate_data_skips_double_underscore(void) {
        sd_journal *j;
        const void *data;
        size_t len;
        bool saw_message = false, saw_double_underscore = false;

        set_env();
        ASSERT_EQ_INT(sd_journal_open(&j, 0), 0);
        sd_journal_seek_head(j);
        ASSERT_EQ_INT(sd_journal_next(j), 1);

        sd_journal_restart_data(j);
        while (sd_journal_enumerate_data(j, &data, &len) > 0) {
                if (len >= 2 && memcmp(data, "__", 2) == 0)
                        saw_double_underscore = true;
                if (len >= 8 && memcmp(data, "MESSAGE=", 8) == 0)
                        saw_message = true;
        }
        ASSERT_TRUE(saw_message);
        ASSERT_TRUE(!saw_double_underscore);

        ASSERT_EQ_INT(sd_journal_get_data(j, "NOSUCHFIELD", &data, &len), -ENOENT);
        ASSERT_EQ_INT(sd_journal_get_data(j, "lowercase", &data, &len), -EINVAL);

        sd_journal_close(j);
}

static void test_data_threshold_truncates(void) {
        sd_journal *j;
        const void *data;
        size_t len;

        set_env();
        ASSERT_EQ_INT(sd_journal_open(&j, 0), 0);
        sd_journal_seek_head(j);
        ASSERT_EQ_INT(sd_journal_next(j), 1);

        ASSERT_EQ_INT(sd_journal_set_data_threshold(j, 10), 0);
        ASSERT_EQ_INT(sd_journal_get_data(j, "MESSAGE", &data, &len), 0);
        ASSERT_TRUE(len == 10);
        ASSERT_TRUE(memcmp(data, "MESSAGE=", 8) == 0); /* never truncated into the prefix */

        {
                size_t got;

                ASSERT_EQ_INT(sd_journal_get_data_threshold(j, &got), 0);
                ASSERT_EQ_INT((int) got, 10);
        }

        sd_journal_close(j);
}

static void test_unique_and_fields(void) {
        sd_journal *j;
        const void *data;
        const char *field_name;
        size_t len;
        int n;

        set_env();
        ASSERT_EQ_INT(sd_journal_open(&j, 0), 0);

        ASSERT_EQ_INT(sd_journal_enumerate_unique(j, &data, &len), -ENODATA); /* no query yet */

        ASSERT_EQ_INT(sd_journal_query_unique(j, "SYSLOG_IDENTIFIER"), 0);
        n = 0;
        while (sd_journal_enumerate_unique(j, &data, &len) > 0)
                n++;
        ASSERT_EQ_INT(n, 2); /* "netd" and "eudev", deduplicated across 3 entries */

        n = 0;
        while (sd_journal_enumerate_fields(j, &field_name) > 0)
                n++;
        ASSERT_TRUE(n >= 4); /* MESSAGE, PRIORITY, SYSLOG_IDENTIFIER, _SYSTEMD_UNIT, ... */

        sd_journal_close(j);
}

static void test_cursor_roundtrip(void) {
        sd_journal *j;
        char *cursor;
        char msg[128];

        set_env();
        ASSERT_EQ_INT(sd_journal_open(&j, 0), 0);
        sd_journal_seek_head(j);
        ASSERT_EQ_INT(sd_journal_next(j), 1);
        ASSERT_EQ_INT(sd_journal_next(j), 1); /* "link down eth0" */

        ASSERT_EQ_INT(sd_journal_get_cursor(j, &cursor), 0);
        ASSERT_EQ_INT(sd_journal_test_cursor(j, cursor), 1);

        sd_journal_close(j);

        /* A fresh journal object, seeked purely from the saved cursor. */
        ASSERT_EQ_INT(sd_journal_open(&j, 0), 0);
        ASSERT_EQ_INT(sd_journal_seek_cursor(j, cursor), 0);
        ASSERT_EQ_INT(sd_journal_next(j), 1);
        get_message(j, msg, sizeof(msg));
        ASSERT_STREQ(msg, "link down eth0");
        ASSERT_EQ_INT(sd_journal_test_cursor(j, cursor), 1);

        free(cursor);

        /* A foreign (non-pico) cursor string fails cleanly. */
        ASSERT_EQ_INT(sd_journal_seek_cursor(j, "s=abcabc123;i=45"), -EINVAL);

        sd_journal_close(j);
}

static void test_info_and_failures(void) {
        sd_journal *j;
        uint64_t from, to, bytes;
        sd_id128_t bogus_boot;

        set_env();
        ASSERT_EQ_INT(sd_journal_open(&j, 0), 0);

        ASSERT_EQ_INT(sd_journal_get_cutoff_realtime_usec(j, &from, &to), 1);
        ASSERT_TRUE(from <= to);

        ASSERT_EQ_INT(sd_journal_get_usage(j, &bytes), 0);
        ASSERT_TRUE(bytes > 0);

        ASSERT_EQ_INT(sd_journal_has_runtime_files(j), 1);
        ASSERT_EQ_INT(sd_journal_has_persistent_files(j), 0);

        {
                uint64_t seqnum;

                ASSERT_EQ_INT(sd_journal_get_seqnum(j, &seqnum, NULL), -EOPNOTSUPP);
        }

        {
                char *cat;

                ASSERT_EQ_INT(sd_journal_get_catalog(j, &cat), -ENOENT);
        }

        memset(&bogus_boot, 0xAA, sizeof(bogus_boot));
        ASSERT_EQ_INT(sd_journal_get_cutoff_monotonic_usec(j, bogus_boot, &from, &to), 0);

        sd_journal_close(j);
}

static void test_open_rejects_bad_flags_and_null(void) {
        sd_journal *j;

        set_env();
        ASSERT_EQ_INT(sd_journal_open(&j, SD_JOURNAL_TAKE_DIRECTORY_FD), -EINVAL);
        ASSERT_EQ_INT(sd_journal_open(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_journal_open_directory(&j, "/anywhere", 0), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_journal_open_files(&j, NULL, 0), -EOPNOTSUPP);

        /* Deprecated upstream too; -Werror would otherwise fail this call. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        ASSERT_EQ_INT(sd_journal_open_container(&j, "anything", 0), -EOPNOTSUPP);
#pragma GCC diagnostic pop

        {
                sd_journal *j2;

                ASSERT_EQ_INT(sd_journal_open_namespace(&j2, "ns", 0), -EOPNOTSUPP);
        }

        sd_journal_close(NULL); /* NULL-tolerant */
}

static void test_empty_ring_is_not_an_error(void) {
        char *empty_dir = test_tmpdir_new();
        sd_journal *j;
        uint64_t from, to;

        ASSERT_TRUE(empty_dir != NULL);
        setenv("LOGD_RUNTIME_DIR", empty_dir, 1);

        ASSERT_EQ_INT(sd_journal_open(&j, 0), 0);
        sd_journal_seek_head(j);
        ASSERT_EQ_INT(sd_journal_next(j), 0);
        ASSERT_EQ_INT(sd_journal_get_cutoff_realtime_usec(j, &from, &to), 0);
        ASSERT_EQ_INT(sd_journal_has_runtime_files(j), 0);

        sd_journal_close(j);
        test_rm_rf(empty_dir);
        free(empty_dir);
}

int main(void) {
        g_dir = test_tmpdir_new();
        ASSERT_TRUE(g_dir != NULL);
        build_fixture();

        test_open_and_forward_walk();
        test_backward_walk_and_step_one();
        test_next_skip_previous_skip();
        test_add_match_filters();
        test_enumerate_data_skips_double_underscore();
        test_data_threshold_truncates();
        test_unique_and_fields();
        test_cursor_roundtrip();
        test_info_and_failures();
        test_open_rejects_bad_flags_and_null();
        test_empty_ring_is_not_an_error();

        test_rm_rf(g_dir);
        free(g_dir);

        printf("test-sd-journal-read: all cases passed\n");
        return 0;
}
