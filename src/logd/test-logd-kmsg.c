/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * logd_kmsg_parse_record() against synthetic buffers -- the edge cases the
 * format comment at the top of logd-kmsg.c documents but nothing exercised:
 * a record with no ';' at all, one with no trailing '\n' (a fresh open()'s
 * last read() can end mid-ring), and an unparseable priority field, which
 * atoi() silently turns into 0 (emerg) rather than failing.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "logd-kmsg-internal.h"

/* Fixed rather than strlen()'d at each call site: a couple of cases below
 * deliberately do not end in '\0' right after the content that matters. */
static int parse(const char *buf, size_t n, char **ret_line, size_t *ret_len, int *ret_priority) {
        return logd_kmsg_parse_record(buf, n, ret_line, ret_len, ret_priority);
}

/* The real first record off a fresh open(), confirmed against a running
 * kernel (logd-kmsg.c's own header comment). */
static void test_well_formed_record(void) {
        static const char rec[] = "6,0,0,-;Booting Linux on physical CPU 0x0\n";
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(parse(rec, strlen(rec), &line, &len, &priority), 1);
        ASSERT_EQ_INT(priority, 6);
        ASSERT_EQ_INT(len, strlen("Booting Linux on physical CPU 0x0"));
        ASSERT_STREQ(line, "Booting Linux on physical CPU 0x0");
        free(line);
}

/* An extra field before the ';' (",extra" in the format comment) does not
 * confuse the priority field: atoi() stops at the first comma regardless. */
static void test_extra_field(void) {
        static const char rec[] = "3,42,1000,-,extra;disk error\n";
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(parse(rec, strlen(rec), &line, &len, &priority), 1);
        ASSERT_EQ_INT(priority, 3);
        ASSERT_STREQ(line, "disk error");
        free(line);
}

/* No ';' anywhere: not a record this format can mean anything from, skipped
 * rather than surfaced. */
static void test_missing_semicolon_is_skipped(void) {
        static const char rec[] = "not a kmsg record at all\n";
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(parse(rec, strlen(rec), &line, &len, &priority), 0);
}

/* No trailing '\n': the whole remainder of the buffer is the message, not an
 * error -- a non-blocking read() can legitimately end here. */
static void test_missing_newline_takes_the_remainder(void) {
        static const char rec[] = "6,0,0,-;incomplete tail";
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(parse(rec, strlen(rec), &line, &len, &priority), 1);
        ASSERT_EQ_INT(priority, 6);
        ASSERT_STREQ(line, "incomplete tail");
        free(line);
}

/* An empty message (';' is the very last byte) is not an error either. */
static void test_empty_message(void) {
        static const char rec[] = "6,0,0,-;";
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(parse(rec, strlen(rec), &line, &len, &priority), 1);
        ASSERT_EQ_INT(len, 0);
        ASSERT_STREQ(line, "");
        free(line);
}

/* A priority field that is not a leading decimal: atoi() returns 0, which
 * masks to priority 0 (emerg) -- documented in logd-kmsg.c as deliberately
 * over-severe rather than a parse failure, and this is what pins that. */
static void test_unparseable_priority_defaults_to_zero(void) {
        static const char rec[] = ";no header at all\n";
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(parse(rec, strlen(rec), &line, &len, &priority), 1);
        ASSERT_EQ_INT(priority, 0);
        ASSERT_STREQ(line, "no header at all");
        free(line);

        line = NULL;
        {
                static const char rec2[] = "garbage,0,0,-;still a message\n";

                ASSERT_EQ_INT(parse(rec2, strlen(rec2), &line, &len, &priority), 1);
                ASSERT_EQ_INT(priority, 0);
                ASSERT_STREQ(line, "still a message");
                free(line);
        }
}

/* A priority value with facility bits set: only the low 3 bits (severity)
 * survive, exactly as the header comment says pico's field set has no
 * facility. 191 = 0b10111111 -> severity 7. */
static void test_priority_is_masked_to_severity(void) {
        static const char rec[] = "191,0,0,-;masked\n";
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(parse(rec, strlen(rec), &line, &len, &priority), 1);
        ASSERT_EQ_INT(priority, 7);
        free(line);
}

static void test_invalid_args(void) {
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(logd_kmsg_parse_record(NULL, 0, &line, &len, &priority), -EINVAL);
        ASSERT_EQ_INT(logd_kmsg_parse_record("6,0,0,-;x\n", 10, NULL, &len, &priority), -EINVAL);
        ASSERT_EQ_INT(logd_kmsg_parse_record("6,0,0,-;x\n", 10, &line, NULL, &priority), -EINVAL);
        ASSERT_EQ_INT(logd_kmsg_parse_record("6,0,0,-;x\n", 10, &line, &len, NULL), -EINVAL);
}

int main(void) {
        test_well_formed_record();
        test_extra_field();
        test_missing_semicolon_is_skipped();
        test_missing_newline_takes_the_remainder();
        test_empty_message();
        test_unparseable_priority_defaults_to_zero();
        test_priority_is_masked_to_severity();
        test_invalid_args();

        printf("test-logd-kmsg: all checks passed\n");
        return 0;
}
