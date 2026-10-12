/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * logd_kmsg_parse_record() against synthetic buffers: a record with no ';',
 * one with no trailing '\n', and an unparseable priority field, which
 * atoi() turns into 0 (emerg) rather than failing.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../test-util.h"
#include "logd-kmsg-internal.h"
#include "logd-read.h"
#include "logd-write.h"

/* Fixed rather than strlen()'d: a couple of cases below do not end in '\0'
 * right after the content that matters. */
static int parse(const char *buf, size_t n, char **ret_line, size_t *ret_len, int *ret_priority) {
        return logd_kmsg_parse_record(buf, n, ret_line, ret_len, ret_priority, NULL, NULL);
}

/* The first record off a fresh open() on a real kernel. */
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

/* No ';' anywhere: skipped. */
static void test_missing_semicolon_is_skipped(void) {
        static const char rec[] = "not a kmsg record at all\n";
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(parse(rec, strlen(rec), &line, &len, &priority), 0);
}

/* No trailing '\n': the rest of the buffer is the message. */
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
 * masks to priority 0 (emerg), not a parse failure. */
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
 * survive; the log entry has no facility field. 191 = 0b10111111 -> severity 7. */
static void test_priority_is_masked_to_severity(void) {
        static const char rec[] = "191,0,0,-;masked\n";
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(parse(rec, strlen(rec), &line, &len, &priority), 1);
        ASSERT_EQ_INT(priority, 7);
        free(line);
}

/* The kernel writes tabs, ESC and '\\' as \xNN; they come out as real bytes,
 * decoded once (\x5cx41 is "\\x41", not "A"). Malformed escapes stay literal. */
static void test_escapes_are_decoded(void) {
        static const char rec[] = "6,1,0,-;a\\x09b\\x5cx41 \\x1b[0m \\xZZ \\x4\n";
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(parse(rec, strlen(rec), &line, &len, &priority), 1);
        ASSERT_STREQ(line, "a\tb\\x41 \033[0m \\xZZ \\x4");
        ASSERT_EQ_INT(len, strlen(line));
        free(line);
}

static void test_facility_and_seqnum(void) {
        static const char rec[] = "30,4711,1000,-;tag: userspace\n";
        static const char noseq[] = "6,x,0,-;m\n";
        char *line = NULL;
        size_t len = 0;
        int priority = -1, facility = -1;
        uint64_t seqnum = 0;

        ASSERT_EQ_INT(logd_kmsg_parse_record(rec, strlen(rec), &line, &len, &priority, &facility, &seqnum), 1);
        ASSERT_EQ_INT(priority, 6);
        ASSERT_EQ_INT(facility, 3);
        ASSERT_TRUE(seqnum == 4711);
        free(line);

        ASSERT_EQ_INT(logd_kmsg_parse_record(noseq, strlen(noseq), &line, &len, &priority, &facility, &seqnum),
                      1);
        ASSERT_TRUE(seqnum == LOGD_KMSG_NO_SEQNUM);
        free(line);
}

static void push(int fd, const char *rec) {
        ASSERT_TRUE(send(fd, rec, strlen(rec), 0) == (ssize_t) strlen(rec));
}

static LogdKmsg *fake_kmsg(int *ret_writer_fd) {
        int sv[2];
        LogdKmsg *k;

        ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, sv), 0);
        ASSERT_EQ_INT(logd_kmsg_new_from_fd(sv[0], &k), 0);
        *ret_writer_fd = sv[1];
        return k;
}

/* A logd restart in the same boot replays the whole kernel ring; the
 * persisted sequence number keeps those records from being logged twice. */
static void test_restart_does_not_duplicate(void) {
        char *dir = test_tmpdir_new();
        LogdWriter *w;
        LogdRing *ring;
        LogdKmsg *k;
        int fd;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, "cafef00ddeadbeefcafef00ddeadbeef"), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        k = fake_kmsg(&fd);
        push(fd, "6,10,0,-;one\n");
        push(fd, "6,11,0,-;two\n");
        ASSERT_EQ_INT(logd_kmsg_drain(k, w), 2);
        logd_kmsg_free(k);
        close(fd);

        /* Fresh descriptor: the ring is replayed from the start. */
        k = fake_kmsg(&fd);
        push(fd, "6,10,0,-;one\n");
        push(fd, "6,11,0,-;two\n");
        push(fd, "6,12,0,-;three\n");
        ASSERT_EQ_INT(logd_kmsg_drain(k, w), 1);
        logd_kmsg_free(k);
        close(fd);

        /* A gap is still logged, not dropped. */
        k = fake_kmsg(&fd);
        push(fd, "6,20,0,-;later\n");
        ASSERT_EQ_INT(logd_kmsg_drain(k, w), 1);
        logd_kmsg_free(k);
        close(fd);
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 4);
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 2), "MESSAGE"), "three"));
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
}

/* A non-kernel facility marks a userspace write; its syslog tag is split off. */
static void test_userspace_record_tag(void) {
        char *dir = test_tmpdir_new();
        LogdWriter *w;
        LogdRing *ring;
        LogdKmsg *k;
        int fd;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, "cafef00ddeadbeefcafef00ddeadbeef"), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        k = fake_kmsg(&fd);
        push(fd, "30,1,0,-;pico-init[1]: started\n");
        push(fd, "6,2,0,-;tag: kernel text\n");
        ASSERT_EQ_INT(logd_kmsg_drain(k, w), 2);
        logd_kmsg_free(k);
        close(fd);
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 2);
        {
                const LogdEntry *e = logd_ring_entry(ring, 0);

                ASSERT_TRUE(logd_field_equals(logd_entry_field(e, "SYSLOG_IDENTIFIER"), "pico-init"));
                ASSERT_TRUE(logd_field_equals(logd_entry_field(e, "MESSAGE"), "started"));
                e = logd_ring_entry(ring, 1);
                ASSERT_TRUE(logd_entry_field(e, "SYSLOG_IDENTIFIER") == NULL);
                ASSERT_TRUE(logd_field_equals(logd_entry_field(e, "MESSAGE"), "tag: kernel text"));
        }
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
}

static void test_invalid_args(void) {
        char *line = NULL;
        size_t len = 0;
        int priority = -1;

        ASSERT_EQ_INT(logd_kmsg_parse_record(NULL, 0, &line, &len, &priority, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(logd_kmsg_parse_record("6,0,0,-;x\n", 10, NULL, &len, &priority, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(logd_kmsg_parse_record("6,0,0,-;x\n", 10, &line, NULL, &priority, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(logd_kmsg_parse_record("6,0,0,-;x\n", 10, &line, &len, NULL, NULL, NULL), -EINVAL);
}

int main(void) {
        test_well_formed_record();
        test_extra_field();
        test_missing_semicolon_is_skipped();
        test_missing_newline_takes_the_remainder();
        test_empty_message();
        test_unparseable_priority_defaults_to_zero();
        test_priority_is_masked_to_severity();
        test_escapes_are_decoded();
        test_facility_and_seqnum();
        test_restart_does_not_duplicate();
        test_userspace_record_tag();
        test_invalid_args();

        printf("test-logd-kmsg: all checks passed\n");
        return 0;
}
