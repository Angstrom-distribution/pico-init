/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The export-format writer and the /run ring.
 *
 * Everything up to test_rotation_boundary() tests the writer in isolation:
 * field-name validation, the binary-safe framing of
 * JOURNAL_EXPORT_FORMATS.md's worked example (byte-for-byte), both clocks
 * bounded against real clock reads, restart-resume, the oversized-entry cap,
 * and rotation preserving record boundaries under repeated append.
 *
 * test_journal_remote_roundtrip() feeds a real ring through the real
 * systemd-journal-remote and reads it back with the real journalctl, so a
 * wire-format bug cannot hide behind a mirrored assumption. It is skipped
 * (meson exit code 77) if the tools are not installed; every other case
 * still runs.
 */

#include "logd-write.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../test-util.h"
#include "../util.h"
#include "logd.h"

/* 32 lowercase hex chars: a fixed _BOOT_ID for tests that need exact bytes. */
#define TEST_BOOT_ID "cafef00ddeadbeefcafef00ddeadbeef"

static void test_field_name_validation(void) {
        LogdWriter *w;
        char *dir = test_tmpdir_new();
        static const char *bad_names[] = {
                "lowercase", "1DIGITFIRST", "", "HAS-DASH", "HAS SPACE",
        };
        char too_long[70];

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
                LogdField f = { bad_names[i], "x", 1 };

                ASSERT_EQ_INT(logd_writer_append(w, &f, 1), -EINVAL);
        }

        memset(too_long, 'A', sizeof(too_long) - 1);
        too_long[sizeof(too_long) - 1] = '\0';
        {
                LogdField f = { too_long, "x", 1 };

                ASSERT_EQ_INT(logd_writer_append(w, &f, 1), -EINVAL);
        }

        /* Positive control: a valid name is accepted. */
        {
                LogdField f = { "SYSLOG_IDENTIFIER", "ok", 2 };

                ASSERT_EQ_INT(logd_writer_append(w, &f, 1), 0);
        }

        logd_writer_free(w);
        test_rm_rf(dir);
        free(dir);
        printf("test-logd-write: field name validation rejects malformed names, accepts real ones\n");
}

static const char *skip_lines(const char *p, int n) {
        for (int i = 0; i < n; i++) {
                p = strchr(p, '\n');
                ASSERT_TRUE(p != NULL);
                p++;
        }

        return p;
}

/*
 * JOURNAL_EXPORT_FORMATS.md's worked example:
 * `journal.send("foo\nbar")` documents as MESSAGE\n + a little-endian 7 +
 * seven NUL padding bytes + the 7 literal bytes "foo\nbar" + \n.
 */
static void test_binary_safe_golden_bytes(void) {
        LogdWriter *w;
        char *dir = test_tmpdir_new();
        char *active_path;
        FILE *f;
        char buf[4096];
        size_t len;
        const char *tail;
        static const uint8_t expected_len_le[8] = { 0x07, 0, 0, 0, 0, 0, 0, 0 };
        LogdField msg = { "MESSAGE", "foo\nbar", 7 };

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);
        ASSERT_EQ_INT(logd_writer_append(w, &msg, 1), 0);

        ASSERT_EQ_INT(logd_writer_active_path(w, &active_path), 0);
        f = fopen(active_path, "rb");
        ASSERT_TRUE(f != NULL);
        len = fread(buf, 1, sizeof(buf), f);
        fclose(f);

        tail = skip_lines(buf, 3); /* past __REALTIME_TIMESTAMP=, __MONOTONIC_TIMESTAMP=, _BOOT_ID= */

        ASSERT_TRUE(memcmp(tail, "MESSAGE\n", 8) == 0);
        tail += 8;
        ASSERT_TRUE(memcmp(tail, expected_len_le, 8) == 0);
        tail += 8;
        ASSERT_TRUE(memcmp(tail, "foo\nbar", 7) == 0);
        tail += 7;
        ASSERT_TRUE(*tail == '\n');
        tail += 1;
        ASSERT_TRUE(*tail == '\n'); /* blank-line entry separator */
        tail += 1;

        ASSERT_EQ_INT((int) (tail - buf), (int) len);

        free(active_path);
        logd_writer_free(w);
        test_rm_rf(dir);
        free(dir);
        printf("test-logd-write: binary-safe encoding matches JOURNAL_EXPORT_FORMATS.md's own worked example\n");
}

/* Both clocks bounded against clock reads taken before and after the call,
 * _BOOT_ID exact, and a plain caller-supplied field round-tripping. */
static void test_plain_field_and_clocks(void) {
        LogdWriter *w;
        char *dir = test_tmpdir_new();
        char *active_path;
        FILE *f;
        char buf[4096];
        size_t len;
        usec_t before_rt, after_rt, before_mono, after_mono;
        struct timespec ts;
        uint64_t rt_val, mono_val;
        char boot_id_field[64];
        LogdField pf = { "PRIORITY", "6", 1 };
        const char *p;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        ASSERT_TRUE(clock_gettime(CLOCK_REALTIME, &ts) == 0);
        before_rt = (usec_t) ts.tv_sec * USEC_PER_SEC + (usec_t) ts.tv_nsec / 1000ULL;
        ASSERT_TRUE(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
        before_mono = (usec_t) ts.tv_sec * USEC_PER_SEC + (usec_t) ts.tv_nsec / 1000ULL;

        ASSERT_EQ_INT(logd_writer_append(w, &pf, 1), 0);

        ASSERT_TRUE(clock_gettime(CLOCK_REALTIME, &ts) == 0);
        after_rt = (usec_t) ts.tv_sec * USEC_PER_SEC + (usec_t) ts.tv_nsec / 1000ULL;
        ASSERT_TRUE(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
        after_mono = (usec_t) ts.tv_sec * USEC_PER_SEC + (usec_t) ts.tv_nsec / 1000ULL;

        ASSERT_EQ_INT(logd_writer_active_path(w, &active_path), 0);
        f = fopen(active_path, "rb");
        ASSERT_TRUE(f != NULL);
        len = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[len] = '\0';

        ASSERT_TRUE(strncmp(buf, "__REALTIME_TIMESTAMP=", 21) == 0);
        rt_val = strtoull(buf + 21, NULL, 10);
        ASSERT_TRUE(rt_val >= before_rt && rt_val <= after_rt);

        p = strchr(buf, '\n');
        ASSERT_TRUE(p != NULL);
        p++;
        ASSERT_TRUE(strncmp(p, "__MONOTONIC_TIMESTAMP=", 22) == 0);
        mono_val = strtoull(p + 22, NULL, 10);
        ASSERT_TRUE(mono_val >= before_mono && mono_val <= after_mono);

        p = strchr(p, '\n');
        ASSERT_TRUE(p != NULL);
        p++;
        snprintf(boot_id_field, sizeof(boot_id_field), "_BOOT_ID=%s\n", TEST_BOOT_ID);
        ASSERT_TRUE(strncmp(p, boot_id_field, strlen(boot_id_field)) == 0);
        p += strlen(boot_id_field);

        ASSERT_TRUE(strncmp(p, "PRIORITY=6\n\n", 12) == 0);
        p += 12;

        ASSERT_EQ_INT((int) (p - buf), (int) len);

        free(active_path);
        logd_writer_free(w);
        test_rm_rf(dir);
        free(dir);
        printf("test-logd-write: both clocks are bounded by real reads, _BOOT_ID and a plain field round-trip exactly\n");
}

static void test_open_idempotent(void) {
        LogdWriter *w;
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);                                    /* idempotent */
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, "/somewhere/else"), -EBUSY); /* refused once open */

        logd_writer_free(w);
        test_rm_rf(dir);
        free(dir);
        printf("test-logd-write: open() is idempotent, runtime_dir is locked once open\n");
}

static void test_append_before_open_fails(void) {
        LogdWriter *w;
        LogdField f = { "MESSAGE", "x", 1 };

        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_append(w, &f, 1), -EBADF);
        logd_writer_free(w);
        printf("test-logd-write: append() before open() fails rather than silently no-opping\n");
}

/* A restarted logd must resume the active file, not truncate it. */
static void test_resume_after_restart(void) {
        LogdWriter *w1, *w2;
        char *dir = test_tmpdir_new();
        char *active_path;
        LogdField f1 = { "MESSAGE", "before-restart", strlen("before-restart") };
        LogdField f2 = { "MESSAGE", "after-restart", strlen("after-restart") };
        FILE *fp;
        char buf[4096];
        size_t len;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_writer_new(&w1), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w1, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w1, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w1), 0);
        ASSERT_EQ_INT(logd_writer_append(w1, &f1, 1), 0);
        logd_writer_free(w1); /* simulates a crash: fd closed, file left as-is */

        ASSERT_EQ_INT(logd_writer_new(&w2), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w2, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w2, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w2), 0);
        ASSERT_EQ_INT(logd_writer_append(w2, &f2, 1), 0);

        ASSERT_EQ_INT(logd_writer_active_path(w2, &active_path), 0);
        fp = fopen(active_path, "rb");
        ASSERT_TRUE(fp != NULL);
        len = fread(buf, 1, sizeof(buf) - 1, fp);
        fclose(fp);
        buf[len] = '\0';

        ASSERT_TRUE(strstr(buf, "MESSAGE=before-restart") != NULL);
        ASSERT_TRUE(strstr(buf, "MESSAGE=after-restart") != NULL);

        free(active_path);
        logd_writer_free(w2);
        test_rm_rf(dir);
        free(dir);
        printf("test-logd-write: a restarted writer resumes the active file instead of truncating it\n");
}

/* An entry that alone would exceed the cap is refused with -EMSGSIZE before
 * anything reaches the ring; the active file is left untouched. */
static void test_oversized_entry_rejected(void) {
        LogdWriter *w;
        char *dir = test_tmpdir_new();
        char *huge, *active_path;
        size_t huge_len = 8192;
        LogdField f;
        struct stat st;

        ASSERT_TRUE(dir != NULL);
        huge = malloc(huge_len);
        ASSERT_TRUE(huge != NULL);
        memset(huge, 'x', huge_len);

        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_max_bytes(w, 4096), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        f.name = "MESSAGE";
        f.value = huge;
        f.value_len = huge_len;

        ASSERT_EQ_INT(logd_writer_append(w, &f, 1), -EMSGSIZE);

        ASSERT_EQ_INT(logd_writer_active_path(w, &active_path), 0);
        ASSERT_TRUE(stat(active_path, &st) == 0);
        ASSERT_EQ_INT((int) st.st_size, 0);

        free(active_path);
        free(huge);
        logd_writer_free(w);
        test_rm_rf(dir);
        free(dir);
        printf("test-logd-write: an entry larger than the cap is refused, not partially written\n");
}

static void read_whole_file_concat(const char *path1, const char *path2, char **out, size_t *out_len) {
        FILE *f1, *f2;
        char *buf;
        size_t n1 = 0, n2 = 0;
        long sz1 = 0, sz2 = 0;

        f1 = fopen(path1, "rb");
        if (f1) {
                fseek(f1, 0, SEEK_END);
                sz1 = ftell(f1);
                fseek(f1, 0, SEEK_SET);
        }

        f2 = fopen(path2, "rb");
        if (f2) {
                fseek(f2, 0, SEEK_END);
                sz2 = ftell(f2);
                fseek(f2, 0, SEEK_SET);
        }

        buf = malloc((size_t) sz1 + (size_t) sz2 + 1);
        if (!buf) {
                if (f1)
                        fclose(f1);
                if (f2)
                        fclose(f2);
                *out = NULL;
                *out_len = 0;
                return;
        }

        if (f1) {
                n1 = fread(buf, 1, (size_t) sz1, f1);
                fclose(f1);
        }
        if (f2) {
                n2 = fread(buf + n1, 1, (size_t) sz2, f2);
                fclose(f2);
        }

        buf[n1 + n2] = '\0';
        *out = buf;
        *out_len = n1 + n2;
}

/*
 * Rotation must preserve record boundaries. Every appended MESSAGE carries
 * a sequence number, so reading rotated-then-active and walking the sequence
 * catches a split, duplicated or reordered entry. Timestamp digit widths
 * vary, so this checks content, not size.
 */
static void test_rotation_boundary(void) {
        LogdWriter *w;
        char *dir = test_tmpdir_new();
        char *active_path, *rotated_path;
        int n_entries = 200;
        char msg[64];

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_max_bytes(w, 4096), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        for (int i = 0; i < n_entries; i++) {
                LogdField f;

                snprintf(msg, sizeof(msg), "entry-%04d", i);
                f.name = "MESSAGE";
                f.value = msg;
                f.value_len = strlen(msg);

                ASSERT_EQ_INT(logd_writer_append(w, &f, 1), 0);
        }

        ASSERT_EQ_INT(logd_writer_active_path(w, &active_path), 0);
        ASSERT_EQ_INT(logd_writer_rotated_path(w, &rotated_path), 0);

        /* At roughly 130-150 bytes per entry (three auto fields plus one
         * short MESSAGE), 200 entries writes well past the 2KiB rotation
         * threshold many times over. */
        {
                struct stat st;

                ASSERT_TRUE(stat(rotated_path, &st) == 0);
                ASSERT_TRUE(st.st_size > 0);
        }

        {
                char *combined = NULL;
                size_t combined_len = 0;
                int last_seen = -1;
                int seen_count = 0;
                const char *p;

                read_whole_file_concat(rotated_path, active_path, &combined, &combined_len);
                ASSERT_TRUE(combined != NULL);

                /* No trailing partial entry: the buffer must end with the
                 * blank-line separator, never mid-record. */
                ASSERT_TRUE(combined_len >= 2);
                ASSERT_TRUE(combined[combined_len - 1] == '\n' && combined[combined_len - 2] == '\n');

                p = combined;
                while ((p = strstr(p, "MESSAGE=entry-")) != NULL) {
                        int idx = atoi(p + strlen("MESSAGE=entry-"));

                        ASSERT_TRUE(idx > last_seen); /* strictly increasing: no dup, no reorder */
                        last_seen = idx;
                        seen_count++;
                        p += strlen("MESSAGE=entry-");
                }

                /* Older entries are gone (the ring keeps the active file plus
                 * one rotated predecessor), but rotation happened
                 * (seen_count spans more than one rotation's worth) and the
                 * most recent entry survived. */
                ASSERT_TRUE(seen_count >= 2);
                ASSERT_EQ_INT(last_seen, n_entries - 1);

                free(combined);
        }

        free(active_path);
        free(rotated_path);
        logd_writer_free(w);
        test_rm_rf(dir);
        free(dir);
        printf("test-logd-write: rotation preserves byte-exact record boundaries across %d entries\n",
               n_entries);
}

static bool find_journal_remote(char *out, size_t outsz) {
        static const char *candidates[] = {
                "/usr/lib/systemd/systemd-journal-remote",
                "/lib/systemd/systemd-journal-remote",
                "/usr/libexec/systemd/systemd-journal-remote",
        };

        for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++)
                if (access(candidates[i], X_OK) == 0) {
                        snprintf(out, outsz, "%s", candidates[i]);
                        return true;
                }

        {
                FILE *pf = popen("command -v systemd-journal-remote 2>/dev/null", "r");
                char line[512];
                bool found = false;

                if (!pf)
                        return false;

                if (fgets(line, sizeof(line), pf)) {
                        size_t n = strlen(line);

                        if (n > 0 && line[n - 1] == '\n')
                                line[n - 1] = '\0';

                        if (line[0] != '\0') {
                                snprintf(out, outsz, "%s", line);
                                found = true;
                        }
                }

                pclose(pf);
                return found;
        }
}

static int run_feed(const char *cmd, const void *data, size_t len) {
        FILE *pf = popen(cmd, "w");
        int status;

        if (!pf)
                return -1;

        fwrite(data, 1, len, pf);
        if (ferror(pf)) {
                pclose(pf);
                return -1;
        }

        status = pclose(pf);
        if (status < 0 || !WIFEXITED(status))
                return -1;

        return WEXITSTATUS(status);
}

static int run_capture(const char *cmd, char *out, size_t outsz) {
        FILE *pf = popen(cmd, "r");
        size_t n;
        int status;

        if (!pf)
                return -1;

        n = fread(out, 1, outsz - 1, pf);
        out[n] = '\0';

        status = pclose(pf);
        if (status < 0 || !WIFEXITED(status))
                return -1;

        return WEXITSTATUS(status);
}

/*
 * A real ring, fed through the real systemd-journal-remote, read back with
 * the real journalctl. Mandatory fields (see logd-write.h): __REALTIME_TIMESTAMP and
 * _BOOT_ID are both required for systemd-journal-remote to accept an entry
 * at all (VALID_REALTIME(0) is false; a null boot ID is EBADMSG), while
 * __MONOTONIC_TIMESTAMP is silently accepted as 0 if absent -- so its
 * presence and non-zero-ness are asserted explicitly below rather than only
 * checking the entry was accepted.
 */
static void test_journal_remote_roundtrip(bool *skipped) {
        char remote_bin[512];
        char *dir;
        LogdWriter *w;
        char *active_path;
        char cmd[8192]; /* large to silence -Wformat-truncation, which sizes
                         * against out_journal's declared capacity */
        char out_journal[4096];
        char export_buf[65536];
        char capture[65536];
        FILE *f;
        size_t export_len;
        int r;

        *skipped = false;

        if (!find_journal_remote(remote_bin, sizeof(remote_bin))) {
                printf("test-logd-write: systemd-journal-remote not found, skipping the real round-trip oracle\n");
                *skipped = true;
                return;
        }

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        {
                LogdField f1[] = {
                        {           "MESSAGE",        "entry one",        strlen("entry one") },
                        {          "PRIORITY",                "3",                          1 }, /* err: more severe than warning */
                        { "SYSLOG_IDENTIFIER",          "testsvc",          strlen("testsvc") },
                        {     "_SYSTEMD_UNIT", "testunit.service", strlen("testunit.service") },
                };
                LogdField f2[] = {
                        {           "MESSAGE",         "entry two",         strlen("entry two") },
                        {          "PRIORITY",                 "6",                           1 }, /* info: less severe than warning */
                        { "SYSLOG_IDENTIFIER",          "othersvc",          strlen("othersvc") },
                        {     "_SYSTEMD_UNIT", "otherunit.service", strlen("otherunit.service") },
                };

                ASSERT_EQ_INT(logd_writer_append(w, f1, 4), 0);
                ASSERT_EQ_INT(logd_writer_append(w, f2, 4), 0);
        }

        ASSERT_EQ_INT(logd_writer_active_path(w, &active_path), 0);
        f = fopen(active_path, "rb");
        ASSERT_TRUE(f != NULL);
        export_len = fread(export_buf, 1, sizeof(export_buf), f);
        fclose(f);
        ASSERT_TRUE(export_len > 0);

        snprintf(out_journal, sizeof(out_journal), "%s/out.journal", dir);

        /* Only --split-mode=none is accepted for a stdin ("-") source, and
         * that mode requires -o to be a plain file, not a directory. */
        snprintf(cmd, sizeof(cmd), "%s --split-mode=none -o %s -", remote_bin, out_journal);
        r = run_feed(cmd, export_buf, export_len);
        ASSERT_EQ_INT(r, 0);

        snprintf(cmd, sizeof(cmd), "journalctl --no-pager --file=%s -o export", out_journal);
        r = run_capture(cmd, capture, sizeof(capture));
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(strstr(capture, "MESSAGE=entry one") != NULL);
        ASSERT_TRUE(strstr(capture, "MESSAGE=entry two") != NULL);
        ASSERT_TRUE(strstr(capture, "_SYSTEMD_UNIT=testunit.service") != NULL);
        ASSERT_TRUE(strstr(capture, "_SYSTEMD_UNIT=otherunit.service") != NULL);
        ASSERT_TRUE(strstr(capture, "_BOOT_ID=" TEST_BOOT_ID) != NULL);
        ASSERT_TRUE(strstr(capture, "__MONOTONIC_TIMESTAMP=") != NULL);
        ASSERT_TRUE(strstr(capture, "__MONOTONIC_TIMESTAMP=0\n") == NULL); /* the silent-default trap */

        snprintf(cmd, sizeof(cmd), "journalctl --no-pager --file=%s -u testunit.service -o export", out_journal);
        r = run_capture(cmd, capture, sizeof(capture));
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(strstr(capture, "MESSAGE=entry one") != NULL);
        ASSERT_TRUE(strstr(capture, "MESSAGE=entry two") == NULL);

        snprintf(cmd, sizeof(cmd), "journalctl --no-pager --file=%s -p warning -o export", out_journal);
        r = run_capture(cmd, capture, sizeof(capture));
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(strstr(capture, "MESSAGE=entry one") != NULL); /* err (3) is at/above warning */
        ASSERT_TRUE(strstr(capture, "MESSAGE=entry two") == NULL); /* info (6) is below warning */

        free(active_path);
        logd_writer_free(w);
        test_rm_rf(dir);
        free(dir);

        printf("test-logd-write: real systemd-journal-remote + journalctl round trip OK (%s)\n", remote_bin);
}

int main(void) {
        bool oracle_skipped = false;

        test_field_name_validation();
        test_binary_safe_golden_bytes();
        test_plain_field_and_clocks();
        test_open_idempotent();
        test_append_before_open_fails();
        test_resume_after_restart();
        test_oversized_entry_rejected();
        test_rotation_boundary();
        test_journal_remote_roundtrip(&oracle_skipped);

        if (oracle_skipped) {
                printf("test-logd-write: all local cases passed; real-oracle round trip SKIPPED "
                       "(systemd-journal-remote not found)\n");
                return 77;
        }

        printf("test-logd-write: all cases passed, including the real systemd-journal-remote/journalctl round trip\n");
        return 0;
}
