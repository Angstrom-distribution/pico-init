/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * picolog: filter/follow/export modes against fixture rings, binary-safe fields under both
 * the default blob-data path and -a, and a rotation boundary crossed mid-follow.
 *
 * Two layers: the logd-read.c reader primitives are tested directly (field
 * lookup, unit/priority/kernel predicates, logd_ring_read_filtered(),
 * reading across a rotation, and following across one crossed mid-poll,
 * driven by interleaving real writer appends with real poll calls). The CLI
 * is then exercised end to end by spawning the built `picolog` binary
 * against a fixture ring via the LOGD_RUNTIME_DIR environment variable,
 * which covers argv parsing and display formatting.
 */

#include "logd-read.h"
#include "logd-write.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../test-util.h"

#define TEST_BOOT_ID "cafef00ddeadbeefcafef00ddeadbeef"

static void build_fixture_ring(const char *dir) {
        LogdWriter *w;

        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        {
                LogdField f[] = {
                        {           "MESSAGE", "hello from netd", strlen("hello from netd") },
                        {          "PRIORITY",               "6",                         1 },
                        { "SYSLOG_IDENTIFIER",            "netd",            strlen("netd") },
                        {              "_PID",              "42",                         2 },
                        {     "_SYSTEMD_UNIT",    "netd.service",    strlen("netd.service") },
                        {        "_TRANSPORT",          "stdout",          strlen("stdout") },
                };
                ASSERT_EQ_INT(logd_writer_append(w, f, sizeof(f) / sizeof(f[0])), 0);
        }
        {
                LogdField f[] = {
                        {           "MESSAGE", "urgent warning", strlen("urgent warning") },
                        {          "PRIORITY",              "3",                        1 },
                        { "SYSLOG_IDENTIFIER",          "eudev",          strlen("eudev") },
                        {     "_SYSTEMD_UNIT",  "eudev.service",  strlen("eudev.service") },
                        {        "_TRANSPORT",         "syslog",         strlen("syslog") },
                };
                ASSERT_EQ_INT(logd_writer_append(w, f, sizeof(f) / sizeof(f[0])), 0);
        }
        {
                LogdField f[] = {
                        {           "MESSAGE", "kernel booted", strlen("kernel booted") },
                        {          "PRIORITY",             "6",                       1 },
                        { "SYSLOG_IDENTIFIER",        "kernel",        strlen("kernel") },
                        {        "_TRANSPORT",        "kernel",        strlen("kernel") },
                };
                ASSERT_EQ_INT(logd_writer_append(w, f, sizeof(f) / sizeof(f[0])), 0);
        }
        {
                /* Binary-safe MESSAGE: the JOURNAL_EXPORT_FORMATS.md worked
                 * example, as in test-logd-write.c. */
                LogdField f[] = {
                        {           "MESSAGE",     "foo\nbar",                      7 },
                        {          "PRIORITY",            "6",                      1 },
                        { "SYSLOG_IDENTIFIER",         "netd",         strlen("netd") },
                        {     "_SYSTEMD_UNIT", "netd.service", strlen("netd.service") },
                        {        "_TRANSPORT",       "stdout",       strlen("stdout") },
                };
                ASSERT_EQ_INT(logd_writer_append(w, f, sizeof(f) / sizeof(f[0])), 0);
        }

        logd_writer_free(w);
}

static void test_reader_empty_ring(void) {
        LogdRing *ring;
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 0);

        logd_ring_free(ring);
        test_rm_rf(dir);
        free(dir);
        printf("test-picolog: an empty/missing ring reads as zero entries, not an error\n");
}

static void test_reader_fields_and_binary(void) {
        LogdRing *ring;
        char *dir = test_tmpdir_new();
        const LogdEntry *e;
        const LogdReadField *f;

        ASSERT_TRUE(dir != NULL);
        build_fixture_ring(dir);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 4);

        e = logd_ring_entry(ring, 0);
        f = logd_entry_field(e, "MESSAGE");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(!f->binary);
        ASSERT_TRUE(logd_field_equals(f, "hello from netd"));

        f = logd_entry_field(e, "_BOOT_ID");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(logd_field_equals(f, TEST_BOOT_ID));

        ASSERT_TRUE(logd_entry_field(e, "NOSUCHFIELD") == NULL);

        e = logd_ring_entry(ring, 3); /* the binary-safe fixture */
        f = logd_entry_field(e, "MESSAGE");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(f->binary);
        ASSERT_EQ_INT((int) f->value_len, 7);
        ASSERT_TRUE(memcmp(f->value, "foo\nbar", 7) == 0);

        logd_ring_free(ring);
        test_rm_rf(dir);
        free(dir);
        printf("test-picolog: field lookup and binary-safe decoding are correct\n");
}

static void test_reader_predicates(void) {
        LogdRing *ring;
        char *dir = test_tmpdir_new();
        const LogdEntry *e0, *e1, *e2;

        ASSERT_TRUE(dir != NULL);
        build_fixture_ring(dir);
        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);

        e0 = logd_ring_entry(ring, 0); /* netd, priority 6 (info) */
        e1 = logd_ring_entry(ring, 1); /* eudev, priority 3 (err) */
        e2 = logd_ring_entry(ring, 2); /* kernel */

        ASSERT_TRUE(logd_entry_matches_unit(e0, "netd.service"));
        ASSERT_TRUE(!logd_entry_matches_unit(e0, "eudev.service"));
        ASSERT_TRUE(logd_entry_matches_unit(e0, NULL));            /* no filter matches anything */
        ASSERT_TRUE(!logd_entry_matches_unit(e2, "netd.service")); /* kernel entry has no _SYSTEMD_UNIT at all */

        /* Bare name mangling: `-u netd` must match _SYSTEMD_UNIT=netd.service,
         * as systemctl/journalctl mangle an unsuffixed argument. */
        ASSERT_TRUE(logd_entry_matches_unit(e0, "netd"));
        ASSERT_TRUE(!logd_entry_matches_unit(e0, "eudev"));
        ASSERT_TRUE(!logd_entry_matches_unit(e0, "netd.socket")); /* known suffix, not mangled, no match */

        ASSERT_TRUE(logd_entry_matches_priority(e1, 4));  /* err(3) <= warning(4) */
        ASSERT_TRUE(!logd_entry_matches_priority(e0, 4)); /* info(6) > warning(4) */

        ASSERT_TRUE(logd_entry_is_kernel(e2));
        ASSERT_TRUE(!logd_entry_is_kernel(e0));

        logd_ring_free(ring);
        test_rm_rf(dir);
        free(dir);
        printf("test-picolog: unit/priority/kernel predicates match the fixture correctly\n");
}

static void test_ring_read_filtered_tail(void) {
        LogdWriter *w;
        char *dir = test_tmpdir_new();
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        for (int i = 0; i < 10; i++) {
                char msg[32];
                LogdField f[2];

                snprintf(msg, sizeof(msg), "netd-%02d", i);
                f[0] = (LogdField){ "MESSAGE", msg, strlen(msg) };
                f[1] = (LogdField){ "_SYSTEMD_UNIT", "netd.service", strlen("netd.service") };
                ASSERT_EQ_INT(logd_writer_append(w, f, 2), 0);

                snprintf(msg, sizeof(msg), "other-%02d", i);
                f[0] = (LogdField){ "MESSAGE", msg, strlen(msg) };
                f[1] = (LogdField){ "_SYSTEMD_UNIT", "other.service", strlen("other.service") };
                ASSERT_EQ_INT(logd_writer_append(w, f, 2), 0);
        }
        logd_writer_free(w);

        /* The call picoctl's status verb uses: the last 3 entries for
         * netd.service. */
        ASSERT_EQ_INT(logd_ring_read_filtered(dir, "netd.service", 3, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 3);
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 0), "MESSAGE"), "netd-07"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 1), "MESSAGE"), "netd-08"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 2), "MESSAGE"), "netd-09"));

        logd_ring_free(ring);
        test_rm_rf(dir);
        free(dir);
        printf("test-picolog: logd_ring_read_filtered() gives picoctl the last N entries for one unit in one call\n");
}

/* Copies `f`'s value into a NUL-terminated buffer; ring values are not
 * NUL-terminated. */
static void field_value_copy(const LogdReadField *f, char *out, size_t outsz) {
        size_t n = f->value_len < outsz - 1 ? f->value_len : outsz - 1;

        memcpy(out, f->value, n);
        out[n] = '\0';
}

static void test_ring_read_across_rotation(void) {
        LogdWriter *w;
        char *dir = test_tmpdir_new();
        LogdRing *ring;
        int n_entries = 200;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_max_bytes(w, 4096), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        for (int i = 0; i < n_entries; i++) {
                char msg[32];
                LogdField f;

                snprintf(msg, sizeof(msg), "entry-%04d", i);
                f = (LogdField){ "MESSAGE", msg, strlen(msg) };
                ASSERT_EQ_INT(logd_writer_append(w, &f, 1), 0);
        }
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        {
                size_t n = logd_ring_n_entries(ring);
                int last_seen = -1;

                ASSERT_TRUE(n >= 2); /* rotation genuinely happened */

                for (size_t i = 0; i < n; i++) {
                        const LogdReadField *f = logd_entry_field(logd_ring_entry(ring, i), "MESSAGE");
                        char numbuf[32];

                        ASSERT_TRUE(f != NULL && !f->binary);
                        field_value_copy(f, numbuf, sizeof(numbuf));

                        {
                                int idx = atoi(numbuf + strlen("entry-"));

                                ASSERT_TRUE(idx > last_seen); /* strictly increasing: no dup, no reorder */
                                last_seen = idx;
                        }
                }

                ASSERT_EQ_INT(last_seen, n_entries - 1);
        }

        logd_ring_free(ring);
        test_rm_rf(dir);
        free(dir);
        printf("test-picolog: logd_ring_read() reads rotated-then-active in order across %d entries\n",
               n_entries);
}

/*
 * Rotation crossed mid-follow: interleave real writer appends with
 * logd_follow_poll() calls across many rotations (4KiB cap, as in
 * test-logd-write.c's rotation test), and confirm every post-follow entry is delivered exactly once, in
 * order, and that nothing written before logd_follow_new() ever appears.
 */
static void test_follow_across_rotation(void) {
        LogdWriter *w;
        char *dir = test_tmpdir_new();
        LogdFollow *f;
        int total_seen = 0, last_seen = -1;
        int n_entries = 200;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_max_bytes(w, 4096), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        for (int i = 0; i < 5; i++) {
                char msg[32];
                LogdField fl;

                snprintf(msg, sizeof(msg), "pre-%02d", i);
                fl = (LogdField){ "MESSAGE", msg, strlen(msg) };
                ASSERT_EQ_INT(logd_writer_append(w, &fl, 1), 0);
        }

        ASSERT_EQ_INT(logd_follow_new(dir, &f), 0);

        {
                LogdRing *ring = NULL;

                ASSERT_EQ_INT(logd_follow_poll(f, &ring), 0);
                ASSERT_TRUE(ring == NULL); /* nothing new yet, and no pre-* backfill */
        }

        for (int i = 0; i < n_entries; i++) {
                char msg[32];
                LogdField fl;
                LogdRing *ring = NULL;

                snprintf(msg, sizeof(msg), "post-%04d", i);
                fl = (LogdField){ "MESSAGE", msg, strlen(msg) };
                ASSERT_EQ_INT(logd_writer_append(w, &fl, 1), 0);

                ASSERT_EQ_INT(logd_follow_poll(f, &ring), 0);
                if (ring) {
                        size_t n = logd_ring_n_entries(ring);

                        for (size_t j = 0; j < n; j++) {
                                const LogdReadField *mf = logd_entry_field(logd_ring_entry(ring, j), "MESSAGE");
                                char numbuf[32];
                                int idx;

                                ASSERT_TRUE(mf != NULL && !mf->binary);
                                field_value_copy(mf, numbuf, sizeof(numbuf));

                                ASSERT_TRUE(strncmp(numbuf, "post-", 5) == 0); /* never a pre-* entry */
                                idx = atoi(numbuf + 5);
                                ASSERT_TRUE(idx > last_seen); /* strictly increasing: no dup, no reorder */
                                last_seen = idx;
                                total_seen++;
                        }
                        logd_ring_free(ring);
                }
        }

        {
                LogdRing *ring = NULL;

                ASSERT_EQ_INT(logd_follow_poll(f, &ring), 0);
                if (ring)
                        logd_ring_free(ring);
        }

        ASSERT_EQ_INT(total_seen, n_entries);
        ASSERT_EQ_INT(last_seen, n_entries - 1);

        logd_follow_free(f);
        logd_writer_free(w);
        test_rm_rf(dir);
        free(dir);
        printf("test-picolog: follow delivers every entry exactly once across a rotation boundary crossed mid-follow\n");
}

static bool find_picolog(char *out, size_t outsz) {
        char self[4096];
        ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
        char *slash;

        if (n <= 0)
                return false;
        self[n] = '\0';

        slash = strrchr(self, '/');
        if (!slash)
                return false;
        *slash = '\0';

        /* Checked: a truncated path could name another file that access()
         * finds executable. */
        if (snprintf(out, outsz, "%s/picolog", self) >= (int) outsz)
                return false;

        return access(out, X_OK) == 0;
}

/* Runs `picolog_path args` via the shell and captures stdout. *out_len, if
 * non-NULL, receives the byte count read (-o export output may not be
 * text). Returns the process
 * exit status, or -1 on a harness-level failure. */
static int run_picolog_capture(
                const char *picolog_path, const char *args, char *out, size_t outsz, size_t *out_len) {
        char cmd[4096];
        FILE *pf;
        size_t n;
        int status;

        snprintf(cmd, sizeof(cmd), "%s %s", picolog_path, args);
        pf = popen(cmd, "r");
        if (!pf)
                return -1;

        n = fread(out, 1, outsz - 1, pf);
        out[n] = '\0';
        if (out_len)
                *out_len = n;

        status = pclose(pf);
        if (status < 0 || !WIFEXITED(status))
                return -1;

        return WEXITSTATUS(status);
}

static void test_cli_short_format_and_filters(void) {
        char picolog_path[4096];
        char *dir = test_tmpdir_new();
        char out[65536];
        int r;

        ASSERT_TRUE(dir != NULL);
        ASSERT_TRUE(find_picolog(picolog_path, sizeof(picolog_path)));
        build_fixture_ring(dir);
        setenv("LOGD_RUNTIME_DIR", dir, 1);

        r = run_picolog_capture(picolog_path, "", out, sizeof(out), NULL);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(strchr(out, '\x1B') == NULL); /* no tty, no colour */
        ASSERT_TRUE(strstr(out, "netd[42]: hello from netd") != NULL);
        ASSERT_TRUE(strstr(out, "eudev: urgent warning") !=
                    NULL); /* no _PID on this fixture entry -> no [pid] */
        ASSERT_TRUE(strstr(out, "kernel: kernel booted") != NULL);
        ASSERT_TRUE(strstr(out, "blob data") != NULL); /* the binary-safe MESSAGE, without -a */
        ASSERT_TRUE(strstr(out, "foo\nbar") == NULL);  /* the raw bytes never reach the default output */

        r = run_picolog_capture(picolog_path, "-u netd.service", out, sizeof(out), NULL);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(strstr(out, "hello from netd") != NULL);
        ASSERT_TRUE(strstr(out, "urgent warning") == NULL);
        ASSERT_TRUE(strstr(out, "kernel booted") == NULL);

        /* bare "-u netd" (no .service) must behave identically */
        r = run_picolog_capture(picolog_path, "-u netd", out, sizeof(out), NULL);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(strstr(out, "hello from netd") != NULL);
        ASSERT_TRUE(strstr(out, "urgent warning") == NULL);
        ASSERT_TRUE(strstr(out, "kernel booted") == NULL);

        r = run_picolog_capture(picolog_path, "-p warning", out, sizeof(out), NULL);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(strstr(out, "urgent warning") != NULL);  /* err(3) is at/above warning */
        ASSERT_TRUE(strstr(out, "hello from netd") == NULL); /* info(6) is below warning */

        r = run_picolog_capture(picolog_path, "-k", out, sizeof(out), NULL);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(strstr(out, "kernel booted") != NULL);
        ASSERT_TRUE(strstr(out, "hello from netd") == NULL);

        r = run_picolog_capture(picolog_path, "-n 1", out, sizeof(out), NULL);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(strstr(out, "blob data") != NULL); /* the last of the four fixture entries */
        ASSERT_TRUE(strstr(out, "hello from netd") == NULL);

        r = run_picolog_capture(picolog_path, "-a", out, sizeof(out), NULL);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(strstr(out, "foo\\x0abar") != NULL); /* -a: decoded, the embedded \n escaped as \x0a */
        ASSERT_TRUE(strstr(out, "blob data") == NULL);

        unsetenv("LOGD_RUNTIME_DIR");
        test_rm_rf(dir);
        free(dir);
        printf("test-picolog: CLI short format, -u/-p/-k/-n filters, and blob-data-vs--a all match the fixture\n");
}

static void test_cli_export_passthrough(void) {
        char picolog_path[4096];
        char *dir = test_tmpdir_new();
        char out[65536];
        char *active_path;
        FILE *fp;
        char raw[65536];
        size_t raw_len, out_len;
        int r;
        LogdWriter *w;

        ASSERT_TRUE(dir != NULL);
        ASSERT_TRUE(find_picolog(picolog_path, sizeof(picolog_path)));

        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);
        {
                LogdField f = { "MESSAGE", "export me", strlen("export me") };

                ASSERT_EQ_INT(logd_writer_append(w, &f, 1), 0);
        }
        ASSERT_EQ_INT(logd_writer_active_path(w, &active_path), 0);
        logd_writer_free(w);

        fp = fopen(active_path, "rb");
        ASSERT_TRUE(fp != NULL);
        raw_len = fread(raw, 1, sizeof(raw), fp);
        fclose(fp);

        setenv("LOGD_RUNTIME_DIR", dir, 1);
        r = run_picolog_capture(picolog_path, "-o export", out, sizeof(out), &out_len);
        unsetenv("LOGD_RUNTIME_DIR");
        ASSERT_EQ_INT(r, 0);

        /* Byte-for-byte identical to the file on disk. */
        ASSERT_EQ_INT((int) out_len, (int) raw_len);
        ASSERT_TRUE(memcmp(out, raw, raw_len) == 0);

        free(active_path);
        test_rm_rf(dir);
        free(dir);
        printf("test-picolog: -o export is a true byte-for-byte passthrough of the on-disk entry\n");
}

static void build_color_fixture_ring(const char *dir) {
        LogdWriter *w;

        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        {
                LogdField f[] = {
                        {  "MESSAGE", "disk failure", strlen("disk failure") },
                        { "PRIORITY",            "3",                      1 }, /* err */
                };
                ASSERT_EQ_INT(logd_writer_append(w, f, sizeof(f) / sizeof(f[0])), 0);
        }
        {
                LogdField f[] = {
                        {  "MESSAGE", "low battery", strlen("low battery") },
                        { "PRIORITY",           "4",                     1 }, /* warning */
                };
                ASSERT_EQ_INT(logd_writer_append(w, f, sizeof(f) / sizeof(f[0])), 0);
        }
        {
                LogdField f[] = {
                        {  "MESSAGE", "link is up", strlen("link is up") },
                        { "PRIORITY",          "5",                    1 }, /* notice  */
                };
                ASSERT_EQ_INT(logd_writer_append(w, f, sizeof(f) / sizeof(f[0])), 0);
        }

        logd_writer_free(w);
}

/* SYSTEMD_COLORS=true forces colour on though popen()'s pipe isn't a tty
 * (see pico-color.h). Mapping as get_log_colors() (terminal-util.c): err
 * red, warning yellow, notice highlighted, wrapped around the message text
 * only. */
static void test_cli_color_priority_escapes(void) {
        char picolog_path[4096];
        char *dir = test_tmpdir_new();
        char out[65536];
        int r;

        ASSERT_TRUE(dir != NULL);
        ASSERT_TRUE(find_picolog(picolog_path, sizeof(picolog_path)));
        build_color_fixture_ring(dir);
        setenv("LOGD_RUNTIME_DIR", dir, 1);
        setenv("SYSTEMD_COLORS", "true", 1);

        r = run_picolog_capture(picolog_path, "", out, sizeof(out), NULL);
        ASSERT_EQ_INT(r, 0);

        /* err (priority 3): ANSI_HIGHLIGHT_RED .. ANSI_NORMAL */
        ASSERT_TRUE(strstr(out, "\x1B[0;1;31mdisk failure\x1B[0m") != NULL);
        /* warning (priority 4): ANSI_HIGHLIGHT_YELLOW (== ANSI_HIGHLIGHT_KHAKI3) .. ANSI_NORMAL */
        ASSERT_TRUE(strstr(out, "\x1B[0;1;38:5:185mlow battery\x1B[0m") != NULL);
        /* notice (priority 5): ANSI_HIGHLIGHT .. ANSI_NORMAL */
        ASSERT_TRUE(strstr(out, "\x1B[0;1;39mlink is up\x1B[0m") != NULL);

        unsetenv("SYSTEMD_COLORS");
        unsetenv("LOGD_RUNTIME_DIR");
        test_rm_rf(dir);
        free(dir);
        printf("test-picolog: SYSTEMD_COLORS=true colours err/warning/notice with upstream's own escapes\n");
}

static void test_cli_invalid_priority_rejected(void) {
        char picolog_path[4096];
        char out[4096];
        int r;

        ASSERT_TRUE(find_picolog(picolog_path, sizeof(picolog_path)));
        r = run_picolog_capture(picolog_path, "-p bogus", out, sizeof(out), NULL);
        ASSERT_TRUE(r != 0);
        printf("test-picolog: an invalid -p value is rejected with a non-zero exit\n");
}

int main(void) {
        test_reader_empty_ring();
        test_reader_fields_and_binary();
        test_reader_predicates();
        test_ring_read_filtered_tail();
        test_ring_read_across_rotation();
        test_follow_across_rotation();
        test_cli_short_format_and_filters();
        test_cli_export_passthrough();
        test_cli_color_priority_escapes();
        test_cli_invalid_priority_rejected();

        printf("test-picolog: all cases passed\n");
        return 0;
}
