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

#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

/* `first` starts a line whose end is a newline, and `next` follows on the
 * next line after indentation: how a multi-line message is rendered. */
static void assert_continuation(const char *out, const char *first, const char *next) {
        const char *p = strstr(out, first);

        ASSERT_TRUE(p != NULL);
        p += strlen(first);
        ASSERT_TRUE(*p == '\n');
        p++;
        ASSERT_TRUE(*p == ' ');
        while (*p == ' ')
                p++;
        ASSERT_TRUE(strncmp(p, next, strlen(next)) == 0);
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
        assert_continuation(out, "netd: foo", "bar"); /* a multi-line MESSAGE is indented, not a blob */
        ASSERT_TRUE(strstr(out, "blob data") == NULL);

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
        ASSERT_TRUE(strstr(out, "bar") != NULL); /* the last of the four fixture entries */
        ASSERT_TRUE(strstr(out, "hello from netd") == NULL);

        r = run_picolog_capture(picolog_path, "-a", out, sizeof(out), NULL);
        ASSERT_EQ_INT(r, 0);
        assert_continuation(out, "netd: foo", "bar");
        ASSERT_TRUE(strstr(out, "blob data") == NULL);

        unsetenv("LOGD_RUNTIME_DIR");
        test_rm_rf(dir);
        free(dir);
        printf("test-picolog: CLI short format and the -u/-p/-k/-n/-a options all match the fixture\n");
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

/*
 * The journalctl-262 option set. These run against a hand-written export
 * file with fixed timestamps (read with --file), so formats and time filters
 * can be compared byte for byte; TZ is pinned to UTC.
 */

#define STARTS(s, lit) (strncmp((s), (lit), sizeof(lit) - 1) == 0)

static char fx_path[4200];
static char pl_path[4096];
static char fx_dir[4096];

static void fx_header(FILE *f, uint64_t real, uint64_t mono) {
        fprintf(f,
                "__REALTIME_TIMESTAMP=%" PRIu64 "\n__MONOTONIC_TIMESTAMP=%" PRIu64 "\n_BOOT_ID=%s\n",
                real,
                mono,
                TEST_BOOT_ID);
}

/* A MESSAGE in the binary-safe framing, then the plain fields in `rest`. */
static void fx_binary_message(FILE *f, const void *msg, size_t len, const char *rest) {
        uint8_t le[8];

        for (size_t i = 0; i < 8; i++)
                le[i] = (uint8_t) ((uint64_t) len >> (8 * i));
        fputs("MESSAGE\n", f);
        fwrite(le, 1, 8, f);
        fwrite(msg, 1, len, f);
        fputc('\n', f);
        fputs(rest, f);
        fputc('\n', f);
}

static void build_fixture_file(void) {
        FILE *f;

        snprintf(fx_dir, sizeof(fx_dir), "%s", test_tmpdir_new());
        snprintf(fx_path, sizeof(fx_path), "%s/fx.export", fx_dir);
        f = fopen(fx_path, "wb");
        ASSERT_TRUE(f != NULL);

        fx_header(f, 1760000000123456ULL, 4821000123ULL);
        fputs("MESSAGE=hello from netd\nPRIORITY=6\nSYSLOG_IDENTIFIER=netd\n_PID=42\n"
              "_SYSTEMD_UNIT=netd.service\n_TRANSPORT=stdout\n\n",
              f);
        fx_header(f, 1760000005000000ULL, 4826000000ULL);
        fputs("MESSAGE=urgent warning\nPRIORITY=3\nSYSLOG_IDENTIFIER=eudev\n_SYSTEMD_UNIT=eudev.service\n"
              "_TRANSPORT=syslog\n\n",
              f);
        fx_header(f, 1760000009000000ULL, 4830000000ULL);
        fputs("MESSAGE=kernel booted\nPRIORITY=6\nSYSLOG_IDENTIFIER=kernel\n_TRANSPORT=kernel\n\n", f);
        fx_header(f, 1760000010000000ULL, 4831000000ULL);
        fx_binary_message(
                        f,
                        "foo\nbar",
                        7,
                        "PRIORITY=6\nSYSLOG_IDENTIFIER=netd\n_SYSTEMD_UNIT=netd.service\n_TRANSPORT=stdout\n");
        fx_header(f, 1760000011000000ULL, 4832000000ULL);
        fx_binary_message(f, "\xff\x01", 2, "PRIORITY=4\nSYSLOG_IDENTIFIER=blobber\n_TRANSPORT=syslog\n");
        fclose(f);

        ASSERT_TRUE(find_picolog(pl_path, sizeof(pl_path)));
        setenv("TZ", "UTC", 1);
        setenv("LC_ALL", "C", 1);
        unsetenv("LOGD_RUNTIME_DIR");
        unsetenv("SYSTEMD_COLORS");
}

static int plx(char *out, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int plx(char *out, const char *fmt, ...) {
        char args[2048], full[6400];
        va_list ap;

        va_start(ap, fmt);
        vsnprintf(args, sizeof(args), fmt, ap);
        va_end(ap);
        snprintf(full, sizeof(full), "-i %s %s", fx_path, args);
        return run_picolog_capture(pl_path, full, out, 65536, NULL);
}

/* Without the fixture file: the command line is passed as given. */
static int plr(char *out, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int plr(char *out, const char *fmt, ...) {
        char args[2048];
        va_list ap;

        va_start(ap, fmt);
        vsnprintf(args, sizeof(args), fmt, ap);
        va_end(ap);
        return run_picolog_capture(pl_path, args, out, 65536, NULL);
}

static void test_output_modes(void) {
        char *out = malloc(65536);

        ASSERT_TRUE(out != NULL);

        ASSERT_EQ_INT(plx(out, "-W -o short-iso -n 4"), 0);
        ASSERT_TRUE(strstr(out, "2025-10-09T08:53:25+00:00 eudev: urgent warning") != NULL);

        ASSERT_EQ_INT(plx(out, "-W -o short-iso-precise -n 4"), 0);
        ASSERT_TRUE(strstr(out, "2025-10-09T08:53:20.123456+00:00") == NULL); /* only the last four */
        ASSERT_TRUE(strstr(out, "2025-10-09T08:53:25.000000+00:00 eudev:") != NULL);

        ASSERT_EQ_INT(plx(out, "-W -o short-precise"), 0);
        ASSERT_TRUE(strstr(out, "Oct 09 08:53:20.123456 netd[42]: hello from netd") != NULL);

        ASSERT_EQ_INT(plx(out, "-W -o short-unix"), 0);
        ASSERT_TRUE(strstr(out, "1760000000.123456 netd[42]: hello from netd") != NULL);

        ASSERT_EQ_INT(plx(out, "-W -o short-full"), 0);
        ASSERT_TRUE(strstr(out, "Thu 2025-10-09 08:53:20 UTC netd[42]: hello from netd") != NULL);

        ASSERT_EQ_INT(plx(out, "-W -o short-monotonic"), 0);
        ASSERT_TRUE(strstr(out, "[ 4821.000123] netd[42]: hello from netd") != NULL);

        ASSERT_EQ_INT(plx(out, "-W -o short-delta"), 0);
        ASSERT_TRUE(strstr(out, "[ 4821.000123                ] netd[42]") != NULL); /* nothing to compare to */
        ASSERT_TRUE(strstr(out, "[ 4826.000000 <    4.999877 >] eudev: urgent warning") != NULL);

        ASSERT_EQ_INT(plx(out, "-W -o with-unit"), 0);
        ASSERT_TRUE(strstr(out, "UTC netd.service[42]: hello from netd") != NULL);
        ASSERT_TRUE(strstr(out, "UTC kernel: kernel booted") != NULL); /* no unit: the identifier */

        ASSERT_EQ_INT(plx(out, "--utc -o short"), 0);
        ASSERT_TRUE(strstr(out, "Oct 09 08:53:20 ") == out);

        ASSERT_EQ_INT(plx(out, "-o cat"), 0);
        ASSERT_STREQ(out, "hello from netd\nurgent warning\nkernel booted\nfoo\nbar\n\xff\x01\n");

        ASSERT_EQ_INT(plx(out, "-o cat --output-fields=SYSLOG_IDENTIFIER -n 5"), 0);
        ASSERT_TRUE(strstr(out, "kernel\n") != NULL);

        ASSERT_EQ_INT(plx(out, "-o help"), 0);
        ASSERT_TRUE(STARTS(out, "short\nshort-iso\nshort-iso-precise\nshort-precise\n"));
        ASSERT_TRUE(strstr(out, "json-seq\ncat\nwith-unit\n") != NULL);
        ASSERT_TRUE(plx(out, "-o bogus 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "Unknown output format 'bogus'.") != NULL);

        free(out);
        printf("test-picolog: every short variant, with-unit and cat render the fixture as journalctl does\n");
}

static void test_verbose_and_json(void) {
        char *out = malloc(65536);
        const char *p;

        ASSERT_TRUE(out != NULL);

        ASSERT_EQ_INT(plx(out, "-o verbose -n 4 -u netd"), 0);
        ASSERT_TRUE(strstr(out, "Thu 2025-10-09 08:53:20.123456 UTC [b=" TEST_BOOT_ID ";m=") == out);
        ASSERT_TRUE(strstr(out, "\n    MESSAGE=hello from netd\n") != NULL);
        ASSERT_TRUE(strstr(out, "\n    _SYSTEMD_UNIT=netd.service\n") != NULL);
        ASSERT_TRUE(strstr(out, "__MONOTONIC_TIMESTAMP") == NULL); /* it is in the header, not a field */
        assert_continuation(out, "    MESSAGE=foo", "bar");

        ASSERT_EQ_INT(plx(out, "-o verbose -n 1"), 0);
        ASSERT_TRUE(strstr(out, "    MESSAGE=[2B blob data]\n") != NULL);
        ASSERT_EQ_INT(plx(out, "-o verbose -a -n 1"), 0);
        ASSERT_TRUE(strstr(out, "    MESSAGE=\\xff\\x01\n") != NULL);

        ASSERT_EQ_INT(plx(out, "-o json -n 1"), 0);
        ASSERT_TRUE(STARTS(out, "{\"__CURSOR\":\"b=" TEST_BOOT_ID ";m="));
        ASSERT_TRUE(strstr(out, "\"MESSAGE\":[255,1]") != NULL); /* not text: an array of bytes */
        ASSERT_TRUE(strstr(out, "\"SYSLOG_IDENTIFIER\":\"blobber\"") != NULL);
        ASSERT_TRUE(strstr(out, "\"__REALTIME_TIMESTAMP\":\"1760000011000000\"") != NULL);
        ASSERT_TRUE(out[strlen(out) - 2] == '}' && out[strlen(out) - 1] == '\n');

        ASSERT_EQ_INT(plx(out, "-o json -n 5 -u netd"), 0);
        ASSERT_TRUE(strstr(out, "\"MESSAGE\":\"foo\\nbar\"") != NULL);
        ASSERT_TRUE(strstr(out, "\"_PID\":\"42\"") != NULL);

        ASSERT_EQ_INT(plx(out, "-o json-pretty -n 3 -u eudev"), 0);
        ASSERT_TRUE(STARTS(out, "{\n        \"__CURSOR\" : \"b="));
        ASSERT_TRUE(strstr(out, "\n        \"MESSAGE\" : \"urgent warning\",\n") != NULL);
        ASSERT_TRUE(strstr(out, "\n}\n") != NULL);

        ASSERT_EQ_INT(plx(out, "-o json-pretty -n 1"), 0);
        ASSERT_TRUE(strstr(out, "\"MESSAGE\" : [\n                255,\n                1\n        ],\n") !=
                    NULL);

        ASSERT_EQ_INT(plx(out, "-o json-seq -n 1"), 0);
        ASSERT_TRUE(out[0] == '\x1e' && out[1] == '{');
        ASSERT_EQ_INT(plx(out, "-o json-sse -n 1"), 0);
        ASSERT_TRUE(STARTS(out, "data: {\"__CURSOR\""));
        p = out + strlen(out);
        ASSERT_TRUE(p[-1] == '\n' && p[-2] == '\n' && p[-3] == '}');

        ASSERT_EQ_INT(plx(out, "-o json --output-fields=MESSAGE -n 3 -k"), 0);
        ASSERT_TRUE(strstr(out, "\"MESSAGE\":\"kernel booted\"") != NULL);
        ASSERT_TRUE(strstr(out, "PRIORITY") == NULL);
        ASSERT_TRUE(strstr(out, "\"_BOOT_ID\":\"" TEST_BOOT_ID "\"") != NULL); /* the header always stays */

        ASSERT_EQ_INT(plx(out, "-o export --output-fields=MESSAGE -n 5 -u eudev"), 0);
        ASSERT_TRUE(strstr(out, "MESSAGE=urgent warning\n\n") != NULL);
        ASSERT_TRUE(strstr(out, "PRIORITY") == NULL);
        ASSERT_TRUE(strstr(out, "__REALTIME_TIMESTAMP=1760000005000000\n") == out);

        free(out);
        printf("test-picolog: verbose and the json variants carry the ring's fields, blobs as byte arrays\n");
}

static void test_filters(void) {
        char *out = malloc(65536);

        ASSERT_TRUE(out != NULL);

        ASSERT_EQ_INT(plx(out, "-p err..warning"), 0);
        ASSERT_TRUE(strstr(out, "urgent warning") != NULL);
        ASSERT_TRUE(strstr(out, "[2B blob data]") != NULL); /* warning (4) is inside the range */
        ASSERT_TRUE(strstr(out, "hello from netd") == NULL);

        ASSERT_EQ_INT(plx(out, "-p warning..err"), 0); /* either order */
        ASSERT_TRUE(strstr(out, "urgent warning") != NULL);

        ASSERT_EQ_INT(plx(out, "-p alert..crit"), 0);
        ASSERT_STREQ(out, "-- No entries --\n");
        ASSERT_EQ_INT(plx(out, "-q -p alert..crit"), 0);
        ASSERT_STREQ(out, "");
        ASSERT_TRUE(plx(out, "-p 3..bogus 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "Failed to parse log level range 3..bogus") != NULL);

        ASSERT_EQ_INT(plx(out, "-o cat -u netd -u eudev"), 0);
        ASSERT_TRUE(strstr(out, "hello from netd\nurgent warning\n") == out);
        ASSERT_EQ_INT(plx(out, "-o cat -u 'e*'"), 0);
        ASSERT_STREQ(out, "urgent warning\n");
        ASSERT_EQ_INT(plx(out, "-o cat -u eudev.service -u kernel.socket"), 0);
        ASSERT_STREQ(out, "urgent warning\n");

        ASSERT_EQ_INT(plx(out, "-o cat -t kernel"), 0);
        ASSERT_STREQ(out, "kernel booted\n");
        ASSERT_EQ_INT(plx(out, "-o cat -T netd -T blobber -T kernel"), 0);
        ASSERT_STREQ(out, "urgent warning\n");

        ASSERT_EQ_INT(plx(out, "-o cat _TRANSPORT=kernel + SYSLOG_IDENTIFIER=eudev"), 0);
        ASSERT_STREQ(out, "urgent warning\nkernel booted\n");
        ASSERT_EQ_INT(plx(out, "-o cat _TRANSPORT=stdout PRIORITY=6 _PID=42"), 0);
        ASSERT_STREQ(out, "hello from netd\n");
        ASSERT_EQ_INT(plx(out, "-o cat PRIORITY=3 PRIORITY=4"), 0); /* the same field: either value */
        ASSERT_STREQ(out, "urgent warning\n\xff\x01\n");
        ASSERT_TRUE(plx(out, "-o cat 'nofield' 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "Failed to add match 'nofield': Invalid argument") != NULL);
        ASSERT_TRUE(plx(out, "-o cat 'A=b' + 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "\"+\" can only be used between terms.") != NULL);

        ASSERT_EQ_INT(plx(out, "-o cat -g URGENT"), 1); /* a capital makes it case sensitive */
        ASSERT_EQ_INT(plx(out, "-o cat -g urg"), 0);
        ASSERT_STREQ(out, "urgent warning\n");
        ASSERT_EQ_INT(plx(out, "-o cat -g URGENT --case-sensitive=no"), 0);
        ASSERT_STREQ(out, "urgent warning\n");
        ASSERT_EQ_INT(plx(out, "-o cat -g 'hello|kernel'"), 0);
        ASSERT_STREQ(out, "hello from netd\nkernel booted\n");
        ASSERT_EQ_INT(plx(out, "-o cat -g nomatch"), 1); /* grep's own convention */
        ASSERT_EQ_INT(plx(out, "-g 'a(' 2>&1"), 1);
        ASSERT_TRUE(strstr(out, "Failed to compile regular expression a(") != NULL);

        ASSERT_EQ_INT(plx(out, "-o cat -S '2025-10-09 08:53:25' -U '2025-10-09 08:53:29'"), 0);
        ASSERT_STREQ(out, "urgent warning\nkernel booted\n");
        ASSERT_EQ_INT(plx(out, "-o cat --since=@1760000010"), 0);
        ASSERT_TRUE(STARTS(out, "foo\nbar\n"));
        ASSERT_EQ_INT(plx(out, "-o cat --until='2025-10-09 08:53:20'"), 0); /* before the .123456 */
        ASSERT_STREQ(out, "");
        ASSERT_EQ_INT(plx(out, "-o cat --since=-1h"), 0); /* the fixture is in the past */
        ASSERT_STREQ(out, "");
        ASSERT_EQ_INT(plx(out, "-o cat --since='2025-10-09 08:53:25 UTC' --until='2025-10-09 10:53:26 +02:00'"),
                      0);
        ASSERT_TRUE(strstr(out, "urgent warning\n") == out);
        ASSERT_TRUE(plx(out, "--since=garbage 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "Failed to parse timestamp: garbage") != NULL);
        ASSERT_TRUE(plx(out, "-S now -U yesterday 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "--since= must be before --until=.") != NULL);

        ASSERT_EQ_INT(plx(out, "-o cat --facility=kern"), 0); /* the ring records no facility */
        ASSERT_STREQ(out, "");
        ASSERT_EQ_INT(plx(out, "--facility=help"), 0);
        ASSERT_TRUE(STARTS(out, "Available facilities:\nkern\nuser\n"));
        ASSERT_TRUE(plx(out, "--facility=bogus 2>&1") != 0);

        free(out);
        printf("test-picolog: -p ranges, -u lists and globs, -t/-T, field matches, -g and --since/--until filter\n");
}

static void test_lines_and_order(void) {
        char *out = malloc(65536);

        ASSERT_TRUE(out != NULL);

        ASSERT_EQ_INT(plx(out, "-o cat -n 1"), 0);
        ASSERT_STREQ(out, "\xff\x01\n");
        ASSERT_EQ_INT(plx(out, "-o cat -n 2 -u netd"), 0);
        ASSERT_STREQ(out, "hello from netd\nfoo\nbar\n");
        ASSERT_EQ_INT(plx(out, "-o cat -n +1"), 0);
        ASSERT_STREQ(out, "hello from netd\n");
        ASSERT_EQ_INT(plx(out, "-o cat --lines=2 -p err"), 0);
        ASSERT_STREQ(out, "urgent warning\n");
        ASSERT_EQ_INT(plx(out, "-o cat -n all -u eudev"), 0);
        ASSERT_STREQ(out, "urgent warning\n");
        ASSERT_EQ_INT(plx(out, "-o cat -u eudev -n"), 0); /* bare -n is 10 */
        ASSERT_STREQ(out, "urgent warning\n");
        ASSERT_EQ_INT(plx(out, "-n 0"), 0);
        ASSERT_STREQ(out, "-- No entries --\n");
        ASSERT_EQ_INT(plx(out, "-o cat -r -u netd"), 0);
        ASSERT_STREQ(out, "foo\nbar\nhello from netd\n");
        ASSERT_EQ_INT(plx(out, "-o cat -r -n 1 -u netd"), 0);
        ASSERT_STREQ(out, "foo\nbar\n");
        ASSERT_EQ_INT(plx(out, "-o cat -g o -n 2"), 0); /* journalctl prints the last N matches newest first */
        ASSERT_STREQ(out, "foo\nbar\nkernel booted\n");
        ASSERT_TRUE(plx(out, "-r -f 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "Please specify either --reverse or --follow, not both.") != NULL);
        ASSERT_TRUE(plx(out, "-r -n +2 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "--lines=+N is unsupported when --reverse or --follow is specified.") != NULL);

        ASSERT_EQ_INT(plx(out, "-W -o short-unix -n 1 --truncate-newline -u netd"), 0);
        ASSERT_STREQ(out, "1760000010.000000 netd: foo\n");

        free(out);
        printf("test-picolog: -n N, -n +N, bare -n, -r and the --grep reversal order output like journalctl\n");
}

static void test_cursors(void) {
        char *out = malloc(65536), cursor[256], cmd[512];
        const char *p;
        char file[4300];
        FILE *f;

        ASSERT_TRUE(out != NULL);

        ASSERT_EQ_INT(plx(out, "-o cat -n +2 --show-cursor"), 0);
        p = strstr(out, "-- cursor: ");
        ASSERT_TRUE(p != NULL);
        snprintf(cursor, sizeof(cursor), "%s", p + strlen("-- cursor: "));
        cursor[strcspn(cursor, "\n")] = '\0';
        ASSERT_EQ_INT((int) strncmp(cursor, "b=" TEST_BOOT_ID ";m=", 2 + 32 + 3), 0);

        ASSERT_EQ_INT(plx(out, "-o cat --cursor='%s' -n 2", cursor), 0); /* starts at the cursor's entry */
        ASSERT_STREQ(out, "urgent warning\nkernel booted\n");
        ASSERT_EQ_INT(plx(out, "-o cat --after-cursor='%s' -n 1", cursor), 0);
        ASSERT_STREQ(out, "kernel booted\n");
        ASSERT_EQ_INT(plx(out, "-o cat --after-cursor='%s' -r", cursor), 0);
        ASSERT_STREQ(out, "hello from netd\n");

        snprintf(file, sizeof(file), "%s/cursor", fx_dir);
        ASSERT_EQ_INT(plx(out, "-o cat -n 1 --cursor-file=%s", file), 0); /* no file yet: from the start */
        ASSERT_STREQ(out, "\xff\x01\n");
        f = fopen(file, "r");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fgets(cmd, sizeof(cmd), f) != NULL);
        fclose(f);
        ASSERT_EQ_INT((int) strncmp(cmd, "b=" TEST_BOOT_ID ";m=", 2 + 32 + 3), 0);
        ASSERT_EQ_INT(plx(out, "-o cat --cursor-file=%s", file), 0); /* now after the last entry */
        ASSERT_STREQ(out, "");

        ASSERT_TRUE(plx(out, "--cursor=garbage 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "Failed to seek to cursor: Invalid argument") != NULL);
        ASSERT_TRUE(plx(out, "--cursor=x --since=@1 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "Please specify only one of --since=, --cursor=") != NULL);

        free(out);
        printf("test-picolog: cursors from --show-cursor round-trip through --cursor, --after-cursor and --cursor-file\n");
}

static void test_blob_and_ellipsis(void) {
        char *out = malloc(65536);

        ASSERT_TRUE(out != NULL);

        ASSERT_EQ_INT(plx(out, "-n 1"), 0);
        ASSERT_TRUE(strstr(out, "blobber: [2B blob data]\n") != NULL);
        ASSERT_EQ_INT(plx(out, "-n 1 -a"), 0);
        ASSERT_TRUE(strstr(out, "blobber: \\xff\\x01\n") != NULL);
        ASSERT_TRUE(strchr(out, '\xff') == NULL); /* no raw byte reaches the terminal */

        ASSERT_EQ_INT(plx(out, "--no-full -n 3 -u netd"), 0); /* short enough: nothing is cut */
        ASSERT_TRUE(strstr(out, "hello from netd") != NULL);

        {
                char path[4300];
                FILE *f;
                char *nl;

                snprintf(path, sizeof(path), "%s/long.export", fx_dir);
                f = fopen(path, "wb");
                ASSERT_TRUE(f != NULL);
                fx_header(f, 1760000000000000ULL, 1000000ULL);
                fputs("MESSAGE=0123456789012345678901234567890123456789012345678901234567890123456789\n\n", f);
                fclose(f);

                setenv("COLUMNS", "50", 1);
                ASSERT_EQ_INT(plr(out, "-W -o short-unix --no-full -i %s", path), 0);
                nl = strchr(out, '\n');
                ASSERT_TRUE(nl != NULL && strstr(out, "...") != NULL && (nl - out) <= 50);
                ASSERT_EQ_INT(plr(out, "-W -o short-unix -i %s", path), 0);
                ASSERT_TRUE(strstr(out, "...") == NULL); /* the default never cuts */
                unsetenv("COLUMNS");
        }

        free(out);
        printf("test-picolog: undisplayable messages are blob placeholders, or escaped with -a\n");
}

static void test_actions(void) {
        char *out = malloc(65536);
        char dir[4200], f1[4300], f2[4300];
        FILE *f;

        ASSERT_TRUE(out != NULL);

        ASSERT_EQ_INT(plx(out, "-N"), 0);
        ASSERT_TRUE(strstr(out, "MESSAGE\n") != NULL);
        ASSERT_TRUE(strstr(out, "_SYSTEMD_UNIT\n") != NULL);
        ASSERT_TRUE(strstr(out, "__REALTIME_TIMESTAMP") == NULL);
        ASSERT_EQ_INT(plx(out, "-F SYSLOG_IDENTIFIER"), 0);
        ASSERT_STREQ(out, "netd\neudev\nkernel\nblobber\n");
        ASSERT_EQ_INT(plx(out, "-F SYSLOG_IDENTIFIER -n 2"), 0);
        ASSERT_STREQ(out, "netd\neudev\n");
        ASSERT_TRUE(plx(out, "-F _PID -u netd 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "cannot be combined with options that limit the journal.") != NULL);

        ASSERT_EQ_INT(plx(out, "--list-boots"), 0);
        ASSERT_TRUE(STARTS(out, "IDX BOOT ID"));
        ASSERT_TRUE(strstr(out,
                           "  0 " TEST_BOOT_ID
                           " Thu 2025-10-09 08:53:20 UTC  Thu 2025-10-09 08:53:30 UTC") == NULL);
        ASSERT_TRUE(strstr(out, "  0 " TEST_BOOT_ID " Thu 2025-10-09 08:53:20 UTC") != NULL);
        ASSERT_TRUE(strstr(out, "Thu 2025-10-09 08:53:31 UTC\n") != NULL);
        ASSERT_EQ_INT(plx(out, "--list-boots -q"), 0);
        ASSERT_TRUE(STARTS(out, "  0 "));

        ASSERT_EQ_INT(plx(out, "-b 0 -o cat -n 1"), 0); /* the one boot a /run ring has */
        ASSERT_STREQ(out, "\xff\x01\n");
        ASSERT_EQ_INT(plx(out, "-b -n 1 -o cat"), 0);
        ASSERT_EQ_INT(plx(out, "-b all -o cat -n 1"), 0);
        ASSERT_EQ_INT(plx(out, "-b " TEST_BOOT_ID " -o cat -u eudev"), 0);
        ASSERT_STREQ(out, "urgent warning\n");
        ASSERT_EQ_INT(plx(out, "-b -1 2>&1"), 0);
        ASSERT_TRUE(strstr(out,
                           "Specifying boot ID or boot offset has no effect, no persistent journal was "
                           "found.") != NULL);
        ASSERT_EQ_INT(plx(out, "-b 0123456789abcdef0123456789abcdef 2>&1"), 1);
        ASSERT_TRUE(strstr(out,
                           "No journal boot entry found for the specified boot (0123456789abcdef"
                           "0123456789abcdef+0).") != NULL);
        ASSERT_TRUE(plx(out, "-b -m 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "Using --boot or --list-boots with --merge is not supported.") != NULL);

        ASSERT_EQ_INT(plr(out, "--disk-usage -i %s", fx_path), 0);
        ASSERT_TRUE(STARTS(out, "Archived and active journals take up "));
        ASSERT_TRUE(strstr(out, " in the file system.\n") != NULL);

        ASSERT_EQ_INT(plr(out, "--new-id128"), 0);
        ASSERT_TRUE(STARTS(out, "As string:\n"));
        ASSERT_TRUE(strstr(out, "\n\nAs UUID:\n") != NULL);
        ASSERT_TRUE(strstr(out, "\n\nAs systemd-id128(1) macro:\n#define XYZ SD_ID128_MAKE(") != NULL);
        ASSERT_TRUE(strstr(out, "\n\nAs Python constant:\n>>> import uuid\n>>> XYZ = uuid.UUID('") != NULL);

        /* -D and --root pick the ring location; --vacuum-* removes the rotated file only. */
        snprintf(dir, sizeof(dir), "%s/run/logd", fx_dir);
        snprintf(f1, sizeof(f1), "%s/run", fx_dir);
        ASSERT_EQ_INT(mkdir(f1, 0755), 0);
        ASSERT_EQ_INT(mkdir(dir, 0755), 0);
        snprintf(f1, sizeof(f1), "%s/active.export", dir);
        snprintf(f2, sizeof(f2), "%s/rotated.export", dir);
        f = fopen(f1, "wb");
        ASSERT_TRUE(f != NULL);
        fx_header(f, 1760000000000000ULL, 1000000ULL);
        fputs("MESSAGE=active one\n\n", f);
        fclose(f);
        f = fopen(f2, "wb");
        ASSERT_TRUE(f != NULL);
        fx_header(f, 1759999990000000ULL, 500000ULL);
        fputs("MESSAGE=rotated one\n\n", f);
        fclose(f);

        ASSERT_EQ_INT(plr(out, "-D %s -o cat", dir), 0);
        ASSERT_STREQ(out, "rotated one\nactive one\n");
        ASSERT_EQ_INT(plr(out, "--root=%s -o cat -n 1", fx_dir), 0);
        ASSERT_STREQ(out, "active one\n");
        ASSERT_EQ_INT(plr(out, "-D %s --vacuum-time=10y 2>&1", dir), 0); /* nothing is that old */
        ASSERT_TRUE(strstr(out, "Vacuuming done, freed 0B of archived journals from ") != NULL);
        ASSERT_EQ_INT(access(f2, F_OK), 0);
        ASSERT_EQ_INT(plr(out, "-D %s --vacuum-files=5 2>&1", dir), 0);
        ASSERT_EQ_INT(access(f2, F_OK), 0);
        ASSERT_EQ_INT(plr(out, "-D %s --vacuum-size=1 -q 2>&1", dir), 0);
        ASSERT_STREQ(out, "");
        ASSERT_TRUE(access(f2, F_OK) != 0); /* the archived file went */
        ASSERT_EQ_INT(access(f1, F_OK), 0); /* the active one stays */
        ASSERT_TRUE(plr(out, "--vacuum-size=bogus 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "Failed to parse vacuum size: bogus") != NULL);
        ASSERT_TRUE(plr(out, "-D %s/nope --vacuum-size=1 2>&1", dir) != 0);
        ASSERT_TRUE(strstr(out, "Failed to vacuum ") != NULL);

        ASSERT_EQ_INT(plr(out, "--list-namespaces --root=%s 2>&1", fx_dir), 1); /* no /etc/machine-id there */
        ASSERT_TRUE(strstr(out, "Failed to get machine ID: ") != NULL);

        ASSERT_EQ_INT(plx(out, "--namespace=other -n 5"), 0);
        ASSERT_STREQ(out, "-- No entries --\n");

        free(out);
        printf("test-picolog: -N/-F, --list-boots, -b, --disk-usage, --new-id128, -D/--root and --vacuum-* work\n");
}

static void test_stubs_and_refusals(void) {
        char *out = malloc(65536);
        static const char * const refused[] = {
                "--sync", "--rotate",      "--header", "--verify",  "--update-catalog",
                "--user", "--user-unit=x", "-M host",  "--image=x", "--image-policy=x",
        };
        static const char * const noops[] = {
                "--flush",
                "--relinquish-var",
                "--smart-relinquish-var",
                "--system",
                "--no-pager",
                "-x",
                "-m",
                "--synchronize-on-exit=yes",
                "--no-tail",
                "-l",
        };

        ASSERT_TRUE(out != NULL);

        /* A refused option fails loudly: a script must not think a rotation or sync happened. */
        for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
                ASSERT_EQ_INT(plx(out, "%s 2>&1", refused[i]), 1);
                ASSERT_TRUE(STARTS(out, "picolog: "));
                ASSERT_TRUE(strstr(out, "not supported") != NULL);
        }
        ASSERT_EQ_INT(plx(out, "--interval=1h 2>&1"), 1);
        ASSERT_TRUE(strstr(out, "Compiled without forward-secure sealing support.") != NULL);
        ASSERT_EQ_INT(plx(out, "--setup-keys 2>&1"), 1);
        ASSERT_TRUE(strstr(out, "Compiled without forward-secure sealing support.") != NULL);
        ASSERT_EQ_INT(plx(out, "--list-catalog 2>&1"), 1);
        ASSERT_TRUE(strstr(out, "Failed to list catalog: No such file or directory") != NULL);

        /* Where doing nothing is the right outcome: accepted, success, no output. */
        for (size_t i = 0; i < sizeof(noops) / sizeof(noops[0]); i++) {
                ASSERT_EQ_INT(plx(out, "%s -q -o cat -u eudev 2>&1", noops[i]), 0);
                ASSERT_TRUE(strstr(out, "urgent warning") != NULL || strcmp(noops[i], "--flush") == 0 ||
                            strncmp(noops[i], "--relinquish", 12) == 0 ||
                            strncmp(noops[i], "--smart", 7) == 0);
                ASSERT_TRUE(strstr(out, "picolog:") == NULL);
        }

        /* Invocation IDs are not recorded: the lookups fail the way journalctl's do for an unknown ID. */
        ASSERT_EQ_INT(plx(out, "-I 2>&1"), 1);
        ASSERT_TRUE(strstr(out, "Using -I/--invocation= with an offset requires a unit.") != NULL);
        ASSERT_EQ_INT(plx(out, "-u netd -I 2>&1"), 1);
        ASSERT_TRUE(strstr(out, "No journal entry found for the invocation (+0).") != NULL);
        ASSERT_EQ_INT(plx(out, "--list-invocations 2>&1"), 1);
        ASSERT_TRUE(strstr(out, "Using --list-invocations requires a unit.") != NULL);
        ASSERT_EQ_INT(plx(out, "--list-invocations -u netd 2>&1"), 1);
        ASSERT_TRUE(strstr(out, "No invocation ID for netd.service found.") != NULL);

        ASSERT_EQ_INT(plx(out, "--version"), 0);
        ASSERT_TRUE(STARTS(out, "picolog "));
        ASSERT_EQ_INT(plx(out, "--help"), 0);
        ASSERT_TRUE(STARTS(out, "picolog [OPTIONS...] [MATCHES...]\n"));
        ASSERT_TRUE(strstr(out, "--list-boots") != NULL &&
                    strstr(out, "Refused, as logd has no counterpart") != NULL);
        ASSERT_EQ_INT(plx(out, "-h"), 0);
        ASSERT_TRUE(plx(out, "--no-such-option 2>&1") != 0);
        ASSERT_TRUE(plx(out, "extra -N 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "Extraneous arguments starting with 'extra'") != NULL);
        ASSERT_TRUE(plx(out, "-D x -i y 2>&1") != 0);
        ASSERT_TRUE(strstr(out, "Please specify at most one of") != NULL);

        free(out);
        printf("test-picolog: unsupported options are refused with status 1, harmless ones accepted as no-ops\n");
}

static void test_follow_and_highlight(void) {
        char *out = malloc(65536);
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(out != NULL && dir != NULL);

        /* -f starts with the last 10 entries, as journalctl does, then waits; SIGINT ends it cleanly. */
        build_fixture_ring(dir);
        setenv("LOGD_RUNTIME_DIR", dir, 1);
        if (system("command -v timeout >/dev/null 2>&1") == 0) {
                char cmd[8200];

                snprintf(cmd, sizeof(cmd), "timeout -s INT 1 %s", pl_path);
                (void) run_picolog_capture(cmd, "-f -o cat", out, 65536, NULL);
                ASSERT_TRUE(strstr(out, "hello from netd\nurgent warning\nkernel booted\n") == out);
                (void) run_picolog_capture(cmd, "-f -n 1 -o cat", out, 65536, NULL);
                ASSERT_TRUE(strstr(out, "hello from netd") == NULL);
                (void) run_picolog_capture(cmd, "-f -n 0 -o cat", out, 65536, NULL);
                ASSERT_STREQ(out, "");
        }

        /* A --grep match is highlighted inside the priority colour when colour is on. */
        setenv("SYSTEMD_COLORS", "true", 1);
        ASSERT_EQ_INT(plr(out, "-g urg -n 1 -u eudev"), 0);
        ASSERT_TRUE(strstr(out, "\x1B[0;1;31m\x1B[0;1;39murg\x1B[0;1;31ment warning\x1B[0m\n") != NULL);
        unsetenv("SYSTEMD_COLORS");
        unsetenv("LOGD_RUNTIME_DIR");

        test_rm_rf(dir);
        free(dir);
        free(out);
        printf("test-picolog: -f starts with 10 lines and stops on SIGINT, and --grep matches are highlighted\n");
}

int main(void) {
        build_fixture_file();
        test_output_modes();
        test_verbose_and_json();
        test_filters();
        test_lines_and_order();
        test_cursors();
        test_blob_and_ellipsis();
        test_actions();
        test_stubs_and_refusals();
        test_follow_and_highlight();
        test_rm_rf(fx_dir);

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
