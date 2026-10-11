/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Fixture-driven test for the boot console channel: real os-release files on
 * disk in, the exact bytes that would reach the console out.
 *
 * The escape sequences are asserted byte for byte, not "contains OK
 * somewhere". Getting an SGR sequence subtly wrong -- a missing reset, a bold
 * where upstream is plain, one space too few inside the brackets -- still
 * prints something that looks broadly right in a log, and is wrong in exactly
 * the way that defeats the point of matching systemd's output at all. A test
 * that only checked for the substring "OK" would pass on all of it.
 *
 * Not covered here: that any of this reaches a real
 * console. status_enable() opens /dev/console, which a test must not do, so
 * the write path is left to booting on a target, the same way dev_setup()'s
 * symlinks are.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os-release.h"
#include "status.h"
#include "test-util.h"
#include "util.h"

/*
 * Write an os-release fixture into a fresh temporary directory, storing the
 * file's path in `path`. Returns the directory, which the caller removes.
 */
static char *fixture(const char *content, char *path, size_t size) {
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "os-release", content), 0);
        ASSERT_TRUE((size_t) snprintf(path, size, "%s/os-release", dir) < size);

        return dir;
}

/*
 * The lookup itself, over one file carrying every shape the format allows and
 * a few it does not. One fixture rather than six, because the interesting
 * failures are interactions: a key matched by prefix, a comment mistaken for
 * an assignment, a malformed line taking the rest of the file down with it.
 */
static void test_os_release_lookup(void) {
        char path[PATH_MAX];
        char *dir, *v;

        dir = fixture("# a comment, and the blank line below it\n"
                      "\n"
                      "PRETTY_NAME=\"Angstrom-pico-init v2026.06\"\n"
                      "NAME=Angstrom\n"
                      "SINGLE='quoted value'\n"
                      "EMPTY=\n"
                      "HALF=\"unterminated\n"
                      "this line has no equals sign at all\n"
                      "SPACED = padded \n"
                      "ANSI_COLOR=\"0;36\"\n"
                      "LAST=first\n"
                      "LAST=second\n",
                      path,
                      sizeof(path));

        /* double-quoted, and the value the real image ships */
        ASSERT_EQ_INT(os_release_get(path, "PRETTY_NAME", &v), 0);
        ASSERT_STREQ(v, "Angstrom-pico-init v2026.06");
        v = pico_mfree(v);

        /* unquoted */
        ASSERT_EQ_INT(os_release_get(path, "NAME", &v), 0);
        ASSERT_STREQ(v, "Angstrom");
        v = pico_mfree(v);

        /* single-quoted */
        ASSERT_EQ_INT(os_release_get(path, "SINGLE", &v), 0);
        ASSERT_STREQ(v, "quoted value");
        v = pico_mfree(v);

        /* An assignment with nothing on the right is a value, not an absence:
         * it is the caller's job to decide an empty PRETTY_NAME is unusable,
         * and status_welcome_line() does exactly that. */
        ASSERT_EQ_INT(os_release_get(path, "EMPTY", &v), 0);
        ASSERT_STREQ(v, "");
        v = pico_mfree(v);

        /* Half-quoted is malformed; the quote is kept rather than guessed
         * away, so the damage stays visible instead of being invented over. */
        ASSERT_EQ_INT(os_release_get(path, "HALF", &v), 0);
        ASSERT_STREQ(v, "\"unterminated");
        v = pico_mfree(v);

        /* whitespace either side of the '=' is not part of key or value */
        ASSERT_EQ_INT(os_release_get(path, "SPACED", &v), 0);
        ASSERT_STREQ(v, "padded");
        v = pico_mfree(v);

        /* the line with no '=' skipped only itself -- everything after it
         * still parsed */
        ASSERT_EQ_INT(os_release_get(path, "ANSI_COLOR", &v), 0);
        ASSERT_STREQ(v, "0;36");
        v = pico_mfree(v);

        /* shell semantics: the last assignment wins */
        ASSERT_EQ_INT(os_release_get(path, "LAST", &v), 0);
        ASSERT_STREQ(v, "second");
        v = pico_mfree(v);

        /* a key that is a prefix of a present one is still absent */
        ASSERT_EQ_INT(os_release_get(path, "PRETTY", &v), -ENOENT);
        ASSERT_EQ_INT(os_release_get(path, "VERSION_ID", &v), -ENOENT);

        /* and neither the comment nor the commented text is an assignment */
        ASSERT_EQ_INT(os_release_get(path, "# a comment, and the blank line below it", &v), -ENOENT);

        test_rm_rf(dir);
        free(dir);
}

/* A missing file reports what a missing key does, so no caller has to tell
 * the two apart. */
static void test_os_release_missing_file(void) {
        char *v = NULL;

        ASSERT_EQ_INT(os_release_get("/nonexistent/definitely/not/here/os-release", "PRETTY_NAME", &v),
                      -ENOENT);
        ASSERT_TRUE(v == NULL);
}

/*
 * The per-unit progress line, byte for byte. "[" then the colour, then six
 * columns with OK centred, then the reset, then "] " -- systemd's own
 * assembly in job_log_done_status_message() and status_vprintf().
 */
static void test_status_line(void) {
        char buf[256];
        size_t n;

        n = status_format_line(buf, sizeof(buf), STATUS_WORD_OK, STATUS_COLOR_OK, "Started Console.");
        ASSERT_STREQ(buf, "[\x1B[0;32m  OK  \x1B[0m] Started Console.\n");
        ASSERT_EQ_INT(n, strlen(buf));

        /* colour off: the brackets and the padding stay, only the escapes go */
        n = status_format_line(buf, sizeof(buf), STATUS_WORD_OK, NULL, "Reached target Default.");
        ASSERT_STREQ(buf, "[  OK  ] Reached target Default.\n");
        ASSERT_EQ_INT(n, strlen(buf));

        /* no word: an unbracketed line, which is what the greeting is */
        n = status_format_line(buf, sizeof(buf), NULL, NULL, "no brackets here");
        ASSERT_STREQ(buf, "no brackets here\n");
        ASSERT_EQ_INT(n, strlen(buf));
}

/*
 * The three remaining words job.c's console output can print, byte for byte
 * against upstream's job_done_messages[] (src/core/job.c), colour on and
 * off. DEPEND is the one of the three that is NOT bold red upstream -- it is
 * ANSI_HIGHLIGHT_YELLOW there, despite FAILED and TIME being
 * ANSI_HIGHLIGHT_RED -- so this is also the test that would fail if that
 * were ever "simplified" to red for consistency.
 */
static void test_status_line_failed_timeout_dependency(void) {
        char buf[256];
        size_t n;

        n = status_format_line(
                        buf, sizeof(buf), STATUS_WORD_FAILED, STATUS_COLOR_FAILED, "Failed to start Console.");
        ASSERT_STREQ(buf, "[\x1B[0;1;31mFAILED\x1B[0m] Failed to start Console.\n");
        ASSERT_EQ_INT(n, strlen(buf));

        n = status_format_line(buf, sizeof(buf), STATUS_WORD_FAILED, NULL, "Failed to start Console.");
        ASSERT_STREQ(buf, "[FAILED] Failed to start Console.\n");
        ASSERT_EQ_INT(n, strlen(buf));

        n = status_format_line(
                        buf,
                        sizeof(buf),
                        STATUS_WORD_TIMEOUT,
                        STATUS_COLOR_TIMEOUT,
                        "Timed out starting Console.");
        ASSERT_STREQ(buf, "[\x1B[0;1;31m TIME \x1B[0m] Timed out starting Console.\n");
        ASSERT_EQ_INT(n, strlen(buf));

        n = status_format_line(buf, sizeof(buf), STATUS_WORD_TIMEOUT, NULL, "Timed out starting Console.");
        ASSERT_STREQ(buf, "[ TIME ] Timed out starting Console.\n");
        ASSERT_EQ_INT(n, strlen(buf));

        n = status_format_line(
                        buf,
                        sizeof(buf),
                        STATUS_WORD_DEPENDENCY,
                        STATUS_COLOR_DEPENDENCY,
                        "Dependency failed for Console.");
        ASSERT_STREQ(buf, "[\x1B[0;1;33mDEPEND\x1B[0m] Dependency failed for Console.\n");
        ASSERT_EQ_INT(n, strlen(buf));

        n = status_format_line(
                        buf, sizeof(buf), STATUS_WORD_DEPENDENCY, NULL, "Dependency failed for Console.");
        ASSERT_STREQ(buf, "[DEPEND] Dependency failed for Console.\n");
        ASSERT_EQ_INT(n, strlen(buf));
}

/*
 * A line longer than the buffer must not lose its newline: two truncated
 * lines without one would run together into a single console row, which
 * misreports what happened rather than merely shortening it.
 */
static void test_status_line_truncated(void) {
        char buf[16];
        size_t n;

        n = status_format_line(buf, sizeof(buf), STATUS_WORD_OK, NULL, "a description far too long to fit");
        ASSERT_EQ_INT(n, sizeof(buf) - 1);
        ASSERT_EQ_INT(buf[sizeof(buf) - 2], '\n');
        ASSERT_EQ_INT(buf[sizeof(buf) - 1], '\0');
        ASSERT_EQ_INT(strlen(buf), n);

        /* and a buffer with no room at all is not written past */
        ASSERT_EQ_INT(status_format_line(buf, 1, NULL, NULL, "x"), 0);
        ASSERT_STREQ(buf, "");
}

/* The greeting over the os-release the real image ships. */
static void test_welcome(void) {
        char buf[512], path[PATH_MAX];
        char *dir;

        dir = fixture("ID=angstrom\n"
                      "NAME=Angstrom\n"
                      "PRETTY_NAME=\"Angstrom-pico-init v2026.06\"\n",
                      path,
                      sizeof(path));

        (void) status_welcome_line(buf, sizeof(buf), path, false);
        ASSERT_STREQ(buf, "\nWelcome to Angstrom-pico-init v2026.06!\n\n");

        /* With colour: "Welcome to" and "!" highlighted, the name itself in
         * the SGR parameters os-release names -- defaulted to "1" here,
         * because this fixture has no ANSI_COLOR=. */
        (void) status_welcome_line(buf, sizeof(buf), path, true);
        ASSERT_STREQ(buf,
                     "\n\x1B[0;1;39mWelcome to \x1B[0m\x1B[1mAngstrom-pico-init v2026.06\x1B[0m"
                     "\x1B[0;1;39m!\x1B[0m\n\n");

        test_rm_rf(dir);
        free(dir);
}

/* ANSI_COLOR= is honoured when it is one, and ignored when it is not: the
 * value is spliced between ESC[ and m, so anything else in it is a terminal
 * reprogrammed by a malformed image. */
static void test_welcome_ansi_color(void) {
        char buf[512], path[PATH_MAX];
        char *dir;

        dir = fixture("PRETTY_NAME=\"Coloured\"\nANSI_COLOR=\"0;36\"\n", path, sizeof(path));
        (void) status_welcome_line(buf, sizeof(buf), path, true);
        ASSERT_STREQ(buf,
                     "\n\x1B[0;1;39mWelcome to \x1B[0m\x1B[0;36mColoured\x1B[0m"
                     "\x1B[0;1;39m!\x1B[0m\n\n");
        test_rm_rf(dir);
        free(dir);

        dir = fixture("PRETTY_NAME=\"Hostile\"\nANSI_COLOR=\"0m\x1B[2J\"\n", path, sizeof(path));
        (void) status_welcome_line(buf, sizeof(buf), path, true);
        ASSERT_STREQ(buf,
                     "\n\x1B[0;1;39mWelcome to \x1B[0m\x1B[1mHostile\x1B[0m"
                     "\x1B[0;1;39m!\x1B[0m\n\n");
        test_rm_rf(dir);
        free(dir);
}

/*
 * The three ways the file can fail to name the system, and the fallback chain
 * upstream uses for them: PRETTY_NAME, then NAME, then "Linux". None of them
 * may produce "Welcome to !" -- an image with a broken os-release still gets
 * a greeting that reads like one.
 */
static void test_welcome_fallbacks(void) {
        char buf[512], path[PATH_MAX];
        char *dir;

        dir = fixture("NAME=Angstrom\nVERSION_ID=2026.06\n", path, sizeof(path));
        (void) status_welcome_line(buf, sizeof(buf), path, false);
        ASSERT_STREQ(buf, "\nWelcome to Angstrom!\n\n");
        test_rm_rf(dir);
        free(dir);

        dir = fixture("PRETTY_NAME=\nNAME=\n", path, sizeof(path));
        (void) status_welcome_line(buf, sizeof(buf), path, false);
        ASSERT_STREQ(buf, "\nWelcome to Linux!\n\n");
        test_rm_rf(dir);
        free(dir);

        (void) status_welcome_line(buf, sizeof(buf), "/nonexistent/os-release", false);
        ASSERT_STREQ(buf, "\nWelcome to Linux!\n\n");
}

/*
 * The version string is assembled from two macros, one of them substituted by
 * meson at build time, so what is checkable without running the real binary
 * is that both halves are present and neither is empty -- a vcs_tag() that
 * silently produced nothing would otherwise ship as "0.1.0 ()".
 */
static void test_version_string(void) {
        const char *v = PICO_INIT_VERSION_STRING;

        ASSERT_TRUE(strlen(PICO_INIT_VERSION) > 0);
        ASSERT_TRUE(strlen(PICO_INIT_GIT_VERSION) > 0);
        ASSERT_TRUE(strncmp(v, PICO_INIT_VERSION, strlen(PICO_INIT_VERSION)) == 0);
        ASSERT_TRUE(strstr(v, "(" PICO_INIT_GIT_VERSION ")") != NULL);
}

int main(void) {
        test_os_release_lookup();
        test_os_release_missing_file();
        test_status_line();
        test_status_line_failed_timeout_dependency();
        test_status_line_truncated();
        test_welcome();
        test_welcome_ansi_color();
        test_welcome_fallbacks();
        test_version_string();

        printf("test-status: all checks passed\n");
        return 0;
}
