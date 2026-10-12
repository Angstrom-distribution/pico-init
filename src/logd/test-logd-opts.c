/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * logd's command line: its own two options, --help and --version, and
 * journald's one optional argument, the log namespace, which is refused.
 * logd.c is included so its static parser can be called; main() is renamed
 * out of the way.
 */

#define _GNU_SOURCE /* struct ucred, via logd-recv.h */

#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#define main logd_main
#pragma GCC diagnostic ignored "-Wunused-function"
#include "logd.c"
#undef main

#include "../test-util.h"

/* Capture stderr: the diagnostics are the contract for what is ignored. */
static char cap_buf[2048];
static int cap_saved = -1;
static FILE *cap_file;

static void cap_begin(void) {
        fflush(stderr);
        cap_file = tmpfile();
        ASSERT_TRUE(cap_file != NULL);
        cap_saved = dup(STDERR_FILENO);
        ASSERT_TRUE(cap_saved >= 0);
        ASSERT_TRUE(dup2(fileno(cap_file), STDERR_FILENO) >= 0);
}

static const char *cap_end(void) {
        size_t n;

        fflush(stderr);
        ASSERT_TRUE(dup2(cap_saved, STDERR_FILENO) >= 0);
        close(cap_saved);
        rewind(cap_file);
        n = fread(cap_buf, 1, sizeof(cap_buf) - 1, cap_file);
        cap_buf[n] = 0;
        fclose(cap_file);
        return cap_buf;
}


static int parse(const char **dir, long *max, const char *first, ...) {
        char *args[8] = { (char *) "logd" };
        int n = 1;
        va_list ap;
        const char *a = first;

        va_start(ap, first);
        while (a && n < 7) {
                args[n++] = (char *) a;
                a = va_arg(ap, const char *);
        }
        va_end(ap);
        args[n] = NULL;

        return logd_parse_argv(n, args, dir, max);
}

int main(void) {
        const char *dir = NULL;
        long max = -1;

        ASSERT_EQ_INT(parse(&dir, &max, NULL), 0);
        ASSERT_TRUE(dir == NULL);
        ASSERT_EQ_INT(max, -1);

        ASSERT_EQ_INT(parse(&dir, &max, "--runtime-dir=/x/y", "--max-bytes=4096", NULL), 0);
        ASSERT_STREQ(dir, "/x/y");
        ASSERT_EQ_INT(max, 4096);

        ASSERT_EQ_INT(parse(&dir, &max, "--help", NULL), 1);
        ASSERT_EQ_INT(parse(&dir, &max, "-h", NULL), 1);
        ASSERT_EQ_INT(parse(&dir, &max, "--version", NULL), 1);

        /* An empty namespace name is no namespace, as in journald. */
        ASSERT_EQ_INT(parse(&dir, &max, "", NULL), 0);

        cap_begin();
        ASSERT_EQ_INT(parse(&dir, &max, "myns", NULL), -EINVAL);
        ASSERT_TRUE(strstr(cap_end(), "namespaces are not supported") != NULL);

        cap_begin();
        ASSERT_EQ_INT(parse(&dir, &max, "a", "b", NULL), -EINVAL);
        ASSERT_TRUE(strstr(cap_end(), "one or no arguments") != NULL);

        cap_begin();
        ASSERT_EQ_INT(parse(&dir, &max, "--no-such-option", NULL), -EINVAL);
        ASSERT_TRUE(strstr(cap_end(), "unrecognized option") != NULL);

        return 0;
}
