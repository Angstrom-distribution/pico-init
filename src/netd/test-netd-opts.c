/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netd's command line: --help and --version, and the refusal of everything
 * networkd also refuses. netd.c is included so its static parser can be
 * called; main() is renamed out of the way.
 */

#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#define main netd_main
#pragma GCC diagnostic ignored "-Wunused-function"
#include "netd.c"
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


static int parse(const char *first, ...) {
        char *args[8] = { (char *) "netd" };
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

        return netd_parse_argv(n, args);
}

int main(void) {
        ASSERT_EQ_INT(parse(NULL), 0);
        ASSERT_EQ_INT(parse("--help", NULL), 1);
        ASSERT_EQ_INT(parse("-h", NULL), 1);
        ASSERT_EQ_INT(parse("--version", NULL), 1);

        cap_begin();
        ASSERT_EQ_INT(parse("--bus-introspect=/tmp/x", NULL), -EINVAL);
        ASSERT_TRUE(strstr(cap_end(), "--bus-introspect is not supported") != NULL);

        cap_begin();
        ASSERT_EQ_INT(parse("--no-such-option", NULL), -EINVAL);
        (void) cap_end();

        cap_begin();
        ASSERT_EQ_INT(parse("eth0", NULL), -EINVAL);
        ASSERT_TRUE(strstr(cap_end(), "takes no arguments") != NULL);

        return 0;
}
