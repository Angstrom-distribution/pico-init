/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * devd's udevd-compatible command line and udev.* kernel parameters. devd.c is
 * included so its static parsers can be called; main() is renamed out of the way.
 */

#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#define main devd_main
#pragma GCC diagnostic ignored "-Wunused-function"
#include "devd.c"
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


static int parse(DevdOpts *o, ...) {
        char *args[16] = { (char *) "devd" };
        int n = 1;
        va_list ap;
        const char *a;

        va_start(ap, o);
        while (n < 15 && (a = va_arg(ap, const char *)) != NULL)
                args[n++] = (char *) a;
        va_end(ap);
        args[n] = NULL;

        return devd_parse_argv(n, args, o);
}

static void test_argv(void) {
        DevdOpts o = { 0 };
        const char *err;

        ASSERT_EQ_INT(parse(&o, NULL), 0);
        ASSERT_TRUE(!o.daemonize);

        ASSERT_EQ_INT(parse(&o, "--daemon", NULL), 0);
        ASSERT_TRUE(o.daemonize);
        o.daemonize = false;
        ASSERT_EQ_INT(parse(&o, "-d", NULL), 0);
        ASSERT_TRUE(o.daemonize);

        ASSERT_EQ_INT(parse(&o, "--help", NULL), 1);
        ASSERT_EQ_INT(parse(&o, "-h", NULL), 1);
        ASSERT_EQ_INT(parse(&o, "--version", NULL), 1);
        ASSERT_EQ_INT(parse(&o, "-V", NULL), 1);

        /* Tuning options in both spellings, with their values. */
        cap_begin();
        o.daemonize = false;
        ASSERT_EQ_INT(parse(&o,
                            "--debug",
                            "-D",
                            "--children-max=4",
                            "-c",
                            "8",
                            "--exec-delay=2",
                            "-e",
                            "1s",
                            "--event-timeout=30",
                            "-t",
                            "2min",
                            "--resolve-names=late",
                            "-N",
                            "never",
                            "--timeout-signal=SIGTERM",
                            NULL),
                      0);
        err = cap_end();
        ASSERT_STREQ(err, "");
        ASSERT_TRUE(!o.daemonize);

        /* A bad value is a warning, not a refusal to start. */
        cap_begin();
        ASSERT_EQ_INT(parse(&o,
                            "--children-max=many",
                            "--exec-delay=soon",
                            "--event-timeout=",
                            "--resolve-names=sometimes",
                            "--timeout-signal=0",
                            NULL),
                      0);
        err = cap_end();
        ASSERT_TRUE(strstr(err, "--children-max=") != NULL);
        ASSERT_TRUE(strstr(err, "--exec-delay=") != NULL);
        ASSERT_TRUE(strstr(err, "--event-timeout=") != NULL);
        ASSERT_TRUE(strstr(err, "--resolve-names=") != NULL);
        ASSERT_TRUE(strstr(err, "--timeout-signal=") != NULL);

        cap_begin();
        ASSERT_EQ_INT(parse(&o, "--no-such-option", NULL), -EINVAL);
        (void) cap_end();
        cap_begin();
        ASSERT_EQ_INT(parse(&o, "-c", NULL), -EINVAL);
        (void) cap_end();
}

static void test_cmdline(void) {
        const char *err;

        cap_begin();
        devd_cmdline_parse(
                        "quiet udev.log_level=debug udev.children_max=4 udev.exec_delay=1 "
                        "udev.event_timeout=60 udev.timeout_signal=SIGABRT udev.trace");
        err = cap_end();
        ASSERT_STREQ(err, "");

        /* Read-only block devices is a security setting: not silent. */
        cap_begin();
        devd_cmdline_parse("udev.blockdev_read_only");
        err = cap_end();
        ASSERT_TRUE(strstr(err, "udev.blockdev_read_only is not implemented") != NULL);
        ASSERT_TRUE(strstr(err, "[warning]") != NULL);

        cap_begin();
        devd_cmdline_parse("rd.udev.blockdev_read_only=yes");
        ASSERT_TRUE(strstr(cap_end(), "not implemented") != NULL);

        cap_begin();
        devd_cmdline_parse("udev.blockdev_read_only=no udev.blockdev_read_only=0");
        ASSERT_STREQ(cap_end(), "");

        /* Nothing after "--" is the kernel command line's. */
        cap_begin();
        devd_cmdline_parse("-- udev.blockdev_read_only");
        ASSERT_STREQ(cap_end(), "");
}

int main(void) {
        test_argv();
        test_cmdline();
        return 0;
}
