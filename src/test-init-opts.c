/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * PID 1's command line: the options and kernel command line words that are
 * acted on, and the ones accepted without effect. main.c is included so its
 * static parsers can be called; main() itself is renamed out of the way.
 */

#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#define main pico_init_main
#pragma GCC diagnostic ignored "-Wunused-function"
#include "main.c"
#undef main

#include "test-util.h"

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

static BootOpts cmdline(const char *line) {
        BootOpts o = BOOT_OPTS_INIT;

        boot_cmdline_parse(line, &o);
        return o;
}

static void test_cmdline_unit(void) {
        BootOpts o;

        o = cmdline("quiet root=/dev/mmcblk0p2 rw");
        ASSERT_STREQ(o.unit, "");
        ASSERT_EQ_INT(o.show_status, -1);

        o = cmdline("systemd.unit=foo.service");
        ASSERT_STREQ(o.unit, "foo.service");

        /* The last word wins. */
        o = cmdline("systemd.unit=a.target systemd.unit=b.target");
        ASSERT_STREQ(o.unit, "b.target");

        o = cmdline("single");
        ASSERT_STREQ(o.unit, "rescue.target");
        o = cmdline("1");
        ASSERT_STREQ(o.unit, "rescue.target");
        o = cmdline("emergency");
        ASSERT_STREQ(o.unit, "emergency.target");
        o = cmdline("3");
        ASSERT_STREQ(o.unit, "multi-user.target");
        o = cmdline("5");
        ASSERT_STREQ(o.unit, "graphical.target");
        o = cmdline("systemd.unit=a.target 5");
        ASSERT_STREQ(o.unit, "graphical.target");

        /* A word with a value is never a runlevel. */
        o = cmdline("single=1 3=x");
        ASSERT_STREQ(o.unit, "");

        /* Not a unit name; initrd-only spelling; after "--". */
        o = cmdline("systemd.unit=bad/name");
        ASSERT_STREQ(o.unit, "");
        o = cmdline("systemd.unit=");
        ASSERT_STREQ(o.unit, "");
        o = cmdline("rd.systemd.unit=a.target");
        ASSERT_STREQ(o.unit, "");
        o = cmdline("-- systemd.unit=a.target");
        ASSERT_STREQ(o.unit, "");
        o = cmdline("systemd.unit=a.target -- single");
        ASSERT_STREQ(o.unit, "a.target");

        /* Quoting keeps a spaced value in one word. */
        o = cmdline("systemd.setenv=\"A=b c\" systemd.unit=x.service");
        ASSERT_STREQ(o.unit, "x.service");
}

static void test_cmdline_switches(void) {
        BootOpts o;

        o = cmdline("systemd.show_status=no");
        ASSERT_EQ_INT(o.show_status, 0);
        o = cmdline("systemd.show-status=0");
        ASSERT_EQ_INT(o.show_status, 0);
        o = cmdline("systemd.show_status");
        ASSERT_EQ_INT(o.show_status, 1);
        o = cmdline("systemd.show_status=error");
        ASSERT_EQ_INT(o.show_status, 1);
        o = cmdline("systemd.show_status=auto");
        ASSERT_EQ_INT(o.show_status, 1);
        o = cmdline("systemd.show_status=no systemd.show_status=yes");
        ASSERT_EQ_INT(o.show_status, 1);
        o = cmdline("systemd.show_status=maybe");
        ASSERT_EQ_INT(o.show_status, -1);

        /* "quiet" is the kernel's; it does not silence the console here. */
        o = cmdline("quiet");
        ASSERT_EQ_INT(o.show_status, -1);

        o = cmdline("systemd.gpt_auto=no fstab=0");
        ASSERT_EQ_INT(o.gpt_auto, 0);
        ASSERT_EQ_INT(o.fstab, 0);
        o = cmdline("systemd.gpt_auto=1 fstab=yes");
        ASSERT_EQ_INT(o.gpt_auto, 1);
        ASSERT_EQ_INT(o.fstab, 1);
        o = cmdline("systemd.gpt_auto");
        ASSERT_EQ_INT(o.gpt_auto, 1);
}

static void test_cmdline_ignored(void) {
        BootOpts o;
        const char *err;

        cap_begin();
        o = cmdline("systemd.log_level=debug debug");
        err = cap_end();
        ASSERT_TRUE(strstr(err, "systemd.log_level is not implemented") != NULL);
        ASSERT_TRUE(strstr(err, "[info]") != NULL);
        ASSERT_STREQ(o.unit, "");
        ASSERT_EQ_INT(o.show_status, -1);

        /* Settings that change what runs are warned about, not just noted. */
        cap_begin();
        o = cmdline("systemd.mask=foo.service systemd.setenv=A=b");
        err = cap_end();
        ASSERT_TRUE(strstr(err, "[warning]") != NULL);
        ASSERT_TRUE(strstr(err, "systemd.mask is not implemented") != NULL);
        ASSERT_TRUE(strstr(err, "systemd.setenv is not implemented") != NULL);

        /* An unknown systemd.* key is silent, as upstream. */
        cap_begin();
        o = cmdline("systemd.no_such_thing=1");
        err = cap_end();
        ASSERT_STREQ(err, "");
}

static int argv_parse(bool pid1, BootOpts *o, ...) {
        char *args[40] = { (char *) "pico-init" };
        int n = 1;
        va_list ap;
        const char *a;

        va_start(ap, o);
        while (n < 39 && (a = va_arg(ap, const char *)) != NULL)
                args[n++] = (char *) a;
        va_end(ap);
        args[n] = NULL;

        return boot_argv_parse(n, args, pid1, o);
}

static void test_argv_real(void) {
        BootOpts o = BOOT_OPTS_INIT;

        ASSERT_EQ_INT(argv_parse(false, &o, "--unit=foo.service", "--show-status=no", NULL), 0);
        ASSERT_STREQ(o.unit, "foo.service");
        ASSERT_EQ_INT(o.show_status, 0);

        o = (BootOpts) BOOT_OPTS_INIT;
        ASSERT_EQ_INT(argv_parse(false, &o, "--show-status", NULL), 0);
        ASSERT_EQ_INT(o.show_status, 1);

        o = (BootOpts) BOOT_OPTS_INIT;
        ASSERT_EQ_INT(argv_parse(false, &o, "--unit", "bar.target", NULL), 0);
        ASSERT_STREQ(o.unit, "bar.target");

        o = (BootOpts) BOOT_OPTS_INIT;
        ASSERT_EQ_INT(argv_parse(false, &o, "--unit=bad/name", NULL), -EINVAL);
        ASSERT_EQ_INT(argv_parse(false, &o, "--show-status=maybe", NULL), -EINVAL);
        ASSERT_STREQ(o.unit, "");

        ASSERT_EQ_INT(argv_parse(false, &o, "--help", NULL), 1);
        ASSERT_EQ_INT(argv_parse(false, &o, "-h", NULL), 1);
        ASSERT_EQ_INT(argv_parse(false, &o, "--version", NULL), 1);
}

static void test_argv_accepted(void) {
        BootOpts o = BOOT_OPTS_INIT;
        const char *err;

        cap_begin();
        ASSERT_EQ_INT(argv_parse(false,
                                 &o,
                                 "--system",
                                 "--no-pager",
                                 "-D",
                                 "--log-level=debug",
                                 "--log-target=kmsg",
                                 "--log-color",
                                 "--log-location=no",
                                 "--log-time=yes",
                                 "--dump-core",
                                 "--crash-shell=yes",
                                 "--crash-reboot",
                                 "--crash-chvt=3",
                                 "--crash-vt=3",
                                 "--crash-action=reboot",
                                 "--confirm-spawn=no",
                                 "--service-watchdogs=no",
                                 "--default-standard-output=journal",
                                 "--default-standard-error=kmsg+console",
                                 "--machine-id=0123456789abcdef0123456789abcdef",
                                 "--switched-root",
                                 "--deserialize=7",
                                 NULL),
                      0);
        err = cap_end();
        ASSERT_TRUE(strstr(err, "--log-level is not implemented") != NULL);
        ASSERT_TRUE(strstr(err, "--deserialize is not implemented") != NULL);
        ASSERT_TRUE(strstr(err, "--crash-chvt is not implemented") != NULL);
        ASSERT_STREQ(o.unit, "");
        ASSERT_EQ_INT(o.show_status, -1);
}

static void test_argv_refused(void) {
        BootOpts o = BOOT_OPTS_INIT;
        static const char * const refused[] = {
                "--test",
                "--user",
                "--dump-configuration-items",
                "--dump-bus-properties",
                "--bus-introspect=/tmp/x",
        };
        static const char * const bad_values[] = {
                "--log-level=loud",
                "--log-target=nowhere",
                "--crash-action=explode",
                "--crash-shell=maybe",
                "--confirm-spawn=maybe",
                "--default-standard-output=nowhere",
                "--machine-id=zz",
                "--machine-id=00000000000000000000000000000000",
                "--deserialize=x",
                "--no-such-option",
                "-b",
                "-s",
        };

        for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
                cap_begin();
                ASSERT_EQ_INT(argv_parse(false, &o, refused[i], NULL), -EINVAL);
                ASSERT_TRUE(strstr(cap_end(), "not supported") != NULL);
        }
        for (size_t i = 0; i < sizeof(bad_values) / sizeof(bad_values[0]); i++) {
                cap_begin();
                ASSERT_EQ_INT(argv_parse(false, &o, bad_values[i], NULL), -EINVAL);
                (void) cap_end();
        }

        cap_begin();
        ASSERT_EQ_INT(argv_parse(false, &o, "stray", NULL), -EINVAL);
        ASSERT_TRUE(strstr(cap_end(), "Excess arguments") != NULL);
}

static void test_argv_pid1(void) {
        BootOpts o = BOOT_OPTS_INIT;
        const char *err;

        /* Kernel-supplied words and switches never stop a boot. */
        cap_begin();
        ASSERT_EQ_INT(argv_parse(true, &o, "single", "-b", "-s", "-z", "x", "rw", NULL), 0);
        err = cap_end();
        ASSERT_STREQ(err, "");

        /* An unknown option ends parsing quietly; --help is not acted on. */
        ASSERT_EQ_INT(argv_parse(true, &o, "--no-such-option", "--unit=late.target", NULL), 0);
        ASSERT_STREQ(o.unit, "");
        ASSERT_EQ_INT(argv_parse(true, &o, "--help", NULL), 0);

        ASSERT_EQ_INT(argv_parse(true, &o, "--unit=a.target", NULL), 0);
        ASSERT_STREQ(o.unit, "a.target");
}

int main(void) {
        test_cmdline_unit();
        test_cmdline_switches();
        test_cmdline_ignored();
        test_argv_real();
        test_argv_accepted();
        test_argv_refused();
        test_argv_pid1();
        return 0;
}
