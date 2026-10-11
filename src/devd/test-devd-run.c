/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * RUN+=, run for real.
 *
 * The end-to-end case below goes through every piece of the rule engine in the order a
 * hotplugged modem would: a rules file is parsed, matched against a device,
 * `%k` is substituted into the command, the device's properties are turned into
 * an environment, a child is forked, and the child is reaped when it exits --
 * with the fork and the reap separated by the test doing something else, which
 * is the property that matters. A synchronous system() would pass a test that
 * only checked the file appeared; nothing but really forking and really
 * waiting later proves the listener is not blocked in the meantime.
 *
 * The helper is a shell script written by the test rather than a real tool: it
 * records its argv[1] and one inherited environment variable, which is exactly
 * what `usb_modeswitch '/%k'` consumes and no more.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../test-util.h"
#include "../util.h"
#include "devd-match.h"
#include "devd-rules.h"
#include "devd-run.h"

#define USB_DEV "/devices/platform/soc/usb1/1-1"

static void write_script(const char *dir, const char *name, const char *body) {
        char path[PATH_MAX];

        ASSERT_EQ_INT(test_write_file(dir, name, body), 0);
        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/%s", dir, name) < sizeof(path));
        ASSERT_EQ_INT(chmod(path, 0755), 0);
}

/* Reap until nothing is left, or until the patience runs out. Milliseconds,
 * because a shell script starting and exiting is a handful of them. */
static void drain(DevdRun *r, unsigned max_ms) {
        for (unsigned i = 0; i < max_ms && devd_run_pending(r) > 0; i++) {
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };

                (void) devd_run_reap(r);
                (void) nanosleep(&ts, NULL);
        }

        (void) devd_run_reap(r);
}

static char *read_all(const char *path) {
        static char buf[512];
        FILE *f = fopen(path, "re");
        size_t n;

        if (!f)
                return NULL;

        n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        (void) fclose(f);

        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
                buf[--n] = '\0';

        return buf;
}

static void test_split(void) {
        char argv[DEVD_RUN_ARGV_MAX][DEVD_RUN_ARG_MAX];

        /* The shape usb-modeswitch's rules use, after substitution. The
         * quotes group and are then gone -- the tool is handed /1-1, not
         * '/1-1'. */
        ASSERT_EQ_INT(devd_run_split("usb_modeswitch '/1-1'", argv, DEVD_RUN_ARGV_MAX), 2);
        ASSERT_STREQ(argv[0], "usb_modeswitch");
        ASSERT_STREQ(argv[1], "/1-1");

        ASSERT_EQ_INT(devd_run_split("  tool   a\tb  ", argv, DEVD_RUN_ARGV_MAX), 3);
        ASSERT_STREQ(argv[0], "tool");
        ASSERT_STREQ(argv[2], "b");

        ASSERT_EQ_INT(devd_run_split("tool \"one arg\" two", argv, DEVD_RUN_ARGV_MAX), 3);
        ASSERT_STREQ(argv[1], "one arg");

        /* An unterminated quote is a command devd cannot know the shape of, and
         * guessing at it would mean running something nobody wrote. */
        ASSERT_EQ_INT(devd_run_split("tool 'unterminated", argv, DEVD_RUN_ARGV_MAX), -EINVAL);
        ASSERT_EQ_INT(devd_run_split("", argv, DEVD_RUN_ARGV_MAX), 0);
}

/*
 * The whole path: rules text -> match -> substitution -> environment -> fork ->
 * reap. The helper is found by its bare name through the helper directory,
 * which is how the shipped rules file reaches /usr/lib/udev/usb_modeswitch.
 */
static void test_run_end_to_end(void) {
        static const char text[] = "ACTION==\"add\", SUBSYSTEM==\"usb\", RUN+=\"mark.sh '/%k'\"\n";

        char *root = test_tmpdir_new(), out[PATH_MAX], prop[PATH_MAX + 16];
        DevdRuleDevice *d;
        DevdRuleResult res;
        DevdRuleSet *rs = NULL;
        DevdRun run;
        char **env = NULL;

        ASSERT_TRUE(root != NULL);

        write_script(root,
                     "mark.sh",
                     "#!/bin/sh\n"
                     "printf '%s|%s|%s' \"$1\" \"$DEVPATH\" \"$PICO_TEST_TAG\" > \"$PICO_TEST_OUT\"\n");

        ASSERT_TRUE((size_t) snprintf(out, sizeof(out), "%s/marker", root) < sizeof(out));

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);
        ASSERT_EQ_INT(devd_ruleset_load_string(rs, text, "run.rules"), 1);

        d = calloc(1, sizeof(*d));
        ASSERT_TRUE(d != NULL);
        d->sys_root = "/sys";
        d->dev_root = "/dev";
        (void) snprintf(d->devpath, sizeof(d->devpath), "%s", USB_DEV);
        (void) snprintf(d->kernel, sizeof(d->kernel), "1-1");
        (void) snprintf(d->subsystem, sizeof(d->subsystem), "usb");
        (void) snprintf(d->action, sizeof(d->action), "add");

        ASSERT_EQ_INT(devd_rule_device_set_property(d, "DEVPATH", USB_DEV, false), 0);
        ASSERT_EQ_INT(devd_rule_device_set_property(d, "PICO_TEST_TAG", "exported", false), 0);
        ASSERT_EQ_INT(devd_rule_device_set_property(d, ".PICO_PRIVATE", "hidden", false), 0);

        ASSERT_TRUE((size_t) snprintf(prop, sizeof(prop), "%s", out) < sizeof(prop));
        ASSERT_EQ_INT(devd_rule_device_set_property(d, "PICO_TEST_OUT", prop, false), 0);

        ASSERT_EQ_INT(devd_rules_apply(rs, d, &res), 0);
        ASSERT_EQ_INT(res.n_runs, 1);
        ASSERT_STREQ(res.runs[0], "mark.sh '/1-1'");

        ASSERT_EQ_INT(devd_rules_environment(d, &env), 0);

        devd_run_init(&run);
        ASSERT_EQ_INT(devd_run_set_helper_dir(&run, root), 0);

        ASSERT_TRUE(devd_run_spawn(&run, res.runs[0], env) > 0);

        /* Still running, and devd is not waiting for it: that is the point. */
        ASSERT_EQ_INT(devd_run_pending(&run), 1);
        ASSERT_EQ_INT(run.n_started, 1);
        ASSERT_EQ_INT(run.n_reaped, 0);

        drain(&run, 5000);

        ASSERT_EQ_INT(devd_run_pending(&run), 0);
        ASSERT_EQ_INT(run.n_reaped, 1);
        ASSERT_EQ_INT(run.n_failed, 0);

        /* argv[1] came from %k with the quotes stripped; DEVPATH came from the
         * device's own properties. */
        ASSERT_STREQ(read_all(out), "/1-1|" USB_DEV "|exported");

        pico_strv_free(env);
        free(d);
        devd_ruleset_free(rs);
        test_rm_rf(root);
        free(root);
}

static void test_absolute_path_and_failure(void) {
        char *root = test_tmpdir_new(), abs[PATH_MAX], cmd[PATH_MAX + 8];
        DevdRun run;

        ASSERT_TRUE(root != NULL);

        write_script(root, "fail.sh", "#!/bin/sh\nexit 3\n");
        ASSERT_TRUE((size_t) snprintf(abs, sizeof(abs), "%s/fail.sh", root) < sizeof(abs));
        ASSERT_TRUE((size_t) snprintf(cmd, sizeof(cmd), "%s", abs) < sizeof(cmd));

        devd_run_init(&run);

        /* An absolute path is used as it stands -- the helper directory is
         * still the default and is not consulted. */
        ASSERT_TRUE(devd_run_spawn(&run, cmd, NULL) > 0);
        drain(&run, 5000);
        ASSERT_EQ_INT(run.n_reaped, 1);
        ASSERT_EQ_INT(run.n_failed, 1);

        /* A rule naming a tool this image does not have is a failed exec in the
         * child, not a failed fork in the daemon: devd hears about it as an
         * ordinary non-zero exit and carries on. */
        ASSERT_EQ_INT(devd_run_set_helper_dir(&run, root), 0);
        ASSERT_TRUE(devd_run_spawn(&run, "there-is-no-such-tool", NULL) > 0);
        drain(&run, 5000);
        ASSERT_EQ_INT(run.n_reaped, 2);
        ASSERT_EQ_INT(run.n_failed, 2);

        test_rm_rf(root);
        free(root);
}

static void test_concurrency_cap(void) {
        static char * const env[] = { (char *) "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };

        char *root = test_tmpdir_new();
        DevdRun run;

        ASSERT_TRUE(root != NULL);

        /* Long enough that all of them are still running when the cap is
         * tested, short enough that the suite does not notice. */
        write_script(root, "slow.sh", "#!/bin/sh\nsleep 1\n");

        devd_run_init(&run);
        ASSERT_EQ_INT(devd_run_set_helper_dir(&run, root), 0);

        for (int i = 0; i < DEVD_RUN_CHILDREN_MAX; i++)
                ASSERT_TRUE(devd_run_spawn(&run, "slow.sh", env) > 0);

        /* The cap is a policy, not just an array bound: a card reader full of
         * partitions must not be able to fork a helper per partition faster
         * than any of them finish. */
        ASSERT_EQ_INT(devd_run_spawn(&run, "slow.sh", env), -EAGAIN);
        ASSERT_EQ_INT(devd_run_pending(&run), DEVD_RUN_CHILDREN_MAX);

        drain(&run, 10000);
        ASSERT_EQ_INT(devd_run_pending(&run), 0);
        ASSERT_EQ_INT(run.n_reaped, DEVD_RUN_CHILDREN_MAX);

        /* And once they are gone there is room again. */
        ASSERT_TRUE(devd_run_spawn(&run, "slow.sh", env) > 0);
        drain(&run, 10000);

        test_rm_rf(root);
        free(root);
}

int main(void) {
        test_split();
        test_run_end_to_end();
        test_absolute_path_and_failure();
        test_concurrency_cap();

        return 0;
}
