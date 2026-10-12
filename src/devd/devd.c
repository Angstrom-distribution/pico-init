/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * devd's main(). Nothing else lives here, for the reason netd.c gives for
 * itself and main.c gives for PID 1: meson.build links devd-core into every
 * devd test binary and never links this file, so anything a test needs to call
 * has to be defined somewhere devd-core reaches. That is devd-loop.c.
 */

#include "devd.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "../util.h"

/*
 * udevd v262's command line and udev.* kernel parameters. devd runs events in
 * its own loop with no worker processes, resolves no names and kills nothing
 * on a timer, so the tuning knobs are accepted and ignored. The exceptions are
 * --daemon, done for real, and udev.blockdev_read_only, which is a safety
 * setting and is warned about rather than dropped quietly.
 */
typedef struct DevdOpts {
        bool daemonize;
} DevdOpts;

/* A number of seconds with the optional unit suffix parse_sec() takes. */
static bool devd_valid_sec(const char *s) {
        static const char * const units[] = {
                "",       "s",       "sec", "second", "seconds", "m",     "min",
                "minute", "minutes", "h",   "hr",     "hour",    "hours", NULL,
        };
        char *end;

        if (!isdigit((unsigned char) *s))
                return false;
        (void) strtod(s, &end);
        while (isspace((unsigned char) *end))
                end++;
        for (size_t i = 0; units[i]; i++)
                if (strcmp(end, units[i]) == 0)
                        return true;
        return false;
}

static bool devd_valid_signal(const char *s) {
        char *end;
        long v;

        if (strncasecmp(s, "SIG", 3) == 0)
                return s[3] != '\0';
        errno = 0;
        v = strtol(s, &end, 10);
        return errno == 0 && *end == '\0' && end != s && v > 0 && v < 65;
}

static void devd_usage(void) {
        puts("devd [OPTIONS...]\n"
             "\n"
             "Device hotplug daemon, udevd-compatible command line.\n"
             "\n"
             "  -h --help                   Show this help\n"
             "  -V --version                Show version\n"
             "  -d --daemon                 Detach and run in the background\n"
             "\n"
             "Accepted and ignored, there are no workers or name resolution:\n"
             "  -D --debug                  Enable debug output\n"
             "  -c --children-max=INT       Set maximum number of workers\n"
             "  -e --exec-delay=SECONDS     Seconds to wait before executing RUN=\n"
             "  -t --event-timeout=SECONDS  Seconds to wait before terminating an event\n"
             "  -N --resolve-names=early|late|never\n"
             "     --timeout-signal=SIGNAL  Signal used when terminating an event");
}

/*
 * 0 to run, 1 when --help or --version was all there was to do, -EINVAL on a
 * bad option. A bad value for a tuning option is a warning, as in udevd.
 */
static int devd_parse_argv(int argc, char *argv[], DevdOpts *o) {
        enum {
                ARG_TIMEOUT_SIGNAL = 0x100,
        };
        static const struct option options[] = {
                {           "help",       no_argument, NULL,                'h' },
                {        "version",       no_argument, NULL,                'V' },
                {         "daemon",       no_argument, NULL,                'd' },
                {          "debug",       no_argument, NULL,                'D' },
                {   "children-max", required_argument, NULL,                'c' },
                {     "exec-delay", required_argument, NULL,                'e' },
                {  "event-timeout", required_argument, NULL,                't' },
                {  "resolve-names", required_argument, NULL,                'N' },
                { "timeout-signal", required_argument, NULL, ARG_TIMEOUT_SIGNAL },
                {             NULL,                 0, NULL,                  0 },
        };
        int c;

        optind = 0;
        while ((c = getopt_long(argc, argv, "hVdDc:e:t:N:", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        devd_usage();
                        return 1;

                case 'V':
                        puts("devd " PICO_INIT_VERSION);
                        return 1;

                case 'd':
                        o->daemonize = true;
                        break;

                case 'D':
                        break;

                case 'c':
                        if (!isdigit((unsigned char) *optarg) || strtoul(optarg, NULL, 10) > 0xffffffffUL)
                                pico_log(PICO_LOG_WARNING,
                                         "devd: failed to parse --children-max= value '%s', ignoring",
                                         optarg);
                        break;

                case 'e':
                case 't':
                        if (!devd_valid_sec(optarg))
                                pico_log(PICO_LOG_WARNING,
                                         "devd: failed to parse --%s= value '%s', ignoring",
                                         c == 'e' ? "exec-delay" : "event-timeout",
                                         optarg);
                        break;

                case 'N':
                        if (strcmp(optarg, "early") != 0 && strcmp(optarg, "late") != 0 &&
                            strcmp(optarg, "never") != 0)
                                pico_log(PICO_LOG_WARNING,
                                         "devd: invalid --resolve-names= value '%s', ignoring",
                                         optarg);
                        break;

                case ARG_TIMEOUT_SIGNAL:
                        if (!devd_valid_signal(optarg))
                                pico_log(PICO_LOG_WARNING,
                                         "devd: failed to parse --timeout-signal= value '%s', ignoring",
                                         optarg);
                        break;

                default:
                        return -EINVAL;
                }
        }

        return 0;
}

/* udev.* keys of the kernel command line, rd. prefix stripped as udevd does. */
static void devd_cmdline_item(const char *key, const char *value) {
        if (strncmp(key, "rd.", 3) == 0)
                key += 3;
        if (strncmp(key, "udev.", 5) != 0)
                return;

        if (strcmp(key, "udev.blockdev_read_only") == 0 || strcmp(key, "udev.blockdev-read-only") == 0) {
                bool on = !value || strcasecmp(value, "1") == 0 || strcasecmp(value, "yes") == 0 ||
                                strcasecmp(value, "true") == 0 || strcasecmp(value, "on") == 0 ||
                                strcasecmp(value, "y") == 0 || strcasecmp(value, "t") == 0;

                if (on)
                        pico_log(PICO_LOG_WARNING,
                                 "devd: udev.blockdev_read_only is not implemented, block devices stay writable");
        }
        /* log_level, log_priority, children_max, exec_delay, event_timeout,
         * timeout_signal and trace tune machinery devd does not have. */
}

static void devd_cmdline_parse(const char *cmdline) {
        char word[256];
        const char *p = cmdline;

        while (*p) {
                size_t n = 0;
                bool quoted = false;
                char *eq;

                while (isspace((unsigned char) *p))
                        p++;
                if (!*p)
                        break;

                for (; *p && (quoted || !isspace((unsigned char) *p)); p++) {
                        if (*p == '"')
                                quoted = !quoted;
                        else if (n < sizeof(word) - 1)
                                word[n++] = *p;
                }
                word[n] = '\0';

                if (strcmp(word, "--") == 0)
                        break;

                eq = strchr(word, '=');
                if (eq)
                        *eq++ = '\0';
                devd_cmdline_item(word, eq);
        }
}

static void devd_cmdline_load(void) {
        char buf[4096];
        FILE *f = fopen("/proc/cmdline", "re");

        if (!f)
                return;
        if (fgets(buf, sizeof(buf), f))
                devd_cmdline_parse(buf);
        fclose(f);
}

/* fork(), setsid() and stdio to /dev/null: what udevd -d does, minus the
 * pidfile it does not write either. Before any fd or timer exists. */
static int devd_daemonize(void) {
        pid_t pid = fork();
        int fd;

        if (pid < 0)
                return -errno;
        if (pid > 0)
                _exit(EXIT_SUCCESS);

        if (setsid() < 0)
                return -errno;
        if (chdir("/") < 0)
                return -errno;

        fd = open("/dev/null", O_RDWR);
        if (fd < 0)
                return -errno;
        if (dup2(fd, STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
                int e = errno;

                close(fd);
                return -e;
        }
        if (fd > STDERR_FILENO)
                close(fd);
        return 0;
}

int main(int argc, char *argv[]) {
        Devd *d = NULL;
        DevdOpts opts = { 0 };
        int r;

        r = devd_parse_argv(argc, argv, &opts);
        if (r < 0)
                return EXIT_FAILURE;
        if (r > 0)
                return EXIT_SUCCESS;

        devd_cmdline_load();

        if (opts.daemonize) {
                r = devd_daemonize();
                if (r < 0) {
                        pico_log(PICO_LOG_ERR, "devd: failed to daemonize: %s", strerror(-r));
                        return EXIT_FAILURE;
                }
        }

        r = devd_new(&d);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "devd: failed to allocate: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        r = devd_startup(d);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "devd: startup failed: %s", strerror(-r));
                devd_free(d);
                return EXIT_FAILURE;
        }

        r = devd_loop_run(d);
        devd_free(d);

        if (r < 0) {
                pico_log(PICO_LOG_ERR, "devd: event loop failed: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
