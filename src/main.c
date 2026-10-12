/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * PID1 entrypoint. Real init behaviour only kicks in when actually running
 * as PID 1, so the binary still builds, runs and exits cleanly from a normal
 * shell (see src/test-m0.sh); the test suite drives the manager by linking
 * the core library directly rather than through here.
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "clock-persist.h"
#include "fstab-mount.h"
#include "fstab.h"
#include "gpt-scan.h"
#include "hostname-setup.h"
#include "machine-id-setup.h"
#include "manager.h"
#include "mount-setup.h"
#include "root-check.h"
#include "status.h"
#include "unit.h"
#include "util.h"

/*
 * The one thing PID 1 must never do is return. The kernel panics on it
 * ("Attempted to kill init"), which turns any ordinary failure -- a manager
 * that would not allocate, an event loop that errored, a reboot() that came
 * back -- into an unrecoverable panic with nothing readable on the console.
 * Freezing instead keeps the log on screen and leaves the machine in a state
 * someone can power-cycle it.
 */
static _Noreturn void freeze(const char *reason) {
        pico_log(PICO_LOG_ERR, "%s -- freezing, as PID 1 must not return", reason);

        for (;;)
                pause();
}

/*
 * The periodic half of clock-persist.h: the first save two minutes in, after
 * netd has had time to correct the clock from NTP, then every
 * CLOCK_PERSIST_INTERVAL_SEC. A battery pull skips the shutdown save, so this
 * bounds how stale the file can be. Failures (a read-only root) are quiet.
 */
#define CLOCK_PERSIST_FIRST_SAVE_SEC 120

static void clock_save_tick(void *userdata, usec_t now) {
        Manager *m = userdata;
        int r;

        r = clock_persist_save(CLOCK_PERSIST_FILE, (int64_t) time(NULL));
        if (r < 0)
                pico_log(PICO_LOG_DEBUG, "clock save: %s", strerror(-r));

        (void) pico_timer_add(
                        m->timer,
                        usec_add(now, (usec_t) CLOCK_PERSIST_INTERVAL_SEC * USEC_PER_SEC),
                        clock_save_tick,
                        m,
                        NULL);
}

static void clock_save_final(void) {
        int r = clock_persist_save(CLOCK_PERSIST_FILE, (int64_t) time(NULL));

        if (r < 0)
                pico_log(PICO_LOG_WARNING, "clock save: %s", strerror(-r));
}

/*
 * Everything still running goes before the final sync(): SIGTERM, up to five
 * seconds for it to exit, then SIGKILL, as systemd-shutdown does. Units were
 * stopped by now; what is left is what a KillMode=process or none unit
 * deliberately left behind, such as a screen or tmux server from an ssh login.
 */
static void kill_remaining_processes(void) {
        struct timespec step = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
        int i;

        if (kill(-1, SIGTERM) < 0 && errno == ESRCH)
                return;
        (void) kill(-1, SIGCONT);

        for (i = 0; i < 50; i++) {
                while (waitpid(-1, NULL, WNOHANG) > 0)
                        ;
                if (kill(-1, 0) < 0 && errno == ESRCH)
                        return;
                nanosleep(&step, NULL);
        }

        pico_log(PICO_LOG_WARNING, "processes ignored SIGTERM, sending SIGKILL");
        (void) kill(-1, SIGKILL);
        while (waitpid(-1, NULL, WNOHANG) > 0)
                ;
}

/*
 * What PID 1 takes from its command line, in the spelling of systemd v262's
 * src/core/main.c: argv (parse_argv()) and the kernel command line
 * (parse_proc_cmdline_item()). Most of those settings configure subsystems
 * pico-init does not have; they are accepted so one command line works with
 * either init, and logged once so the omission is visible. The few that map
 * onto something real are in BootOpts.
 */
typedef struct BootOpts {
        char unit[256];  /* "" when unset: boot PICO_DEFAULT_TARGET */
        int show_status; /* -1 unset, 0 off, 1 on */
        int gpt_auto;    /* systemd.gpt_auto=: -1 unset, 0 no swap discovery */
        int fstab;       /* fstab=: -1 unset, 0 no /etc/fstab mounts */
} BootOpts;

#define BOOT_OPTS_INIT \
        { .unit = "", .show_status = -1, .gpt_auto = -1, .fstab = -1 }

/* systemd.* keys with no counterpart here whose absence changes nothing a
 * running system depends on. */
static const char * const boot_ignored_quiet[] = {
        "systemd.dump_core",
        "systemd.early_core_pattern",
        "systemd.crash_chvt",
        "systemd.crash_shell",
        "systemd.crash_reboot",
        "systemd.crash_action",
        "systemd.status_unit_format",
        "systemd.log_color",
        "systemd.log_level",
        "systemd.log_location",
        "systemd.log_target",
        "systemd.log_time",
        "systemd.log_tid",
        "systemd.log_ratelimit_kmsg",
        "systemd.debug_shell",
        "systemd.default_debug_tty",
        "systemd.reload_limit_interval_sec",
        "systemd.reload_limit_burst",
        "systemd.event_loop_ratelimit_interval_sec",
        "systemd.event_loop_ratelimit_burst",
        "systemd.minimum_uptime_sec",
        NULL,
};

/* The ones whose omission changes what the machine does, so they are warned
 * about rather than noted. */
static const char * const boot_ignored_loud[] = {
        "systemd.confirm_spawn",
        "systemd.service_watchdogs",
        "systemd.default_standard_output",
        "systemd.default_standard_error",
        "systemd.setenv",
        "systemd.machine_id",
        "systemd.default_timeout_start_sec",
        "systemd.default_device_timeout_sec",
        "systemd.cpu_affinity",
        "systemd.watchdog_device",
        "systemd.watchdog_sec",
        "systemd.watchdog_pre_sec",
        "systemd.watchdog_pretimeout_governor",
        "systemd.clock_usec",
        "systemd.random_seed",
        "systemd.restrict_filesystem_access",
        "systemd.mask",
        "systemd.wants",
        "systemd.set_credential",
        "systemd.set_credential_binary",
        "systemd.import_credentials",
        "systemd.credentials_boot_policy",
        NULL,
};

/* Keys differ by '-' versus '_' only count as the same, as proc_cmdline_key_streq(). */
static bool key_is(const char *key, const char *want) {
        for (; *key && *want; key++, want++) {
                char a = *key == '-' ? '_' : *key;
                char b = *want == '-' ? '_' : *want;

                if (a != b)
                        return false;
        }
        return *key == *want;
}

static bool key_in(const char *key, const char * const *set) {
        for (; *set; set++)
                if (key_is(key, *set))
                        return true;
        return false;
}

/* 1 or 0 for the spellings parse_boolean() takes, -EINVAL otherwise. */
static int parse_bool(const char *s) {
        static const char * const yes[] = { "1", "yes", "y", "true", "t", "on", NULL };
        static const char * const no[] = { "0", "no", "n", "false", "f", "off", NULL };

        for (size_t i = 0; yes[i]; i++)
                if (strcasecmp(s, yes[i]) == 0)
                        return 1;
        for (size_t i = 0; no[i]; i++)
                if (strcasecmp(s, no[i]) == 0)
                        return 0;
        return -EINVAL;
}

static bool in_list(const char *s, const char * const *set) {
        for (; *set; set++)
                if (strcmp(s, *set) == 0)
                        return true;
        return false;
}

static bool valid_log_level(const char *s) {
        static const char * const names[] = {
                "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug", NULL,
        };

        return in_list(s, names) || (s[0] >= '0' && s[0] <= '7' && s[1] == '\0');
}

static bool valid_log_target(const char *s) {
        static const char * const names[] = {
                "console", "console-prefixed", "kmsg", "journal", "journal-or-kmsg",
                "syslog",  "syslog-or-kmsg",   "auto", "null",    NULL,
        };

        return in_list(s, names);
}

static bool valid_exec_output(const char *s) {
        static const char * const names[] = {
                "inherit", "null",           "tty",    "journal", "kmsg", "journal+console", "kmsg+console",
                "syslog",  "syslog+console", "socket", NULL,
        };

        return in_list(s, names) || strncmp(s, "fd:", 3) == 0 || strncmp(s, "file:", 5) == 0 ||
                        strncmp(s, "append:", 7) == 0 || strncmp(s, "truncate:", 9) == 0;
}

static bool valid_crash_action(const char *s) {
        static const char * const names[] = { "freeze", "reboot", "poweroff", NULL };

        return in_list(s, names);
}

static bool valid_machine_id(const char *s) {
        size_t i;
        bool nonzero = false;

        for (i = 0; s[i]; i++) {
                if (!isxdigit((unsigned char) s[i]))
                        return false;
                if (s[i] != '0')
                        nonzero = true;
        }
        return i == 32 && nonzero;
}

static bool valid_number(const char *s, long max) {
        char *end;
        long v;

        if (!*s)
                return false;
        errno = 0;
        v = strtol(s, &end, 10);
        return errno == 0 && *end == '\0' && v >= 0 && v <= max;
}

/*
 * The target a SysV-style kernel command line word asks for, or NULL. As
 * systemd's runlevel_to_target(): "emergency" and "rescue" also work as
 * systemd.unit= shortcuts, "single"/"1" are rescue mode.
 */
static const char *runlevel_target(const char *word) {
        static const struct {
                const char *word;
                const char *target;
        } map[] = {
                { "emergency",  "emergency.target" },
                {        "-b",  "emergency.target" },
                {    "rescue",     "rescue.target" },
                {    "single",     "rescue.target" },
                {         "s",     "rescue.target" },
                {         "S",     "rescue.target" },
                {        "-s",     "rescue.target" },
                {         "1",     "rescue.target" },
                {         "2", "multi-user.target" },
                {         "3", "multi-user.target" },
                {         "4", "multi-user.target" },
                {         "5",  "graphical.target" },
        };

        for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++)
                if (strcmp(word, map[i].word) == 0)
                        return map[i].target;
        return NULL;
}

static void boot_set_unit(BootOpts *o, const char *unit) {
        if (!unit_name_is_valid(unit) || strlen(unit) >= sizeof(o->unit)) {
                pico_log(PICO_LOG_WARNING, "unit name \"%s\" is not valid, ignoring", unit);
                return;
        }
        strcpy(o->unit, unit);
}

static void boot_set_show_status(BootOpts *o, const char *value) {
        int r;

        if (!value) {
                o->show_status = 1;
                return;
        }

        /* "auto" and "error" are the other two spellings systemd has; with
         * no per-job suppression here they show everything, like "yes". */
        if (strcmp(value, "auto") == 0 || strcmp(value, "error") == 0) {
                o->show_status = 1;
                return;
        }

        r = parse_bool(value);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "invalid show status \"%s\", ignoring", value);
        else
                o->show_status = r;
}

static void boot_set_switch(int *ret, const char *name, const char *value) {
        int r = value ? parse_bool(value) : 1;

        if (r < 0)
                pico_log(PICO_LOG_WARNING, "invalid %s=%s, ignoring", name, value);
        else
                *ret = r;
}

static void boot_cmdline_item(BootOpts *o, const char *key, const char *value) {
        if (key_is(key, "systemd.unit")) {
                if (!value || !*value)
                        pico_log(PICO_LOG_WARNING, "%s= needs a value, ignoring", key);
                else
                        boot_set_unit(o, value);
        } else if (key_is(key, "systemd.show_status"))
                boot_set_show_status(o, value);
        else if (key_is(key, "systemd.gpt_auto"))
                boot_set_switch(&o->gpt_auto, "systemd.gpt_auto", value);
        else if (key_is(key, "fstab"))
                boot_set_switch(&o->fstab, "fstab", value);
        else if (key_in(key, boot_ignored_quiet))
                pico_log(PICO_LOG_INFO, "kernel command line: %s is not implemented, ignored", key);
        else if (key_in(key, boot_ignored_loud))
                pico_log(PICO_LOG_WARNING, "kernel command line: %s is not implemented, ignored", key);
        else if (!value) {
                /* "quiet" and "debug" are the kernel's as much as ours: the
                 * kernel logging they select has no pico-init counterpart, and
                 * "quiet" would hide failures if it silenced the console. */
                const char *target = runlevel_target(key);

                if (target)
                        boot_set_unit(o, target);
        }
}

/*
 * Whitespace-separated words, double quotes grouping and dropped, key=value
 * split at the first '='. Stops at "--": what follows is for the init process
 * and reaches main() as argv.
 */
static void boot_cmdline_parse(const char *cmdline, BootOpts *o) {
        char word[512];
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
                boot_cmdline_item(o, word, eq);
        }
}

static void boot_cmdline_load(BootOpts *o) {
        static char buf[4096];
        FILE *f = fopen("/proc/cmdline", "re");

        if (!f)
                return;
        if (fgets(buf, sizeof(buf), f))
                boot_cmdline_parse(buf, o);
        fclose(f);
}

static void usage(void) {
        puts("pico-init [OPTIONS...]\n"
             "\n"
             "Start and monitor system services.\n"
             "\n"
             "  -h --help                   Show this help\n"
             "     --version                Show version\n"
             "     --unit=UNIT              Set default unit\n"
             "     --show-status[=BOOL]     Show status updates on the console during boot\n"
             "     --system                 Accepted, the only mode there is\n"
             "\n"
             "Accepted and ignored, with a note in the log:\n"
             "     --dump-core[=BOOL]  --crash-chvt=NR  --crash-action=ACTION\n"
             "     --crash-shell[=BOOL]  --crash-reboot[=BOOL]  --confirm-spawn[=BOOL]\n"
             "     --log-target=TARGET  --log-level=LEVEL  --log-color[=BOOL]\n"
             "     --log-location[=BOOL]  --log-time[=BOOL]  --service-watchdogs=BOOL\n"
             "     --default-standard-output=OUT  --default-standard-error=OUT\n"
             "     --machine-id=ID  --switched-root  --deserialize=FD  --no-pager\n"
             "     -D  -b  -s  -z ARG\n"
             "\n"
             "Refused: --test  --user  --dump-configuration-items  --dump-bus-properties\n"
             "         --bus-introspect=PATH\n"
             "\n"
             "Kernel command line: systemd.unit=, systemd.show_status=, systemd.gpt_auto=,\n"
             "fstab=, and the single, rescue, emergency, 1-5 shortcuts. Other systemd.*\n"
             "settings are accepted and ignored.");
}

/*
 * Returns 0 to run, 1 when the options were all there was to do (--help,
 * --version), -EINVAL on a bad command line. As PID 1 a bad option is
 * reported and parsing stops: refusing to boot over an argument the kernel
 * passed along would be worse.
 */
static int boot_argv_parse(int argc, char *argv[], bool pid1, BootOpts *o) {
        enum {
                ARG_VERSION = 0x100,
                ARG_TEST,
                ARG_SYSTEM,
                ARG_USER,
                ARG_DUMP_CONFIGURATION_ITEMS,
                ARG_DUMP_BUS_PROPERTIES,
                ARG_BUS_INTROSPECT,
                ARG_UNIT,
                ARG_DUMP_CORE,
                ARG_CRASH_CHVT,
                ARG_CRASH_ACTION,
                ARG_CRASH_SHELL,
                ARG_CRASH_REBOOT,
                ARG_CONFIRM_SPAWN,
                ARG_SHOW_STATUS,
                ARG_LOG_TARGET,
                ARG_LOG_LEVEL,
                ARG_LOG_COLOR,
                ARG_LOG_LOCATION,
                ARG_LOG_TIME,
                ARG_DEFAULT_STDOUT,
                ARG_DEFAULT_STDERR,
                ARG_NO_PAGER,
                ARG_SERVICE_WATCHDOGS,
                ARG_DESERIALIZE,
                ARG_SWITCHED_ROOT,
                ARG_MACHINE_ID,
        };
        static const struct option options[] = {
                {                     "help",       no_argument, NULL,                          'h' },
                {                  "version",       no_argument, NULL,                  ARG_VERSION },
                {                     "test",       no_argument, NULL,                     ARG_TEST },
                {                   "system",       no_argument, NULL,                   ARG_SYSTEM },
                {                     "user",       no_argument, NULL,                     ARG_USER },
                { "dump-configuration-items",       no_argument, NULL, ARG_DUMP_CONFIGURATION_ITEMS },
                {      "dump-bus-properties",       no_argument, NULL,      ARG_DUMP_BUS_PROPERTIES },
                {           "bus-introspect", required_argument, NULL,           ARG_BUS_INTROSPECT },
                {                     "unit", required_argument, NULL,                     ARG_UNIT },
                {                "dump-core", optional_argument, NULL,                ARG_DUMP_CORE },
                {               "crash-chvt", required_argument, NULL,               ARG_CRASH_CHVT },
                {                 "crash-vt", required_argument, NULL,               ARG_CRASH_CHVT },
                {             "crash-action", required_argument, NULL,             ARG_CRASH_ACTION },
                {              "crash-shell", optional_argument, NULL,              ARG_CRASH_SHELL },
                {             "crash-reboot", optional_argument, NULL,             ARG_CRASH_REBOOT },
                {            "confirm-spawn", optional_argument, NULL,            ARG_CONFIRM_SPAWN },
                {              "show-status", optional_argument, NULL,              ARG_SHOW_STATUS },
                {               "log-target", required_argument, NULL,               ARG_LOG_TARGET },
                {                "log-level", required_argument, NULL,                ARG_LOG_LEVEL },
                {                "log-color", optional_argument, NULL,                ARG_LOG_COLOR },
                {             "log-location", optional_argument, NULL,             ARG_LOG_LOCATION },
                {                 "log-time", optional_argument, NULL,                 ARG_LOG_TIME },
                {  "default-standard-output", required_argument, NULL,           ARG_DEFAULT_STDOUT },
                {   "default-standard-error", required_argument, NULL,           ARG_DEFAULT_STDERR },
                {                 "no-pager",       no_argument, NULL,                 ARG_NO_PAGER },
                {        "service-watchdogs", required_argument, NULL,        ARG_SERVICE_WATCHDOGS },
                {              "deserialize", required_argument, NULL,              ARG_DESERIALIZE },
                {            "switched-root",       no_argument, NULL,            ARG_SWITCHED_ROOT },
                {               "machine-id", required_argument, NULL,               ARG_MACHINE_ID },
                {                       NULL,                 0, NULL,                            0 },
        };
        const char *bad = NULL;
        bool ignored;
        int c;

        optind = 0;
        opterr = pid1 ? 0 : 1;

        while ((c = getopt_long(argc, argv, "hDbsz:", options, NULL)) >= 0) {
                ignored = false;

                switch (c) {
                case 'h':
                        if (pid1)
                                return 0;
                        usage();
                        return 1;

                case ARG_VERSION:
                        if (pid1)
                                return 0;
                        puts("pico-init " PICO_INIT_VERSION_STRING);
                        return 1;

                case ARG_TEST:
                case ARG_DUMP_CONFIGURATION_ITEMS:
                case ARG_DUMP_BUS_PROPERTIES:
                case ARG_BUS_INTROSPECT:
                        /* Output a script would parse; an empty success would be a lie. */
                        pico_log(PICO_LOG_ERR, "%s is not supported by pico-init", argv[optind - 1]);
                        return -EINVAL;

                case ARG_USER:
                        pico_log(PICO_LOG_ERR, "--user is not supported: pico-init is a system manager only");
                        return -EINVAL;

                case ARG_SYSTEM:
                        break;

                case ARG_UNIT:
                        if (!unit_name_is_valid(optarg) || strlen(optarg) >= sizeof(o->unit)) {
                                pico_log(PICO_LOG_ERR,
                                         "Failed to set default unit \"%s\": invalid unit name",
                                         optarg);
                                return -EINVAL;
                        }
                        strcpy(o->unit, optarg);
                        break;

                case ARG_SHOW_STATUS:
                        if (optarg && strcmp(optarg, "auto") != 0 && strcmp(optarg, "error") != 0 &&
                            parse_bool(optarg) < 0) {
                                pico_log(PICO_LOG_ERR, "Failed to parse show status boolean: \"%s\"", optarg);
                                return -EINVAL;
                        }
                        boot_set_show_status(o, optarg);
                        break;

                case ARG_DUMP_CORE:
                case ARG_CRASH_SHELL:
                case ARG_CRASH_REBOOT:
                case ARG_LOG_COLOR:
                case ARG_LOG_LOCATION:
                case ARG_LOG_TIME:
                case ARG_SERVICE_WATCHDOGS:
                        if (optarg && parse_bool(optarg) < 0)
                                bad = optarg;
                        ignored = true;
                        break;

                case ARG_CONFIRM_SPAWN:
                        if (optarg && parse_bool(optarg) < 0 && optarg[0] != '/')
                                bad = optarg;
                        ignored = true;
                        break;

                case ARG_CRASH_CHVT:
                        if (!valid_number(optarg, 63) && parse_bool(optarg) < 0)
                                bad = optarg;
                        ignored = true;
                        break;

                case ARG_CRASH_ACTION:
                        if (!valid_crash_action(optarg))
                                bad = optarg;
                        ignored = true;
                        break;

                case ARG_LOG_TARGET:
                        if (!valid_log_target(optarg))
                                bad = optarg;
                        ignored = true;
                        break;

                case ARG_LOG_LEVEL:
                        if (!valid_log_level(optarg))
                                bad = optarg;
                        ignored = true;
                        break;

                case ARG_DEFAULT_STDOUT:
                case ARG_DEFAULT_STDERR:
                        if (!valid_exec_output(optarg))
                                bad = optarg;
                        ignored = true;
                        break;

                case ARG_MACHINE_ID:
                        if (!valid_machine_id(optarg))
                                bad = optarg;
                        ignored = true;
                        break;

                case ARG_DESERIALIZE:
                        if (!valid_number(optarg, INT_MAX))
                                bad = optarg;
                        ignored = true;
                        break;

                case ARG_SWITCHED_ROOT:
                        ignored = true;
                        break;

                case ARG_NO_PAGER:
                case 'D':
                        break;

                case 'b':
                case 's':
                case 'z':
                        if (!pid1) {
                                pico_log(PICO_LOG_ERR, "Switch -%c is only supported when running as PID 1.", c);
                                return -EINVAL;
                        }
                        break;

                default:
                        if (pid1)
                                return 0;
                        return -EINVAL;
                }

                if (bad || ignored) {
                        const struct option *opt = options;

                        while (opt->name && opt->val != c)
                                opt++;
                        if (bad) {
                                pico_log(PICO_LOG_ERR, "Failed to parse --%s: \"%s\"", opt->name, bad);
                                return -EINVAL;
                        }
                        pico_log(PICO_LOG_INFO, "--%s is not implemented, ignored", opt->name);
                }
        }

        if (!pid1 && optind < argc) {
                pico_log(PICO_LOG_ERR, "Excess arguments.");
                return -EINVAL;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        BootOpts boot = BOOT_OPTS_INIT;
        FstabTable fstab = { 0 };
        bool fstab_swap;
        bool first_boot = false;
        Manager *m = NULL;
        int64_t clock_target = 0;
        int clock_restored;
        int objective;
        int r;

        if (getpid() != 1) {
                r = boot_argv_parse(argc, argv, false, &boot);
                if (r < 0)
                        return EXIT_FAILURE;
                if (r > 0)
                        return EXIT_SUCCESS;

                puts("pico-init: not running as PID 1, exiting");
                return EXIT_SUCCESS;
        }

        /*
         * Before anything else. The kernel mounts the root filesystem and
         * nothing more, so /proc, /sys, /run and /sys/fs/cgroup do not exist
         * yet -- and this manager's own cgroup supervision needs the last of
         * those to work at all. Doing it after manager_new() would start the
         * first services into a system with no /proc.
         */
        r = mount_setup();
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "mount_setup: %s", strerror(-r));
                freeze("could not mount the API filesystems");
        }

        /*
         * Immediately after, and for the same reason: devtmpfs gives /dev its
         * device nodes and nothing gives it /dev/fd or /dev/std{in,out,err},
         * so without this every `foo >/dev/stderr` and every /dev/fd/N idiom
         * in any script the image runs fails. Needs the /proc mount_setup()
         * just made, both because the links point into it and because the
         * /dev/core check reads it.
         *
         * Not fatal. A board missing /dev/stdout is worth a warning, never a
         * refusal to boot.
         */
        r = dev_setup(NULL);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "dev_setup: %s", strerror(-r));
        else
                pico_log(PICO_LOG_DEBUG, "dev_setup: %d /dev symlinks in place", r);

        /* Needs the root filesystem mount_setup() left alone (/etc/hostname
         * lives there) and nothing else; best-effort, same as dev_setup. */
        r = hostname_setup();
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "hostname_setup: %s", strerror(-r));

        /*
         * Before anything that timestamps: the RTC on the boards this runs on
         * is dead or reset by a reboot, so the clock starts in 1970 and every
         * early log line, fsck and certificate check would see that. Moved
         * forward from /etc/timestamp, its mtime and the build epoch, never
         * backwards; netd's NTP sync corrects it later.
         */
        clock_restored = clock_persist_restore(
                        CLOCK_PERSIST_FILE, (int64_t) time(NULL), clock_persist_set_realtime, &clock_target);

        /* Needs the /proc that mount_setup() just made, and must land before
         * the first service exists to write into a log socket. */
        sysctl_setup();

        /*
         * PID 1's own output has nowhere else to go: it is not a supervised
         * service, so nothing connects its stdout to logd, and the console it
         * writes to otherwise is captured nowhere. /dev/kmsg is -- and a fresh
         * reader sees the whole ring, so a logd started later in the boot
         * backfills every line pico-init emitted before logd existed, with no
         * persistent state involved.
         *
         * PID 1 only, not every daemon. netd and logd are
         * supervised services whose stdout service-exec.c already connects
         * straight to logd, which is strictly better: those records arrive
         * with _TRANSPORT=stdout and a real _SYSTEMD_UNIT resolved from
         * kernel-verified credentials, where a kmsg record has neither.
         * Redirecting them would trade correct attribution for none, and in
         * logd's case would have it ingesting its own output as kernel
         * records.
         */
        pico_log_to_kmsg();

        /*
         * Who is running this machine, before it does anything to it. A log
         * record rather than console status output, like systemd's own
         * version banner in src/core/main.c: it is the line someone reads
         * back out of a log to find what was running. status.h has the other
         * half of that split.
         */
        pico_log(PICO_LOG_INFO, "pico-init " PICO_INIT_VERSION_STRING " running as PID 1");

        /* argv after the kernel command line, as upstream: it wins. */
        boot_cmdline_load(&boot);
        (void) boot_argv_parse(argc, argv, true, &boot);

        /* The restore above ran before this process logged anywhere that is kept,
         * so it is reported here. */
        if (clock_restored > 0) {
                char stamp[CLOCK_PERSIST_TEXT_MAX];

                if (clock_persist_format(clock_target, stamp) > 0)
                        pico_log(PICO_LOG_INFO,
                                 "clock moved forward to %.14s UTC from " CLOCK_PERSIST_FILE,
                                 stamp);
        } else if (clock_restored < 0)
                pico_log(PICO_LOG_WARNING, "clock restore: %s", strerror(-clock_restored));

        /*
         * And the console channel itself, opened here rather than lazily on
         * first use so that the greeting is the first thing this init puts on
         * a console -- before any unit starts reporting progress against it.
         * Needs the /dev mount_setup() made above.
         */
        if (boot.show_status != 0) {
                status_enable();
                status_welcome(NULL);
        }

        /*
         * The root filesystem's integrity, before anything is allowed to write
         * to it -- which means before swap discovery and before the first
         * service, not merely before the first service. Needs everything above
         * it: /proc for the mountinfo, /sys for the block topology, /dev for
         * the node to check, and the kmsg sink already installed so what it
         * finds survives into logd's backfill.
         *
         * The reboot is done here rather than inside the check because this is
         * where PID 1's one sync()/reboot() path lives, and because freeze() --
         * the thing that must catch a reboot() that came back -- belongs to
         * this file. root-check.h has the decision table behind the verdict.
         *
         * /etc/fstab is read first, from a root that may still be read-only,
         * because its "/" line decides how the check's remount ends.
         */
        r = fstab_load("/etc/fstab", &fstab);
        if (r < 0 && r != -ENOENT)
                pico_log(PICO_LOG_WARNING, "/etc/fstab: %s", strerror(-r));

        r = pico_root_check(fstab_find(&fstab, "/"));
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "pico_root_check: %s", strerror(-r));
        else if (r == PICO_ROOT_REBOOT) {
                pico_log(PICO_LOG_INFO, "rebooting after the root filesystem check");
                sync();
                reboot(RB_AUTOBOOT);
                freeze("reboot() returned");
        }

        /*
         * The rest of /etc/fstab. After the root check, because mount points
         * may need creating on a root that has only now settled; before swap
         * discovery and before the manager, so that no unit, whatever its
         * ordering, can see an fstab path before it is mounted.
         * fstab-mount.h has the rest of the reasoning.
         */
        if (boot.fstab == 0) {
                pico_log(PICO_LOG_INFO, "fstab=no, not mounting /etc/fstab entries");
                r = 0;
        } else
                r = fstab_pass(&fstab, NULL);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "fstab_pass: %s", strerror(-r));
        else if (r > 0)
                pico_log(PICO_LOG_WARNING, "%d /etc/fstab line(s) not mounted, see %s", r, PICO_FSTAB_RECORD);
        fstab_swap = fstab_has_swap(&fstab);
        fstab_table_done(&fstab);

        /*
         * Swap, off the partition table alone. Placed here because it needs the /proc and /sys that
         * mount_setup() mounted and the /dev nodes devtmpfs put there, it wants
         * the kmsg sink already installed so its record survives into logd's
         * backfill, and swap should exist before the first service does -- on a
         * 64 MiB machine the units started moments from now are exactly the
         * ones that would benefit.
         *
         * Before manager_new() and not a unit: gpt-scan.h says why the whole
         * mechanism is a function call.
         *
         * Not at all once /etc/fstab names any swap, noauto lines included:
         * upstream's gpt-auto generator stands down on exactly that rule
         * (systemd #6192), since fstab then says what the swap is.
         */
        if (fstab_swap)
                pico_log(PICO_LOG_INFO, "/etc/fstab names swap, not discovering swap partitions");
        else if (boot.gpt_auto == 0)
                pico_log(PICO_LOG_INFO, "systemd.gpt_auto=no, not discovering swap partitions");
        else {
                r = dps_scan();
                if (r < 0)
                        pico_log(PICO_LOG_WARNING, "dps_scan: %s", strerror(-r));
                else if (r > 0)
                        pico_log(PICO_LOG_DEBUG, "dps_scan: %d discovered swap partition(s) activated", r);
        }

        /*
         * First-boot detection, same signal upstream's own log_execution_mode()
         * uses (src/core/main.c): /etc/machine-id missing, empty, or literally
         * "uninitialized". After the root check and fstab pass, so the decision
         * is made against the root filesystem's final, settled mount state
         * (writable or genuinely read-only), not whatever it was before either
         * ran; before manager_new(), because manager_startup() below gates
         * preset application on the result (manager_set_first_boot()) and that
         * must be known before a single unit is enabled.
         */
        r = machine_id_setup(NULL, NULL, &first_boot);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "machine_id_setup: %s", strerror(-r));

        r = manager_new(&m);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "manager_new: %s", strerror(-r));
                freeze("could not create the manager");
        }

        manager_set_first_boot(m, first_boot);

        (void) pico_timer_add(
                        m->timer,
                        usec_add(now_monotonic(), (usec_t) CLOCK_PERSIST_FIRST_SAVE_SEC * USEC_PER_SEC),
                        clock_save_tick,
                        m,
                        NULL);

        /* With C-A-D left enabled the kernel reboots at once, unsynced; this
         * makes it send SIGINT, which the manager turns into an orderly
         * reboot (v30 src/manager.c enable_special_signals()). After
         * manager_new(), which has SIGINT blocked into its signalfd. */
        if (m->is_system && reboot(RB_DISABLE_CAD) < 0)
                pico_log(PICO_LOG_WARNING, "failed to enable ctrl-alt-del handling: %s", strerror(errno));

        /*
         * A failed startup is not fatal. A board that cannot reach
         * default.target -- a missing unit, a bad fragment -- is far more
         * useful sitting in the event loop with a console than dead, because
         * that is exactly the state someone needs to debug it from.
         */
        r = manager_startup(m, boot.unit[0] ? boot.unit : NULL);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "startup failed: %s, entering the event loop anyway", strerror(-r));

        objective = manager_loop(m);
        m = manager_free(m);

        if (objective < 0) {
                pico_log(PICO_LOG_ERR, "manager_loop: %s", strerror(-objective));
                freeze("event loop failed");
        }

        switch ((ManagerObjective) objective) {
        case MANAGER_REBOOT:
                pico_log(PICO_LOG_INFO, "rebooting");
                kill_remaining_processes();
                clock_save_final();
                sync();
                reboot(RB_AUTOBOOT);
                freeze("reboot() returned");

        case MANAGER_POWEROFF:
                pico_log(PICO_LOG_INFO, "powering off");
                kill_remaining_processes();
                clock_save_final();
                sync();
                reboot(RB_POWER_OFF);
                freeze("reboot(RB_POWER_OFF) returned");

        case MANAGER_EXIT:
        default:
                /* MANAGER_EXIT is only legal for a non-PID-1 manager, and we
                 * established above that we are PID 1. */
                freeze("event loop asked to exit, which PID 1 cannot do");
        }
}
