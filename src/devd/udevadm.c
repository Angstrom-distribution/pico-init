/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udevadm for devd: the subset of udevadm v262's command line that scripts
 * written for udev call on a running system, dracut's shell /init above all
 * (80base/init.sh, dracut-lib.sh, 77initqueue/dracut-initqueue.sh and
 * 70fs-lib/fs-lib.sh in dracut-ng 110). Nothing here is copied from systemd;
 * options, defaults and exit statuses follow src/udev/udevadm-{settle,trigger,
 * control,info}.c at v262.
 *
 *  - settle waits on the queue state devd publishes (devd-queue.h). As with
 *    udevd, no running devd means there is nothing to wait for.
 *  - trigger writes the action to each matching uevent file, which is all
 *    udevadm trigger does; devd then sees the events like any other.
 *  - control --exit stops devd and waits for it to go. Every other control
 *    command is accepted and has no effect: devd loads its rules once, has no
 *    worker pool, no global properties and no log level to set.
 *  - info reads sysfs, devd's /run/udev/data entry and the filesystem
 *    identity straight off the device node (fsid.h), so ID_FS_TYPE, ID_FS_UUID
 *    and ID_FS_LABEL are there for a block device although devd runs no blkid
 *    builtin. ext2, ext3 and ext4 all report ID_FS_TYPE=ext4.
 *
 * Options that would select devices by something devd does not record (tags,
 * initialization state) or change what is written (--uuid) fail loudly
 * rather than widening a trigger to every device. Verbs other than these four
 * and `version` fail the same way.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../fsid.h"
#include "../util.h"
#include "devd-queue.h"
#include "devd-udev-db.h"

/*
 * What `udevadm --version` prints: the udev release whose command line this
 * follows, so that version checks against udev are satisfied. A bare number
 * rather than pico-init's own version.
 */
#define UDEVADM_UDEV_VERSION "262"

/* udevadm v262's defaults. */
#define UDEVADM_SETTLE_TIMEOUT_USEC (120 * USEC_PER_SEC)
#define UDEVADM_CONTROL_TIMEOUT_USEC (60 * USEC_PER_SEC)
#define UDEVADM_PING_TIMEOUT_USEC (5 * USEC_PER_SEC)

/* How often settle and control --exit look again. Short enough not to add
 * visibly to a boot, long enough to cost nothing while devd works. */
#define UDEVADM_POLL_USEC (10 * USEC_PER_MSEC)

#define INFO_PROPS_MAX 96
#define INFO_KEY_MAX 64
#define INFO_VALUE_MAX 512
#define INFO_LINKS_MAX 1024

/* The roots everything is read under; a test points them at a fixture. */
typedef struct Udevadm {
        const char *sys_root;
        const char *dev_root;
        const char *run_root;
        const char *udev_run_root;
        const char *db_root;
} Udevadm;

static Udevadm ctx = {
        .sys_root = "/sys",
        .dev_root = "/dev",
        .run_root = DEVD_RUN_ROOT,
        .udev_run_root = DEVD_UDEV_RUN_ROOT,
        .db_root = DEVD_UDEV_DB_ROOT,
};

/* --- small helpers --- */

static void sleep_usec(usec_t usec) {
        struct timespec ts = {
                .tv_sec = (time_t) (usec / USEC_PER_SEC),
                .tv_nsec = (long) ((usec % USEC_PER_SEC) * 1000),
        };

        while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
                ;
}

/*
 * A time span the way systemd's parse_sec() reads one for these options: a
 * non-negative number, optionally fractional, with an optional unit; no unit
 * means seconds, "infinity" means no limit. 0 or -EINVAL.
 */
static int parse_sec(const char *s, usec_t *ret) {
        static const struct {
                const char *suffix;
                usec_t mult;
        } units[] = {
                {        "",        USEC_PER_SEC },
                {       "s",        USEC_PER_SEC },
                {     "sec",        USEC_PER_SEC },
                {  "second",        USEC_PER_SEC },
                { "seconds",        USEC_PER_SEC },
                {      "ms",       USEC_PER_MSEC },
                {    "msec",       USEC_PER_MSEC },
                {      "us",                   1 },
                {    "usec",                   1 },
                {       "m",   60 * USEC_PER_SEC },
                {     "min",   60 * USEC_PER_SEC },
                {  "minute",   60 * USEC_PER_SEC },
                { "minutes",   60 * USEC_PER_SEC },
                {       "h", 3600 * USEC_PER_SEC },
                {      "hr", 3600 * USEC_PER_SEC },
                {    "hour", 3600 * USEC_PER_SEC },
                {   "hours", 3600 * USEC_PER_SEC },
        };
        double v;
        char *end;

        if (!s || !ret)
                return -EINVAL;

        if (strcmp(s, "infinity") == 0) {
                *ret = USEC_INFINITY;
                return 0;
        }

        if (!isdigit((unsigned char) s[0]) && s[0] != '.')
                return -EINVAL;

        errno = 0;
        v = strtod(s, &end);
        if (errno != 0 || end == s || v < 0)
                return -EINVAL;

        while (isspace((unsigned char) *end))
                end++;

        for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
                double us;

                if (strcmp(end, units[i].suffix) != 0)
                        continue;

                us = v * (double) units[i].mult;
                *ret = us >= 18446744073709551615.0 ? USEC_INFINITY : (usec_t) us;
                return 0;
        }

        return -EINVAL;
}

static int parse_bool(const char *s) {
        static const char * const yes[] = { "1", "yes", "y", "true", "t", "on" };
        static const char * const no[] = { "0", "no", "n", "false", "f", "off" };

        for (size_t i = 0; i < sizeof(yes) / sizeof(yes[0]); i++)
                if (strcasecmp(s, yes[i]) == 0)
                        return 1;
        for (size_t i = 0; i < sizeof(no) / sizeof(no[0]); i++)
                if (strcasecmp(s, no[i]) == 0)
                        return 0;
        return -EINVAL;
}

/* "%s/%s" into a PATH_MAX buffer; false when it does not fit. */
static bool join(char ret[static PATH_MAX], const char *a, const char *b) {
        return (size_t) snprintf(ret, PATH_MAX, "%s/%s", a, b) < PATH_MAX;
}

/*
 * The first line of a file, without its newline or trailing whitespace. 0,
 * or -errno. Used for sysfs attributes and /proc entries, all short.
 */
static int read_line(const char *path, char *buf, size_t size) {
        FILE *f;
        size_t n;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        if (!fgets(buf, (int) size, f)) {
                int r = ferror(f) ? -EIO : 0;

                (void) fclose(f);
                buf[0] = '\0';
                return r;
        }
        (void) fclose(f);

        n = strlen(buf);
        while (n > 0 && isspace((unsigned char) buf[n - 1]))
                buf[--n] = '\0';
        return 0;
}

/* The basename a sysfs `subsystem` link points at, or "" when there is none. */
static void read_subsystem(const char *syspath, char *ret, size_t size) {
        char path[PATH_MAX], target[PATH_MAX];
        const char *base;
        ssize_t n;

        ret[0] = '\0';
        if (!join(path, syspath, "subsystem"))
                return;

        n = readlink(path, target, sizeof(target) - 1);
        if (n < 0)
                return;
        target[n] = '\0';

        base = strrchr(target, '/');
        (void) snprintf(ret, size, "%.*s", (int) (size - 1), base ? base + 1 : target);
}

/* The long name of option `c` in `options`, for a diagnostic. */
static const char *option_name(const struct option *options, int c) {
        for (size_t i = 0; options[i].name; i++)
                if (options[i].val == c)
                        return options[i].name;
        return "?";
}

/* --- is devd running --- */

/*
 * Whether `pid` exists and is not a zombie. A zombie counts as gone, because
 * the init that should reap it may be a shell that never does.
 */
static bool pid_alive(pid_t pid) {
        char path[32], buf[512];
        const char *state;

        if (kill(pid, 0) < 0 && errno == ESRCH)
                return false;

        (void) snprintf(path, sizeof(path), "/proc/%d/stat", (int) pid);
        if (read_line(path, buf, sizeof(buf)) < 0)
                return false;

        /* "pid (comm) S ...": comm may itself contain ") ", so the last one. */
        state = strrchr(buf, ')');
        return state && state[1] == ' ' && state[2] != '\0' && state[2] != 'Z' && state[2] != 'X';
}

/*
 * devd's pid, from the file it publishes, when that process is alive and
 * really is devd: a pid file left by a devd that was killed outright can name
 * a reused pid, and control --exit sends a signal to it. The command name is
 * whatever devd was executed as, which is udevd or systemd-udevd when dracut
 * starts it through its alias. A zombie counts as gone (pid_alive()).
 */
static bool devd_pid(pid_t *ret) {
        static const char * const names[] = { "devd", "udevd", "systemd-udevd" };
        char path[PATH_MAX], comm[64];
        uint64_t pid;
        bool known = false;

        if (!join(path, ctx.run_root, DEVD_QUEUE_PID_FILE) || devd_queue_read_u64(path, &pid) < 0)
                return false;

        if (pid == 0 || pid > INT_MAX)
                return false;

        (void) snprintf(path, sizeof(path), "/proc/%llu/comm", (unsigned long long) pid);
        if (read_line(path, comm, sizeof(comm)) < 0)
                return false;

        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
                if (strcmp(comm, names[i]) == 0)
                        known = true;
        if (!known)
                return false;

        if (!pid_alive((pid_t) pid))
                return false;

        if (ret)
                *ret = (pid_t) pid;
        return true;
}

/* --- settle --- */

/* 1 when devd has published a state that covers `target`, else 0. */
static int settle_check(uint64_t target) {
        char path[PATH_MAX];
        uint64_t published;

        if (!join(path, ctx.run_root, DEVD_QUEUE_SEQNUM_FILE) || devd_queue_read_u64(path, &published) < 0)
                return 0;

        if (!devd_queue_covers(published, target))
                return 0;

        if (!join(path, ctx.udev_run_root, DEVD_QUEUE_FLAG_FILE) || access(path, F_OK) == 0)
                return 0;

        return 1;
}

/*
 * Wait until devd has handled every event the kernel had sent when this
 * started, `exists` appears, or `timeout` passes. 0 or -ETIMEDOUT.
 */
static int settle_wait(usec_t timeout, const char *exists) {
        char path[PATH_MAX];
        uint64_t target;
        usec_t deadline;

        /* No counter means no sysfs, and then there are no events either. */
        if (!join(path, ctx.sys_root, DEVD_KERNEL_SEQNUM_FILE) || devd_queue_read_u64(path, &target) < 0)
                return 0;

        deadline = timeout == USEC_INFINITY ? USEC_INFINITY : usec_add(now_monotonic(), timeout);

        for (;;) {
                usec_t now;

                if (exists && access(exists, F_OK) == 0)
                        return 0;

                if (!devd_pid(NULL))
                        return 0;

                if (settle_check(target))
                        return 0;

                now = now_monotonic();
                if (now >= deadline) {
                        fprintf(stderr, "udevadm: Timed out while waiting for udev queue to empty.\n");
                        return -ETIMEDOUT;
                }

                sleep_usec(deadline - now < UDEVADM_POLL_USEC ? deadline - now : UDEVADM_POLL_USEC);
        }
}

static void settle_usage(void) {
        puts("udevadm settle [OPTIONS]\n"
             "\n"
             "Wait for pending udev events.\n"
             "\n"
             "  -h --help                 Show this help\n"
             "  -V --version              Show package version\n"
             "  -t --timeout=SEC          Maximum time to wait for events\n"
             "  -E --exit-if-exists=FILE  Stop waiting if file exists");
}

static int verb_settle(int argc, char *argv[]) {
        static const struct option options[] = {
                {           "help",       no_argument, NULL, 'h' },
                {        "version",       no_argument, NULL, 'V' },
                {        "timeout", required_argument, NULL, 't' },
                { "exit-if-exists", required_argument, NULL, 'E' },
                {      "seq-start", required_argument, NULL, 's' },
                {        "seq-end", required_argument, NULL, 'e' },
                {          "quiet",       no_argument, NULL, 'q' },
                {             NULL,                 0, NULL,   0 },
        };
        usec_t timeout = UDEVADM_SETTLE_TIMEOUT_USEC;
        const char *exists = NULL;
        int c;

        optind = 0;
        while ((c = getopt_long(argc, argv, "hVt:E:s:e:q", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        settle_usage();
                        return 0;
                case 'V':
                        puts(UDEVADM_UDEV_VERSION);
                        return 0;
                case 't':
                        if (parse_sec(optarg, &timeout) < 0) {
                                fprintf(stderr, "udevadm: Failed to parse timeout value '%s'.\n", optarg);
                                return 1;
                        }
                        break;
                case 'E':
                        if (optarg[0] == '\0') {
                                fprintf(stderr, "udevadm: Invalid path: %s\n", optarg);
                                return 1;
                        }
                        exists = optarg;
                        break;
                case 's':
                case 'e':
                case 'q':
                        fprintf(stderr, "udevadm: Option -%c no longer supported.\n", c);
                        return 1;
                default:
                        return 1;
                }

        if (optind < argc) {
                fprintf(stderr, "udevadm: This subprogram takes no positional arguments.\n");
                return 1;
        }

        return settle_wait(timeout, exists) < 0 ? 1 : 0;
}

/* --- device lookup, shared by trigger and info --- */

/*
 * The sysfs directory of a device named the ways udevadm accepts: a path
 * under /sys (or a devpath, "/devices/...", with `as_path`), or a device
 * node, symlinks to one included; a bare name is taken as relative to /dev.
 * A path under /dev is a node even with `as_path`, as in v262's
 * find_device(). 0 or -ENODEV.
 */
static int resolve_device(const char *arg, bool as_path, char ret[static PATH_MAX]) {
        char path[PATH_MAX], probe[PATH_MAX];
        size_t sys_len = strlen(ctx.sys_root), dev_len = strlen(ctx.dev_root);
        bool under_sys, under_dev;
        struct stat st;
        int k;

        if (!arg || arg[0] == '\0')
                return -ENODEV;

        under_sys = strncmp(arg, ctx.sys_root, sys_len) == 0 && arg[sys_len] == '/';
        under_dev = strncmp(arg, ctx.dev_root, dev_len) == 0 && arg[dev_len] == '/';

        if (under_sys)
                k = snprintf(path, sizeof(path), "%s", arg);
        else if (as_path && !under_dev)
                k = snprintf(path, sizeof(path), "%s/%s", ctx.sys_root, arg[0] == '/' ? arg + 1 : arg);
        else {
                if (arg[0] == '/')
                        (void) snprintf(probe, sizeof(probe), "%s", arg);
                else if (!join(probe, ctx.dev_root, arg))
                        return -ENODEV;

                if (stat(probe, &st) < 0 || (!S_ISBLK(st.st_mode) && !S_ISCHR(st.st_mode)))
                        return -ENODEV;

                k = snprintf(path,
                             sizeof(path),
                             "%s/dev/%s/%u:%u",
                             ctx.sys_root,
                             S_ISBLK(st.st_mode) ? "block" : "char",
                             major(st.st_rdev),
                             minor(st.st_rdev));
        }

        if (k < 0 || (size_t) k >= sizeof(path))
                return -ENODEV;

        if (!realpath(path, ret))
                return -ENODEV;

        if (!join(probe, ret, "uevent") || access(probe, F_OK) < 0)
                return -ENODEV;

        return 0;
}

/* --- trigger --- */

typedef enum TriggerType {
        TRIGGER_DEVICES,
        TRIGGER_SUBSYSTEMS,
        TRIGGER_ALL,
} TriggerType;

typedef struct TriggerFilter {
        char **subsystem_match;
        char **subsystem_nomatch;
        char **sysname_match;
        char **attr_match;
        char **attr_nomatch;
        char **property_match;
        char **parents; /* resolved syspaths */
} TriggerFilter;

static void trigger_filter_done(TriggerFilter *f) {
        f->subsystem_match = pico_strv_free(f->subsystem_match);
        f->subsystem_nomatch = pico_strv_free(f->subsystem_nomatch);
        f->sysname_match = pico_strv_free(f->sysname_match);
        f->attr_match = pico_strv_free(f->attr_match);
        f->attr_nomatch = pico_strv_free(f->attr_nomatch);
        f->property_match = pico_strv_free(f->property_match);
        f->parents = pico_strv_free(f->parents);
}

static bool glob_any(char * const *patterns, const char *s) {
        for (size_t i = 0; patterns && patterns[i]; i++)
                if (fnmatch(patterns[i], s, 0) == 0)
                        return true;
        return false;
}

/* "FILE[=VALUE]": FILE exists, and when a value is given its content matches. */
static bool attr_holds(const char *syspath, const char *spec) {
        char name[PATH_MAX], path[PATH_MAX], value[4096];
        const char *eq = strchr(spec, '=');
        size_t n = eq ? (size_t) (eq - spec) : strlen(spec);

        if (n == 0 || n >= sizeof(name))
                return false;
        memcpy(name, spec, n);
        name[n] = '\0';

        if (!join(path, syspath, name))
                return false;

        if (!eq)
                return access(path, F_OK) == 0;

        if (read_line(path, value, sizeof(value)) < 0)
                return false;

        return fnmatch(eq + 1, value, 0) == 0;
}

/* "KEY=VALUE" against the device's uevent file and its SUBSYSTEM. */
static bool property_holds(const char *syspath, const char *subsystem, const char *spec) {
        char path[PATH_MAX], line[1024];
        const char *eq = strchr(spec, '=');
        size_t n = eq ? (size_t) (eq - spec) : 0;
        bool found = false;
        FILE *f;

        if (n == 0)
                return false;

        if (n == strlen("SUBSYSTEM") && strncmp(spec, "SUBSYSTEM", n) == 0)
                return fnmatch(eq + 1, subsystem, 0) == 0;

        if (!join(path, syspath, "uevent"))
                return false;

        f = fopen(path, "re");
        if (!f)
                return false;

        while (!found && fgets(line, sizeof(line), f)) {
                line[strcspn(line, "\n")] = '\0';
                if (strncmp(line, spec, n) == 0 && line[n] == '=')
                        found = fnmatch(eq + 1, line + n + 1, 0) == 0;
        }

        (void) fclose(f);
        return found;
}

static bool trigger_match(const TriggerFilter *f, const char *syspath, const char *subsystem) {
        const char *sysname = strrchr(syspath, '/');

        sysname = sysname ? sysname + 1 : syspath;

        if (f->subsystem_match && !glob_any(f->subsystem_match, subsystem))
                return false;
        if (glob_any(f->subsystem_nomatch, subsystem))
                return false;
        if (f->sysname_match && !glob_any(f->sysname_match, sysname))
                return false;

        if (f->parents) {
                bool under = false;

                for (size_t i = 0; f->parents[i] && !under; i++) {
                        size_t n = strlen(f->parents[i]);

                        under = strncmp(syspath, f->parents[i], n) == 0 &&
                                        (syspath[n] == '\0' || syspath[n] == '/');
                }
                if (!under)
                        return false;
        }

        for (size_t i = 0; f->attr_match && f->attr_match[i]; i++)
                if (!attr_holds(syspath, f->attr_match[i]))
                        return false;
        for (size_t i = 0; f->attr_nomatch && f->attr_nomatch[i]; i++)
                if (attr_holds(syspath, f->attr_nomatch[i]))
                        return false;

        if (f->property_match) {
                bool any = false;

                for (size_t i = 0; f->property_match[i] && !any; i++)
                        any = property_holds(syspath, subsystem, f->property_match[i]);
                if (!any)
                        return false;
        }

        return true;
}

/*
 * Every entry of `dir` that resolves to a directory with a uevent file and
 * passes the filter, appended to *list as a resolved path. A missing `dir` is
 * not an error. 0 or -ENOMEM.
 */
static int trigger_scan_dir(const char *dir, const char *subsystem, const TriggerFilter *f, char ***list) {
        struct dirent *e;
        DIR *dd;
        int r = 0;

        dd = opendir(dir);
        if (!dd)
                return 0;

        while (r == 0 && (e = readdir(dd))) {
                char link[PATH_MAX], real[PATH_MAX], probe[PATH_MAX];

                if (e->d_name[0] == '.')
                        continue;

                if (!join(link, dir, e->d_name) || !realpath(link, real))
                        continue;

                if (!join(probe, real, "uevent") || access(probe, F_OK) < 0)
                        continue;

                if (!trigger_match(f, real, subsystem))
                        continue;

                r = pico_strv_extend(list, real);
        }

        (void) closedir(dd);
        return r;
}

/*
 * For each subdirectory S of <sys_root>/<top>, scan <sys_root>/<top>/S[/<sub>]
 * with S as the subsystem name. Subsystems the filter rules out are skipped
 * whole. 0 or -ENOMEM.
 */
static int trigger_scan_subsystems(const char *top, const char *sub, const TriggerFilter *f, char ***list) {
        char base[PATH_MAX];
        struct dirent *e;
        DIR *dd;
        int r = 0;

        if (!join(base, ctx.sys_root, top))
                return 0;

        dd = opendir(base);
        if (!dd)
                return 0;

        while (r == 0 && (e = readdir(dd))) {
                char dir[PATH_MAX], path[PATH_MAX];

                if (e->d_name[0] == '.')
                        continue;

                if (f->subsystem_match && !glob_any(f->subsystem_match, e->d_name))
                        continue;
                if (glob_any(f->subsystem_nomatch, e->d_name))
                        continue;

                if (!join(dir, base, e->d_name))
                        continue;
                if (sub) {
                        if (!join(path, dir, sub))
                                continue;
                } else
                        (void) snprintf(path, sizeof(path), "%s", dir);

                r = trigger_scan_dir(path, e->d_name, f, list);
        }

        (void) closedir(dd);
        return r;
}

static int cmp_str(const void *a, const void *b) {
        return strcmp(*(char * const *) a, *(char * const *) b);
}

/*
 * The syspaths a trigger of `type` covers, sorted (which puts every parent
 * before its children, as a disk before its partitions) and without
 * duplicates. Devices are what udev's enumerator lists: every entry of
 * /sys/bus/<bus>/devices/ and /sys/class/<class>/. Subsystems are the entries
 * of /sys/module/, /sys/bus/ and /sys/bus/<bus>/drivers/, matched as the
 * subsystems "module", "subsystem" and "drivers". *ret is owned by the
 * caller. 0 or -ENOMEM.
 */
static int trigger_collect(TriggerType type, const TriggerFilter *f, char ***ret) {
        char **list = NULL;
        char path[PATH_MAX];
        size_t n, k;
        int r = 0;

        if (type != TRIGGER_DEVICES) {
                if (r == 0 && join(path, ctx.sys_root, "module") &&
                    (!f->subsystem_match || glob_any(f->subsystem_match, "module")) &&
                    !glob_any(f->subsystem_nomatch, "module"))
                        r = trigger_scan_dir(path, "module", f, &list);

                if (r == 0 && join(path, ctx.sys_root, "bus") &&
                    (!f->subsystem_match || glob_any(f->subsystem_match, "subsystem")) &&
                    !glob_any(f->subsystem_nomatch, "subsystem"))
                        r = trigger_scan_dir(path, "subsystem", f, &list);

                if (r == 0 && (!f->subsystem_match || glob_any(f->subsystem_match, "drivers")) &&
                    !glob_any(f->subsystem_nomatch, "drivers")) {
                        /* The bus name selects nothing here: "drivers" is the
                         * subsystem, as in sd-device-enumerator. */
                        TriggerFilter g = *f;

                        g.subsystem_match = NULL;
                        g.subsystem_nomatch = NULL;
                        r = trigger_scan_subsystems("bus", "drivers", &g, &list);
                }
        }

        if (r == 0 && type != TRIGGER_SUBSYSTEMS)
                r = trigger_scan_subsystems("bus", "devices", f, &list);
        if (r == 0 && type != TRIGGER_SUBSYSTEMS)
                r = trigger_scan_subsystems("class", NULL, f, &list);

        if (r < 0) {
                pico_strv_free(list);
                return r;
        }

        n = pico_strv_length(list);
        if (n > 1) {
                qsort(list, n, sizeof(list[0]), cmp_str);

                k = 1;
                for (size_t i = 1; i < n; i++) {
                        if (strcmp(list[i], list[k - 1]) == 0) {
                                free(list[i]);
                                continue;
                        }
                        list[k++] = list[i];
                }
                list[k] = NULL;
        }

        *ret = list;
        return 0;
}

/* Write `action` to <syspath>/uevent. 0 or -errno. */
static int trigger_write(const char *syspath, const char *action) {
        char path[PATH_MAX];
        size_t len = strlen(action);
        ssize_t n;
        int fd, r = 0;

        if (!join(path, syspath, "uevent"))
                return -ENAMETOOLONG;

        fd = open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        errno = 0;
        n = write(fd, action, len);
        if (n < 0 || (size_t) n != len)
                r = errno > 0 ? -errno : -EIO;

        (void) close(fd);
        return r;
}

static const char * const trigger_actions[] = {
        "add", "remove", "change", "move", "online", "offline", "bind", "unbind",
};

static bool trigger_action_valid(const char *a) {
        for (size_t i = 0; i < sizeof(trigger_actions) / sizeof(trigger_actions[0]); i++)
                if (strcmp(a, trigger_actions[i]) == 0)
                        return true;
        return false;
}

static void trigger_usage(void) {
        puts("udevadm trigger [OPTIONS] DEVPATH\n"
             "\n"
             "Request events from the kernel.\n"
             "\n"
             "  -h --help                         Show this help\n"
             "  -V --version                      Show package version\n"
             "  -v --verbose                      Print the list of devices while running\n"
             "  -n --dry-run                      Do not actually trigger the events\n"
             "  -q --quiet                        Suppress error logging in triggering events\n"
             "  -t --type=                        Type of events to trigger\n"
             "          devices                     sysfs devices (default)\n"
             "          subsystems                  sysfs subsystems and drivers\n"
             "          all                         sysfs devices, subsystems, and drivers\n"
             "  -c --action=ACTION|help           Event action value, default is \"change\"\n"
             "  -s --subsystem-match=SUBSYSTEM    Trigger devices from a matching subsystem\n"
             "  -S --subsystem-nomatch=SUBSYSTEM  Exclude devices from a matching subsystem\n"
             "  -a --attr-match=FILE[=VALUE]      Trigger devices with a matching attribute\n"
             "  -A --attr-nomatch=FILE[=VALUE]    Exclude devices with a matching attribute\n"
             "  -p --property-match=KEY=VALUE     Trigger devices with a matching property\n"
             "  -y --sysname-match=NAME           Trigger devices with this /sys path\n"
             "     --name-match=NAME              Trigger devices with this /dev name\n"
             "  -b --parent-match=NAME            Trigger devices with that parent device\n"
             "  -w --settle                       Wait for the triggered events to complete\n"
             "     --wait-daemon[=SECONDS]        Wait for devd to be running before triggering\n"
             "     --prioritized-subsystem=...    Accepted, no effect\n"
             "\n"
             "Not supported by devd: --tag-match, --include-parents, --initialized-match,\n"
             "--initialized-nomatch and --uuid.");
}

static int verb_trigger(int argc, char *argv[]) {
        enum {
                ARG_NAME = 0x100,
                ARG_PING,
                ARG_UUID,
                ARG_PRIORITIZED,
                ARG_INCLUDE_PARENTS,
                ARG_INITIALIZED_MATCH,
                ARG_INITIALIZED_NOMATCH,
        };
        static const struct option options[] = {
                {                  "help",       no_argument, NULL,                     'h' },
                {               "version",       no_argument, NULL,                     'V' },
                {               "verbose",       no_argument, NULL,                     'v' },
                {               "dry-run",       no_argument, NULL,                     'n' },
                {                 "quiet",       no_argument, NULL,                     'q' },
                {                  "type", required_argument, NULL,                     't' },
                {                "action", required_argument, NULL,                     'c' },
                {       "subsystem-match", required_argument, NULL,                     's' },
                {     "subsystem-nomatch", required_argument, NULL,                     'S' },
                {            "attr-match", required_argument, NULL,                     'a' },
                {          "attr-nomatch", required_argument, NULL,                     'A' },
                {        "property-match", required_argument, NULL,                     'p' },
                {             "tag-match", required_argument, NULL,                     'g' },
                {         "sysname-match", required_argument, NULL,                     'y' },
                {            "name-match", required_argument, NULL,                ARG_NAME },
                {          "parent-match", required_argument, NULL,                     'b' },
                {       "include-parents",       no_argument, NULL,     ARG_INCLUDE_PARENTS },
                {     "initialized-match",       no_argument, NULL,   ARG_INITIALIZED_MATCH },
                {   "initialized-nomatch",       no_argument, NULL, ARG_INITIALIZED_NOMATCH },
                {                "settle",       no_argument, NULL,                     'w' },
                {           "wait-daemon", optional_argument, NULL,                ARG_PING },
                {                  "uuid",       no_argument, NULL,                ARG_UUID },
                { "prioritized-subsystem", required_argument, NULL,         ARG_PRIORITIZED },
                {                    NULL,                 0, NULL,                       0 },
        };
        TriggerFilter f = { 0 };
        TriggerType type = TRIGGER_DEVICES;
        const char *action = "change";
        bool verbose = false, dry_run = false, quiet = false, settle = false, ping = false;
        usec_t ping_timeout = UDEVADM_PING_TIMEOUT_USEC;
        char **list = NULL;
        int c, ret = 1, r;

        optind = 0;
        while ((c = getopt_long(argc, argv, "hVvnqt:c:s:S:a:A:p:g:y:b:w", options, NULL)) >= 0) {
                char ***target = NULL;
                char syspath[PATH_MAX];

                switch (c) {
                case 'h':
                        trigger_usage();
                        ret = 0;
                        goto out;
                case 'V':
                        puts(UDEVADM_UDEV_VERSION);
                        ret = 0;
                        goto out;
                case 'v':
                        verbose = true;
                        break;
                case 'n':
                        dry_run = true;
                        break;
                case 'q':
                        quiet = true;
                        break;
                case 't':
                        if (strcmp(optarg, "devices") == 0)
                                type = TRIGGER_DEVICES;
                        else if (strcmp(optarg, "subsystems") == 0)
                                type = TRIGGER_SUBSYSTEMS;
                        else if (strcmp(optarg, "all") == 0)
                                type = TRIGGER_ALL;
                        else {
                                fprintf(stderr, "udevadm: Unknown type --type=%s\n", optarg);
                                goto out;
                        }
                        break;
                case 'c':
                        if (strcmp(optarg, "help") == 0) {
                                for (size_t i = 0; i < sizeof(trigger_actions) / sizeof(trigger_actions[0]);
                                     i++)
                                        puts(trigger_actions[i]);
                                ret = 0;
                                goto out;
                        }
                        if (!trigger_action_valid(optarg)) {
                                fprintf(stderr, "udevadm: Unknown action '%s'\n", optarg);
                                goto out;
                        }
                        action = optarg;
                        break;
                case 's':
                        target = &f.subsystem_match;
                        break;
                case 'S':
                        target = &f.subsystem_nomatch;
                        break;
                case 'a':
                        target = &f.attr_match;
                        break;
                case 'A':
                        target = &f.attr_nomatch;
                        break;
                case 'p':
                        if (!strchr(optarg, '=') || optarg[0] == '=') {
                                fprintf(stderr,
                                        "udevadm: Expected KEY=VALUE for --property-match, got '%s'\n",
                                        optarg);
                                goto out;
                        }
                        target = &f.property_match;
                        break;
                case 'y':
                        target = &f.sysname_match;
                        break;
                case ARG_NAME:
                case 'b':
                        if (resolve_device(optarg, c == 'b', syspath) < 0) {
                                fprintf(stderr, "udevadm: Failed to open the device '%s'\n", optarg);
                                goto out;
                        }
                        if (pico_strv_extend(&f.parents, syspath) < 0)
                                goto oom;
                        break;
                case 'w':
                        settle = true;
                        break;
                case ARG_PING:
                        ping = true;
                        if (optarg && parse_sec(optarg, &ping_timeout) < 0) {
                                fprintf(stderr, "udevadm: Failed to parse timeout value '%s'.\n", optarg);
                                goto out;
                        }
                        break;
                case ARG_PRIORITIZED:
                        /* Only an ordering hint; the set triggered is the same. */
                        break;
                case 'g':
                case ARG_INCLUDE_PARENTS:
                case ARG_INITIALIZED_MATCH:
                case ARG_INITIALIZED_NOMATCH:
                case ARG_UUID:
                        fprintf(stderr,
                                "udevadm: trigger: --%s is not supported by devd.\n",
                                option_name(options, c));
                        goto out;
                default:
                        goto out;
                }

                if (target && pico_strv_extend(target, optarg) < 0)
                        goto oom;
        }

        for (int i = optind; i < argc; i++) {
                char syspath[PATH_MAX];

                if (resolve_device(argv[i], false, syspath) < 0) {
                        fprintf(stderr, "udevadm: Failed to open the device '%s'\n", argv[i]);
                        goto out;
                }
                if (pico_strv_extend(&f.parents, syspath) < 0)
                        goto oom;
        }

        if (ping) {
                usec_t deadline = usec_add(now_monotonic(), ping_timeout);

                while (!devd_pid(NULL)) {
                        if (now_monotonic() >= deadline) {
                                fprintf(stderr, "udevadm: Timed out waiting for devd.\n");
                                goto out;
                        }
                        sleep_usec(UDEVADM_POLL_USEC);
                }
        }

        r = trigger_collect(type, &f, &list);
        if (r < 0)
                goto oom;

        ret = 0;
        for (size_t i = 0; list && list[i]; i++) {
                if (verbose)
                        puts(list[i]);
                if (dry_run)
                        continue;

                r = trigger_write(list[i], action);
                if (r == -ENOENT || r == -ENODEV || r == -ENXIO)
                        continue; /* gone since the scan */
                if (r < 0) {
                        if (!quiet)
                                fprintf(stderr,
                                        "udevadm: Failed to write '%s' to '%s/uevent': %s\n",
                                        action,
                                        list[i],
                                        strerror(-r));
                        ret = 1;
                }
        }

        if (settle && !dry_run && settle_wait(UDEVADM_SETTLE_TIMEOUT_USEC, NULL) < 0)
                ret = 1;

        goto out;

oom:
        fprintf(stderr, "udevadm: Out of memory.\n");
        ret = 1;
out:
        pico_strv_free(list);
        trigger_filter_done(&f);
        return ret;
}

/* --- control --- */

static bool log_level_valid(const char *s) {
        static const char * const names[] = {
                "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
        };
        char *end;
        long v;

        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
                if (strcmp(s, names[i]) == 0)
                        return true;

        errno = 0;
        v = strtol(s, &end, 10);
        return errno == 0 && end != s && *end == '\0' && v >= 0 && v <= 7;
}

/*
 * SIGTERM devd and wait for it to be gone. 0, or 1 on timeout. The wait is on
 * the process, not the pid file: devd removes that before it has finished
 * exiting, and switch_root must not race a devd still running.
 */
static int control_exit(usec_t timeout) {
        usec_t deadline;
        pid_t pid;

        /* Not running is what --exit asks for. v262 fails when it cannot reach
         * udevd; exiting 0 is deliberate (docs/DEVD.md). */
        if (!devd_pid(&pid))
                return 0;

        if (kill(pid, SIGTERM) < 0 && errno != ESRCH) {
                fprintf(stderr, "udevadm: Failed to stop devd: %s\n", strerror(errno));
                return 1;
        }

        deadline = timeout == USEC_INFINITY ? USEC_INFINITY : usec_add(now_monotonic(), timeout);
        while (pid_alive(pid)) {
                if (now_monotonic() >= deadline) {
                        fprintf(stderr, "udevadm: Timed out waiting for devd to exit.\n");
                        return 1;
                }
                sleep_usec(UDEVADM_POLL_USEC);
        }

        return 0;
}

static void control_usage(void) {
        puts("udevadm control OPTION\n"
             "\n"
             "Control the device manager.\n"
             "\n"
             "  -h --help                Show this help\n"
             "  -V --version             Show package version\n"
             "  -e --exit                Stop devd and wait for it to exit\n"
             "     --ping                Check that devd is running\n"
             "  -t --timeout=SEC         Maximum time to wait for --exit\n"
             "\n"
             "Accepted, no effect with devd: -l --log-level=LEVEL, -s --stop-exec-queue,\n"
             "-S --start-exec-queue, -R --reload, -p --property=KEY=VALUE,\n"
             "-m --children-max=N, --trace=BOOL, --revert, --load-credentials.");
}

static int verb_control(int argc, char *argv[]) {
        enum {
                ARG_PING = 0x100,
                ARG_TRACE,
                ARG_REVERT,
                ARG_LOAD_CREDENTIALS,
        };
        static const struct option options[] = {
                {             "help",       no_argument, NULL,                  'h' },
                {          "version",       no_argument, NULL,                  'V' },
                {             "exit",       no_argument, NULL,                  'e' },
                {     "log-priority", required_argument, NULL,                  'l' },
                {        "log-level", required_argument, NULL,                  'l' },
                {  "stop-exec-queue",       no_argument, NULL,                  's' },
                { "start-exec-queue",       no_argument, NULL,                  'S' },
                {     "reload-rules",       no_argument, NULL,                  'R' },
                {           "reload",       no_argument, NULL,                  'R' },
                {              "env", required_argument, NULL,                  'p' },
                {         "property", required_argument, NULL,                  'p' },
                {     "children-max", required_argument, NULL,                  'm' },
                {             "ping",       no_argument, NULL,             ARG_PING },
                {            "trace", required_argument, NULL,            ARG_TRACE },
                {           "revert",       no_argument, NULL,           ARG_REVERT },
                {          "timeout", required_argument, NULL,                  't' },
                { "load-credentials",       no_argument, NULL, ARG_LOAD_CREDENTIALS },
                {               NULL,                 0, NULL,                    0 },
        };
        usec_t timeout = UDEVADM_CONTROL_TIMEOUT_USEC;
        bool do_exit = false, do_ping = false, any = false;
        char *end = NULL;
        int c;

        optind = 0;
        while ((c = getopt_long(argc, argv, "hVel:sSRp:m:t:", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        control_usage();
                        return 0;
                case 'V':
                        puts(UDEVADM_UDEV_VERSION);
                        return 0;
                case 'e':
                        do_exit = any = true;
                        break;
                case 'l':
                        if (!log_level_valid(optarg)) {
                                fprintf(stderr, "udevadm: Failed to parse log level '%s'.\n", optarg);
                                return 1;
                        }
                        any = true;
                        break;
                case 's':
                case 'S':
                case 'R':
                case ARG_REVERT:
                case ARG_LOAD_CREDENTIALS:
                        any = true;
                        break;
                case 'p':
                        if (!strchr(optarg, '=')) {
                                fprintf(stderr, "udevadm: expect <KEY>=<value> instead of '%s'\n", optarg);
                                return 1;
                        }
                        any = true;
                        break;
                case 'm':
                        errno = 0;
                        if (!isdigit((unsigned char) optarg[0]) || strtoul(optarg, &end, 10) > INT_MAX ||
                            errno != 0 || *end != '\0') {
                                fprintf(stderr,
                                        "udevadm: Failed to parse maximum number of children '%s'.\n",
                                        optarg);
                                return 1;
                        }
                        any = true;
                        break;
                case ARG_PING:
                        do_ping = any = true;
                        break;
                case ARG_TRACE:
                        if (parse_bool(optarg) < 0) {
                                fprintf(stderr, "udevadm: Failed to parse --trace= value '%s'.\n", optarg);
                                return 1;
                        }
                        any = true;
                        break;
                case 't':
                        if (parse_sec(optarg, &timeout) < 0) {
                                fprintf(stderr, "udevadm: Failed to parse timeout value '%s'.\n", optarg);
                                return 1;
                        }
                        break;
                default:
                        return 1;
                }

        if (!any) {
                fprintf(stderr, "udevadm: No control command option is specified.\n");
                return 1;
        }

        if (optind < argc) {
                fprintf(stderr, "udevadm: This subprogram takes no positional arguments.\n");
                return 1;
        }

        if (do_ping && !devd_pid(NULL)) {
                fprintf(stderr, "udevadm: devd is not running.\n");
                return 1;
        }

        return do_exit ? control_exit(timeout) : 0;
}

/* --- info --- */

typedef struct InfoProp {
        char key[INFO_KEY_MAX];
        char value[INFO_VALUE_MAX];
} InfoProp;

typedef struct InfoDevice {
        char syspath[PATH_MAX];
        const char *devpath; /* into syspath */
        const char *sysname; /* into syspath */
        char subsystem[64];
        char devname[PATH_MAX]; /* absolute, "" for a device with no node */
        char devtype[64];
        unsigned major_n, minor_n;
        bool have_devno;
        char links[INFO_LINKS_MAX]; /* space-separated, relative to dev_root */
        InfoProp props[INFO_PROPS_MAX];
        size_t n_props;
} InfoDevice;

/* Bounded like every table here: past the cap a property is dropped. */
static void info_add(InfoDevice *d, const char *key, const char *value) {
        InfoProp *p;

        if (d->n_props >= INFO_PROPS_MAX)
                return;

        p = &d->props[d->n_props];
        if ((size_t) snprintf(p->key, sizeof(p->key), "%s", key) >= sizeof(p->key))
                return;
        (void) snprintf(p->value, sizeof(p->value), "%s", value);
        d->n_props++;
}

static const char *info_get(const InfoDevice *d, const char *key) {
        for (size_t i = 0; i < d->n_props; i++)
                if (strcmp(d->props[i].key, key) == 0)
                        return d->props[i].value;
        return NULL;
}

/*
 * blkid's two spellings of an identifier: `safe` with whitespace and control
 * characters made '_' (ID_FS_LABEL), and `enc` with every byte outside udev's
 * whitelist as \xNN (ID_FS_LABEL_ENC), the escaping devd's by-label links use.
 */
static void fs_string_safe(const char *s, char *ret, size_t size) {
        size_t n = 0;

        for (; *s && n + 1 < size; s++)
                ret[n++] = isspace((unsigned char) *s) || iscntrl((unsigned char) *s) ? '_' : *s;
        ret[n] = '\0';
}

static void fs_string_enc(const char *s, char *ret, size_t size) {
        size_t n = 0;

        for (; *s; s++) {
                unsigned char ch = (unsigned char) *s;

                if (isalnum(ch) || strchr("#+-.:=@_", ch)) {
                        if (n + 2 > size)
                                break;
                        ret[n++] = (char) ch;
                } else {
                        if (n + 5 > size)
                                break;
                        (void) snprintf(ret + n, 5, "\\x%02x", ch);
                        n += 4;
                }
        }
        ret[n] = '\0';
}

/* The device's links under dev_root, at most three levels down. */
static void info_links_dir(InfoDevice *d, const char *dir, const char *rel, unsigned depth) {
        struct dirent *e;
        DIR *dd;

        dd = opendir(dir);
        if (!dd)
                return;

        while ((e = readdir(dd))) {
                char path[PATH_MAX], sub[PATH_MAX], real[PATH_MAX];
                struct stat st;

                if (e->d_name[0] == '.')
                        continue;

                if (!join(path, dir, e->d_name) || lstat(path, &st) < 0)
                        continue;

                if (rel[0] == '\0')
                        (void) snprintf(sub, sizeof(sub), "%s", e->d_name);
                else if (!join(sub, rel, e->d_name))
                        continue;

                if (S_ISDIR(st.st_mode)) {
                        /* Pseudo-filesystems with nothing udev would name. */
                        if (depth == 0 &&
                            (strcmp(e->d_name, "pts") == 0 || strcmp(e->d_name, "shm") == 0 ||
                             strcmp(e->d_name, "mqueue") == 0 || strcmp(e->d_name, "hugepages") == 0))
                                continue;
                        if (depth < 2)
                                info_links_dir(d, path, sub, depth + 1);
                        continue;
                }

                if (!S_ISLNK(st.st_mode) || !realpath(path, real) || strcmp(real, d->devname) != 0)
                        continue;

                if (strlen(d->links) + strlen(sub) + 2 > sizeof(d->links))
                        continue;
                if (d->links[0] != '\0')
                        strcat(d->links, " ");
                strcat(d->links, sub);
        }

        (void) closedir(dd);
}

/* Everything info prints about the device at `syspath`. 0 or -errno. */
static int info_load(const char *syspath, InfoDevice *d) {
        char path[PATH_MAX], line[1024], id[DEVD_UDEV_DB_ID_MAX];
        size_t sys_len = strlen(ctx.sys_root);
        const char *s;
        FILE *f;

        memset(d, 0, sizeof(*d));

        if ((size_t) snprintf(d->syspath, sizeof(d->syspath), "%s", syspath) >= sizeof(d->syspath))
                return -ENAMETOOLONG;
        if (strncmp(d->syspath, ctx.sys_root, sys_len) != 0 || d->syspath[sys_len] != '/')
                return -EINVAL;

        d->devpath = d->syspath + sys_len;
        s = strrchr(d->syspath, '/');
        d->sysname = s + 1;

        read_subsystem(d->syspath, d->subsystem, sizeof(d->subsystem));

        info_add(d, "DEVPATH", d->devpath);

        if (!join(path, d->syspath, "uevent"))
                return -ENAMETOOLONG;
        f = fopen(path, "re");
        if (!f)
                return -errno;

        while (fgets(line, sizeof(line), f)) {
                char *eq;

                line[strcspn(line, "\n")] = '\0';
                eq = strchr(line, '=');
                if (!eq || eq == line)
                        continue;
                *eq++ = '\0';

                if (strcmp(line, "DEVNAME") == 0) {
                        if (eq[0] == '/')
                                (void) snprintf(d->devname, sizeof(d->devname), "%s", eq);
                        else if (!join(d->devname, ctx.dev_root, eq))
                                d->devname[0] = '\0';
                        info_add(d, line, d->devname);
                        continue;
                }

                if (strcmp(line, "DEVTYPE") == 0)
                        (void) snprintf(d->devtype, sizeof(d->devtype), "%s", eq);
                else if (strcmp(line, "MAJOR") == 0)
                        d->major_n = (unsigned) strtoul(eq, NULL, 10);
                else if (strcmp(line, "MINOR") == 0) {
                        d->minor_n = (unsigned) strtoul(eq, NULL, 10);
                        d->have_devno = true;
                }

                info_add(d, line, eq);
        }
        (void) fclose(f);

        if (d->subsystem[0] != '\0')
                info_add(d, "SUBSYSTEM", d->subsystem);

        /* devd's own entry, keyed as devd-udev-db.h's devd_udev_db_id(). */
        if (d->have_devno)
                (void) snprintf(id,
                                sizeof(id),
                                "%c%u:%u",
                                strcmp(d->subsystem, "block") == 0 ? 'b' : 'c',
                                d->major_n,
                                d->minor_n);
        else if ((s = info_get(d, "IFINDEX")) && atoi(s) > 0)
                (void) snprintf(id, sizeof(id), "n%d", atoi(s));
        else
                (void) snprintf(id, sizeof(id), "+%s:%s", d->subsystem, d->sysname);

        if (join(path, ctx.db_root, id) && (f = fopen(path, "re"))) {
                while (fgets(line, sizeof(line), f)) {
                        char *eq;

                        line[strcspn(line, "\n")] = '\0';
                        if (strncmp(line, "I:", 2) == 0) {
                                info_add(d, "USEC_INITIALIZED", line + 2);
                                continue;
                        }
                        if (strncmp(line, "E:", 2) != 0)
                                continue;
                        eq = strchr(line + 2, '=');
                        if (!eq || eq == line + 2)
                                continue;
                        *eq++ = '\0';
                        info_add(d, line + 2, eq);
                }
                (void) fclose(f);
        }

        if (strcmp(d->subsystem, "block") == 0 && d->devname[0] != '\0') {
                PicoFsId fs;
                char buf[INFO_VALUE_MAX];

                /* Best-effort: an unreadable node (not root, no medium) has
                 * no filesystem to report, as with blkid. */
                if (pico_fs_probe(d->devname, PICO_FS_NONE, &fs) > 0 && pico_fs_kind_to_string(fs.kind)) {
                        if (fs.uuid[0] != '\0') {
                                info_add(d, "ID_FS_UUID", fs.uuid);
                                fs_string_enc(fs.uuid, buf, sizeof(buf));
                                info_add(d, "ID_FS_UUID_ENC", buf);
                        }
                        if (fs.label[0] != '\0') {
                                fs_string_safe(fs.label, buf, sizeof(buf));
                                info_add(d, "ID_FS_LABEL", buf);
                                fs_string_enc(fs.label, buf, sizeof(buf));
                                info_add(d, "ID_FS_LABEL_ENC", buf);
                        }
                        info_add(d, "ID_FS_TYPE", pico_fs_kind_to_string(fs.kind));
                        info_add(d, "ID_FS_USAGE", fs.kind == PICO_FS_SWAP ? "other" : "filesystem");
                }
        }

        if (d->devname[0] != '\0') {
                info_links_dir(d, ctx.dev_root, "", 0);

                if (d->links[0] != '\0') {
                        char devlinks[INFO_VALUE_MAX];
                        size_t n = 0;
                        const char *p = d->links;

                        /* DEVLINKS carries absolute paths, S: relative ones. */
                        devlinks[0] = '\0';
                        while (*p) {
                                size_t len = strcspn(p, " ");
                                int k = snprintf(
                                                devlinks + n,
                                                sizeof(devlinks) - n,
                                                "%s%s/%.*s",
                                                n ? " " : "",
                                                ctx.dev_root,
                                                (int) len,
                                                p);

                                if (k < 0 || (size_t) k >= sizeof(devlinks) - n) {
                                        devlinks[n] = '\0';
                                        break;
                                }
                                n += (size_t) k;
                                p += len;
                                if (*p == ' ')
                                        p++;
                        }
                        info_add(d, "DEVLINKS", devlinks);
                }
        }

        return 0;
}

typedef enum InfoQuery {
        QUERY_ALL,
        QUERY_NAME,
        QUERY_SYMLINK,
        QUERY_PATH,
        QUERY_PROPERTY,
} InfoQuery;

typedef struct InfoOutput {
        InfoQuery query;
        bool root;
        bool export;
        const char *export_prefix;
        bool value_only;
        char **properties; /* --property= names, NULL for all */
} InfoOutput;

static bool info_wanted(const InfoOutput *o, const char *key) {
        if (!o->properties)
                return true;
        for (size_t i = 0; o->properties[i]; i++)
                if (strcmp(o->properties[i], key) == 0)
                        return true;
        return false;
}

/* The node name relative to dev_root, as N: and --query=name print it. */
static const char *info_node_name(const InfoDevice *d) {
        size_t n = strlen(ctx.dev_root);

        if (strncmp(d->devname, ctx.dev_root, n) == 0 && d->devname[n] == '/')
                return d->devname + n + 1;
        return d->devname;
}

static int info_print(const InfoDevice *d, const InfoOutput *o) {
        const char *prefix = o->export_prefix ? o->export_prefix : "";

        switch (o->query) {
        case QUERY_NAME:
                if (d->devname[0] == '\0') {
                        fprintf(stderr, "udevadm: No device node found\n");
                        return 1;
                }
                puts(o->root ? d->devname : info_node_name(d));
                return 0;

        case QUERY_SYMLINK:
                if (!o->root) {
                        puts(d->links);
                        return 0;
                }
                for (const char *p = d->links; *p;) {
                        size_t len = strcspn(p, " ");

                        printf("%s%s/%.*s", p == d->links ? "" : " ", ctx.dev_root, (int) len, p);
                        p += len;
                        if (*p == ' ')
                                p++;
                }
                putchar('\n');
                return 0;

        case QUERY_PATH:
                puts(d->devpath);
                return 0;

        case QUERY_PROPERTY:
                for (size_t i = 0; i < d->n_props; i++) {
                        const InfoProp *p = &d->props[i];

                        if (!info_wanted(o, p->key))
                                continue;
                        if (o->value_only)
                                puts(p->value);
                        else if (o->export || o->export_prefix)
                                printf("%s%s='%s'\n", prefix, p->key, p->value);
                        else
                                printf("%s=%s\n", p->key, p->value);
                }
                return 0;

        case QUERY_ALL:
                printf("P: %s\n", d->devpath);
                printf("M: %s\n", d->sysname);
                if (d->subsystem[0] != '\0')
                        printf("U: %s\n", d->subsystem);
                if (d->devtype[0] != '\0')
                        printf("T: %s\n", d->devtype);
                if (d->have_devno)
                        printf("D: %c %u:%u\n",
                               strcmp(d->subsystem, "block") == 0 ? 'b' : 'c',
                               d->major_n,
                               d->minor_n);
                if (d->devname[0] != '\0')
                        printf("N: %s\n", info_node_name(d));
                for (const char *p = d->links; *p;) {
                        size_t len = strcspn(p, " ");

                        printf("S: %.*s\n", (int) len, p);
                        p += len;
                        if (*p == ' ')
                                p++;
                }
                for (size_t i = 0; i < d->n_props; i++)
                        printf("E: %s=%s\n", d->props[i].key, d->props[i].value);
                putchar('\n');
                return 0;
        }

        return 1;
}

static void info_usage(void) {
        puts("udevadm info [OPTIONS] [DEVPATH|FILE]\n"
             "\n"
             "Query sysfs or the udev database.\n"
             "\n"
             "  -h --help                   Print this message\n"
             "  -V --version                Print version of the program\n"
             "  -q --query=TYPE             Query device information:\n"
             "       name                     Name of device node\n"
             "       symlink                  Pointing to node\n"
             "       path                     sysfs device path\n"
             "       property                 The device properties\n"
             "       all                      All values\n"
             "     --property=NAME          Show only properties by this name\n"
             "     --value                  When showing properties, print only their values\n"
             "  -p --path=SYSPATH           sysfs device path used for query or attribute walk\n"
             "  -n --name=NAME              Node or symlink name used for query or attribute walk\n"
             "  -r --root                   Prepend dev directory to path names\n"
             "  -x --export                 Export key/value pairs\n"
             "  -P --export-prefix          Export the key name with a prefix\n"
             "  -e --export-db              Accepted, prints nothing with devd\n"
             "  -c --cleanup-db             Accepted, no effect with devd\n"
             "  -w --wait-for-initialization[=SEC]  Accepted, devd handles events in order");
}

static int verb_info(int argc, char *argv[]) {
        enum {
                ARG_PROPERTY = 0x100,
                ARG_VALUE,
                ARG_NO_PAGER,
                ARG_JSON,
                ARG_SUBSYSTEM_MATCH,
                ARG_SUBSYSTEM_NOMATCH,
                ARG_ATTR_MATCH,
                ARG_ATTR_NOMATCH,
                ARG_PROPERTY_MATCH,
                ARG_TAG_MATCH,
                ARG_SYSNAME_MATCH,
                ARG_NAME_MATCH,
                ARG_PARENT_MATCH,
                ARG_INITIALIZED_MATCH,
                ARG_INITIALIZED_NOMATCH,
        };
        static const struct option options[] = {
                {                    "help",       no_argument, NULL,                     'h' },
                {                 "version",       no_argument, NULL,                     'V' },
                {                   "query", required_argument, NULL,                     'q' },
                {                    "path", required_argument, NULL,                     'p' },
                {                    "name", required_argument, NULL,                     'n' },
                {                    "root",       no_argument, NULL,                     'r' },
                {          "attribute-walk",       no_argument, NULL,                     'a' },
                {                    "tree",       no_argument, NULL,                     't' },
                {                  "export",       no_argument, NULL,                     'x' },
                {           "export-prefix", required_argument, NULL,                     'P' },
                {       "device-id-of-file", required_argument, NULL,                     'd' },
                {               "export-db",       no_argument, NULL,                     'e' },
                {              "cleanup-db",       no_argument, NULL,                     'c' },
                { "wait-for-initialization", optional_argument, NULL,                     'w' },
                {                "property", required_argument, NULL,            ARG_PROPERTY },
                {                   "value",       no_argument, NULL,               ARG_VALUE },
                {                "no-pager",       no_argument, NULL,            ARG_NO_PAGER },
                {                    "json", required_argument, NULL,                ARG_JSON },
                {         "subsystem-match", required_argument, NULL,     ARG_SUBSYSTEM_MATCH },
                {       "subsystem-nomatch", required_argument, NULL,   ARG_SUBSYSTEM_NOMATCH },
                {              "attr-match", required_argument, NULL,          ARG_ATTR_MATCH },
                {            "attr-nomatch", required_argument, NULL,        ARG_ATTR_NOMATCH },
                {          "property-match", required_argument, NULL,      ARG_PROPERTY_MATCH },
                {               "tag-match", required_argument, NULL,           ARG_TAG_MATCH },
                {           "sysname-match", required_argument, NULL,       ARG_SYSNAME_MATCH },
                {              "name-match", required_argument, NULL,          ARG_NAME_MATCH },
                {            "parent-match", required_argument, NULL,        ARG_PARENT_MATCH },
                {       "initialized-match",       no_argument, NULL,   ARG_INITIALIZED_MATCH },
                {     "initialized-nomatch",       no_argument, NULL, ARG_INITIALIZED_NOMATCH },
                {                      NULL,                 0, NULL,                       0 },
        };
        InfoOutput o = { .query = QUERY_ALL };
        bool have_query = false, export_db = false, cleanup_db = false;
        char **devices = NULL, **paths = NULL;
        InfoDevice *d = NULL;
        int c, ret = 1;

        optind = 0;
        while ((c = getopt_long(argc, argv, "hVq:p:n:ratxP:d:ecw::", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        info_usage();
                        ret = 0;
                        goto out;
                case 'V':
                        puts(UDEVADM_UDEV_VERSION);
                        ret = 0;
                        goto out;
                case 'q':
                        have_query = true;
                        if (strcmp(optarg, "name") == 0)
                                o.query = QUERY_NAME;
                        else if (strcmp(optarg, "symlink") == 0)
                                o.query = QUERY_SYMLINK;
                        else if (strcmp(optarg, "path") == 0)
                                o.query = QUERY_PATH;
                        else if (strcmp(optarg, "property") == 0 || strcmp(optarg, "env") == 0)
                                o.query = QUERY_PROPERTY;
                        else if (strcmp(optarg, "all") == 0)
                                o.query = QUERY_ALL;
                        else {
                                fprintf(stderr, "udevadm: unknown query type '%s'\n", optarg);
                                goto out;
                        }
                        break;
                case 'p':
                        if (pico_strv_extend(&paths, optarg) < 0)
                                goto oom;
                        break;
                case 'n':
                        if (pico_strv_extend(&devices, optarg) < 0)
                                goto oom;
                        break;
                case 'r':
                        o.root = true;
                        break;
                case 'x':
                        o.export = true;
                        break;
                case 'P':
                        o.export_prefix = optarg;
                        break;
                case 'e':
                        export_db = true;
                        break;
                case 'c':
                        cleanup_db = true;
                        break;
                case 'w':
                        if (optarg) {
                                usec_t unused;

                                if (parse_sec(optarg, &unused) < 0) {
                                        fprintf(stderr,
                                                "udevadm: Failed to parse timeout value '%s'.\n",
                                                optarg);
                                        goto out;
                                }
                        }
                        break;
                case ARG_PROPERTY: {
                        const char *p = optarg;

                        /* Comma-separated, and repeatable. */
                        while (*p) {
                                char name[INFO_KEY_MAX];
                                size_t len = strcspn(p, ",");

                                if (len > 0 && len < sizeof(name)) {
                                        memcpy(name, p, len);
                                        name[len] = '\0';
                                        if (pico_strv_extend(&o.properties, name) < 0)
                                                goto oom;
                                }
                                p += len;
                                if (*p == ',')
                                        p++;
                        }
                        break;
                }
                case ARG_VALUE:
                        o.value_only = true;
                        break;
                case ARG_NO_PAGER:
                        break;
                case 'a':
                case 't':
                case 'd':
                case ARG_JSON:
                case ARG_SUBSYSTEM_MATCH:
                case ARG_SUBSYSTEM_NOMATCH:
                case ARG_ATTR_MATCH:
                case ARG_ATTR_NOMATCH:
                case ARG_PROPERTY_MATCH:
                case ARG_TAG_MATCH:
                case ARG_SYSNAME_MATCH:
                case ARG_NAME_MATCH:
                case ARG_PARENT_MATCH:
                case ARG_INITIALIZED_MATCH:
                case ARG_INITIALIZED_NOMATCH:
                        fprintf(stderr,
                                "udevadm: info: --%s is not supported by devd.\n",
                                option_name(options, c));
                        goto out;
                default:
                        goto out;
                }

        /* The database is devd's own and is rebuilt by the next devd from
         * sysfs, so there is nothing to clean or export. */
        if (export_db || cleanup_db) {
                ret = 0;
                goto out;
        }

        for (int i = optind; i < argc; i++)
                if (pico_strv_extend(&devices, argv[i]) < 0)
                        goto oom;

        if (!devices && !paths) {
                fprintf(stderr, "udevadm: A device name or path is required\n");
                goto out;
        }

        /* udevadm's own rule: --value only makes sense for properties. */
        if (o.value_only && have_query && o.query != QUERY_PROPERTY) {
                fprintf(stderr, "udevadm: --value is only allowed with --query=property\n");
                goto out;
        }
        if (o.value_only || o.properties)
                o.query = QUERY_PROPERTY;

        d = malloc(sizeof(*d));
        if (!d)
                goto oom;

        ret = 0;
        for (int pass = 0; pass < 2; pass++) {
                char * const *list = pass == 0 ? paths : devices;

                for (size_t i = 0; list && list[i]; i++) {
                        char syspath[PATH_MAX];
                        int r;

                        if (resolve_device(list[i], pass == 0, syspath) < 0) {
                                fprintf(stderr, "udevadm: Unknown device \"%s\": No such device\n", list[i]);
                                ret = 1;
                                continue;
                        }

                        r = info_load(syspath, d);
                        if (r < 0) {
                                fprintf(stderr, "udevadm: Failed to read %s: %s\n", syspath, strerror(-r));
                                ret = 1;
                                continue;
                        }

                        if (info_print(d, &o) != 0)
                                ret = 1;
                }
        }
        goto out;

oom:
        fprintf(stderr, "udevadm: Out of memory.\n");
        ret = 1;
out:
        free(d);
        pico_strv_free(devices);
        pico_strv_free(paths);
        pico_strv_free(o.properties);
        return ret;
}

/* --- main --- */

static void udevadm_usage(void) {
        puts("udevadm [--help] [--version] [--debug] COMMAND [COMMAND OPTIONS]\n"
             "\n"
             "Send control commands or test the device manager (devd).\n"
             "\n"
             "Commands:\n"
             "  info          Query sysfs or the udev database\n"
             "  trigger       Request events from the kernel\n"
             "  settle        Wait for pending udev events\n"
             "  control       Control the device manager\n"
             "  version       Show package version\n"
             "\n"
             "Not supported by devd: monitor, test, test-builtin, hwdb, wait, lock, cat, verify.");
}

int main(int argc, char *argv[]) {
        static const char * const unsupported[] = {
                "monitor", "test", "test-builtin", "hwdb", "wait", "lock", "cat", "verify",
        };
        const char *verb;
        int i;

        for (i = 1; i < argc && argv[i][0] == '-'; i++) {
                if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                        udevadm_usage();
                        return 0;
                }
                if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
                        puts(UDEVADM_UDEV_VERSION);
                        return 0;
                }
                if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0)
                        continue;

                fprintf(stderr, "udevadm: unrecognized option '%s'\n", argv[i]);
                return 1;
        }

        if (i >= argc) {
                fprintf(stderr, "udevadm: missing command\n");
                udevadm_usage();
                return 1;
        }

        verb = argv[i];
        argc -= i;
        argv += i;

        if (strcmp(verb, "settle") == 0)
                return verb_settle(argc, argv);
        if (strcmp(verb, "trigger") == 0)
                return verb_trigger(argc, argv);
        if (strcmp(verb, "control") == 0)
                return verb_control(argc, argv);
        if (strcmp(verb, "info") == 0)
                return verb_info(argc, argv);
        if (strcmp(verb, "version") == 0) {
                puts(UDEVADM_UDEV_VERSION);
                return 0;
        }
        if (strcmp(verb, "help") == 0) {
                udevadm_usage();
                return 0;
        }

        for (size_t k = 0; k < sizeof(unsupported) / sizeof(unsupported[0]); k++)
                if (strcmp(verb, unsupported[k]) == 0) {
                        fprintf(stderr, "udevadm: '%s' is not supported by devd.\n", verb);
                        return 1;
                }

        fprintf(stderr, "udevadm: Unknown command verb '%s'.\n", verb);
        return 1;
}
