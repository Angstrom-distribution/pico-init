/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Clock, timezone and the boot clock floor. See netd-time.h.
 *
 * Derived from systemd v261.2 (commit 4925d9f07f):
 *   - src/timesync/timesyncd-manager.c's manager_adjust_clock() ->
 *     netd_time_build_timex()/netd_time_adjust_clock() (the slew/step
 *     threshold and struct timex shape).
 *   - src/timesync/timesyncd.c's load_clock_timestamp()/advance_tstamp() ->
 *     netd_time_clock_floor_decide()/netd_time_clock_floor_apply()/
 *     netd_time_clock_floor_touch() (both TIME_EPOCH-and-mtime floor halves,
 *     and the coarse-filesystem retry ladder).
 *   - src/timedate/timedated.c's context_write_data_timezone()/
 *     method_set_timezone() -> netd_time_set_timezone() (atomic symlink
 *     swap, the empty-or-UTC unlink case, the tzset()-then-kernel-push
 *     order, and the kernel push being logged-and-ignored on failure).
 *   - src/shared/clock-util.c's clock_set_timezone() -> netd_time_build_tz().
 * None of the four carries a per-file copyright line upstream (verified
 * against the checkout at the quarry point, not assumed), so this file
 * follows the project-default attribution the rest of the lift set uses.
 *
 * Quarry-discipline history review (plan §2.2's prose block records the
 * window's methodology): `4925d9f07f..main` touches src/timedate in exactly
 * one commit, 844c44a0d4 "timedated: roll back state on config write
 * failure" -- not applicable. It saves and restores a bus-facing Context
 * object's cached c->zone/c->local_rtc across a failed write so a repeated
 * SetTimezone() D-Bus call retries instead of reporting stale success; netd
 * has no such cache and no bus -- netd_time_get_timezone() always re-reads
 * the real symlink rather than trusting an in-memory value, so the class of
 * bug that commit fixes cannot occur here by construction. The window's two
 * src/timesync commits (98e7cc36f0, 8027ff6ecd) are cited in netd-sntp.c,
 * the file whose scope they actually touch; src/shared/clock-util.c and
 * src/timedate/timedated.c beyond the one commit above are untouched in the
 * window.
 *
 * Three pure decision functions exist purely for testability, the same
 * reason netd_time_build_timex() does (its own header comment predates this
 * file's real implementation and already explains it): clock_adjtime(),
 * settimeofday() and clock_settime() all mutate real, process-global or
 * kernel-global state that a test cannot safely apply, and settimeofday()/
 * clock_settime() specifically need CAP_SYS_TIME, which this project's own
 * verify.sh container denies even to root (confirmed directly: EPERM) --
 * so netd_time_build_tz() and netd_time_clock_floor_decide() split "what
 * would happen" from "make it happen" exactly as netd_time_build_timex()
 * already does for the clock_adjtime() case.
 */

/* clock_adjtime(), clock_settime()'s ADJ_ and STA_ constants, and futimens()
 * are declared under glibc's __USE_GNU guard -- -std=gnu17 alone does not
 * imply _GNU_SOURCE, so this has to be explicit and first, before any header
 * pulls in <features.h> (same fix test-netd-rtnl.c already needed for
 * unshare()). */
#define _GNU_SOURCE

#include "netd-time.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <time.h>
#include <unistd.h>

#include "netd.h"

/* --- clock: slew or step --- */

int netd_time_build_timex(int64_t offset_usec, struct timex *ret_tmx, NetdClockAdjust *ret_mode) {
        struct timex tmx = { 0 };
        int64_t abs_offset;

        if (!ret_tmx || !ret_mode)
                return -EINVAL;

        abs_offset = offset_usec < 0 ? -offset_usec : offset_usec;

        if (abs_offset < (int64_t) NETD_TIME_STEP_THRESHOLD_USEC) {
                /*
                 * Slew: ADJ_NANO makes .offset nanoseconds. The time constant
                 * is fixed rather than derived from a poll interval (§2.6
                 * drops adaptive polling): 7, upstream's own
                 * log2i(poll_interval_usec / USEC_PER_SEC) - 4 with netd's
                 * fixed NETD_SNTP_POLL_INTERVAL_USEC of 2048s substituted in
                 * -- log2(2048) - 4 == 7 -- so the formula collapses to a
                 * constant rather than disappearing.
                 */
                tmx.modes = ADJ_STATUS | ADJ_NANO | ADJ_OFFSET | ADJ_TIMECONST | ADJ_MAXERROR | ADJ_ESTERROR;
                tmx.status = STA_PLL;
                tmx.offset = (long) (offset_usec * 1000);
                tmx.constant = 7;

                *ret_mode = NETD_CLOCK_SLEW;
        } else {
                /* ADJ_SETOFFSET adds .time to the current time; ADJ_NANO
                 * makes .time.tv_usec nanoseconds despite the field name.
                 * The kernel expects a negative offset as e.g. -0.3s ==
                 * {-1, 700000000}, not {0, -300000000} -- normalize. */
                int64_t sec = offset_usec / (int64_t) USEC_PER_SEC;
                int64_t nsec = (offset_usec % (int64_t) USEC_PER_SEC) * 1000;

                if (nsec < 0) {
                        sec -= 1;
                        nsec += 1000000000L;
                }

                tmx.modes = ADJ_STATUS | ADJ_NANO | ADJ_SETOFFSET | ADJ_MAXERROR | ADJ_ESTERROR;
                tmx.time.tv_sec = (time_t) sec;
                tmx.time.tv_usec = (long) nsec;

                *ret_mode = NETD_CLOCK_STEP;
        }

        /* STA_UNSYNC deliberately left clear (netd-time.h, plan §2.6 step 5). */

        *ret_tmx = tmx;
        return 0;
}

int netd_time_adjust_clock(Netd *n, int64_t offset_usec) {
        struct timex tmx;
        NetdClockAdjust mode;
        int r;

        if (!n)
                return -EINVAL;

        r = netd_time_build_timex(offset_usec, &tmx, &mode);
        if (r < 0)
                return r;

        pico_log(PICO_LOG_DEBUG,
                 "netd: time: %s by %+lld usec",
                 netd_clock_adjust_to_string(mode),
                 (long long) offset_usec);

        if (clock_adjtime(CLOCK_REALTIME, &tmx) < 0)
                return -errno;

        return 0;
}

/* --- timezone --- */

/* Reject a leading '/' and any "." or ".." path component: `tz` is
 * attacker-controlled (DHCP option 101) and about to become a symlink
 * target under Netd.zoneinfo_dir. */
static bool tz_name_is_safe(const char *tz) {
        const char *p = tz;

        if (!tz || tz[0] == '\0' || tz[0] == '/')
                return false;

        while (*p) {
                const char *slash = strchr(p, '/');
                size_t len = slash ? (size_t) (slash - p) : strlen(p);

                if (len == 0)
                        return false; /* "//" or a trailing slash */
                if (len == 1 && p[0] == '.')
                        return false;
                if (len == 2 && p[0] == '.' && p[1] == '.')
                        return false;

                if (!slash)
                        break;
                p = slash + 1;
        }

        return true;
}

bool netd_time_timezone_is_valid(Netd *n, const char *tz) {
        char path[PATH_MAX];
        struct stat st;
        int len;

        if (!n || !n->zoneinfo_dir || !tz_name_is_safe(tz))
                return false;

        len = snprintf(path, sizeof(path), "%s/%s", n->zoneinfo_dir, tz);
        if (len < 0 || (size_t) len >= sizeof(path))
                return false;

        /* stat(), not lstat(): follows a zoneinfo symlink (e.g. "UTC" ->
         * "Etc/UTC" on some distributions) through to the real TZif file. */
        if (stat(path, &st) < 0)
                return false;

        return S_ISREG(st.st_mode);
}

int netd_time_build_tz(struct timezone *ret_tz) {
        time_t now_t;
        struct tm tm;

        if (!ret_tz)
                return -EINVAL;

        now_t = time(NULL);
        if (now_t == (time_t) -1)
                return -errno;

        if (!localtime_r(&now_t, &tm))
                return -EINVAL;

        ret_tz->tz_minuteswest = -(int) (tm.tm_gmtoff / 60);
        ret_tz->tz_dsttime = 0; /* DST_NONE */

        return 0;
}

/* Write `target` as a symlink at `linkpath`, atomically: create it under a
 * fixed temporary name next to `linkpath` and rename() over the real name,
 * so no reader ever observes a missing or half-written link (timedated.c's
 * symlinkat_atomic_full()). A fixed suffix is enough, not a random one:
 * netd is single-threaded and this runs to completion within one epoll
 * iteration, so there is no concurrent writer to race. */
static int atomic_symlink(const char *target, const char *linkpath) {
        char tmp[PATH_MAX];
        int len, r;

        len = snprintf(tmp, sizeof(tmp), "%s.netd-tmp", linkpath);
        if (len < 0 || (size_t) len >= sizeof(tmp))
                return -ENAMETOOLONG;

        if (unlink(tmp) < 0 && errno != ENOENT)
                return -errno;

        if (symlink(target, tmp) < 0)
                return -errno;

        if (rename(tmp, linkpath) < 0) {
                r = -errno;
                (void) unlink(tmp);
                return r;
        }

        return 0;
}

char *netd_time_get_timezone(Netd *n) {
        char buf[PATH_MAX];
        ssize_t len;
        const char *prefix, *name;
        size_t prefix_len;

        if (!n || !n->localtime_path || !n->zoneinfo_dir)
                return NULL;

        len = readlink(n->localtime_path, buf, sizeof(buf) - 1);
        if (len < 0)
                return NULL;
        buf[len] = '\0';

        prefix = n->zoneinfo_dir;
        prefix_len = strlen(prefix);
        name = buf;

        if (strncmp(buf, prefix, prefix_len) == 0 && buf[prefix_len] == '/')
                name = buf + prefix_len + 1;

        return pico_strdup(name);
}

int netd_time_set_timezone(Netd *n, const char *tz) {
        char *current;
        struct timezone kt;
        int r;

        if (!n || !tz)
                return -EINVAL;

        current = netd_time_get_timezone(n);

        if (tz[0] == '\0' || strcmp(tz, "UTC") == 0) {
                bool had = current != NULL;

                free(current);

                if (!had)
                        return 1;

                if (unlink(n->localtime_path) < 0 && errno != ENOENT)
                        return -errno;
        } else {
                bool same = current && strcmp(current, tz) == 0;

                free(current);

                if (same)
                        return 1;

                if (!netd_time_timezone_is_valid(n, tz))
                        return -EINVAL;

                {
                        char source[PATH_MAX];
                        int len;

                        len = snprintf(source, sizeof(source), "%s/%s", n->zoneinfo_dir, tz);
                        if (len < 0 || (size_t) len >= sizeof(source))
                                return -ENAMETOOLONG;

                        r = atomic_symlink(source, n->localtime_path);
                        if (r < 0)
                                return r;
                }
        }

        /*
         * timedated.c's method_set_timezone() steps 2-3, run unconditionally
         * for every branch above including the unlink one: "make glibc
         * notice the new timezone", then "tell the kernel our timezone".
         * tzset() first is load-bearing -- netd_time_build_tz() reads
         * tm_gmtoff off localtime_r(), which only reflects the zone just
         * installed once tzset() has reloaded it.
         *
         * A failure here is logged and ignored, not propagated: the symlink
         * swap above is the durable state and has already succeeded, and
         * upstream treats a failing clock_set_timezone() the same way
         * (timedated.c:717-719, "ignoring").
         */
        tzset();

        r = netd_time_build_tz(&kt);
        if (r < 0)
                pico_log(PICO_LOG_DEBUG,
                         "netd: time: failed to compute kernel timezone, ignoring: %s",
                         strerror(-r));
        else {
                /* Not "%m": pico_log_internal() is declared with the ISO
                 * "printf" format archetype, and -Wpedantic rejects glibc's
                 * %m extension against it (verified: -Werror=format=). */
                int sr = settimeofday(NULL, &kt);

                if (sr < 0)
                        pico_log(PICO_LOG_DEBUG,
                                 "netd: time: failed to tell kernel about timezone, ignoring: %s",
                                 strerror(errno));
        }

        return 0;
}

/* --- the clock floor (§2.6 step 6) --- */

bool netd_time_clock_floor_decide(usec_t clock_file_mtime_usec, usec_t now_usec, usec_t *ret_target_usec) {
        usec_t epoch_usec, floor_usec;

        epoch_usec = (usec_t) NETD_TIME_EPOCH_SEC * USEC_PER_SEC;
        floor_usec = clock_file_mtime_usec > epoch_usec ? clock_file_mtime_usec : epoch_usec;

        if (now_usec > floor_usec)
                return false;

        if (ret_target_usec)
                *ret_target_usec = usec_add(floor_usec, USEC_PER_SEC);

        return true;
}

/* "<state_dir>/<name>", malloc'd. Not netd_runtime_path(): that helper is
 * rooted at Netd.runtime_dir (/run/netd, tmpfs, cleared every boot), and the
 * clock floor needs to survive a reboot to mean anything -- it belongs under
 * Netd.state_dir (/var/lib/netd) instead, exactly as NETD_CLOCK_FILE's own
 * doc comment in netd-time.h says. */
static int state_path(Netd *n, const char *name, char **ret) {
        char path[PATH_MAX];
        char *copy;
        int len;

        if (!n || !n->state_dir || !name || !ret)
                return -EINVAL;

        len = snprintf(path, sizeof(path), "%s/%s", n->state_dir, name);
        if (len < 0 || (size_t) len >= sizeof(path))
                return -ENAMETOOLONG;

        copy = pico_strdup(path);
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return 0;
}

static usec_t timespec_to_usec(const struct timespec *ts) {
        return (usec_t) ts->tv_sec * USEC_PER_SEC + (usec_t) ts->tv_nsec / 1000;
}

int netd_time_clock_floor_apply(Netd *n) {
        char *path = NULL;
        struct stat st;
        usec_t mtime_usec = 0, now_usec, target;
        struct timespec ts, set_ts;
        int r;

        if (!n)
                return -EINVAL;

        r = state_path(n, NETD_CLOCK_FILE, &path);
        if (r < 0)
                return r;

        /* Any stat() failure (typically ENOENT on first boot) leaves
         * mtime_usec at 0, which netd_time_clock_floor_decide() then never
         * prefers over TIME_EPOCH -- "first boot: TIME_EPOCH is the only
         * floor there is" falls out of the comparison rather than needing
         * its own branch. */
        if (stat(path, &st) == 0)
                mtime_usec = timespec_to_usec(&st.st_mtim);
        free(path);

        if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
                return -errno;
        now_usec = timespec_to_usec(&ts);

        if (!netd_time_clock_floor_decide(mtime_usec, now_usec, &target))
                return 0;

        set_ts.tv_sec = (time_t) (target / USEC_PER_SEC);
        set_ts.tv_nsec = (long) ((target % USEC_PER_SEC) * 1000);

        if (clock_settime(CLOCK_REALTIME, &set_ts) < 0)
                return -errno;

        return 1;
}

int netd_time_clock_floor_touch(Netd *n) {
        char *path = NULL;
        int fd, r;
        struct timespec ts;
        usec_t base;

        if (!n || !n->state_dir)
                return -EINVAL;

        if (mkdir(n->state_dir, 0755) < 0 && errno != EEXIST)
                return -errno;

        r = state_path(n, NETD_CLOCK_FILE, &path);
        if (r < 0)
                return r;

        fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        free(path);
        if (fd < 0)
                return -errno;

        if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
                r = -errno;
                goto done;
        }
        base = timespec_to_usec(&ts);

        /*
         * timesyncd.c's advance_tstamp(): try bumping the mtime by 1us, then
         * 10us, 100us, ... up to 10s, stopping at the first bump the
         * filesystem's timestamp granularity can actually record. Directly
         * relevant on the JFFS2/UBIFS-class rootfs this project's h2200
         * target would use, where sub-second granularity is not a given.
         */
        r = 0;
        for (usec_t a = 1; a <= 10 * USEC_PER_SEC; a *= 10) {
                usec_t candidate = usec_add(base, a);
                struct timespec set_ts[2];
                struct stat st;

                set_ts[0].tv_sec = (time_t) (candidate / USEC_PER_SEC);
                set_ts[0].tv_nsec = (long) ((candidate % USEC_PER_SEC) * 1000);
                set_ts[1] = set_ts[0];

                if (futimens(fd, set_ts) < 0) {
                        /* Can't touch mtimes at all -- give up quietly, as
                         * upstream does ("ignoring"). */
                        r = 0;
                        break;
                }

                if (fstat(fd, &st) < 0) {
                        r = -errno;
                        break;
                }

                if (timespec_to_usec(&st.st_mtim) > base) {
                        r = 0;
                        break;
                }

                /* Granularity too coarse at this step; try the next one. */
        }

done:
        (void) close(fd);
        return r;
}

static const char * const netd_clock_adjust_table[_NETD_CLOCK_ADJUST_MAX] = {
        [NETD_CLOCK_SLEW] = "slew",
        [NETD_CLOCK_STEP] = "step",
};

const char *netd_clock_adjust_to_string(NetdClockAdjust a) {
        if (a < 0 || a >= _NETD_CLOCK_ADJUST_MAX)
                return "invalid";

        return netd_clock_adjust_table[a];
}
