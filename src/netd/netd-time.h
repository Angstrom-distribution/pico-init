/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Applying time: the clock, the timezone, and the boot-time clock floor
 * (plan §2.6 steps 3, 5 and 6).
 *
 * This is the half of netd that exists because of the founding requirement --
 * a DHCP server that hands out a timezone (option 101) should set the
 * timezone. Upstream needs networkd, a state file, inotify, timesyncd, D-Bus
 * and timedated to get that from the wire to /etc/localtime; here it is a
 * function call from netd-link.c.
 *
 * The mechanics are timedated's and clock-util.c's, reimplemented rather than
 * lifted (they amount to a symlink swap and two syscalls), so this file is
 * GPL-2.0-or-later with the rest of netd's own code.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h> /* struct timezone */
#include <sys/timex.h>

#include "../util.h"

typedef struct Netd Netd;

#define NETD_ZONEINFO_DIR "/usr/share/zoneinfo"
#define NETD_LOCALTIME_PATH "/etc/localtime"

/* Bumped on every successful sync, read at boot. Its mtime is the whole
 * state: no content, no format, nothing to parse or corrupt. */
#define NETD_CLOCK_FILE "clock" /* relative to Netd.state_dir */

/*
 * Upstream's TIME_EPOCH (plan §2.6 step 6, and the SNTP epoch-floor
 * rejection the history review added -- see NETD_SNTP_REJECT_EPOCH in
 * netd-sntp.h). Used two ways: as the floor netd_time_clock_floor_apply()
 * will not let CLOCK_REALTIME sit below, and as the floor netd_sntp_validate()
 * will not accept a reply's recv_time/trans_time claiming a time before.
 *
 * Upstream derives this at build time from `git log` on the latest tag (or,
 * failing that, NEWS's mtime) via meson -- see meson.build's `time_epoch`.
 * meson.build is not this milestone's file to edit, so there is no build-
 * system plumbing for a computed value here: this is a fixed calendar
 * constant instead, chosen at implementation time. It only ever needs to move
 * forward, never back, and only if a real netd release manages to postdate
 * it, which has ample headroom.
 */
#define NETD_TIME_EPOCH_SEC ((int64_t) 1767225600) /* 2026-01-01T00:00:00Z */

/*
 * Below this, slew; at or above it, step. 0.4s is upstream's threshold and
 * the right one: a slew of more than a few hundred ms takes long enough that
 * anything watching a timestamp sees the clock visibly wrong for minutes.
 */
#define NETD_TIME_STEP_THRESHOLD_USEC ((usec_t) (400ULL * USEC_PER_MSEC))

typedef enum NetdClockAdjust {
        NETD_CLOCK_SLEW, /* ADJ_OFFSET | ADJ_STATUS with STA_PLL */
        NETD_CLOCK_STEP, /* ADJ_SETOFFSET, ns-precision */
        _NETD_CLOCK_ADJUST_MAX,
} NetdClockAdjust;

/* --- netd-time.c --- */

/*
 * Turn a signed offset into the struct timex that would apply it, and say
 * which of the two kinds of adjustment it is. Pure: no syscall, no clock
 * read.
 *
 * Split out from netd_time_adjust_clock() precisely so it can be tested.
 * clock_adjtime() is process-global -- it stays global inside a network
 * namespace, so the netns trick that makes the rtnl and DHCP tests safe does
 * nothing for this one, and a test that actually stepped the clock would be a
 * test that broke the machine running it (§2.8).
 *
 * STA_UNSYNC is deliberately left clear in the slew case: that is what lets
 * the kernel's own 11-minute mode write the RTC, so netd never touches
 * /dev/rtc on the sync path at all.
 *
 * 0 or -errno.
 */
int netd_time_build_timex(int64_t offset_usec, struct timex *ret_tmx, NetdClockAdjust *ret_mode);

/* Build it and apply it with clock_adjtime(CLOCK_REALTIME, ...). 0 or -errno. */
int netd_time_adjust_clock(Netd *n, int64_t offset_usec);

/* --- timezone --- */

/*
 * True when `tz` is a name netd is willing to install: a plausible TZDB name
 * (no leading '/', no "..", no absolute-path or traversal shapes) that
 * actually exists under Netd.zoneinfo_dir.
 *
 * The string arrives from a DHCP server, so it is attacker-controlled input
 * being turned into a symlink target -- validate before use, never after.
 */
bool netd_time_timezone_is_valid(Netd *n, const char *tz);

/*
 * Compute the struct timezone netd_time_set_timezone() would push into the
 * kernel for the zone *currently loaded by tzset()*, without calling
 * settimeofday(). Split out for the same reason netd_time_build_timex() is:
 * settimeofday() needs CAP_SYS_TIME, which the netns-capable but otherwise
 * unprivileged-for-clock-purposes test container does not grant even to
 * root (verified directly: EPERM), and it mutates a piece of real kernel
 * state a test cannot safely apply regardless of privilege.
 *
 * It is also the hook that makes the tzset()-before-this-computation
 * ordering testable at all: call tzset() to load a known zone (or don't) and
 * compare what this returns -- reading tm_gmtoff off localtime_r() only
 * reflects the zone tzset() most recently loaded, so a caller that got the
 * order backwards is directly observable through this function without ever
 * touching /etc/localtime or the kernel.
 *
 * 0 or -errno.
 */
int netd_time_build_tz(struct timezone *ret_tz);

/*
 * Point /etc/localtime at <zoneinfo_dir>/<tz>, exactly the way timedated
 * does it: create the symlink under a temporary name in the same directory
 * and rename() it over the target, so no reader ever observes a missing or
 * half-written link. Then tzset(), and push the offset into the kernel with
 * settimeofday(NULL, &tz) (via netd_time_build_tz(), above) so a local-time
 * RTC and anything reading the kernel timezone agree.
 *
 * The tzset()-before-netd_time_build_tz() ordering is load-bearing:
 * netd_time_build_tz() reads tm_gmtoff off localtime_r(), which only
 * reflects the zone just installed once tzset() has reloaded it -- get this
 * backwards and the kernel is handed the *previous* zone's offset.
 *
 * A failure of the kernel push (including a plain CAP_SYS_TIME EPERM) is
 * logged and ignored rather than returned, exactly as timedated.c's own
 * method_set_timezone() treats a failing clock_set_timezone(): the symlink
 * is the durable, load-bearing state, and its swap already succeeded by the
 * time the kernel push is attempted.
 *
 * The empty-or-"UTC" case unlinks /etc/localtime rather than leaving a
 * stale symlink in place (so a DHCP server that stops sending option 101
 * does not leave the previous zone applied forever), and still runs the
 * tzset()/kernel-push tail below it -- upstream's method_set_timezone()
 * does not special-case that branch either.
 *
 * Nothing notifies already-running processes -- true of upstream as well;
 * glibc re-stats /etc/localtime on later localtime() calls.
 *
 * 0 on success, 1 when the timezone was already the requested one and nothing
 * was written, -EINVAL for a name that fails validation, or -errno (symlink
 * write/unlink failure only -- see above for the kernel-push failure case).
 */
int netd_time_set_timezone(Netd *n, const char *tz);

/* The currently installed zone name, read back from the symlink, or NULL.
 * Malloc'd. */
char *netd_time_get_timezone(Netd *n);

/* --- the clock floor (§2.6 step 6) --- */

/*
 * The max(TIME_EPOCH, clock-file mtime) floor decision and step target,
 * without calling clock_settime() -- split out for the same reason as
 * netd_time_build_tz() above: clock_settime() needs CAP_SYS_TIME (denied in
 * the test container, verified directly) and mutates real wall-clock time a
 * test cannot safely apply. `clock_file_mtime_usec` is 0 when the clock file
 * does not exist yet (first boot: TIME_EPOCH is the only floor there is,
 * plan §2.6 prose). Pure function of its three arguments.
 *
 * Returns true (and fills *ret_target_usec, the floor plus one second,
 * matching upstream's "restore to n+1 so as not to report the same time
 * twice") when now_usec does not already clear the floor; false otherwise.
 */
bool netd_time_clock_floor_decide(usec_t clock_file_mtime_usec, usec_t now_usec, usec_t *ret_target_usec);

/*
 * Cheap insurance for a board with no RTC or a dead battery: if
 * CLOCK_REALTIME is earlier than the last recorded sync, move it forward to
 * that time plus one second. Called from netd_startup() before any network
 * exists, so nothing has yet stamped a file or validated a certificate
 * against 1970.
 *
 * Harmless where the RTC is real (h2200 has one): the condition is simply
 * false. 0 when nothing was needed, 1 when the clock was moved, or -errno.
 */
int netd_time_clock_floor_apply(Netd *n);

/*
 * Bump the mtime of the clock file to now, retrying at increasing offsets
 * (1us, 10us, ... up to 10s) when the filesystem's timestamp granularity is
 * too coarse to record a smaller bump -- ported from timesyncd.c's
 * advance_tstamp(), directly relevant on the JFFS2/UBIFS-class rootfs this
 * project's h2200 target would use. Called after each accepted sync. 0 or
 * -errno.
 */
int netd_time_clock_floor_touch(Netd *n);

const char *netd_clock_adjust_to_string(NetdClockAdjust a);
