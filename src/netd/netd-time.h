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
#include <sys/timex.h>

#include "../util.h"

typedef struct Netd Netd;

#define NETD_ZONEINFO_DIR "/usr/share/zoneinfo"
#define NETD_LOCALTIME_PATH "/etc/localtime"

/* Bumped on every successful sync, read at boot. Its mtime is the whole
 * state: no content, no format, nothing to parse or corrupt. */
#define NETD_CLOCK_FILE "clock" /* relative to Netd.state_dir */

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
 * Point /etc/localtime at <zoneinfo_dir>/<tz>, exactly the way timedated
 * does it: create the symlink under a temporary name in the same directory
 * and rename() it over the target, so no reader ever observes a missing or
 * half-written link. Then tzset(), and push the offset into the kernel with
 * settimeofday(NULL, &tz) so a local-time RTC and anything reading the kernel
 * timezone agree.
 *
 * Nothing notifies already-running processes -- true of upstream as well;
 * glibc re-stats /etc/localtime on later localtime() calls.
 *
 * 0 on success, 1 when the timezone was already the requested one and nothing
 * was written, -EINVAL for a name that fails validation, or -errno.
 */
int netd_time_set_timezone(Netd *n, const char *tz);

/* The currently installed zone name, read back from the symlink, or NULL.
 * Malloc'd. */
char *netd_time_get_timezone(Netd *n);

/* --- the clock floor (§2.6 step 6) --- */

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

/* Bump the mtime of the clock file to now. Called after each accepted sync.
 * 0 or -errno. */
int netd_time_clock_floor_touch(Netd *n);

const char *netd_clock_adjust_to_string(NetdClockAdjust a);
