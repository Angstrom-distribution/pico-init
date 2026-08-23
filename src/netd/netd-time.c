/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Clock, timezone and the boot clock floor. See netd-time.h.
 *
 * N0 scaffold: -ENOSYS until N4, except the name table.
 */

#include "netd-time.h"

#include <errno.h>
#include <stddef.h>

#include "netd.h"

int netd_time_build_timex(int64_t offset_usec, struct timex *ret_tmx, NetdClockAdjust *ret_mode) {
        (void) offset_usec;

        if (!ret_tmx || !ret_mode)
                return -EINVAL;

        return -ENOSYS;
}

int netd_time_adjust_clock(Netd *n, int64_t offset_usec) {
        (void) offset_usec;

        if (!n)
                return -EINVAL;

        return -ENOSYS;
}

bool netd_time_timezone_is_valid(Netd *n, const char *tz) {
        (void) n;
        (void) tz;

        return false;
}

int netd_time_set_timezone(Netd *n, const char *tz) {
        if (!n || !tz)
                return -EINVAL;

        return -ENOSYS;
}

char *netd_time_get_timezone(Netd *n) {
        (void) n;

        return NULL;
}

int netd_time_clock_floor_apply(Netd *n) {
        if (!n)
                return -EINVAL;

        return -ENOSYS;
}

int netd_time_clock_floor_touch(Netd *n) {
        if (!n)
                return -EINVAL;

        return -ENOSYS;
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
