/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The receive path (plan §3, J1): a fake service writing multi-line/partial/oversized output, a real syslog(3)
 * client against a bound test socket, and correct ucred+cgroup attribution and framing for every entry.
 *
 * Registered up front and placeholder-bodied, matching the convention the
 * rest of this suite already follows: milestone J1 owns this file, and
 * adding its real cases must never mean editing meson.build while another
 * milestone is also editing it.
 *
 * Placeholder status is asserted, not merely printed -- a test that passes
 * by doing nothing should say so in its own output, so a green run is never
 * mistaken for coverage that does not exist yet.
 */

#include <stdio.h>

int main(void) {
        printf("test-logd-recv: placeholder, no cases yet (J1)\n");
        return 0;
}
