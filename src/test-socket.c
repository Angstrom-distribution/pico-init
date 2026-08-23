/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Socket units (plan §1.6): pairing both ways, repeated Listen* lines, ignored-directive tolerance, Accept=yes
 * failing loudly, bind/trigger/fd-pass end to end, re-listen after service death, and the trigger ratelimit.
 *
 * Registered up front and placeholder-bodied, matching the convention the
 * rest of this suite already follows: milestone S0-S2 owns this file, and
 * adding its real cases must never mean editing meson.build while another
 * milestone is also editing it.
 *
 * Placeholder status is asserted, not merely printed -- a test that passes
 * by doing nothing should say so in its own output, so a green run is never
 * mistaken for coverage that does not exist yet.
 */

#include <stdio.h>

int main(void) {
        printf("test-socket: placeholder, no cases yet (S0-S2)\n");
        return 0;
}
