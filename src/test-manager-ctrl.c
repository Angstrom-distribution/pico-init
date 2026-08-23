/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The control socket (plan §1.7, C2): deferred replies driven through the real manager loop, reset-failed,
 * early-disconnect leak checks, and oversized/malformed/unknown-verb rejection without allocation.
 *
 * Registered up front and placeholder-bodied, matching the convention the
 * rest of this suite already follows: milestone C2 owns this file, and
 * adding its real cases must never mean editing meson.build while another
 * milestone is also editing it.
 *
 * Placeholder status is asserted, not merely printed -- a test that passes
 * by doing nothing should say so in its own output, so a green run is never
 * mistaken for coverage that does not exist yet.
 */

#include <stdio.h>

int main(void) {
        printf("test-manager-ctrl: placeholder, no cases yet (C2)\n");
        return 0;
}
