/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * picolog (plan §3.4, J3): filter/follow/export modes against fixture rings, binary-safe fields under both
 * the default blob-data path and -a, and a rotation boundary crossed mid-follow.
 *
 * Registered up front and placeholder-bodied, matching the convention the
 * rest of this suite already follows: milestone J3 owns this file, and
 * adding its real cases must never mean editing meson.build while another
 * milestone is also editing it.
 *
 * Placeholder status is asserted, not merely printed -- a test that passes
 * by doing nothing should say so in its own output, so a green run is never
 * mistaken for coverage that does not exist yet.
 */

#include <stdio.h>

int main(void) {
        printf("test-picolog: placeholder, no cases yet (J3)\n");
        return 0;
}
