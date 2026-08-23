/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * picoctl's file and symlink half (plan §1.7, C1): golden-output tests per verb against fixture state trees,
 * systemctl-matching exit codes, and symlink layouts byte-identical to systemctl --root on the same fixtures.
 *
 * Registered up front and placeholder-bodied, matching the convention the
 * rest of this suite already follows: milestone C1 owns this file, and
 * adding its real cases must never mean editing meson.build while another
 * milestone is also editing it.
 *
 * Placeholder status is asserted, not merely printed -- a test that passes
 * by doing nothing should say so in its own output, so a green run is never
 * mistaken for coverage that does not exist yet.
 */

#include <stdio.h>

int main(void) {
        printf("test-picoctl: placeholder, no cases yet (C1)\n");
        return 0;
}
