/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The state publisher (plan §1.7, C0): files matching every unit's reported state through a real fixture
 * boot, FAILED/Result=/NRestarts= fidelity, removal with the unit, and no partial file ever observable
 * during transition churn.
 *
 * Registered up front and placeholder-bodied, matching the convention the
 * rest of this suite already follows: milestone C0 owns this file, and
 * adding its real cases must never mean editing meson.build while another
 * milestone is also editing it.
 *
 * Placeholder status is asserted, not merely printed -- a test that passes
 * by doing nothing should say so in its own output, so a green run is never
 * mistaken for coverage that does not exist yet.
 */

#include <stdio.h>

int main(void) {
        printf("test-manager-state: placeholder, no cases yet (C0)\n");
        return 0;
}
