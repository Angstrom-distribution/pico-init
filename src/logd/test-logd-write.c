/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The export-format writer and ring (plan §3, J0): golden-byte fixtures including binary-safe fields, rotation
 * preserving byte-exact record boundaries, and a round trip through real systemd-journal-remote + journalctl --file.
 *
 * Registered up front and placeholder-bodied, matching the convention the
 * rest of this suite already follows: milestone J0 owns this file, and
 * adding its real cases must never mean editing meson.build while another
 * milestone is also editing it.
 *
 * Placeholder status is asserted, not merely printed -- a test that passes
 * by doing nothing should say so in its own output, so a green run is never
 * mistaken for coverage that does not exist yet.
 */

#include <stdio.h>

int main(void) {
        printf("test-logd-write: placeholder, no cases yet (J0)\n");
        return 0;
}
