/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * picoctl -- the on-device systemctl equivalent (plan §1.7), the systemctl
 * half of the owner's on-device-tooling requirement.
 *
 * Scaffolding: milestones C1 and C2 own this file.
 *
 * It ships in the main pico-init package rather than as its own: it is the
 * init's own tool, not an optional daemon like netd or logd.
 *
 * The split it implements is the one every shipped D-Bus-free supervisor
 * converged on -- status is files, control is one tiny channel. Read verbs
 * (status/list-units/is-active/is-failed/show) and the pure-symlink verbs
 * (enable/disable/is-enabled/preset) touch no IPC at all; only
 * start/stop/restart/reset-failed go over the control socket.
 */

#include <stdio.h>

int main(int argc, char *argv[]) {
        (void) argc;
        (void) argv;

        fputs("picoctl: not implemented yet (plan §1.7, milestones C1/C2)\n", stderr);
        return 1;
}
