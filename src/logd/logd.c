/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * logd -- pico-init's log daemon (plan §3), main().
 *
 * Scaffolding: milestone J1 owns this file and lands the real daemon.
 *
 * logd is a supervised Type=simple service in its own cgroup, restarted on
 * failure -- the netd model, for the same reasons: PID 1 must never block on
 * log I/O, parsing attacker-influenceable client bytes stays out of PID 1,
 * and a logd crash must be cheap.
 *
 * The property that makes a crash cheap is fd ownership, not an fd store:
 * PID 1 binds and holds the datagram sockets via logd.socket, so they outlive
 * logd, datagrams queue in the receive buffer across a crash and restart, and
 * the respawned logd gets the same fds back through LISTEN_FDS and drains the
 * backlog. Every service's connected stdout fd stays valid throughout.
 */

#include <stdio.h>

int main(int argc, char *argv[]) {
        (void) argc;
        (void) argv;

        fputs("logd: not implemented yet (plan §3, milestone J1)\n", stderr);
        return 1;
}
