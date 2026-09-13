/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * A Type=notify service for test-service.c: sleeps <delay-ms>, sends
 * READY=1 through the real sd_notify() (libsystemd.so.0, $NOTIFY_SOCKET as
 * injected by service-exec.c), then waits for SIGTERM. Exits 2 if
 * sd_notify() reports no socket, so a test cannot pass on an injection
 * regression by accident. Not a test itself; test-service.c execs it.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "sd-daemon.h"

int main(int argc, char **argv) {
        long delay_ms = argc > 1 ? strtol(argv[1], NULL, 10) : 0;
        struct timespec ts = { .tv_sec = delay_ms / 1000, .tv_nsec = (delay_ms % 1000) * 1000000L };
        int r;

        nanosleep(&ts, NULL);

        r = sd_notify(1, "READY=1");
        if (r <= 0) {
                fprintf(stderr, "test-notify-helper: sd_notify: %d\n", r);
                return 2;
        }

        for (;;)
                pause();
}
