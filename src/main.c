/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * PID1 entrypoint. Real init behaviour only kicks in when actually running
 * as PID 1, so the binary still builds, runs and exits cleanly from a normal
 * shell (see src/test-m0.sh); the test suite drives the manager by linking
 * the core library directly rather than through here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <unistd.h>

#include "manager.h"
#include "mount-setup.h"
#include "util.h"

/*
 * The one thing PID 1 must never do is return. The kernel panics on it
 * ("Attempted to kill init"), which turns any ordinary failure -- a manager
 * that would not allocate, an event loop that errored, a reboot() that came
 * back -- into an unrecoverable panic with nothing readable on the console.
 * Freezing instead keeps the log on screen and leaves the machine in a state
 * someone can power-cycle deliberately.
 */
static _Noreturn void freeze(const char *reason) {
        pico_log(PICO_LOG_ERR, "%s -- freezing, as PID 1 must not return", reason);

        for (;;)
                pause();
}

int main(void) {
        Manager *m = NULL;
        int objective;
        int r;

        if (getpid() != 1) {
                puts("pico-init: not running as PID 1, exiting");
                return EXIT_SUCCESS;
        }

        /*
         * Before anything else. The kernel mounts the root filesystem and
         * nothing more, so /proc, /sys, /run and /sys/fs/cgroup do not exist
         * yet -- and this manager's own cgroup supervision needs the last of
         * those to work at all. Doing it after manager_new() would start the
         * first services into a system with no /proc.
         */
        r = mount_setup();
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "mount_setup: %s", strerror(-r));
                freeze("could not mount the API filesystems");
        }

        /* Needs the /proc that mount_setup() just made, and must land before
         * the first service exists to write into a log socket. */
        sysctl_setup();

        r = manager_new(&m);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "manager_new: %s", strerror(-r));
                freeze("could not create the manager");
        }

        /*
         * A failed startup is not fatal. A board that cannot reach
         * default.target -- a missing unit, a bad fragment -- is far more
         * useful sitting in the event loop with a console than dead, because
         * that is exactly the state someone needs to debug it from.
         */
        r = manager_startup(m, NULL);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "startup failed: %s, entering the event loop anyway", strerror(-r));

        objective = manager_loop(m);
        m = manager_free(m);

        if (objective < 0) {
                pico_log(PICO_LOG_ERR, "manager_loop: %s", strerror(-objective));
                freeze("event loop failed");
        }

        switch ((ManagerObjective) objective) {
        case MANAGER_REBOOT:
                pico_log(PICO_LOG_INFO, "rebooting");
                sync();
                reboot(RB_AUTOBOOT);
                freeze("reboot() returned");

        case MANAGER_POWEROFF:
                pico_log(PICO_LOG_INFO, "powering off");
                sync();
                reboot(RB_POWER_OFF);
                freeze("reboot(RB_POWER_OFF) returned");

        case MANAGER_EXIT:
        default:
                /* MANAGER_EXIT is only legal for a non-PID-1 manager, and we
                 * established above that we are PID 1. */
                freeze("event loop asked to exit, which PID 1 cannot do");
        }
}
