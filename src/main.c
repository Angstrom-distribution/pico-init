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

#include "gpt-scan.h"
#include "manager.h"
#include "mount-setup.h"
#include "status.h"
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

        /*
         * Immediately after, and for the same reason: devtmpfs gives /dev its
         * device nodes and nothing gives it /dev/fd or /dev/std{in,out,err},
         * so without this every `foo >/dev/stderr` and every /dev/fd/N idiom
         * in any script the image runs fails. Needs the /proc mount_setup()
         * just made, both because the links point into it and because the
         * /dev/core check reads it.
         *
         * Not fatal. A board missing /dev/stdout is worth a warning, never a
         * refusal to boot.
         */
        r = dev_setup(NULL);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "dev_setup: %s", strerror(-r));
        else
                pico_log(PICO_LOG_DEBUG, "dev_setup: %d /dev symlinks in place", r);

        /* Needs the /proc that mount_setup() just made, and must land before
         * the first service exists to write into a log socket. */
        sysctl_setup();

        /*
         * PID 1's own output has nowhere else to go: it is not a supervised
         * service, so nothing connects its stdout to logd, and the console it
         * writes to otherwise is captured nowhere. /dev/kmsg is -- and a fresh
         * reader sees the whole ring, so a logd started later in the boot
         * backfills every line pico-init emitted before logd existed, with no
         * persistent state involved.
         *
         * Deliberately PID 1 only, not every daemon. netd and logd are
         * supervised services whose stdout service-exec.c already connects
         * straight to logd, which is strictly better: those records arrive
         * with _TRANSPORT=stdout and a real _SYSTEMD_UNIT resolved from
         * kernel-verified credentials, where a kmsg record has neither.
         * Redirecting them would trade correct attribution for none, and in
         * logd's case would have it ingesting its own output as kernel
         * records.
         */
        pico_log_to_kmsg();

        /*
         * Who is running this machine, before it does anything to it. A log
         * record rather than console status output, and deliberately so:
         * systemd's own version banner is log_info("systemd " GIT_VERSION
         * " running in %ssystem mode (%s)") in src/core/main.c, for the same
         * reason -- this is the line someone reads back out of a log to find
         * out what was actually running, which is exactly what the prefix,
         * the level and the kmsg mirror are for. status.h has the other half
         * of that split.
         */
        pico_log(PICO_LOG_INFO, "pico-init " PICO_INIT_VERSION_STRING " running as PID 1");

        /*
         * And the console channel itself, opened here rather than lazily on
         * first use so that the greeting is the first thing this init puts on
         * a console -- before any unit starts reporting progress against it.
         * Needs the /dev mount_setup() made above.
         */
        status_enable();
        status_welcome(NULL);

        /*
         * Swap, off the partition table alone. Placed here for three separate
         * reasons rather than by taste: it needs the /proc and /sys that
         * mount_setup() mounted and the /dev nodes devtmpfs put there, it wants
         * the kmsg sink already installed so its record survives into logd's
         * backfill, and swap should exist before the first service does -- on a
         * 64 MiB machine the units started moments from now are exactly the
         * ones that would benefit.
         *
         * Before manager_new() and not a unit: gpt-scan.h says why the whole
         * mechanism is a function call.
         */
        r = dps_scan();
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "dps_scan: %s", strerror(-r));
        else if (r > 0)
                pico_log(PICO_LOG_DEBUG, "dps_scan: %d discovered swap partition(s) activated", r);

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
