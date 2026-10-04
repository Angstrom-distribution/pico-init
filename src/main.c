/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * PID1 entrypoint. Real init behaviour only kicks in when actually running
 * as PID 1, so the binary still builds, runs and exits cleanly from a normal
 * shell (see src/test-m0.sh); the test suite drives the manager by linking
 * the core library directly rather than through here.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <time.h>
#include <unistd.h>

#include "clock-persist.h"
#include "fstab-mount.h"
#include "fstab.h"
#include "gpt-scan.h"
#include "hostname-setup.h"
#include "machine-id-setup.h"
#include "manager.h"
#include "mount-setup.h"
#include "root-check.h"
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

/*
 * The periodic half of clock-persist.h: the first save two minutes in, after
 * netd has had time to correct the clock from NTP, then every
 * CLOCK_PERSIST_INTERVAL_SEC. A battery pull skips the shutdown save, so this
 * bounds how stale the file can be. Failures (a read-only root) are quiet.
 */
#define CLOCK_PERSIST_FIRST_SAVE_SEC 120

static void clock_save_tick(void *userdata, usec_t now) {
        Manager *m = userdata;
        int r;

        r = clock_persist_save(CLOCK_PERSIST_FILE, (int64_t) time(NULL));
        if (r < 0)
                pico_log(PICO_LOG_DEBUG, "clock save: %s", strerror(-r));

        (void) pico_timer_add(
                        m->timer,
                        usec_add(now, (usec_t) CLOCK_PERSIST_INTERVAL_SEC * USEC_PER_SEC),
                        clock_save_tick,
                        m,
                        NULL);
}

static void clock_save_final(void) {
        int r = clock_persist_save(CLOCK_PERSIST_FILE, (int64_t) time(NULL));

        if (r < 0)
                pico_log(PICO_LOG_WARNING, "clock save: %s", strerror(-r));
}

int main(void) {
        FstabTable fstab = { 0 };
        bool fstab_swap;
        bool first_boot = false;
        Manager *m = NULL;
        int64_t clock_target = 0;
        int clock_restored;
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

        /* Needs the root filesystem mount_setup() left alone (/etc/hostname
         * lives there) and nothing else; best-effort, same as dev_setup. */
        r = hostname_setup();
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "hostname_setup: %s", strerror(-r));

        /*
         * Before anything that timestamps: the RTC on the boards this runs on
         * is dead or reset by a reboot, so the clock starts in 1970 and every
         * early log line, fsck and certificate check would see that. Moved
         * forward from /etc/timestamp, its mtime and the build epoch, never
         * backwards; netd's NTP sync corrects it later.
         */
        clock_restored = clock_persist_restore(
                        CLOCK_PERSIST_FILE, (int64_t) time(NULL), clock_persist_set_realtime, &clock_target);

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

        /* The restore above ran before this process logged anywhere that is kept,
         * so it is reported here. */
        if (clock_restored > 0) {
                char stamp[CLOCK_PERSIST_TEXT_MAX];

                if (clock_persist_format(clock_target, stamp) > 0)
                        pico_log(PICO_LOG_INFO,
                                 "clock moved forward to %.14s UTC from " CLOCK_PERSIST_FILE,
                                 stamp);
        } else if (clock_restored < 0)
                pico_log(PICO_LOG_WARNING, "clock restore: %s", strerror(-clock_restored));

        /*
         * And the console channel itself, opened here rather than lazily on
         * first use so that the greeting is the first thing this init puts on
         * a console -- before any unit starts reporting progress against it.
         * Needs the /dev mount_setup() made above.
         */
        status_enable();
        status_welcome(NULL);

        /*
         * The root filesystem's integrity, before anything is allowed to write
         * to it -- which means before swap discovery and before the first
         * service, not merely before the first service. Needs everything above
         * it: /proc for the mountinfo, /sys for the block topology, /dev for
         * the node to check, and the kmsg sink already installed so what it
         * finds survives into logd's backfill.
         *
         * The reboot is done here rather than inside the check because this is
         * where PID 1's one sync()/reboot() path lives, and because freeze() --
         * the thing that must catch a reboot() that came back -- belongs to
         * this file. root-check.h has the decision table behind the verdict.
         *
         * /etc/fstab is read first, from a root that may still be read-only,
         * because its "/" line decides how the check's remount ends.
         */
        r = fstab_load("/etc/fstab", &fstab);
        if (r < 0 && r != -ENOENT)
                pico_log(PICO_LOG_WARNING, "/etc/fstab: %s", strerror(-r));

        r = pico_root_check(fstab_find(&fstab, "/"));
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "pico_root_check: %s", strerror(-r));
        else if (r == PICO_ROOT_REBOOT) {
                pico_log(PICO_LOG_INFO, "rebooting after the root filesystem check");
                sync();
                reboot(RB_AUTOBOOT);
                freeze("reboot() returned");
        }

        /*
         * The rest of /etc/fstab. After the root check, because mount points
         * may need creating on a root that has only now settled; before swap
         * discovery and before the manager, so that no unit, whatever its
         * ordering, can see an fstab path before it is mounted.
         * fstab-mount.h has the rest of the reasoning.
         */
        r = fstab_pass(&fstab, NULL);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "fstab_pass: %s", strerror(-r));
        else if (r > 0)
                pico_log(PICO_LOG_WARNING, "%d /etc/fstab line(s) not mounted, see %s", r, PICO_FSTAB_RECORD);
        fstab_swap = fstab_has_swap(&fstab);
        fstab_table_done(&fstab);

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
         *
         * Not at all once /etc/fstab names any swap, noauto lines included:
         * upstream's gpt-auto generator stands down on exactly that rule
         * (systemd #6192), since fstab then says what the swap is.
         */
        if (fstab_swap)
                pico_log(PICO_LOG_INFO, "/etc/fstab names swap, not discovering swap partitions");
        else {
                r = dps_scan();
                if (r < 0)
                        pico_log(PICO_LOG_WARNING, "dps_scan: %s", strerror(-r));
                else if (r > 0)
                        pico_log(PICO_LOG_DEBUG, "dps_scan: %d discovered swap partition(s) activated", r);
        }

        /*
         * First-boot detection, same signal upstream's own log_execution_mode()
         * uses (src/core/main.c): /etc/machine-id missing, empty, or literally
         * "uninitialized". After the root check and fstab pass, so the decision
         * is made against the root filesystem's final, settled mount state
         * (writable or genuinely read-only), not whatever it was before either
         * ran; before manager_new(), because manager_startup() below gates
         * preset application on the result (manager_set_first_boot()) and that
         * must be known before a single unit is enabled.
         */
        r = machine_id_setup(NULL, NULL, &first_boot);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "machine_id_setup: %s", strerror(-r));

        r = manager_new(&m);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "manager_new: %s", strerror(-r));
                freeze("could not create the manager");
        }

        manager_set_first_boot(m, first_boot);

        (void) pico_timer_add(
                        m->timer,
                        usec_add(now_monotonic(), (usec_t) CLOCK_PERSIST_FIRST_SAVE_SEC * USEC_PER_SEC),
                        clock_save_tick,
                        m,
                        NULL);

        /* With C-A-D left enabled the kernel reboots at once, unsynced; this
         * makes it send SIGINT, which the manager turns into an orderly
         * reboot (v30 src/manager.c enable_special_signals()). After
         * manager_new(), which has SIGINT blocked into its signalfd. */
        if (m->is_system && reboot(RB_DISABLE_CAD) < 0)
                pico_log(PICO_LOG_WARNING, "failed to enable ctrl-alt-del handling: %s", strerror(errno));

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
                clock_save_final();
                sync();
                reboot(RB_AUTOBOOT);
                freeze("reboot() returned");

        case MANAGER_POWEROFF:
                pico_log(PICO_LOG_INFO, "powering off");
                clock_save_final();
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
