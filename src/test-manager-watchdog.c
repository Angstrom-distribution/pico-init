/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The hardware watchdog feeder (manager-watchdog.c): everything provable
 * without real watchdog hardware -- graceful degrade with no device (the
 * exact path this container and every qemu dev boot takes), a rejected
 * non-chardev path, the timeout/4 interval contract, event-priority
 * placement, and the single most important correctness property, that the
 * feed cannot be silently starved by a higher-priority-band event storm.
 *
 * NOT covered here, and not coverable without real hardware: a successful
 * WDIOC_GETSUPPORT/SETTIMEOUT/GETTIMEOUT/SETOPTIONS/KEEPALIVE sequence, a
 * driver clamping the requested timeout, EBUSY contention, MAGICCLOSE/
 * nowayout close behavior, or an actual reset when feeding stops. Those are
 * argued correct by inspection against the real uapi header and upstream's
 * shape; see manager-watchdog.h's file comment for the open dependency.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "manager-watchdog.h"
#include "manager.h"
#include "sd-event.h"
#include "test-util.h"
#include "util.h"

static void test_setup_enoent_nonfatal(void) {
        Manager *m;
        char *dir, *unitdir;
        char bogus[PATH_MAX];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(bogus, sizeof(bogus), "%s/no-such-watchdog-node", dir);

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_EQ_INT(manager_set_watchdog_device(m, bogus), 0);

        ASSERT_EQ_INT(manager_watchdog_setup(m), -ENOENT);
        ASSERT_TRUE(m->watchdog == NULL);
        ASSERT_EQ_INT(manager_watchdog_armed(m), false);
        ASSERT_EQ_INT(manager_watchdog_ping_interval(m), 0);

        manager_free(m);

        /* Same bogus device, but through the real boot path: a full
         * manager_startup() must still succeed, proving the non-fatal
         * policy end to end rather than just at manager_watchdog_setup()'s
         * own return value. */
        unitdir = test_tmpdir_new();
        ASSERT_TRUE(unitdir != NULL);
        ASSERT_EQ_INT(test_write_file(unitdir, "default.target", "[Unit]\nDescription=Default\n"), 0);

        ASSERT_EQ_INT(manager_new(&m), 0);
        {
                const char * const up[] = { unitdir, NULL };
                const char * const pd[] = { NULL };

                ASSERT_EQ_INT(manager_set_unit_path(m, up), 0);
                ASSERT_EQ_INT(manager_set_preset_path(m, pd), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(m, dir), 0);
        ASSERT_EQ_INT(manager_set_watchdog_device(m, bogus), 0);

        ASSERT_EQ_INT(manager_startup(m, NULL), 0);
        ASSERT_TRUE(m->watchdog == NULL);

        manager_free(m);
        test_rm_rf(unitdir);
        test_rm_rf(dir);
        free(unitdir);
        free(dir);
}

/* A misconfigured path pointing at a regular file must never "succeed"
 * while every later ioctl would silently fail -- the S_ISCHR guard catches
 * it at open time instead. */
static void test_setup_rejects_non_chardev(void) {
        Manager *m;
        char *dir;
        char path[PATH_MAX];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "not-a-watchdog", "x"), 0);
        snprintf(path, sizeof(path), "%s/not-a-watchdog", dir);

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_EQ_INT(manager_set_watchdog_device(m, path), 0);

        ASSERT_EQ_INT(manager_watchdog_setup(m), -ENODEV);
        ASSERT_TRUE(m->watchdog == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* Locks the timeout/4 contract the design's missed-feed-margin argument
 * depends on: three consecutively missed feed opportunities of margin
 * before the hardware fires. */
static void test_interval_from_timeout(void) {
        ASSERT_EQ_INT(manager_watchdog_interval_from_timeout(30 * USEC_PER_SEC), 7500 * USEC_PER_MSEC);
        ASSERT_EQ_INT(manager_watchdog_interval_from_timeout(1 * USEC_PER_SEC), 250 * USEC_PER_MSEC);
        ASSERT_EQ_INT(manager_watchdog_interval_from_timeout(60 * USEC_PER_SEC), 15000 * USEC_PER_MSEC);
}

static void test_feed_fires_and_rearms(void) {
        Manager *m;
        sd_event_source *src;
        int64_t prio;
        int iterations;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_EQ_INT(manager_watchdog_debug_arm(m, 10 * USEC_PER_MSEC), 0);
        ASSERT_EQ_INT(manager_watchdog_armed(m), true);

        src = manager_watchdog_debug_source(m);
        ASSERT_TRUE(src != NULL);
        ASSERT_EQ_INT(sd_event_source_get_priority(src, &prio), 0);
        ASSERT_EQ_INT(prio, EVENT_PRIORITY_WATCHDOG);
        ASSERT_TRUE(prio < EVENT_PRIORITY_CGROUP_EVENTS);

        /* Block until due rather than busy-polling: each call waits for
         * the next real timerfd expiry, so a bounded iteration count is
         * also a bounded wall-clock bound (a few times the 10ms interval,
         * plus slack for the harmless always-on shutdown-check post
         * source interleaving between fires). */
        for (iterations = 0; iterations < 200 && manager_watchdog_debug_n_pings(m) < 3; iterations++)
                ASSERT_TRUE(sd_event_run(m->event, 200 * USEC_PER_MSEC) >= 0);

        ASSERT_TRUE(manager_watchdog_debug_n_pings(m) >= 3);

        manager_free(m);
}

/*
 * The single most important property: a due -20 watchdog timer is picked up
 * by the zero-timeout re-poll and dispatched ahead of a perpetually-pending
 * higher-priority-band storm (EVENT_PRIORITY_NOTIFY, the notify-flood
 * shape), rather than being starved behind it for as long as the storm
 * keeps re-arming.
 */
struct storm_ctx {
        size_t n_dispatched;
};

static int storm_cb(sd_event_source *s, void *userdata) {
        struct storm_ctx *ctx = userdata;

        ctx->n_dispatched++;
        sd_event_source_set_enabled(s, SD_EVENT_ONESHOT); /* re-arm: a perpetual, never-idle storm */
        return 0;
}

static void test_feed_not_starved_by_event_storm(void) {
        Manager *m;
        sd_event_source *storm_source = NULL;
        struct storm_ctx ctx = { 0 };
        usec_t deadline;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_EQ_INT(manager_watchdog_debug_arm(m, 20 * USEC_PER_MSEC), 0);

        ASSERT_EQ_INT(sd_event_add_defer(m->event, &storm_source, storm_cb, &ctx), 0);
        sd_event_source_set_priority(storm_source, EVENT_PRIORITY_NOTIFY);
        sd_event_source_set_enabled(storm_source, SD_EVENT_ONESHOT);

        /* One dispatch at a time, zero timeout -- the exact primitive
         * manager_loop() itself calls in a loop -- for a generous wall-
         * clock window. Bounds chosen loose against loaded-CI flakiness;
         * the assertions below are at-least, never exact. */
        deadline = usec_add(now_monotonic(), 150 * USEC_PER_MSEC);
        while (now_monotonic() < deadline)
                ASSERT_TRUE(sd_event_run(m->event, 0) >= 0);

        ASSERT_TRUE(ctx.n_dispatched >= 20);                 /* the storm was real */
        ASSERT_TRUE(manager_watchdog_debug_n_pings(m) >= 2); /* and the feed still advanced through it */

        sd_event_source_unref(storm_source);
        manager_free(m);
}

static void test_done_idempotent_teardown(void) {
        Manager *m;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_EQ_INT(manager_watchdog_debug_arm(m, 10 * USEC_PER_MSEC), 0);

        manager_watchdog_done(m);
        ASSERT_TRUE(m->watchdog == NULL);
        ASSERT_EQ_INT(manager_watchdog_armed(m), false);

        manager_watchdog_done(m); /* idempotent no-op */

        manager_free(m); /* clean after done() already ran */
}

int main(void) {
        test_setup_enoent_nonfatal();
        test_setup_rejects_non_chardev();
        test_interval_from_timeout();
        test_feed_fires_and_rearms();
        test_feed_not_starved_by_event_storm();
        test_done_idempotent_teardown();

        printf("test-manager-watchdog: graceful-degrade and cannot-be-starved properties verified\n");
        return 0;
}
