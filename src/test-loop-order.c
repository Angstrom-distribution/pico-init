/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Manager-level regression test for the SIGCHLD-before-cgroup-empty
 * dispatch-order property manager.h's EVENT_PRIORITY_* table exists to
 * guarantee. No existing test drives m->event finely enough to make
 * dispatch order observable: manager_loop() only exposes the final state
 * once a whole batch has fully drained, and service_cgroup_empty_event()'s
 * own main_pid_good() guard means a wrong order would still, eventually,
 * settle on the right final answer here -- so the property under test is
 * checked BETWEEN dispatches, not just at the end.
 *
 * sd_event_run(m->event, 0) -- the exact primitive manager_loop() itself
 * calls in a loop -- dispatches at most one source per call. Calling it
 * directly, once per checkpoint, is what makes the ordering observable: with
 * the real priorities, the FIRST call must be the signal source (attributing
 * the real exit status), and only the SECOND call may be the cgroup-empty
 * confirmation. If the priorities were ever swapped, the first call would
 * instead be a no-op cgroup-empty dispatch (service_cgroup_empty_event()
 * returns early while main_pid is still live), and the assertions on
 * s->main_pid/s->result right after that first call would fail.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "manager.h"
#include "sd-event.h"
#include "service.h"
#include "test-util.h"
#include "unit.h"
#include "util.h"

static const char *crash_service =
                "[Service]\n"
                "Type=simple\n"
                "Restart=on-failure\n"
                "RestartSec=50ms\n"
                "ExecStart=/bin/sh -c \"exit 7\"\n";

static const char *steady_service =
                "[Service]\n"
                "Type=simple\n"
                "ExecStart=/bin/sh -c \"exec sleep 30\"\n";

static Manager *manager_for(const char *dir) {
        const char * const path[] = { dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);

        /*
         * Point cgroup_root at a plain (non-cgroupfs) directory so
         * service_ensure_cgroup() degrades gracefully to s->cgroup == NULL
         * (cgroup_v2_new() fails opening the nonexistent cgroup.procs/
         * cgroup.events, exactly like running without privilege -- see
         * test-service.c's own note on this). This test's whole point is
         * the manually-driven manager_enqueue_cgroup_empty() call standing
         * in for a real cgroup.events wakeup; a REAL cgroup2 hierarchy
         * (this host has one) would otherwise also notice the same exit on
         * its own EVENT_PRIORITY_CGROUP_EVENTS source and enqueue a second,
         * redundant, differently-timed copy of the same event.
         */
        ASSERT_EQ_INT(manager_set_cgroup_root(m, dir), 0);

        return m;
}

static Service *load_service(Manager *m, const char *dir, const char *name, const char *contents) {
        Unit *u;

        ASSERT_EQ_INT(test_write_file(dir, name, contents), 0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        u = manager_get_unit(m, name);
        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->type, UNIT_SERVICE);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);

        return SERVICE(u);
}

static void test_sigchld_precedes_cgroup_empty(void) {
        Manager *m;
        Service *s;
        char *dir;
        pid_t child_pid;
        siginfo_t si;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(m, dir, "crash.service", crash_service);
        ASSERT_EQ_INT(service_start(s), 0);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING); /* Type=simple: forked and running already */

        child_pid = s->main_pid;
        ASSERT_TRUE(child_pid > 0);

        /*
         * Block for the real ExecStart= to genuinely exit(7), WITHOUT
         * reaping it, so SIGCHLD is already queued in the kernel by the time
         * this test drives the loop -- not raced against it. WNOWAIT is what
         * makes this safe to do from outside the manager's own signalfd
         * path: kill(pid, 0) would instead report an unreaped zombie as
         * "alive" forever (manager-loop.c's own header note on why a pid is
         * never probed for liveness this way), and plain waitid() without
         * WNOWAIT would reap it here and leave nothing for the signal
         * source to attribute.
         */
        memset(&si, 0, sizeof(si));
        ASSERT_TRUE(waitid(P_PID, child_pid, &si, WEXITED | WNOWAIT) == 0);
        ASSERT_EQ_INT(si.si_pid, child_pid);

        /*
         * Simulate cgroup.events going populated=0 in the very same batch --
         * no real cgroup needed, this calls exactly the manager's own queue
         * mechanism a real cgroup.events wakeup would (manager-loop.c's
         * manager_note_cgroup_event()), regardless of whether s->cgroup
         * exists on this host.
         */
        manager_enqueue_cgroup_empty(m, UNIT(s));

        /*
         * One dispatch. With cgroup_root pointed away from a real
         * cgroupfs (see manager_for()), the only thing pending in this
         * batch besides the signal source is the cgroup-empty defer itself
         * -- so with the real priorities (SIGNALS=-4 < CGROUP_EMPTY=-2)
         * this first dispatch must be the signal source: it drains the
         * whole signalfd and fully attributes the real exit status
         * synchronously, inside this one call.
         */
        ASSERT_EQ_INT(sd_event_run(m->event, 0), 1);
        ASSERT_EQ_INT(s->main_pid, 0);
        ASSERT_EQ_INT(s->main_exit_code, CLD_EXITED);
        ASSERT_EQ_INT(s->main_exit_status, 7);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_EXIT_CODE);
        ASSERT_EQ_INT(s->state, SERVICE_AUTO_RESTART); /* Restart=on-failure already scheduled it */

        /* The cgroup-empty defer is still pending; dispatching it now must
         * be a pure confirmation, not a second, different verdict. (The
         * always-on shutdown-check post source is marked pending by every
         * non-post dispatch, this one included, so a further run() legally
         * returns 1 again for that harmless no-op -- not asserted here.) */
        ASSERT_EQ_INT(sd_event_run(m->event, 0), 1);
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_EXIT_CODE); /* unchanged */
        ASSERT_EQ_INT(s->state, SERVICE_AUTO_RESTART);       /* unchanged */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Dequeue cancellation: emptiness observed and then retracted before the
 * pass produces no cgroup-empty action at all -- manager_dequeue_cgroup_
 * empty()'s whole reason to exist (cgroup.events notifications coalesce).
 */
static void test_cgroup_empty_dequeue_cancels(void) {
        Manager *m;
        Service *s;
        char *dir;
        pid_t pid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        s = load_service(m, dir, "steady.service", steady_service);
        ASSERT_EQ_INT(service_start(s), 0);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        ASSERT_TRUE(s->main_pid > 0);
        pid = s->main_pid;

        manager_enqueue_cgroup_empty(m, UNIT(s));
        manager_dequeue_cgroup_empty(m, UNIT(s));

        /*
         * The defer source is still armed (manager_dequeue_cgroup_empty()
         * only unlinks the queue entry, never disarms the source -- an
         * enabled source finding an empty queue is a harmless, expected
         * no-op per its own callback), so this run() legitimately still
         * dispatches something and returns 1. The property under test is
         * that dispatching it touches nothing: the service is still
         * legitimately running its own ExecStart=, untouched.
         */
        ASSERT_EQ_INT(sd_event_run(m->event, 0), 1);
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        ASSERT_EQ_INT(s->main_pid, pid);

        /* Reaped directly, not through the manager: this test is done with
         * it and does not want a real SIGCHLD racing the assertions above. */
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_sigchld_precedes_cgroup_empty();
        test_cgroup_empty_dequeue_cancels();

        printf("test-loop-order: SIGCHLD-before-cgroup-empty ordering verified\n");
        return 0;
}
