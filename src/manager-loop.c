/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * PID 1's own main loop: an sd_event (src/compat/libsystemd/sd-event.h)
 * embedded as m->event, the same architecture as modern systemd's own PID 1
 * (src/core/manager.c). manager_events_setup() creates every source once,
 * at manager_new() time; manager_loop() is then the thin real-systemd-shaped
 * wrapper `while (m->objective == MANAGER_RUNNING) sd_event_run(...)`.
 *
 * The dispatch ORDER across one epoll batch is still the load-bearing part
 * of this file, not an implementation detail -- now expressed as the
 * EVENT_PRIORITY_* table in manager.h rather than a hand-coded two-pass
 * walk. SIGCHLD carries an exit status; cgroup-empty does not -- the
 * process that happens to empty a cgroup is an arbitrary descendant whose
 * exit code says nothing about the service. So if a cgroup-empty event were
 * acted on before the SIGCHLD that accompanies it, the exit status would be
 * thrown away: Restart=on-failure would see success and a crashed service
 * would be reported as a clean exit.
 *
 * The shim's own dispatch rule is what enforces this: sd_event_wait()
 * marks every ready source pending together, and sd_event_dispatch() then
 * drains pending sources strictly lowest-priority-first, one per call, with
 * a zero-timeout re-poll between dispatches while anything stays pending
 * (sd-event.c). So within one batch:
 *
 *   -20  watchdog feed    -- one WDIOC_KEEPALIVE ioctl + re-arm (manager-
 *                            watchdog.c); carries no unit attribution and no
 *                            exit status, so it has no ordering interaction
 *                            with anything below. Placed first, ahead of
 *                            everything, so no event storm at any other
 *                            priority can ever starve the feed -- see
 *                            manager-watchdog.c's starvation argument.
 *   -10  cgroup.events   -- verified and queued only, never acts
 *    -5  notify           -- sd_notify() datagrams applied here (manager-
 *                            notify.c), before SIGCHLD: service_sigchld_
 *                            event() zeroes s->main_pid, so a service's
 *                            final notify (sent moments before it exits)
 *                            would be unattributable if SIGCHLD ran first
 *                            in the same batch
 *    -5  exec fd          -- a Type=exec service's execve() confirmation
 *                            (service.c), before SIGCHLD for the same
 *                            reason: an exec'd-then-exited process went
 *                            RUNNING before it died
 *    -4  signals         -- SIGCHLD reaped and attributed here, in full,
 *                            before anything at a higher priority runs
 *    -3  sockets / ctrl   -- may enqueue jobs, carry no exit status
 *    -2  cgroup-empty queue drained
 *     0  timers
 *   101  the job run queue
 *   102  shutdown check
 *
 * Two deliberate, strictly-tightening changes from the old hand-coded
 * ordering: signals now always precede sockets/ctrl (the old code dispatched
 * those in arbitrary events[] order); and because the shim re-polls with a
 * zero timeout between dispatches, a SIGCHLD arriving mid-batch is picked up
 * and, at -4 < -2, still beats a pending cgroup-empty -- the old code could
 * only see it on the next batch.
 *
 * CALLBACK CONTRACT: every callback here returns 0, never a negative value,
 * on anything short of "this source must never fire again." The shim
 * disables a source whose callback returns < 0 (event_source_apply_failure()
 * in sd-event.c) -- a transient -EIO from pico_signal_read() must never
 * permanently kill PID 1's signal handling, so every real error is logged
 * and swallowed instead of propagated.
 *
 * RUN-QUEUE CONTRACT: manager_trigger_run_queue() is the one choke point
 * that makes queued-but-not-yet-runnable work eventually run: it is called
 * unconditionally from job_add_to_run_queue(), covering every path that
 * might make some job runnable (job_install(), a completed restart's
 * start-conversion, a finished job's neighbour wakeup, manager_shutdown()'s
 * stop sweep). A future runnability change that does not route through
 * job_add_to_run_queue() will deadlock the boot instead of costing one
 * spin -- the old brute-force "dispatch the run queue every iteration"
 * masked exactly this class of bug, and the new design trades that safety
 * net for not busy-polling once only unrunnable jobs are queued.
 */

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>

#include "cgroups-v2.h"
#include "manager-ctrl.h"
#include "manager.h"
#include "sd-event.h"
#include "service.h"
#include "socket.h"
#include "unit.h"

/*
 * Reap children: peek, attribute, then reap.
 *
 * WNOWAIT first, so the zombie stays unreaped while we look it up. That is
 * what makes the attribution safe -- an unreaped PID cannot be recycled, so it
 * still unambiguously means the child we think it does. Reaping first and then
 * looking up would leave a window in which the number belongs to someone else.
 *
 * Never probe a pid for liveness inside its own SIGCHLD handling: an unreaped
 * zombie is "alive" by both kill(pid, 0) and /proc/<pid>, and treating it as
 * running is a real upstream bug class (systemd e10c9985bb, 62220cf70e).
 *
 * As PID 1 we inherit every orphan on the system, so a pid belonging to no
 * unit is the common case, not an error: it is reaped and ignored, explicitly.
 */
static int manager_dispatch_sigchld(Manager *m) {
        for (;;) {
                siginfo_t si;
                Unit *u;

                si.si_pid = 0;

                if (waitid(P_ALL, 0, &si, WEXITED | WNOHANG | WNOWAIT) < 0) {
                        /* Every error path leaves the loop. Logging and
                         * continuing on a non-ECHILD error spins PID 1
                         * (systemd 8afabc5090). */
                        if (errno != ECHILD && errno != EINTR)
                                pico_log(PICO_LOG_ERR, "waitid: %s", strerror(errno));
                        break;
                }

                if (si.si_pid <= 0)
                        break;

                u = manager_get_unit_by_pid(m, si.si_pid);
                if (u && u->type == UNIT_SERVICE)
                        service_sigchld_event(SERVICE(u), si.si_pid, si.si_code, si.si_status);

                /* now actually reap it */
                if (waitid(P_PID, si.si_pid, &si, WEXITED) < 0 && errno != ECHILD)
                        pico_log(PICO_LOG_WARNING, "waitid(reap %d): %s", (int) si.si_pid, strerror(errno));
        }

        return 0;
}

int manager_dispatch_signal(Manager *m, int signo) {
        if (!m)
                return -EINVAL;

        if (signo == SIGCHLD)
                return manager_dispatch_sigchld(m);

        if (signo == SIGHUP) {
                /* TODO (post-M5): reload unit fragments. */
                pico_log(PICO_LOG_INFO, "SIGHUP received, reload not implemented yet");
                return 0;
        }

        /* ctrl-alt-del */
        if (signo == SIGINT)
                return manager_shutdown(m, MANAGER_REBOOT);

        if (signo == SIGRTMIN + 3 || signo == SIGRTMIN + 4)
                return manager_shutdown(m, MANAGER_POWEROFF);

        if (signo == SIGTERM) {
                /*
                 * As PID 1 there is no such thing as "just exit" -- returning
                 * from main() panics the kernel. systemd's system manager
                 * ignores SIGTERM for the same reason; a real shutdown comes
                 * in as SIGINT or SIGRTMIN+3/+4 above.
                 *
                 * When not PID 1 it stays useful: it is how the test suite
                 * stops the loop.
                 */
                if (m->is_system) {
                        pico_log(PICO_LOG_WARNING,
                                 "SIGTERM ignored: PID 1 cannot exit, use SIGINT or SIGRTMIN+4");
                        return 0;
                }

                return manager_shutdown(m, MANAGER_EXIT);
        }

        return 0;
}

/*
 * A cgroup wakeup: verify and queue, never act.
 *
 * The wakeup itself is unspecific, so emptiness is confirmed by reading
 * `populated`. A queued event must also stay cancellable -- cgroup.events
 * notifications coalesce, so a cgroup that has become populated again since
 * being queued must come back off the queue rather than be acted on.
 */
static void manager_note_cgroup_event(Manager *m, struct pico_cgroup *cg) {
        Unit *u = cg->userdata;
        int r;

        if (!u)
                return;

        r = cgroup_v2_is_empty(cg);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "%s: cgroup.events: %s", u->id, strerror(-r));
                return;
        }

        if (r > 0)
                manager_enqueue_cgroup_empty(m, u);
        else
                manager_dequeue_cgroup_empty(m, u);
}

/* io callback for one service's cgroup.events fd (EVENT_PRIORITY_CGROUP_EVENTS).
 * Declared in cgroups-v2.h, defined here: cgroups-v2.c itself must stay
 * unaware of Unit/Manager (its own header says why), so cgroup_v2_monitor()
 * registers this by name and reaches the Manager only via cg->userdata. */
int manager_dispatch_cgroup_events(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        struct pico_cgroup *cg = userdata;
        Unit *u;

        (void) s;
        (void) fd;
        (void) revents;

        u = cg->userdata;
        if (!u || !u->manager)
                return 0;

        manager_note_cgroup_event(u->manager, cg);
        return 0;
}

/* io callback for the signalfd (EVENT_PRIORITY_SIGNALS): drains it to
 * -EAGAIN in one dispatch, so every waitid() result in the current batch is
 * consumed and attributed before anything at a lower priority (cgroup-empty,
 * the run queue) can act on it. */
static int manager_dispatch_signal_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;

        (void) s;
        (void) fd;
        (void) revents;

        for (;;) {
                int signo, r;

                r = pico_signal_read(m->signal, &signo);
                if (r == -EAGAIN)
                        return 0;
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING, "signalfd read: %s", strerror(-r));
                        return 0;
                }

                r = manager_dispatch_signal(m, signo);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING, "signal %d dispatch: %s", signo, strerror(-r));
        }
}

/* io callback for PicoTimer's timerfd (EVENT_PRIORITY_PICO_TIMER). */
static int manager_dispatch_timer_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        int r;

        (void) s;
        (void) fd;
        (void) revents;

        r = pico_timer_dispatch(m->timer);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "timer dispatch: %s", strerror(-r));

        return 0;
}

/* defer callback for the run queue (EVENT_PRIORITY_RUN_QUEUE), ONESHOT-armed
 * by manager_trigger_run_queue(). manager_dispatch_run_queue() already loops
 * until nothing is runnable, so one dispatch drains everything that can run
 * right now. */
static int manager_on_run_queue(sd_event_source *s, void *userdata) {
        Manager *m = userdata;

        (void) s;

        manager_dispatch_run_queue(m);
        return 0;
}

/*
 * defer callback for the cgroup-empty queue (EVENT_PRIORITY_CGROUP_EMPTY),
 * ONESHOT-armed by manager_enqueue_cgroup_empty(). Pops exactly ONE unit and
 * re-arms itself if more remain, the same shape real systemd's own
 * manager_dispatch_cgroup_empty_queue() dispatch takes (quarry
 * src/core/cgroup.c) -- manager_dispatch_cgroup_empty_queue() in manager.c
 * still drains the whole queue in one call and is kept for direct test use,
 * but is not what this source calls.
 */
static int manager_on_cgroup_empty(sd_event_source *s, void *userdata) {
        Manager *m = userdata;
        Unit *u;

        u = m->cgroup_empty_queue;
        if (!u)
                return 0; /* dequeued after being marked pending but before this ran */

        m->cgroup_empty_queue = u->cgroup_empty_queue_next;
        u->cgroup_empty_queue_next = NULL;
        u->in_cgroup_empty_queue = false;

        if (m->cgroup_empty_queue)
                sd_event_source_set_enabled(s, SD_EVENT_ONESHOT); /* more queued: re-arm */

        if (u->type == UNIT_SERVICE)
                service_cgroup_empty_event(SERVICE(u));

        return 0;
}

/* post callback (EVENT_PRIORITY_SHUTDOWN_CHECK), always ON: the shim marks
 * every enabled post source pending after any non-post dispatch, so this
 * runs after the run-queue defer (101 < 102) -- a shutdown only takes effect
 * once its stop jobs have actually run, which is what makes it orderly
 * rather than immediate. */
static int manager_on_shutdown_check(sd_event_source *s, void *userdata) {
        Manager *m = userdata;

        (void) s;

        if (manager_shutdown_finished(m))
                m->objective = m->pending_objective;

        return 0;
}

/* time callback for the shutdown deadline: the callback itself does nothing
 * -- dispatching it at all is what re-marks the shutdown-check post source
 * pending, which is what then observes the passed deadline. */
static int manager_on_shutdown_deadline(sd_event_source *s, uint64_t usec, void *userdata) {
        (void) s;
        (void) usec;
        (void) userdata;
        return 0;
}

void manager_arm_shutdown_deadline(Manager *m) {
        int r;

        if (!m || !m->event)
                return;

        r = sd_event_add_time(
                        m->event,
                        &m->shutdown_deadline_source,
                        CLOCK_MONOTONIC,
                        m->shutdown_deadline,
                        0,
                        manager_on_shutdown_deadline,
                        m);
        if (r < 0) {
                /* No deadline wakeup at all beats an unbounded wait: adopt
                 * the objective directly rather than risk a shutdown that
                 * never notices its own timeout passed. */
                pico_log(PICO_LOG_ERR,
                         "failed to arm the shutdown deadline timer: %s, adopting the objective now",
                         strerror(-r));
                m->objective = m->pending_objective;
        }
}

void manager_trigger_run_queue(Manager *m) {
        if (!m || !m->run_queue_source)
                return;

        sd_event_source_set_enabled(m->run_queue_source, SD_EVENT_ONESHOT);
}

int manager_events_setup(Manager *m) {
        int r;

        if (!m || !m->event || !m->signal || !m->timer)
                return -EINVAL;

        r = sd_event_add_io(
                        m->event,
                        &m->signal_source,
                        pico_signal_fd(m->signal),
                        EPOLLIN,
                        manager_dispatch_signal_io,
                        m);
        if (r < 0)
                return r;
        sd_event_source_set_priority(m->signal_source, EVENT_PRIORITY_SIGNALS);

        r = sd_event_add_io(
                        m->event,
                        &m->timer_source,
                        pico_timer_fd(m->timer),
                        EPOLLIN,
                        manager_dispatch_timer_io,
                        m);
        if (r < 0)
                return r;
        sd_event_source_set_priority(m->timer_source, EVENT_PRIORITY_PICO_TIMER);

        /* Both defer sources start OFF: run_queue_source is armed ONESHOT by
         * manager_trigger_run_queue(), cgroup_empty_source by
         * manager_enqueue_cgroup_empty() -- see manager.c. */
        r = sd_event_add_defer(m->event, &m->run_queue_source, manager_on_run_queue, m);
        if (r < 0)
                return r;
        sd_event_source_set_priority(m->run_queue_source, EVENT_PRIORITY_RUN_QUEUE);
        sd_event_source_set_enabled(m->run_queue_source, SD_EVENT_OFF);

        r = sd_event_add_defer(m->event, &m->cgroup_empty_source, manager_on_cgroup_empty, m);
        if (r < 0)
                return r;
        sd_event_source_set_priority(m->cgroup_empty_source, EVENT_PRIORITY_CGROUP_EMPTY);
        sd_event_source_set_enabled(m->cgroup_empty_source, SD_EVENT_OFF);

        r = sd_event_add_post(m->event, &m->shutdown_check_source, manager_on_shutdown_check, m);
        if (r < 0)
                return r;
        sd_event_source_set_priority(m->shutdown_check_source, EVENT_PRIORITY_SHUTDOWN_CHECK);

        return 0;
}

int manager_loop(Manager *m) {
        int r;

        if (!m)
                return -EINVAL;

        /*
         * One pre-loop check for the enter-the-loop-with-a-pending-empty-
         * shutdown case: a post source only becomes pending after some other
         * dispatch, so a shutdown requested with an already-empty run queue
         * (the direct API/test path, rather than one arriving through a
         * signal or ctrl request already inside the loop) would otherwise
         * never get adopted.
         */
        if (manager_shutdown_finished(m))
                m->objective = m->pending_objective;

        while (m->objective == MANAGER_RUNNING) {
                r = sd_event_run(m->event, UINT64_MAX);
                if (r < 0)
                        return r;
        }

        return (int) m->objective;
}
