/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The single epoll loop.
 *
 * The dispatch ORDER within one wakeup batch is the load-bearing part of this
 * file, not an implementation detail. SIGCHLD carries an exit status;
 * cgroup-empty does not -- the process that happens to empty a cgroup is an
 * arbitrary descendant whose exit code says nothing about the service. So if
 * a cgroup-empty event is acted on before the SIGCHLD that accompanies it, the
 * exit status is thrown away: Restart=on-failure sees success and a crashed
 * service is reported as a clean exit.
 *
 * Hence the fixed order below, which mirrors systemd's own event priorities:
 *
 *   1. cgroup wakeups   -- verified only, never acted on
 *   2. signals          -- SIGCHLD reaped and attributed here
 *   3. cgroup-empty queue drained
 *   4. timers
 *   5. the job run queue
 *
 * Step 1 never calls into a service. A cgroup.events wakeup is unspecific and
 * fires for several reasons, so it is re-verified by reading `populated` and
 * merely queued; step 3 is where anything actually happens, by which time
 * every waitid() result for the batch has already been consumed.
 */

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/wait.h>

#include "cgroups-v2.h"
#include "manager-ctrl.h"
#include "manager.h"
#include "service.h"
#include "socket.h"
#include "unit.h"

#define MANAGER_MAX_EVENTS 16

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

static int manager_dispatch_epoll_event(Manager *m, struct pico_epoll_tag *tag, bool cgroup_pass) {
        switch (tag->source) {
        case PICO_EPOLL_CGROUP:
                if (cgroup_pass)
                        manager_note_cgroup_event(m, (struct pico_cgroup *) tag);
                return 0;

        case PICO_EPOLL_SIGNAL:
                if (cgroup_pass)
                        return 0;

                for (;;) {
                        int signo;
                        int r = pico_signal_read(m->signal, &signo);

                        if (r == -EAGAIN)
                                return 0;
                        if (r < 0)
                                return r;

                        r = manager_dispatch_signal(m, signo);
                        if (r < 0)
                                return r;
                }

        case PICO_EPOLL_TIMER:
                /* drained after the queue, in manager_loop() */
                return 0;

        /*
         * Both of the arms below run in pass 2 only, alongside signals and
         * for the same reason the cgroup arm does not: neither carries an
         * exit status, and both may enqueue a job. Queueing work during the
         * cgroup-verification pass would let a job run before the SIGCHLDs in
         * the same batch had been reaped.
         */
        case PICO_EPOLL_SOCKET:
                if (cgroup_pass)
                        return 0;

                return socket_dispatch_io(m, tag);

        case PICO_EPOLL_CONTROL:
                if (cgroup_pass)
                        return 0;

                return manager_ctrl_dispatch(m, tag);
        }

        return 0;
}

int manager_loop(Manager *m) {
        struct epoll_event events[MANAGER_MAX_EVENTS];

        if (!m)
                return -EINVAL;

        while (m->objective == MANAGER_RUNNING) {
                bool timer_ready = false;
                int timeout;
                int n, i;

                /*
                 * Dispatch BEFORE waiting, not only after.
                 *
                 * Queued work is not an event: nothing wakes epoll to announce
                 * that a job has become runnable. Waiting first means the boot
                 * transaction sits in the run queue while PID 1 blocks
                 * indefinitely for an event that could only be produced by
                 * starting it -- a hang on real hardware. This is why the
                 * dispatch is at the top of the loop as well as the bottom.
                 */
                manager_dispatch_run_queue(m);

                if (manager_shutdown_finished(m)) {
                        m->objective = m->pending_objective;
                        break;
                }

                /*
                 * Never block while runnable work remains. Poll while a
                 * shutdown is pending, because its drain deadline is
                 * wall-clock and a wedged unit produces no events to wake us.
                 * Otherwise block until something actually happens.
                 */
                if (m->run_queue)
                        timeout = 0;
                else if (m->pending_objective != MANAGER_RUNNING)
                        timeout = 250;
                else
                        timeout = -1;

                n = epoll_wait(m->epoll_fd, events, MANAGER_MAX_EVENTS, timeout);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }

                /* pass 1: cgroup wakeups, verified and queued only */
                for (i = 0; i < n; i++) {
                        struct pico_epoll_tag *tag = events[i].data.ptr;

                        if (tag->source == PICO_EPOLL_TIMER)
                                timer_ready = true;

                        manager_dispatch_epoll_event(m, tag, true);
                }

                /* pass 2: signals, so every waitid() result is consumed before
                 * any cgroup-empty event is acted on */
                for (i = 0; i < n; i++) {
                        struct pico_epoll_tag *tag = events[i].data.ptr;
                        int r = manager_dispatch_epoll_event(m, tag, false);

                        if (r < 0)
                                pico_log(PICO_LOG_WARNING, "event on fd %d: %s", tag->fd, strerror(-r));
                }

                /* 3: now it is safe to act on emptiness */
                manager_dispatch_cgroup_empty_queue(m);

                /* 4: timers */
                if (timer_ready) {
                        int r = pico_timer_dispatch(m->timer);

                        if (r < 0)
                                pico_log(PICO_LOG_WARNING, "timer dispatch: %s", strerror(-r));
                }

                /* 5: and only then start whatever became runnable */
                manager_dispatch_run_queue(m);

                /*
                 * A shutdown only takes effect once its stop jobs have
                 * actually run. Checking here, after the run queue has been
                 * dispatched, is what makes it orderly rather than immediate.
                 */
                if (manager_shutdown_finished(m))
                        m->objective = m->pending_objective;
        }

        return (int) m->objective;
}
