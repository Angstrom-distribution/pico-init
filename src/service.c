/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Service units: the state machine. service-exec.c has the fork/exec + fd/
 * cgroup child-side setup. Quarried from systemd's ~2011-era src/service.c
 * (tag v30, commit 501c92c, copyright 2010 Lennart Poettering,
 * GPL-2.0-or-later), reduced to the two-state-machine shape pico-init needs
 * (Type=simple/oneshot, no ExecStop=/ExecStopPost=/notify/watchdog/D-Bus),
 * with a full history review (v30 -> 2026, ~2299 commits enumerated, ~300
 * read in full) applied on top so the reduction does not re-ship bugs
 * upstream has since fixed. No CVE has ever been assigned against
 * service.c/execute.c in 15 years; the real risk here is state-machine
 * errors and races, not memory safety, so the ordering rules below are the
 * security-critical part of this file, not an afterthought.
 *
 * Backports (commit hashes from github.com/systemd/systemd), each in the
 * function it applies to:
 *
 *  - 92c1622e14 / 36c16a7cdd -- TimeoutStartSec=/TimeoutStopSec=0 means
 *    "never time out", the opposite of RestartSec=0 ("restart immediately").
 *    The unit-parse.c side of this fix is documented there; this file's
 *    side is service_arm_timeout() skipping pico_timer_add() entirely on
 *    USEC_INFINITY, and service_enter_restart() using restart_usec verbatim
 *    (0 produces a deadline of "now", not "never").
 *  - 1f0958f640 / e51237253e / f42806df7d -- exit-status-to-result mapping
 *    splits two ways: CLD_DUMPED is never clean for any signal, and the
 *    SIGHUP/SIGINT/SIGTERM/SIGPIPE amnesty applies only to a long-running
 *    daemon's own exit, never to a oneshot/control command's. v30 amnestied
 *    both alike; a Type=oneshot boot-plumbing unit killed at its start
 *    timeout would have reported success under that rule and boot would
 *    have proceeded as if it had worked. See pico_is_clean_exit() below.
 *  - a0fef983ab -- s->result is the *first* failure, not the last: read the
 *    guarded assignment in service_sigchld_event() and its callers.
 *  - ec5b1452ac -- service_enter_running() checks s->result before
 *    service_good() before remain_after_exit, in that order; the reverse
 *    order lets RemainAfterExit=yes silently swallow a failed main process
 *    and Restart=on-failure never fires.
 *  - 51894d706f / 3c751b1bfa -- main_pid_good()/control_pid_good() are
 *    tri-state (0 known-dead, >0 alive, <0 unknown), not bool.
 *  - 4b9397474f .. 90f4c0473a -- start-rate limiting. v30 already had this;
 *    pico-init dropping it was a quarrying regression, not a deferred
 *    feature -- see service_start_limit_check().
 *  - a509f0e631 / 0c7f15b3a9 / c972880640 / 2e9d6c1251 -- the restart
 *    decision: service_enter_dead() always visits DEAD/FAILED before ever
 *    considering AUTO_RESTART; a pending stop job vetoes a restart outright;
 *    a start while AUTO_RESTART is pending is "proceed now", not a failure;
 *    a stop from AUTO_RESTART goes through service_enter_dead(), never a
 *    raw state assignment.
 *  - 69339ae9f7 / 29500cf8c4 / 8688a389ca -- service_verify(), called from
 *    unit-parse.c once a fragment has finished parsing.
 *  - 1378a3b5a1 -- systemd shipped a state-to-string table missing an
 *    enumerator twice; service_state_table[] below is checked for density.
 *  - 8f53a7b8ea -- pre-existing cgroup members are killed before both
 *    SERVICE_START_PRE and SERVICE_EXEC_START, not just once.
 *  - f52e9ed62b -- a cgroup-empty event during START_PRE/EXEC_START is
 *    terminal for that start attempt, never "start completed".
 *  - abaf5edd08 -- the reason service_cgroup_empty_event() never invents an
 *    exit status: systemd reverted a whole feature over this. See the
 *    SIGCHLD-vs-cgroup-empty ordering note above service_sigchld_event().
 *  - v30's own sigchld_code_to_string() and its log_full() severity split,
 *    both dropped by the original quarry while its log line kept the
 *    arguments that needed them. Restored, not diverged from: see
 *    sigchld_code_to_string() and format_exit_status().
 *
 * Not backported: ExecStop=/ExecStopPost=/ExecReload=, ExecCondition=,
 * Type=forking/dbus/notify/idle, socket activation, the watchdog, cgroup
 * accounting/resource-control directives, D-Bus property change signals --
 * none of it has a field in service.h, and pico-init's stop path (SIGTERM,
 * then cgroup_v2_kill() on timeout) makes an ExecStop= directive redundant
 * for this MVP's scope.
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "job.h"
#include "manager.h"
#include "sd-event.h"
#include "service.h"
#include "socket.h"
#include "timer.h"
#include "unit.h"
#include "util.h"

/*
 * Upstream's defaults, so a unit file that omits these behaves the way its
 * author expected: DefaultTimeoutStartSec and DefaultTimeoutStopSec are 90s,
 * DefaultRestartSec is 100ms.
 */
#define PICO_DEFAULT_TIMEOUT_USEC (90 * USEC_PER_SEC)
#define PICO_DEFAULT_RESTART_USEC (100 * USEC_PER_MSEC)

/* B7: v30's own hardcoded numbers, still upstream's real defaults today.
 * Deliberately not exposed as StartLimitIntervalSec=/StartLimitBurst=
 * parseable settings -- these values being load-bearing regardless of unit
 * authorship is the entire point. */
#define PICO_START_LIMIT_INTERVAL_USEC (10 * USEC_PER_SEC)
#define PICO_START_LIMIT_BURST 5

/* --- tri-state pid liveness (B5) --- */

/*
 * 0 = known dead (we hold no pid for it), >0 = alive/tracked, <0 (-EAGAIN)
 * reserved for a future "pid known but not yet confirmed" case pico-init
 * does not have today (no Type=forking/notify main-pid race exists here --
 * s->main_pid/control_pid are only ever 0 or a pid this process itself
 * forked and has not yet reaped). Kept int rather than bool anyway, per B5:
 * a bool caller cannot later distinguish "positively dead" from "unknown",
 * and that collapse is a real upstream bug class. Deliberately does NOT
 * probe with kill(pid, 0) or /proc/<pid> -- an unreaped zombie is "alive" by
 * either cheap test, which is exactly wrong when called from inside this
 * service's own SIGCHLD handling.
 */
static int main_pid_good(Service *s) {
        return s->main_pid > 0 ? 1 : 0;
}

static int control_pid_good(Service *s) {
        return s->control_pid > 0 ? 1 : 0;
}

/* --- exit-status classification (B2) --- */

typedef enum { PICO_EXIT_CLEAN_DAEMON, PICO_EXIT_CLEAN_COMMAND } PicoExitClean;

/*
 * v30 amnestied SIGHUP/SIGINT/SIGTERM/SIGPIPE as a clean death for
 * everything alike. That is wrong: it must apply only to a long-running
 * daemon's own main process (which really does routinely die that way,
 * e.g. our own SIGTERM on stop), never to a oneshot main command or an
 * ExecStartPre= control command, where a signal death -- including our own
 * start-timeout SIGTERM -- is unambiguously a failure. CLD_DUMPED is never
 * clean, for any signal, for anything.
 */
static bool pico_is_clean_exit(int code, int status, PicoExitClean clean) {
        if (code == CLD_EXITED)
                return status == 0;
        if (code == CLD_KILLED)
                return clean == PICO_EXIT_CLEAN_DAEMON &&
                                (status == SIGHUP || status == SIGINT || status == SIGTERM ||
                                 status == SIGPIPE);
        return false; /* CLD_DUMPED, or anything else waitid() might report */
}

/* service-exec.c's child _exit()s with one of these when its own setup
 * fails; the parent must never mistake that for an ordinary bad ExecStart=
 * exit code. */
static bool pico_exit_status_is_internal(int status) {
        switch (status) {
        case PICO_EXIT_CHDIR:
        case PICO_EXIT_FDS:
        case PICO_EXIT_EXEC:
        case PICO_EXIT_MEMORY:
        case PICO_EXIT_SIGNAL_MASK:
        case PICO_EXIT_STDIN:
        case PICO_EXIT_STDOUT:
        case PICO_EXIT_GROUP:
        case PICO_EXIT_USER:
        case PICO_EXIT_CGROUP:
        case PICO_EXIT_SETSID:
        case PICO_EXIT_STDERR:
                return true;
        default:
                return false;
        }
}

/* --- timers --- */

static void service_timer_reset(Service *s) {
        if (s->timer_event && UNIT(s)->manager && UNIT(s)->manager->timer)
                pico_timer_cancel(UNIT(s)->manager->timer, s->timer_event);
        /* pico_timer_cancel() already clears s->timer_event via the owner
         * slot it was armed with; nothing left to do if it was never armed. */
}

static void service_timer_start_timeout(void *userdata, usec_t now);
static void service_timer_stop_timeout(void *userdata, usec_t now);
static void service_timer_restart(void *userdata, usec_t now);

/* B1: timer.h's own rule -- a caller with an infinite timeout skips
 * pico_timer_add() entirely rather than relying on some sentinel deadline. */
static void service_arm_timeout(Service *s, usec_t timeout, pico_timer_callback_t cb) {
        usec_t deadline;
        int r;

        if (timeout == USEC_INFINITY)
                return;

        deadline = usec_add(now_monotonic(), timeout);

        r = pico_timer_add(UNIT(s)->manager->timer, deadline, cb, s, &s->timer_event);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "%s: failed to arm timer: %s", UNIT(s)->id, strerror(-r));
}

/* --- cgroup helpers --- */

static void service_kill_stale_cgroup_members(Service *s) {
        if (!s->cgroup)
                return;

        if (cgroup_v2_is_empty(s->cgroup) == 1)
                return;

        /* B11/8f53a7b8ea: leftovers from a previous run, or anything
         * ExecStartPre= itself leaked, must never survive into this run. */
        pico_log(PICO_LOG_WARNING, "%s: killing leftover processes in the cgroup before starting", UNIT(s)->id);
        cgroup_v2_kill(s->cgroup);
}

/* Called once the main process is confirmed gone. Kills or logs whatever
 * else is still in the cgroup, per the SIGCHLD-vs-cgroup-empty ordering
 * note above service_sigchld_event(). */
static void service_reap_cgroup_remainder(Service *s) {
        if (!s->cgroup)
                return;

        if (cgroup_v2_is_empty(s->cgroup) == 1)
                return;

        if (s->remain_after_exit) {
                /* Deliberately not killed: this log line is what later
                 * explains a failed rmdir on the cgroup directory. */
                pico_log(PICO_LOG_INFO,
                         "%s: main process exited, leftover processes remain (RemainAfterExit=yes)",
                         UNIT(s)->id);
                return;
        }

        pico_log(PICO_LOG_INFO, "%s: main process exited, killing the remainder of its cgroup", UNIT(s)->id);
        cgroup_v2_kill(s->cgroup);
}

static int service_ensure_cgroup(Service *s) {
        Manager *m = UNIT(s)->manager;
        char slice[PATH_MAX];
        char path[PATH_MAX];
        int n, r;

        if (s->cgroup)
                return 0;

        if (!m || !m->cgroup_root)
                return -EINVAL;

        /* cgroups-v2.h's own contract: one cgroup per unit at <cgroup
         * root>/system.slice/<unit>. cgroup_v2_new() only mkdir()s the leaf,
         * so the slice directory has to exist first; best-effort, an
         * already-existing one is not an error. */
        n = snprintf(slice, sizeof(slice), "%s/system.slice", m->cgroup_root);
        if (n < 0 || (size_t) n >= sizeof(slice))
                return -ENAMETOOLONG;
        if (mkdir(slice, 0755) < 0 && errno != EEXIST)
                return -errno;

        n = snprintf(path, sizeof(path), "%s/%s", slice, UNIT(s)->id);
        if (n < 0 || (size_t) n >= sizeof(path))
                return -ENAMETOOLONG;

        r = cgroup_v2_new(path, &s->cgroup);
        if (r < 0)
                return r;

        s->cgroup->userdata = s;

        r = cgroup_v2_monitor(s->cgroup, m->event);
        if (r < 0)
                /* Not fatal: SIGCHLD alone still drives the state machine,
                 * cgroup-empty events just never arrive for this unit. */
                pico_log(PICO_LOG_WARNING,
                         "%s: cgroup created but epoll registration failed: %s, continuing without it",
                         UNIT(s)->id,
                         strerror(-r));

        return 0;
}

/* --- start-rate limiting (B7) --- */

/*
 * v30 already had this; pico-init lacking it is a quarrying regression, not
 * a deferred feature. Without it, Restart=on-failure + a small RestartSec=
 * + a nonexistent ExecStart= path spins fork/execve/ENOENT as fast as the
 * kernel allows, forever, as PID 1, on a device with no second console --
 * and because the run queue dispatches after this, a tight restart loop can
 * starve job dispatch badly enough that even shutdown never gets scheduled.
 *
 * CLOCK_BOOTTIME would be the more correct clock here (a monotonic window
 * survives a suspend/resume as a stale prohibition), but util.h only
 * exposes CLOCK_MONOTONIC today and pico-init has no suspend/resume story
 * yet; noted rather than inventing new time plumbing for this MVP.
 */
static bool service_start_limit_check(Service *s) {
        usec_t now = now_monotonic();

        if (s->start_limit_begin == 0 || now - s->start_limit_begin > s->start_limit_interval) {
                s->start_limit_begin = now;
                s->start_limit_num = 1;
                return true;
        }

        return ++s->start_limit_num <= s->start_limit_burst;
}

/* --- the restart decision (B8) --- */

static bool service_shall_restart(Service *s, const char **reason) {
        if (s->forbid_restart) {
                *reason = "manual stop";
                return false;
        }

        *reason = "Restart=";
        switch (s->restart) {
        case SERVICE_RESTART_NO:
                return false;
        case SERVICE_RESTART_ON_FAILURE:
                return s->result != SERVICE_SUCCESS;
        default:
                return false;
        }
}

/* --- state transitions --- */

static UnitActiveState service_active_state_of(ServiceState state, bool remain_after_exit);

static void service_set_state(Service *s, ServiceState state) {
        UnitActiveState old_active, new_active;

        if (s->state == state)
                return;

        old_active = service_active_state_of(s->state, s->remain_after_exit);
        s->state = state;
        new_active = service_active_state_of(s->state, s->remain_after_exit);

        unit_notify(UNIT(s), old_active, new_active);
}

static void service_enter_dead(Service *s) {
        bool restart;
        const char *reason = "";

        service_timer_reset(s);

        /* B8/a509f0e631: always the real DEAD/FAILED state first, then --
         * and only then -- AUTO_RESTART is even considered. Skipping this
         * made "start" never return in the systemd bug this fixed. */
        service_set_state(s, s->result != SERVICE_SUCCESS ? SERVICE_FAILED : SERVICE_DEAD);

        /* Terminal, so a paired .socket unit may go back to listening and
         * re-trigger on the next connection. No-op when nothing pairs. */
        socket_notify_service_dead(UNIT(s));

        restart = service_shall_restart(s, &reason);
        if (!restart) {
                pico_log(PICO_LOG_DEBUG, "%s: not restarting (%s)", UNIT(s)->id, reason);
                return;
        }

        /* B8/c972880640: a pending stop job vetoes a restart outright rather
         * than rescheduling one -- with RestartSec=0 the reschedule alone
         * would busy-loop PID 1 and starve the job queue so thoroughly the
         * rate limiter itself would never get a chance to fire. */
        if (UNIT(s)->job && UNIT(s)->job->type == JOB_STOP) {
                pico_log(PICO_LOG_DEBUG, "%s: stop job pending, not scheduling a restart", UNIT(s)->id);
                return;
        }

        s->n_restarts++;
        service_set_state(s, SERVICE_AUTO_RESTART);
        service_arm_timeout(s, s->restart_usec, service_timer_restart);
}

static void service_enter_stop(Service *s) {
        int mp = main_pid_good(s);
        int cp = control_pid_good(s);

        service_timer_reset(s);

        if (mp <= 0 && cp <= 0) {
                /* Nothing left to wait for -- skip SERVICE_STOP entirely
                 * rather than arm a timeout for a death that already
                 * happened (or never started at all: a failed fork). */
                service_enter_dead(s);
                return;
        }

        service_set_state(s, SERVICE_STOP);

        if (mp > 0)
                kill(s->main_pid, SIGTERM);
        if (cp > 0)
                kill(s->control_pid, SIGTERM);

        service_arm_timeout(s, s->timeout_stop_usec, service_timer_stop_timeout);
}

/* B4/ec5b1452ac: result checked before service_good() before
 * remain_after_exit, in exactly that order. The reverse order lets
 * RemainAfterExit=yes silently swallow a failed main process, and
 * Restart=on-failure then never fires -- reachable in pico-init the moment
 * ExecStartPre= and ExecStart= can be outstanding together. */
static void service_enter_running(Service *s) {
        /*
         * Bug found in review, not in any upstream commit: every branch below
         * leaves the start attempt behind for good (RUNNING, EXITED, or a
         * stop/dead on failure), so whichever start timeout got us here no
         * longer applies. Without this, a Type=simple daemon that forked
         * cleanly and has been happily RUNNING for TimeoutStartSec= (90s by
         * default) gets SIGTERM'd out from under itself the moment that
         * timer -- armed at service_enter_start() and never cancelled --
         * finally fires. service_enter_stop() below cancels it too on the
         * failure path, making this a harmless duplicate there; it is not
         * harmless on the RUNNING/EXITED paths, which never called it at all.
         */
        service_timer_reset(s);

        if (s->result != SERVICE_SUCCESS) {
                service_enter_stop(s);
                return;
        }

        if (main_pid_good(s) != 0) {
                service_set_state(s, SERVICE_RUNNING);
                return;
        }

        if (s->remain_after_exit) {
                service_set_state(s, SERVICE_EXITED);
                return;
        }

        service_enter_stop(s);
}

static void service_enter_start(Service *s) {
        int r;

        service_timer_reset(s);
        service_kill_stale_cgroup_members(s); /* B11: before EXEC_START too, not just START_PRE */

        service_set_state(s, SERVICE_EXEC_START);
        service_arm_timeout(s, s->timeout_start_usec, service_timer_start_timeout);

        r = service_spawn(s, s->exec_start, &s->main_pid);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "%s: failed to spawn ExecStart=: %s", UNIT(s)->id, strerror(-r));
                if (s->result == SERVICE_SUCCESS)
                        s->result = SERVICE_FAILURE_RESOURCES;
                service_enter_stop(s);
                return;
        }

        /* "simple counts as started the moment the process is forked" (see
         * this file's own top-of-header comment): for Type=oneshot the
         * process is still running and EXEC_START is correct; simple is
         * done right here. */
        if (s->type == SERVICE_TYPE_SIMPLE)
                service_enter_running(s);
}

static void service_enter_start_pre(Service *s) {
        int r;

        service_timer_reset(s);
        service_kill_stale_cgroup_members(s); /* B11: before START_PRE */

        service_set_state(s, SERVICE_START_PRE);
        service_arm_timeout(s, s->timeout_start_usec, service_timer_start_timeout);

        r = service_spawn(s, s->exec_start_pre, &s->control_pid);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "%s: failed to spawn ExecStartPre=: %s", UNIT(s)->id, strerror(-r));
                if (s->result == SERVICE_SUCCESS)
                        s->result = SERVICE_FAILURE_RESOURCES;
                service_enter_stop(s);
        }
}

/* --- the public entry points --- */

/* Shared by service_start() (after its own state-legality checks) and the
 * restart timer (which reaches here directly from SERVICE_AUTO_RESTART, an
 * inherently legal predecessor). */
static void service_do_start(Service *s) {
        int r;

        /* B7: after "is a start even legal" (the caller already checked),
         * before any state change or fork -- this is where upstream's own
         * placement settled after moving it four times over 14 years. */
        if (!service_start_limit_check(s)) {
                pico_log(PICO_LOG_WARNING,
                         "%s: start request repeated too quickly (limit %u per %llu us), refusing",
                         UNIT(s)->id,
                         s->start_limit_burst,
                         (unsigned long long) s->start_limit_interval);
                /* The one result allowed to overwrite a stored failure: this
                 * is a fresh attempt, and going through service_enter_dead()
                 * here would let Restart= immediately re-trigger the very
                 * limit that just fired. */
                s->result = SERVICE_FAILURE_START_LIMIT;
                service_timer_reset(s);
                service_set_state(s, SERVICE_FAILED);

                /* This path deliberately skips service_enter_dead(), so it
                 * needs its own notify -- and it is the one that matters most:
                 * a paired socket must go FAILED here rather than re-arm, or
                 * it re-triggers the crash loop its own start limit just
                 * stopped (c2f3480897, "so sockets won't act as tarpits"). */
                socket_notify_service_dead(UNIT(s));
                return;
        }

        s->result = SERVICE_SUCCESS;

        /* A fresh start must never carry a stale READY/STATUS from a
         * previous run forward -- see service.h's own comment on these. */
        s->notify_ready = false;
        s->status_text = pico_mfree(s->status_text);
        s->status_errno = 0;

        r = service_ensure_cgroup(s);
        if (r < 0)
                pico_log(PICO_LOG_WARNING,
                         "%s: could not set up a cgroup (%s), starting without process supervision",
                         UNIT(s)->id,
                         strerror(-r));

        if (s->exec_start_pre)
                service_enter_start_pre(s);
        else
                service_enter_start(s);
}

int service_start(Service *s) {
        if (!s)
                return -EINVAL;

        switch (s->state) {
        case SERVICE_START_PRE:
        case SERVICE_EXEC_START:
        case SERVICE_RUNNING:
        case SERVICE_EXITED:
                return 0; /* already starting or started */

        case SERVICE_STOP:
                return -EAGAIN; /* mid-shutdown; let it finish first */

        case SERVICE_AUTO_RESTART:
                /* B8/0c7f15b3a9: an explicit start must not fail just
                 * because a restart is already pending -- proceed now
                 * rather than waiting out the rest of RestartSec=. */
                service_timer_reset(s);
                break;

        case SERVICE_DEAD:
        case SERVICE_FAILED:
                break;

        default:
                return -EINVAL;
        }

        s->forbid_restart = false;
        service_do_start(s);
        return 0;
}

int service_stop(Service *s) {
        if (!s)
                return -EINVAL;

        switch (s->state) {
        case SERVICE_DEAD:
        case SERVICE_FAILED:
        case SERVICE_STOP:
                return 0; /* already stopped or stopping */

        case SERVICE_AUTO_RESTART:
                /* B8/2e9d6c1251: through service_enter_dead(), never a raw
                 * state assignment -- that is what makes forbid_restart
                 * actually take effect instead of a stale timer reviving
                 * the service anyway. */
                s->forbid_restart = true;
                service_timer_reset(s);
                service_enter_dead(s);
                return 0;

        case SERVICE_START_PRE:
        case SERVICE_EXEC_START:
        case SERVICE_RUNNING:
        case SERVICE_EXITED:
                s->forbid_restart = true;
                service_enter_stop(s);
                return 0;

        default:
                return -EINVAL;
        }
}

/*
 * Naming the (si_code, si_status) pair, because printing it raw is actively
 * misleading. si_code is CLD_EXITED/CLD_KILLED/CLD_DUMPED, whose values are
 * 1/2/3 -- so a clean `exit 0` logged as "code=1 status=0, result=success"
 * reads as an exit status of 1 sitting next to a success verdict. si_status
 * is worse: it is an exit status under CLD_EXITED and a *signal number*
 * otherwise, so a SIGTERM at shutdown logs as "status=15". Both halves get
 * named here, giving systemd's own "code=exited, status=0" shape.
 *
 * v30 had sigchld_code_to_string() and this file's quarry dropped it while
 * keeping its arguments; this restores the upstream behaviour rather than
 * diverging from it.
 */
static const char *sigchld_code_to_string(int code) {
        switch (code) {
        case CLD_EXITED:
                return "exited";
        case CLD_KILLED:
                return "killed";
        case CLD_DUMPED:
                return "dumped";
        default:
                return "unknown";
        }
}

static void format_exit_status(char *buf, size_t size, int code, int status) {
        const char *name;

        if (code == CLD_EXITED) {
                (void) snprintf(buf, size, "%d", status);
                return;
        }

        name = strsignal(status);
        (void) snprintf(buf, size, "%d/%s", status, name ? name : "unknown signal");
}

/*
 * SIGCHLD vs cgroup-empty -- the ordering hazard.
 *
 * SIGCHLD carries an exit status; cgroup-empty does not. That asymmetry is
 * why systemd reverted a whole feature (abaf5edd08): the process that
 * happens to find the cgroup empty is an arbitrary descendant, and its exit
 * code says nothing about the service. So: this function is the sole writer
 * of s->result and the sole input to the restart decision.
 * service_cgroup_empty_event() below may change state but has no legitimate
 * way to invent an exit status of its own.
 *
 * Another agent is making the manager loop dispatch cgroup-empty strictly
 * after SIGCHLD, and re-verify emptiness before dispatching -- this file
 * relies on that ordering rather than re-deriving it.
 */
void service_sigchld_event(Service *s, pid_t pid, int code, int status) {
        char statusbuf[64];
        bool is_main, is_control;
        PicoExitClean clean;
        ServiceResult f;

        if (!s)
                return;

        is_main = s->main_pid > 0 && pid == s->main_pid;
        is_control = s->control_pid > 0 && pid == s->control_pid;
        if (!is_main && !is_control)
                return; /* not ours */

        clean = (s->type == SERVICE_TYPE_ONESHOT || is_control) ? PICO_EXIT_CLEAN_COMMAND :
                                                                  PICO_EXIT_CLEAN_DAEMON;

        if (pico_is_clean_exit(code, status, clean))
                f = SERVICE_SUCCESS;
        else if (code == CLD_EXITED && pico_exit_status_is_internal(status))
                f = SERVICE_FAILURE_RESOURCES; /* our own setup failed, not the workload */
        else if (code == CLD_EXITED)
                f = SERVICE_FAILURE_EXIT_CODE;
        else if (code == CLD_KILLED || code == CLD_DUMPED)
                f = SERVICE_FAILURE_SIGNAL;
        else {
                /* Not reachable for a real waitid() result, but this project
                 * never asserts on input it did not itself fully control --
                 * see the 35b1078e1 note in unit-parse.c for why. */
                pico_log(PICO_LOG_WARNING,
                         "%s: unrecognized wait status code %d, treating as a failure",
                         UNIT(s)->id,
                         code);
                f = SERVICE_FAILURE_RESOURCES;
        }

        /* B3/a0fef983ab: write-once -- the *first* failure wins, not the
         * last. A watchdog-style timeout that goes on to SIGABRT the
         * service must report the timeout, not the coredump it caused. */
        if (s->result == SERVICE_SUCCESS)
                s->result = f;

        /* v30 logged this through log_full() at NOTICE when the unit failed
         * and DEBUG when it did not; the quarry collapsed both to DEBUG, so a
         * service failing on a board whose only output is a serial console
         * announced itself at the same level as every routine exit.
         *
         * The level follows s->result rather than v30's local f, so that it
         * agrees with the result= this same line prints: under the write-once
         * rule an earlier failure survives a later clean exit, and logging
         * "result=timeout" at debug would hide exactly the case that matters. */
        format_exit_status(statusbuf, sizeof statusbuf, code, status);
        pico_log(s->result == SERVICE_SUCCESS ? PICO_LOG_DEBUG : PICO_LOG_WARNING,
                 "%s: %s process exited, code=%s, status=%s, result=%s",
                 UNIT(s)->id,
                 is_control ? "control" : "main",
                 sigchld_code_to_string(code),
                 statusbuf,
                 service_result_to_string(s->result));

        if (is_control) {
                s->control_pid = 0;

                if (s->state == SERVICE_START_PRE) {
                        if (f == SERVICE_SUCCESS)
                                service_enter_start(s);
                        else
                                service_enter_stop(s);
                } else if (s->state == SERVICE_STOP && main_pid_good(s) == 0) {
                        service_enter_dead(s);
                }
                return;
        }

        /* is_main */
        s->main_exit_code = code;
        s->main_exit_status = status;
        s->main_pid = 0;

        switch (s->state) {
        case SERVICE_EXEC_START:
        case SERVICE_RUNNING:
                /*
                 * SIGCHLD for the main pid while the cgroup may still be
                 * populated is the ordinary Type=simple-with-helpers case:
                 * the service is gone either way, so declare it and reap the
                 * remainder -- except under RemainAfterExit=yes, which parks
                 * in SERVICE_EXITED and leaves stragglers (logged).
                 */
                service_reap_cgroup_remainder(s);
                service_enter_running(s);
                break;

        case SERVICE_STOP:
                if (control_pid_good(s) == 0)
                        service_enter_dead(s);
                break;

        default:
                break;
        }
}

void service_cgroup_empty_event(Service *s) {
        if (!s)
                return;

        /*
         * cgroup-empty carries no exit status; service_sigchld_event() above
         * is the only place that ever learns a real one. So this only acts
         * once both pids are positively known dead -- if either is still
         * >0, that pid's SIGCHLD simply has not been processed yet (not a
         * sign the service is done), and doing anything here would be
         * racing our own other event source (abaf5edd08).
         */
        if (main_pid_good(s) != 0 || control_pid_good(s) != 0)
                return;

        switch (s->state) {
        case SERVICE_START_PRE:
        case SERVICE_EXEC_START:
                /*
                 * B11/f52e9ed62b: reaching here means whatever was spawned
                 * is gone -- cgroup empty -- without either this function or
                 * the SIGCHLD path (already checked above) ever learning how
                 * it exited. That is not "the start completed"; it is a
                 * resources-class failure with no attributable exit status,
                 * the one legitimate case where this function reports
                 * failure rather than passing success through untouched.
                 */
                if (s->result == SERVICE_SUCCESS)
                        s->result = SERVICE_FAILURE_RESOURCES;
                service_enter_stop(s);
                break;

        case SERVICE_RUNNING:
        case SERVICE_STOP:
                /* Cleanup confirmation only: whatever service_sigchld_event()
                 * already recorded in s->result stands untouched. */
                service_enter_stop(s);
                break;

        default:
                break;
        }
}

/* --- timer callbacks --- */

static void service_timer_start_timeout(void *userdata, usec_t now) {
        Service *s = userdata;
        (void) now;

        pico_log(PICO_LOG_WARNING, "%s: start operation timed out", UNIT(s)->id);

        /* Report the cause, not whatever signal death this timeout is about
         * to cause: set before killing anything, per B3's watchdog example. */
        if (s->result == SERVICE_SUCCESS)
                s->result = SERVICE_FAILURE_TIMEOUT;

        service_enter_stop(s);
}

static void service_timer_stop_timeout(void *userdata, usec_t now) {
        Service *s = userdata;
        (void) now;

        pico_log(PICO_LOG_WARNING, "%s: stop operation timed out, escalating", UNIT(s)->id);

        if (s->result == SERVICE_SUCCESS)
                s->result = SERVICE_FAILURE_TIMEOUT;

        if (s->cgroup)
                cgroup_v2_kill(s->cgroup);
        else {
                /* No cgroup to sweep with: escalate directly on whichever
                 * pid we still hold. */
                if (main_pid_good(s) > 0)
                        kill(s->main_pid, SIGKILL);
                if (control_pid_good(s) > 0)
                        kill(s->control_pid, SIGKILL);
        }

        /* The kill may not be synchronous (the SIGKILL-sweep fallback in
         * cgroup_v2_kill() in particular); only finish now if we already
         * know both pids are gone, otherwise wait for their SIGCHLD. */
        if (main_pid_good(s) == 0 && control_pid_good(s) == 0)
                service_enter_dead(s);
}

static void service_timer_restart(void *userdata, usec_t now) {
        Service *s = userdata;
        (void) now;

        if (s->forbid_restart) {
                /* Defensive only: service_stop() already cancels this timer
                 * and routes through service_enter_dead() directly when
                 * stopping from SERVICE_AUTO_RESTART, so this should not be
                 * reachable in practice. */
                service_set_state(s, SERVICE_DEAD);
                return;
        }

        service_do_start(s);
}

/* --- service_verify() (B9) --- */

static bool exec_line_is_valid(char * const *argv) {
        /* 69339ae9f7: never let a unit load with an ExecStart= that would
         * reach execve() with a NULL or empty argv[0] -- the CVE-2021-4034
         * (PwnKit) primitive, and no PAM/seccomp/namespaces stand between
         * pico-init and it. The parser already rejects a non-absolute path
         * for anything it actually stores (see unit-parse.c's
         * parse_exec_line()); what it cannot catch is a unit that never sets
         * ExecStart= at all, leaving this NULL.
         */
        return argv && argv[0] && argv[0][0] == '/';
}

int service_verify(Service *s) {
        if (!s)
                return -EINVAL;

        if (!exec_line_is_valid(s->exec_start)) {
                pico_log(PICO_LOG_ERR, "%s: no valid ExecStart=, refusing to load", UNIT(s)->id);
                return -ENOEXEC;
        }

        if (s->exec_start_pre && !exec_line_is_valid(s->exec_start_pre)) {
                pico_log(PICO_LOG_ERR, "%s: invalid ExecStartPre=, refusing to load", UNIT(s)->id);
                return -ENOEXEC;
        }

        /* Type=oneshot + Restart=on-failure is legal in modern systemd
         * (the old blanket ban is not carried forward) -- nothing to check. */

        return 0;
}

/* --- string tables --- */

static const char * const service_type_table[_SERVICE_TYPE_MAX] = {
        [SERVICE_TYPE_SIMPLE] = "simple",
        [SERVICE_TYPE_ONESHOT] = "oneshot",
};

const char *service_type_to_string(ServiceType t) {
        if (t < 0 || t >= _SERVICE_TYPE_MAX)
                return "invalid";

        return service_type_table[t];
}

/* 1378a3b5a1: systemd shipped a state-to-string table missing an enumerator
 * twice. Every _SERVICE_STATE_MAX entry above has a designated initializer
 * here; a missing one would leave service_state_to_string() returning NULL
 * for a state main.c's own logging paths can reach. */
static const char * const service_state_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = "dead",
        [SERVICE_START_PRE] = "start-pre",
        [SERVICE_EXEC_START] = "exec-start",
        [SERVICE_RUNNING] = "running",
        [SERVICE_EXITED] = "exited",
        [SERVICE_STOP] = "stop",
        [SERVICE_AUTO_RESTART] = "auto-restart",
        [SERVICE_FAILED] = "failed",
};

const char *service_state_to_string(ServiceState s) {
        if (s < 0 || s >= _SERVICE_STATE_MAX)
                return "invalid";

        return service_state_table[s];
}

static const char * const service_restart_table[_SERVICE_RESTART_MAX] = {
        [SERVICE_RESTART_NO] = "no",
        [SERVICE_RESTART_ON_FAILURE] = "on-failure",
};

const char *service_restart_to_string(ServiceRestart r) {
        if (r < 0 || r >= _SERVICE_RESTART_MAX)
                return "invalid";

        return service_restart_table[r];
}

static const char * const service_result_table[_SERVICE_RESULT_MAX] = {
        [SERVICE_SUCCESS] = "success",         [SERVICE_FAILURE_RESOURCES] = "resources",
        [SERVICE_FAILURE_TIMEOUT] = "timeout", [SERVICE_FAILURE_EXIT_CODE] = "exit-code",
        [SERVICE_FAILURE_SIGNAL] = "signal",   [SERVICE_FAILURE_START_LIMIT] = "start-limit-hit",
};

const char *service_result_to_string(ServiceResult r) {
        if (r < 0 || r >= _SERVICE_RESULT_MAX)
                return "invalid";

        return service_result_table[r];
}

/* --- vtable thunks --- */

static void service_init(Unit *u) {
        Service *s = SERVICE(u);

        s->type = SERVICE_TYPE_SIMPLE;
        s->state = SERVICE_DEAD;
        s->result = SERVICE_SUCCESS;
        s->restart = SERVICE_RESTART_NO;
        s->restart_usec = PICO_DEFAULT_RESTART_USEC;
        s->timeout_start_usec = PICO_DEFAULT_TIMEOUT_USEC;
        s->timeout_stop_usec = PICO_DEFAULT_TIMEOUT_USEC;
        s->start_limit_interval = PICO_START_LIMIT_INTERVAL_USEC;
        s->start_limit_burst = PICO_START_LIMIT_BURST;
}

/*
 * The per-type destructor. Everything freed here is invisible to unit_free(),
 * which is exactly why the vtable hook exists: without it a started service
 * leaks both argv vectors, its cgroup, and leaves a queued timer event holding
 * a pointer into memory that is about to be freed.
 */
static void service_done(Unit *u) {
        Service *s = SERVICE(u);

        s->exec_start = pico_strv_free(s->exec_start);
        s->exec_start_pre = pico_strv_free(s->exec_start_pre);
        s->user = pico_mfree(s->user);
        s->group = pico_mfree(s->group);
        s->status_text = pico_mfree(s->status_text);

        /*
         * Cancel before freeing, never after. A pending event holds
         * &s->timer_event as its owner slot (see timer.h), so an event left
         * queued past this point would write into freed memory when it fires.
         */
        if (s->timer_event && u->manager && u->manager->timer)
                pico_timer_cancel(u->manager->timer, s->timer_event);
        s->timer_event = NULL;

        /* B13: disable/unref the events_source before cgroup_v2_free() closes
         * the fd underneath it, or a pending dispatch could still run its
         * callback against memory that is about to be freed. */
        if (s->cgroup && s->cgroup->events_source)
                s->cgroup->events_source = sd_event_source_disable_unref(s->cgroup->events_source);

        s->cgroup = cgroup_v2_free(s->cgroup);
}

static int service_start_thunk(Unit *u) {
        return service_start(SERVICE(u));
}

static int service_stop_thunk(Unit *u) {
        return service_stop(SERVICE(u));
}

static UnitActiveState service_active_state_of(ServiceState state, bool remain_after_exit) {
        switch (state) {
        case SERVICE_DEAD:
                return UNIT_INACTIVE;

        case SERVICE_START_PRE:
        case SERVICE_EXEC_START:
        case SERVICE_AUTO_RESTART:
                return UNIT_ACTIVATING;

        case SERVICE_RUNNING:
                return UNIT_ACTIVE;

        case SERVICE_EXITED:
                /* A cleanly exited service is still "active" only if it said
                 * so: that is the whole meaning of RemainAfterExit=, and it is
                 * how a Type=oneshot boot-plumbing unit stays satisfied after
                 * its process is gone. service_enter_running() only ever
                 * enters this state when remain_after_exit is already true,
                 * so the ternary below is defensive, not load-bearing. */
                return remain_after_exit ? UNIT_ACTIVE : UNIT_INACTIVE;

        case SERVICE_STOP:
                return UNIT_DEACTIVATING;

        case SERVICE_FAILED:
                return UNIT_FAILED;

        default:
                return UNIT_INACTIVE;
        }
}

static UnitActiveState service_active_state_thunk(Unit *u) {
        Service *s = SERVICE(u);

        return service_active_state_of(s->state, s->remain_after_exit);
}

const UnitVTable service_vtable = {
        .object_size = sizeof(Service),
        .init = service_init,
        .done = service_done,
        .start = service_start_thunk,
        .stop = service_stop_thunk,
        .active_state = service_active_state_thunk,
};
