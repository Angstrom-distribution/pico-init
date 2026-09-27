/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Service units: the state machine. service-exec.c has the fork/exec + fd/
 * cgroup child-side setup. Quarried from systemd's ~2011-era src/service.c
 * (tag v30, commit 501c92c, copyright 2010 Lennart Poettering,
 * GPL-2.0-or-later), reduced to the two-state-machine shape pico-init needs
 * (Type=simple/oneshot at first, no watchdog/D-Bus),
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
 *  - v30's Type=forking, quarried later than the rest: ExecStart= runs as
 *    the control process, its clean exit is the start signal, and the main
 *    pid is then read from PIDFile= (service_load_pid_file()) or, under
 *    GuessMainPID=, found as the sole survivor of the cgroup
 *    (service_search_main_pid()). Two later upstream rules ride along:
 *    db256aab13 / e1b02726ec -- a PIDFile= pid that is not a member of the
 *    unit's own cgroup is refused, so a compromised or confused daemon
 *    cannot point PID 1 at an arbitrary process to SIGTERM on stop; and a
 *    PIDFile= naming the control process itself (a daemon writing its pid
 *    *before* forking) is refused rather than adopting a zombie.
 *
 *  - ExecStop=, v30's SERVICE_STOP state under pico-init's own name
 *    (SERVICE_EXEC_STOP; pico's SERVICE_STOP is upstream's STOP_SIGTERM):
 *    a stop from RUNNING/EXITED runs every ExecStop= line in turn as the
 *    control process before anything is signalled, a clean main-process
 *    exit without RemainAfterExit= does too (service_enter_exited_or_stop()
 *    upstream), and a stop mid-start skips it and signals at once. A failed
 *    line ends the chain and fails the unit, but the stop still proceeds --
 *    a stop command can never keep a unit up. TimeoutStopSec= bounds the
 *    whole chain, then again the signal phase after it.
 *
 *  - ExecStopPost= and ExecCondition=, modern upstream rather than v30,
 *    shaped like ExecStop=. ExecStopPost= (SERVICE_STOP_POST) runs once
 *    every other process of the unit is gone, on every path to DEAD/FAILED
 *    that started something: a stop, a crash, a failed start, a skipped
 *    condition. A failed line fails the unit and ends the chain, anything
 *    it leaves in the cgroup is SIGKILLed (upstream's FINAL_SIGTERM,
 *    without the SIGTERM step), and TimeoutStopSec= bounds it.
 *    ExecCondition= (SERVICE_CONDITION) runs before ExecStartPre=; an exit
 *    status of 1-254 is SERVICE_SKIP_CONDITION, which ends the start
 *    cleanly in DEAD, completes the start job, and never triggers
 *    Restart=. 255, a signal or one of pico-init's own setup exit codes
 *    fails it as ExecStartPre= would.
 *
 * Not backported: running ExecReload= (it is parsed and stored, but
 * nothing asks a single unit to reload yet), Type=dbus/idle, the watchdog,
 * cgroup accounting/resource-control directives, D-Bus property change
 * signals -- none of it has a field in service.h.
 *
 * Type=exec and Type=notify are modern upstream, not v30: exec follows
 * exec-invoke.c's exec_fd protocol (service_exec_fd_cb() below), notify
 * follows service_notify_message()'s READY=1 gating with the
 * exited-before-READY case mapped to SERVICE_FAILURE_PROTOCOL as upstream
 * does; NotifyAccess= is not built, so only the main pid's READY=1 counts
 * (upstream's own default for Type=notify).
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

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
 * reserved for a "pid known but not yet confirmed" case pico-init does not
 * have today: s->control_pid is only ever 0 or a pid this process forked
 * and has not yet reaped, and s->main_pid is that or an alien pid (Type=
 * forking, MAINPID=) whose SIGCHLD still reaches us as PID 1 or subreaper
 * (manager.c). Kept int rather than bool anyway, per B5: a bool caller
 * cannot later distinguish "positively dead" from "unknown", and that
 * collapse is a real upstream bug class. Deliberately does NOT probe with
 * kill(pid, 0) or /proc/<pid> -- an unreaped zombie is "alive" by either
 * cheap test, which is exactly wrong when called from inside this service's
 * own SIGCHLD handling.
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

/* Everything but success and a skipped ExecCondition=: the one non-success
 * result that still ends in DEAD rather than FAILED. */
static bool service_result_is_failure(ServiceResult r) {
        return r != SERVICE_SUCCESS && r != SERVICE_SKIP_CONDITION;
}

/* --- timers --- */

static void service_timer_reset(Service *s) {
        if (s->timer_event && UNIT(s)->manager && UNIT(s)->manager->timer)
                pico_timer_cancel(UNIT(s)->manager->timer, s->timer_event);
        /* pico_timer_cancel() already clears s->timer_event via the owner
         * slot it was armed with; nothing left to do if it was never armed. */
}

static void service_timer_start_timeout(void *userdata, usec_t now);
static void service_timer_exec_stop_timeout(void *userdata, usec_t now);
static void service_timer_stop_timeout(void *userdata, usec_t now);
static void service_timer_stop_post_timeout(void *userdata, usec_t now);
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

/* 0 if the cgroup is known empty or absent, 1 if it still has members. */
static int service_cgroup_populated(Service *s) {
        if (!s->cgroup)
                return 0;

        return cgroup_v2_is_empty(s->cgroup) == 0 ? 1 : 0;
}

/* --- Type=forking: locating the main pid once the parent has exited --- */

/* True when pid is listed in the unit's own cgroup.procs. A cgroup that
 * could not be created (service_ensure_cgroup() failed, logged there) has
 * no membership to check against, and then the answer is "unknown", which
 * this reports as false so the caller's refusal message is honest. */
static bool service_pid_in_cgroup(Service *s, pid_t pid) {
        pid_t pids[64];
        size_t n = 0, i;

        if (!s->cgroup)
                return false;

        if (cgroup_v2_get_pids(s->cgroup, pids, sizeof(pids) / sizeof(pids[0]), &n) < 0)
                return false;

        for (i = 0; i < n && i < sizeof(pids) / sizeof(pids[0]); i++)
                if (pids[i] == pid)
                        return true;

        return false;
}

/*
 * Read PIDFile=. 0 with s->main_pid set, -ENOENT/-errno when the file is not
 * there or unreadable (a forking daemon may legitimately not have written
 * it yet), -EINVAL for content that is not a pid, -ESRCH for a pid that is
 * not a live member of this unit's cgroup. Only the first line is read,
 * and only up to the first non-digit after it, matching parse_pid() on the
 * output of read_one_line_file() in v30.
 *
 * The cgroup membership check is upstream's db256aab13/e1b02726ec: with
 * User= real, a service running as an unprivileged user could otherwise
 * write any pid into its own PIDFile= and have PID 1 SIGTERM it on stop.
 * Membership also rules out the two classic self-inflicted mistakes at once:
 * the pid of a process that was never ours, and a stale pid from a previous
 * boot that now belongs to someone else.
 */
static int service_load_pid_file(Service *s) {
        char buf[64];
        char *end;
        ssize_t n;
        long long v;
        int fd;

        if (!s->pid_file)
                return -ENOENT;

        fd = open(s->pid_file, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (fd < 0)
                return -errno;

        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n < 0)
                return -errno;
        if (n == 0)
                return -EINVAL;
        buf[n] = '\0';

        errno = 0;
        v = strtoll(buf, &end, 10);
        if (errno != 0 || end == buf || v <= 0 || v > INT_MAX)
                return -EINVAL;
        if (*end != '\0' && *end != '\n' && *end != ' ' && *end != '\t' && *end != '\r')
                return -EINVAL;

        if ((pid_t) v == getpid() || (pid_t) v == s->control_pid) {
                /* The daemon wrote its pid before forking: the control
                 * process is exactly what has just exited. Adopting it would
                 * track a zombie as the main process. */
                pico_log(PICO_LOG_WARNING,
                         "%s: PIDFile= %s names the process that just exited (pid %d), ignoring",
                         UNIT(s)->id,
                         s->pid_file,
                         (int) v);
                return -ESRCH;
        }

        if (!service_pid_in_cgroup(s, (pid_t) v)) {
                pico_log(PICO_LOG_WARNING,
                         "%s: PIDFile= %s names pid %d, which is not running in this unit's cgroup, ignoring",
                         UNIT(s)->id,
                         s->pid_file,
                         (int) v);
                return -ESRCH;
        }

        s->main_pid = (pid_t) v;
        s->main_pid_alien = true;
        pico_log(PICO_LOG_DEBUG, "%s: main pid %d read from %s", UNIT(s)->id, (int) v, s->pid_file);
        return 0;
}

/*
 * GuessMainPID= (v30's cgroup_bonding_search_main_pid()): with exactly one
 * process left in the cgroup besides the control process that just exited,
 * that one is the daemon. More than one and there is no way to tell, so
 * nothing is guessed; the unit then runs with no main pid and its lifetime
 * is the cgroup's. The control pid is still listed -- it is an unreaped
 * zombie until manager-loop.c's second waitid() -- which is why it is
 * excluded by number rather than assumed gone. 0 with s->main_pid set, or
 * -ENOENT.
 */
static int service_search_main_pid(Service *s) {
        pid_t pids[64];
        pid_t found = 0;
        size_t n = 0, i;

        if (!s->guess_main_pid || !s->cgroup)
                return -ENOENT;

        if (cgroup_v2_get_pids(s->cgroup, pids, sizeof(pids) / sizeof(pids[0]), &n) < 0)
                return -ENOENT;

        if (n > sizeof(pids) / sizeof(pids[0]))
                return -ENOENT; /* far more than one candidate: not guessable */

        for (i = 0; i < n; i++) {
                if (pids[i] == s->control_pid)
                        continue;
                if (found != 0)
                        return -ENOENT; /* two candidates: no guess */
                found = pids[i];
        }

        if (found == 0)
                return -ENOENT;

        s->main_pid = found;
        s->main_pid_alien = true;
        pico_log(PICO_LOG_DEBUG, "%s: main pid %d guessed from the cgroup", UNIT(s)->id, (int) found);
        return 0;
}

/* The forking parent has exited 0: PIDFile= first, the cgroup guess second,
 * neither is fatal. Without a main pid the unit is still up as long as its
 * cgroup is populated (service_enter_running()). */
static void service_forking_locate_main_pid(Service *s) {
        int r;

        if (s->pid_file) {
                r = service_load_pid_file(s);
                if (r == 0)
                        return;
                if (r == -ENOENT)
                        pico_log(PICO_LOG_INFO,
                                 "%s: PIDFile= %s not present after start",
                                 UNIT(s)->id,
                                 s->pid_file);
                else if (r == -EINVAL)
                        pico_log(PICO_LOG_WARNING,
                                 "%s: PIDFile= %s does not contain a pid",
                                 UNIT(s)->id,
                                 s->pid_file);
                else if (r != -ESRCH)
                        pico_log(PICO_LOG_WARNING, "%s: PIDFile= %s: %s", UNIT(s)->id, s->pid_file, strerror(-r));
        }

        if (service_search_main_pid(s) == 0)
                return;

        pico_log(PICO_LOG_INFO, "%s: no main pid known, supervising by cgroup only", UNIT(s)->id);
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
                return service_result_is_failure(s->result); /* a skip would only skip again */
        default:
                return false;
        }
}

/* --- Type=exec's readiness pipe --- */

/* Idempotent; the source owns the fd once registered, the raw fd before. */
static void service_exec_fd_close(Service *s) {
        if (s->exec_fd_source)
                s->exec_fd_source = sd_event_source_disable_unref(s->exec_fd_source);
        else if (s->exec_fd >= 0)
                close(s->exec_fd);

        s->exec_fd = -1;
        s->exec_fd_hot = false;
}

static void service_enter_running(Service *s);

/*
 * The io callback (EVENT_PRIORITY_EXEC_FD). Protocol per service.h: bytes
 * set/clear "hot", EOF while hot means execve() succeeded. EOF while not
 * hot means the child never reached execve() or it failed (it wrote the
 * 0): nothing to do here, its exit code reaches service_sigchld_event().
 * CALLBACK CONTRACT (manager-loop.c): every path returns 0.
 */
static int service_exec_fd_cb(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Service *s = userdata;
        (void) es;
        (void) revents;

        for (;;) {
                uint8_t x;
                ssize_t n = read(fd, &x, sizeof(x));

                if (n < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                return 0;

                        pico_log(PICO_LOG_WARNING,
                                 "%s: exec fd read failed (%s), start will be judged by exit status",
                                 UNIT(s)->id,
                                 strerror(errno));
                        service_exec_fd_close(s);
                        return 0;
                }

                if (n == 0) {
                        bool hot = s->exec_fd_hot;

                        service_exec_fd_close(s);

                        if (hot && s->state == SERVICE_EXEC_START) {
                                pico_log(PICO_LOG_DEBUG, "%s: execve() confirmed", UNIT(s)->id);
                                service_enter_running(s);
                        }
                        return 0;
                }

                s->exec_fd_hot = x != 0;
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
        service_exec_fd_close(s);

        /* B8/a509f0e631: always the real DEAD/FAILED state first, then --
         * and only then -- AUTO_RESTART is even considered. Skipping this
         * made "start" never return in the systemd bug this fixed. */
        service_set_state(s, service_result_is_failure(s->result) ? SERVICE_FAILED : SERVICE_DEAD);

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

/*
 * v30's default KillMode=control-group (service_enter_signal()): a stop
 * signals every process in the unit's cgroup, main and control pids
 * excluded so they are not signalled twice. More members than fit here
 * get one cgroup-wide pass instead.
 */
static void service_signal_cgroup_rest(Service *s, int sig) {
        pid_t pids[64];
        size_t n = 0, i;

        if (!s->cgroup || cgroup_v2_get_pids(s->cgroup, pids, sizeof(pids) / sizeof(pids[0]), &n) < 0)
                return;

        if (n > sizeof(pids) / sizeof(pids[0])) {
                (void) cgroup_v2_signal(s->cgroup, sig);
                return;
        }

        for (i = 0; i < n; i++)
                if (pids[i] != s->main_pid && pids[i] != s->control_pid)
                        (void) kill(pids[i], sig);
}

/* Spawns ExecStopPost= line exec_stop_post_idx as the control process. A
 * spawn failure ends the chain the way a failed line does. */
static void service_run_exec_stop_post(Service *s) {
        int r;

        r = service_spawn(s, s->exec_stop_post[s->exec_stop_post_idx].argv, &s->control_pid);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "%s: failed to spawn ExecStopPost=: %s", UNIT(s)->id, strerror(-r));
                if (s->result == SERVICE_SUCCESS)
                        s->result = SERVICE_FAILURE_RESOURCES;
                service_enter_dead(s);
        }
}

/* Upstream's service_enter_stop_post(): the last step before DEAD/FAILED,
 * reached only once the main process, any control process and the rest of
 * the cgroup are gone. */
static void service_enter_stop_post(Service *s) {
        if (s->n_exec_stop_post == 0) {
                service_enter_dead(s);
                return;
        }

        service_timer_reset(s);
        service_exec_fd_close(s);

        s->exec_stop_post_idx = 0;
        service_set_state(s, SERVICE_STOP_POST);
        service_arm_timeout(s, s->timeout_stop_usec, service_timer_stop_post_timeout);
        service_run_exec_stop_post(s);
}

static void service_enter_stop(Service *s) {
        int mp = main_pid_good(s);
        int cp = control_pid_good(s);

        service_timer_reset(s);
        service_exec_fd_close(s); /* a stop while still waiting on execve() */

        if (mp <= 0 && cp <= 0) {
                /* No pid to wait for, but a Type=forking unit whose main pid
                 * was never found is alive as long as its cgroup is: SIGTERM
                 * the members and let cgroup-empty (or the stop timeout's
                 * SIGKILL) finish it. Otherwise skip SERVICE_STOP entirely
                 * rather than arm a timeout for a death that already
                 * happened (or never started at all: a failed fork). */
                if (service_cgroup_populated(s) == 0) {
                        service_enter_stop_post(s);
                        return;
                }

                service_set_state(s, SERVICE_STOP);
                cgroup_v2_signal(s->cgroup, SIGTERM);
                service_arm_timeout(s, s->timeout_stop_usec, service_timer_stop_timeout);
                return;
        }

        service_set_state(s, SERVICE_STOP);

        if (mp > 0)
                kill(s->main_pid, SIGTERM);
        if (cp > 0)
                kill(s->control_pid, SIGTERM);
        service_signal_cgroup_rest(s, SIGTERM);

        service_arm_timeout(s, s->timeout_stop_usec, service_timer_stop_timeout);
}

/* Spawns ExecStop= line exec_stop_idx as the control process. A spawn
 * failure goes straight on to the signal phase, as upstream: a stop command
 * that cannot even run must never keep the unit up. */
static void service_run_exec_stop(Service *s) {
        int r;

        r = service_spawn(s, s->exec_stop[s->exec_stop_idx].argv, &s->control_pid);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "%s: failed to spawn ExecStop=: %s", UNIT(s)->id, strerror(-r));
                if (s->result == SERVICE_SUCCESS)
                        s->result = SERVICE_FAILURE_RESOURCES;
                service_enter_stop(s);
        }
}

/* v30's service_enter_stop(): the ExecStop= chain first, when there is one,
 * then service_enter_stop()'s signalling. One TimeoutStopSec= covers the
 * whole chain, as upstream's per-state timer does. */
static void service_enter_exec_stop(Service *s) {
        if (s->n_exec_stop == 0) {
                service_enter_stop(s);
                return;
        }

        service_timer_reset(s);
        service_exec_fd_close(s);

        s->exec_stop_idx = 0;
        service_set_state(s, SERVICE_EXEC_STOP);
        service_arm_timeout(s, s->timeout_stop_usec, service_timer_exec_stop_timeout);
        service_run_exec_stop(s);
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
        service_exec_fd_close(s); /* whichever way EXEC_START ended, nothing waits on it now */

        if (s->result != SERVICE_SUCCESS) {
                service_enter_stop(s);
                return;
        }

        if (main_pid_good(s) != 0) {
                service_set_state(s, SERVICE_RUNNING);
                return;
        }

        /* v30's cgroup_good(): a Type=forking daemon whose main pid could
         * not be determined is still running for as long as its cgroup has
         * members; service_cgroup_empty_event() ends it. Only forking --
         * for every other type a live main pid was never in doubt. */
        if (s->type == SERVICE_TYPE_FORKING && service_cgroup_populated(s) == 1) {
                service_set_state(s, SERVICE_RUNNING);
                return;
        }

        if (s->remain_after_exit) {
                service_set_state(s, SERVICE_EXITED);
                return;
        }

        /* A clean exit is a completed run, and upstream stops it the full
         * way, ExecStop= included (service_enter_exited_or_stop()). */
        service_enter_exec_stop(s);
}

static void service_enter_start(Service *s) {
        int r;

        service_timer_reset(s);
        service_kill_stale_cgroup_members(s); /* B11: before EXEC_START too, not just START_PRE */

        service_set_state(s, SERVICE_EXEC_START);
        service_arm_timeout(s, s->timeout_start_usec, service_timer_start_timeout);

        /* Type=forking: ExecStart= is the control process, exactly as v30
         * had it. It exits to signal readiness, and the daemon it leaves
         * behind becomes main_pid only once located
         * (service_forking_locate_main_pid(), from the SIGCHLD path). */
        r = service_spawn(s, s->exec_start, s->type == SERVICE_TYPE_FORKING ? &s->control_pid : &s->main_pid);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "%s: failed to spawn ExecStart=: %s", UNIT(s)->id, strerror(-r));
                if (s->result == SERVICE_SUCCESS)
                        s->result = SERVICE_FAILURE_RESOURCES;
                service_enter_stop(s);
                return;
        }

        /* Type=exec: service_spawn() handed back the pipe's read end; watch
         * it. Priority per manager.h. A registration failure leaves the
         * start to be judged the way Type=simple's is -- the process IS
         * running, refusing it now would be worse than an optimistic
         * "started" -- and says so. */
        if (s->exec_fd >= 0) {
                r = sd_event_add_io(
                                UNIT(s)->manager->event,
                                &s->exec_fd_source,
                                s->exec_fd,
                                EPOLLIN,
                                service_exec_fd_cb,
                                s);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: cannot watch the exec fd (%s), counting the start as complete now",
                                 UNIT(s)->id,
                                 strerror(-r));
                        service_exec_fd_close(s);
                        service_enter_running(s);
                        return;
                }
                sd_event_source_set_priority(s->exec_fd_source, EVENT_PRIORITY_EXEC_FD);
                sd_event_source_set_io_fd_own(s->exec_fd_source, 1);
        }

        /* "simple counts as started the moment the process is forked" (see
         * this file's own top-of-header comment). oneshot stays here until
         * the process exits, exec until service_exec_fd_cb() sees the
         * execve() go through, notify until service_notify_ready(), forking
         * until the control process exits cleanly. */
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

static void service_enter_start_pre_or_start(Service *s) {
        if (s->exec_start_pre)
                service_enter_start_pre(s);
        else
                service_enter_start(s);
}

/* Spawns ExecCondition= line exec_condition_idx as the control process; a
 * condition that cannot even run fails the start rather than skipping it. */
static void service_run_exec_condition(Service *s) {
        int r;

        r = service_spawn(s, s->exec_condition[s->exec_condition_idx].argv, &s->control_pid);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "%s: failed to spawn ExecCondition=: %s", UNIT(s)->id, strerror(-r));
                if (s->result == SERVICE_SUCCESS)
                        s->result = SERVICE_FAILURE_RESOURCES;
                service_enter_stop(s);
        }
}

/* Upstream's service_enter_condition(): START_PRE's shape, one state
 * earlier, under the same TimeoutStartSec=. */
static void service_enter_condition(Service *s) {
        service_timer_reset(s);
        service_kill_stale_cgroup_members(s); /* B11: before the first thing this start spawns */

        s->exec_condition_idx = 0;
        service_set_state(s, SERVICE_CONDITION);
        service_arm_timeout(s, s->timeout_start_usec, service_timer_start_timeout);
        service_run_exec_condition(s);
}

/* --- the public entry points --- */

/* Shared by service_start() (after its own state-legality checks) and the
 * restart timer (which reaches here directly from SERVICE_AUTO_RESTART, an
 * inherently legal predecessor). */
static int service_do_start(Service *s) {
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

                /* From FAILED the state change above was a no-op and nothing
                 * finished the start job: fail it (v30 service_start()
                 * returns -ECANCELED here). */
                return -ECANCELED;
        }

        s->result = SERVICE_SUCCESS;

        /* A fresh start must never carry a stale READY/STATUS from a
         * previous run forward -- see service.h's own comment on these. */
        s->notify_ready = false;
        s->status_text = pico_mfree(s->status_text);
        s->status_errno = 0;
        s->main_pid_alien = false;

        r = service_ensure_cgroup(s);
        if (r < 0)
                pico_log(PICO_LOG_WARNING,
                         "%s: could not set up a cgroup (%s), starting without process supervision",
                         UNIT(s)->id,
                         strerror(-r));

        if (s->n_exec_condition > 0)
                service_enter_condition(s);
        else
                service_enter_start_pre_or_start(s);

        return 0;
}

int service_start(Service *s) {
        if (!s)
                return -EINVAL;

        switch (s->state) {
        case SERVICE_CONDITION:
        case SERVICE_START_PRE:
        case SERVICE_EXEC_START:
        case SERVICE_RUNNING:
        case SERVICE_EXITED:
                return 0; /* already starting or started */

        case SERVICE_EXEC_STOP:
        case SERVICE_STOP:
        case SERVICE_STOP_POST:
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
        return service_do_start(s);
}

int service_stop(Service *s) {
        if (!s)
                return -EINVAL;

        switch (s->state) {
        case SERVICE_DEAD:
        case SERVICE_FAILED:
        case SERVICE_EXEC_STOP:
        case SERVICE_STOP:
        case SERVICE_STOP_POST:
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

        case SERVICE_CONDITION:
        case SERVICE_START_PRE:
        case SERVICE_EXEC_START:
                /* Something is still starting: signal it at once, no
                 * ExecStop= for a run that never completed (upstream's
                 * service_stop() does the same). */
                s->forbid_restart = true;
                service_enter_stop(s);
                return 0;

        case SERVICE_RUNNING:
        case SERVICE_EXITED:
                s->forbid_restart = true;
                service_enter_exec_stop(s);
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

/* The directive the exiting process was spawned from, for the log. */
static const char *service_command_name(Service *s, bool is_control) {
        if (!is_control)
                return "ExecStart";
        if (s->state == SERVICE_CONDITION)
                return "ExecCondition";
        if (s->state == SERVICE_START_PRE)
                return "ExecStartPre";
        if (s->state == SERVICE_EXEC_STOP)
                return "ExecStop";
        if (s->state == SERVICE_STOP_POST)
                return "ExecStopPost";
        return "ExecStart"; /* Type=forking's parent */
}

/* The "-" flag of the ExecCondition=/ExecStopPost= line now running as the
 * control process. */
static bool service_list_command_ignore(Service *s) {
        if (s->state == SERVICE_CONDITION)
                return s->exec_condition[s->exec_condition_idx].ignore;
        if (s->state == SERVICE_STOP_POST && s->exec_stop_post_idx < s->n_exec_stop_post)
                return s->exec_stop_post[s->exec_stop_post_idx].ignore;
        return false;
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

        /*
         * "-" prefix (ExecCommand.ignore, v30 service.c:2597-2598/2669-2670):
         * a failing command this unit marked ignorable is success as far as
         * the unit's own state is concerned, whatever its raw exit looked
         * like. ExecStartPre= is always the control process; ExecStart= is
         * the control process too under Type=forking (its child is the real
         * daemon), main otherwise.
         */
        if (f != SERVICE_SUCCESS &&
            ((is_control && s->state == SERVICE_START_PRE && s->exec_start_pre_ignore) ||
             (is_control && s->state == SERVICE_EXEC_START && s->type == SERVICE_TYPE_FORKING &&
              s->exec_start_ignore) ||
             (is_control && s->state == SERVICE_EXEC_STOP && s->exec_stop[s->exec_stop_idx].ignore) ||
             (is_control && service_list_command_ignore(s)) || (is_main && s->exec_start_ignore))) {
                pico_log(PICO_LOG_DEBUG,
                         "%s: %s process failed, but its %s= line is marked '-', ignoring",
                         UNIT(s)->id,
                         is_control ? "control" : "main",
                         service_command_name(s, is_control));
                f = SERVICE_SUCCESS;
        }

        /* ExecCondition='s own exit space, after the '-' rule as upstream
         * orders it: 1-254 means "condition not met". 255, a signal, and
         * pico-init's setup codes (already SERVICE_FAILURE_RESOURCES above)
         * stay failures -- a condition that could not run must not pass for
         * one that said no. */
        if (is_control && s->state == SERVICE_CONDITION && f == SERVICE_FAILURE_EXIT_CODE && status < 255)
                f = SERVICE_SKIP_CONDITION;

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
        pico_log(service_result_is_failure(s->result) ? PICO_LOG_WARNING : PICO_LOG_DEBUG,
                 "%s: %s process exited, code=%s, status=%s, result=%s",
                 UNIT(s)->id,
                 is_control ? "control" : "main",
                 sigchld_code_to_string(code),
                 statusbuf,
                 service_result_to_string(s->result));

        if (is_control) {
                if (s->state == SERVICE_CONDITION) {
                        /* Every line must pass; the first that does not
                         * ends the chain, a skip and a failure alike, and
                         * the start unwinds through ExecStopPost=. */
                        s->control_pid = 0;
                        if (f == SERVICE_SUCCESS && s->exec_condition_idx + 1 < s->n_exec_condition) {
                                s->exec_condition_idx++;
                                service_run_exec_condition(s);
                                return;
                        }

                        if (f == SERVICE_SUCCESS)
                                service_enter_start_pre_or_start(s);
                        else {
                                /* Upstream's condition_result = false: the
                                 * start job completes, with no "Started"
                                 * line for a unit that never started. */
                                if (f == SERVICE_SKIP_CONDITION) {
                                        UNIT(s)->condition_result = false;
                                        pico_log(PICO_LOG_INFO,
                                                 "%s: ExecCondition= %s not met, skipping start",
                                                 UNIT(s)->id,
                                                 s->exec_condition[s->exec_condition_idx].argv[0]);
                                }
                                service_enter_stop(s);
                        }
                } else if (s->state == SERVICE_START_PRE) {
                        s->control_pid = 0;
                        if (f == SERVICE_SUCCESS)
                                service_enter_start(s);
                        else
                                service_enter_stop(s);
                } else if (s->state == SERVICE_EXEC_START && s->type == SERVICE_TYPE_FORKING) {
                        /*
                         * The whole point of forking: the parent exiting IS
                         * the start completing, never a failure by itself.
                         * Its exit status still decides whether the start
                         * worked (a daemon that could not bind its port
                         * exits non-zero before ever forking). control_pid
                         * stays set through the search so the pid-file and
                         * cgroup checks can exclude the zombie by number.
                         */
                        if (f == SERVICE_SUCCESS)
                                service_forking_locate_main_pid(s);
                        s->control_pid = 0;
                        service_enter_running(s); /* s->result routes the failure case */
                } else if (s->state == SERVICE_EXEC_STOP) {
                        /* The next line only after a success, as with v30's
                         * control_command_next; a failure (already logged
                         * above, already in s->result) skips the rest and
                         * the stop carries on to the signal phase. */
                        s->control_pid = 0;
                        if (f == SERVICE_SUCCESS && s->exec_stop_idx + 1 < s->n_exec_stop) {
                                s->exec_stop_idx++;
                                service_run_exec_stop(s);
                                return;
                        }

                        if (f != SERVICE_SUCCESS)
                                pico_log(PICO_LOG_WARNING,
                                         "%s: ExecStop= command %s failed, stopping anyway",
                                         UNIT(s)->id,
                                         s->exec_stop[s->exec_stop_idx].argv[0]);
                        service_enter_stop(s);
                } else if (s->state == SERVICE_STOP_POST) {
                        /* ExecStop='s chain rule. Whatever the chain left in
                         * the cgroup is killed outright, the just-exited
                         * control pid excluded by number while still set. */
                        if (f == SERVICE_SUCCESS && s->exec_stop_post_idx + 1 < s->n_exec_stop_post) {
                                s->control_pid = 0;
                                s->exec_stop_post_idx++;
                                service_run_exec_stop_post(s);
                                return;
                        }

                        if (f != SERVICE_SUCCESS && s->exec_stop_post_idx < s->n_exec_stop_post)
                                pico_log(PICO_LOG_WARNING,
                                         "%s: ExecStopPost= command %s failed",
                                         UNIT(s)->id,
                                         s->exec_stop_post[s->exec_stop_post_idx].argv[0]);
                        service_signal_cgroup_rest(s, SIGKILL);
                        s->control_pid = 0;
                        service_enter_dead(s);
                } else if (s->state == SERVICE_STOP && main_pid_good(s) == 0) {
                        s->control_pid = 0;
                        /* The rest of the cgroup was signalled too: its
                         * cgroup-empty event, or the stop timeout, ends it. */
                        if (service_cgroup_populated(s) == 0)
                                service_enter_stop_post(s);
                } else
                        s->control_pid = 0;
                return;
        }

        /* is_main */
        s->main_exit_code = code;
        s->main_exit_status = status;
        s->main_pid = 0;

        switch (s->state) {
        case SERVICE_EXEC_START:
                /*
                 * Type=notify: only READY=1 ever makes this service active,
                 * so a main process that exits "cleanly" first never was,
                 * and RemainAfterExit= has nothing to keep. Upstream's
                 * SERVICE_FAILURE_PROTOCOL, minus its NotifyAccess=all
                 * escape (some other cgroup member might still send READY),
                 * which pico-init does not attribute anyway.
                 */
                if (s->type == SERVICE_TYPE_NOTIFY && s->result == SERVICE_SUCCESS) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: main process exited before sending READY=1 (Type=notify)",
                                 UNIT(s)->id);
                        s->result = SERVICE_FAILURE_PROTOCOL;
                }
                /* fall through */
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
                /* Not dead while the rest of the cgroup is still exiting:
                 * its cgroup-empty event, or the stop timeout, ends it. */
                if (control_pid_good(s) == 0 && service_cgroup_populated(s) == 0)
                        service_enter_stop_post(s);
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
        if (control_pid_good(s) != 0)
                return;

        if (main_pid_good(s) != 0) {
                /*
                 * An alien main pid (Type=forking, MAINPID=) is not one this
                 * process forked; its SIGCHLD still arrives as PID 1 or as
                 * the subreaper manager.c makes a non-PID-1 manager, and
                 * that SIGCHLD carries the exit status this event cannot
                 * (abaf5edd08 above) -- so as long as the pid still exists,
                 * as a zombie awaiting our own reap, wait for it exactly as
                 * for a child of ours. Only a pid that no longer exists at
                 * all was reaped by a foreign init and will never be
                 * reported here: then it is gone with an unknowable status,
                 * and s->result is left untouched. A liveness probe is safe
                 * in this path precisely because it is not SIGCHLD handling
                 * (manager-loop.c): the zombie answer is the wanted one.
                 */
                if (!s->main_pid_alien)
                        return;
                if (kill(s->main_pid, 0) == 0 || errno == EPERM)
                        return;

                pico_log(PICO_LOG_DEBUG,
                         "%s: cgroup empty and main pid %d (not our child) already reaped elsewhere, exit status unknown",
                         UNIT(s)->id,
                         (int) s->main_pid);
                s->main_pid = 0;
                s->main_pid_alien = false;
        }

        switch (s->state) {
        case SERVICE_CONDITION:
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

void service_notify_ready(Service *s) {
        if (!s)
                return;

        if (s->type != SERVICE_TYPE_NOTIFY || s->state != SERVICE_EXEC_START)
                return;

        pico_log(PICO_LOG_DEBUG, "%s: READY=1 received, start complete", UNIT(s)->id);
        service_enter_running(s);
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

/* v30's SERVICE_STOP timeout: give up on the ExecStop= chain and move on to
 * SIGTERM, which reaches the stop command too, with the stop timeout armed
 * afresh for that phase. */
static void service_timer_exec_stop_timeout(void *userdata, usec_t now) {
        Service *s = userdata;
        (void) now;

        pico_log(PICO_LOG_WARNING, "%s: ExecStop= timed out, terminating", UNIT(s)->id);

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
                service_enter_stop_post(s);
}

/* Upstream's STOP_POST timeout: kill the running line and whatever else is
 * left, run no further line, and let the control process's SIGCHLD finish
 * the unit. */
static void service_timer_stop_post_timeout(void *userdata, usec_t now) {
        Service *s = userdata;
        (void) now;

        pico_log(PICO_LOG_WARNING,
                 "%s: ExecStopPost= command %s timed out, killing",
                 UNIT(s)->id,
                 s->exec_stop_post[s->exec_stop_post_idx].argv[0]);

        if (s->result == SERVICE_SUCCESS)
                s->result = SERVICE_FAILURE_TIMEOUT;

        /* One past the last line: the chain is abandoned, and the killed
         * line's SIGCHLD neither continues it nor counts as '-'-ignorable. */
        s->exec_stop_post_idx = s->n_exec_stop_post;

        if (s->cgroup)
                cgroup_v2_kill(s->cgroup);
        else if (control_pid_good(s) > 0)
                kill(s->control_pid, SIGKILL);

        if (control_pid_good(s) == 0)
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

        (void) service_do_start(s); /* no job to fail: AUTO_RESTART -> FAILED notifies */
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

static bool exec_commands_are_valid(const ServiceExecCommand *cmds, unsigned n) {
        unsigned i;

        for (i = 0; i < n; i++)
                if (!exec_line_is_valid(cmds[i].argv))
                        return false;

        return true;
}

int service_verify(Service *s) {
        unsigned i;

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

        for (i = 0; i < s->n_exec_stop; i++)
                if (!exec_line_is_valid(s->exec_stop[i].argv)) {
                        pico_log(PICO_LOG_ERR, "%s: invalid ExecStop=, refusing to load", UNIT(s)->id);
                        return -ENOEXEC;
                }

        if (!exec_commands_are_valid(s->exec_condition, s->n_exec_condition) ||
            !exec_commands_are_valid(s->exec_stop_post, s->n_exec_stop_post) ||
            !exec_commands_are_valid(s->exec_reload, s->n_exec_reload)) {
                pico_log(PICO_LOG_ERR,
                         "%s: invalid ExecCondition=, ExecStopPost= or ExecReload=, refusing to load",
                         UNIT(s)->id);
                return -ENOEXEC;
        }

        /* Type=oneshot + Restart=on-failure is legal in modern systemd
         * (the old blanket ban is not carried forward) -- nothing to check. */

        return 0;
}

/* --- string tables --- */

static const char * const service_type_table[_SERVICE_TYPE_MAX] = {
        [SERVICE_TYPE_SIMPLE] = "simple", [SERVICE_TYPE_ONESHOT] = "oneshot", [SERVICE_TYPE_EXEC] = "exec",
        [SERVICE_TYPE_NOTIFY] = "notify", [SERVICE_TYPE_FORKING] = "forking",
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
        [SERVICE_DEAD] = "dead",           [SERVICE_CONDITION] = "condition",
        [SERVICE_START_PRE] = "start-pre", [SERVICE_EXEC_START] = "exec-start",
        [SERVICE_RUNNING] = "running",     [SERVICE_EXITED] = "exited",
        [SERVICE_EXEC_STOP] = "exec-stop", [SERVICE_STOP] = "stop",
        [SERVICE_STOP_POST] = "stop-post", [SERVICE_AUTO_RESTART] = "auto-restart",
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
        [SERVICE_SUCCESS] = "success",           [SERVICE_FAILURE_RESOURCES] = "resources",
        [SERVICE_FAILURE_TIMEOUT] = "timeout",   [SERVICE_FAILURE_EXIT_CODE] = "exit-code",
        [SERVICE_FAILURE_SIGNAL] = "signal",     [SERVICE_FAILURE_START_LIMIT] = "start-limit-hit",
        [SERVICE_FAILURE_PROTOCOL] = "protocol", [SERVICE_SKIP_CONDITION] = "exec-condition",
};

const char *service_result_to_string(ServiceResult r) {
        if (r < 0 || r >= _SERVICE_RESULT_MAX)
                return "invalid";

        return service_result_table[r];
}

void service_exec_stop_clear(Service *s) {
        unsigned i;

        for (i = 0; i < s->n_exec_stop; i++)
                pico_strv_free(s->exec_stop[i].argv);

        s->exec_stop = pico_mfree(s->exec_stop);
        s->n_exec_stop = 0;
        s->exec_stop_idx = 0;
}

void service_exec_commands_free(ServiceExecCommand **cmds, unsigned *n) {
        unsigned i;

        for (i = 0; i < *n; i++)
                pico_strv_free((*cmds)[i].argv);

        *cmds = pico_mfree(*cmds);
        *n = 0;
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
        s->exec_fd = -1;
        s->guess_main_pid = true; /* GuessMainPID= defaults to yes */
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
        service_exec_stop_clear(s);
        service_exec_commands_free(&s->exec_condition, &s->n_exec_condition);
        service_exec_commands_free(&s->exec_stop_post, &s->n_exec_stop_post);
        service_exec_commands_free(&s->exec_reload, &s->n_exec_reload);
        s->environment = pico_strv_free(s->environment);
        s->environment_files = pico_strv_free(s->environment_files);
        s->user = pico_mfree(s->user);
        s->group = pico_mfree(s->group);
        s->pid_file = pico_mfree(s->pid_file);
        s->status_text = pico_mfree(s->status_text);

        /*
         * Cancel before freeing, never after. A pending event holds
         * &s->timer_event as its owner slot (see timer.h), so an event left
         * queued past this point would write into freed memory when it fires.
         */
        if (s->timer_event && u->manager && u->manager->timer)
                pico_timer_cancel(u->manager->timer, s->timer_event);
        s->timer_event = NULL;

        service_exec_fd_close(s); /* same hazard as the timer: a source outliving its Service */

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

        case SERVICE_CONDITION:
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

        case SERVICE_EXEC_STOP:
        case SERVICE_STOP:
        case SERVICE_STOP_POST:
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
