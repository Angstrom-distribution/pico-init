/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Service units. service.c implements the state machine, service-exec.c the
 * fork/exec + fd/cgroup setup.
 *
 * Type=simple, oneshot, exec, notify and forking are supported
 * (notify-reload loads as notify with a recorded degradation). oneshot is
 * not a luxury: nearly every real boot-plumbing unit is one, and an init
 * that cannot express "run once, then stay exited" cannot boot an
 * unmodified image. The five differ only in when the start job completes --
 * simple counts as started the moment the process is forked, exec once
 * execve() has actually succeeded, notify once the process sends READY=1,
 * oneshot not until it has exited successfully, forking once the ExecStart=
 * process has exited successfully (it is a control process, never the main
 * one) and the daemon it left behind has been found through PIDFile= or, by
 * GuessMainPID=, as the sole survivor in the unit's cgroup.
 */

#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "cgroups-v2.h"
#include "timer.h"
#include "unit.h"
#include "util.h"

/* Where a service's stdout/stderr go until the journal (plan §3) exists. Not
 * /dev/null, which would make early hardware bring-up on h2200 miserable, and
 * not syslog, which would be a dependency PID1's own milestones do not need. */
#define PICO_CONSOLE_PATH "/dev/console"

/*
 * Exit codes service-exec.c's forked child _exit()s with when its own setup
 * fails, matching systemd.exec(5) numerically. The post-fork/pre-execve
 * region cannot report a failure any other way (no malloc, no logger --
 * see service-exec.c), so these are the sole channel back to the parent:
 * service_sigchld_event() recognizes them on a CLD_EXITED status and maps
 * every one of them to SERVICE_FAILURE_RESOURCES rather than treating them
 * as an ordinary nonzero ExecStart= exit, because they mean pico-init's own
 * setup failed, not the workload. Not every code here is currently
 * reachable (EXIT_CHDIR, EXIT_MEMORY: pico-init does none of
 * WorkingDirectory=/rlimits/MemoryLimit= yet) -- defined now so the mapping
 * table does not need revisiting when they become reachable.
 */
#define PICO_EXIT_CHDIR 200
#define PICO_EXIT_FDS 202
#define PICO_EXIT_EXEC 203
#define PICO_EXIT_MEMORY 204
#define PICO_EXIT_SIGNAL_MASK 207
#define PICO_EXIT_STDIN 208
#define PICO_EXIT_STDOUT 209
#define PICO_EXIT_GROUP 216 /* setgroups()/setgid() for Group= (or User='s primary group) failed */
#define PICO_EXIT_USER 217  /* setuid() for User= failed */
#define PICO_EXIT_CGROUP 219
#define PICO_EXIT_SETSID 220
#define PICO_EXIT_STDERR 222

typedef enum ServiceType {
        SERVICE_TYPE_SIMPLE,  /* started once forked */
        SERVICE_TYPE_ONESHOT, /* started once it has exited successfully */
        SERVICE_TYPE_EXEC,    /* started once execve() succeeded (exec_fd below) */
        SERVICE_TYPE_NOTIFY,  /* started once the main process sent READY=1 */
        SERVICE_TYPE_FORKING, /* started once ExecStart= exited 0 and the main pid was located */
        _SERVICE_TYPE_MAX,
        _SERVICE_TYPE_INVALID = -1,
} ServiceType;

typedef enum ServiceState {
        SERVICE_DEAD,
        SERVICE_START_PRE,    /* ExecStartPre= running */
        SERVICE_EXEC_START,   /* ExecStart= forked; oneshot: still running, exec: execve()
                               * not yet confirmed, notify: READY=1 not yet received,
                               * forking: the parent (control_pid) has not exited yet */
        SERVICE_RUNNING,      /* simple: main process up */
        SERVICE_EXITED,       /* main process gone, cgroup empty, clean exit */
        SERVICE_STOP,         /* SIGTERM sent, waiting for exit or TimeoutStopSec */
        SERVICE_AUTO_RESTART, /* waiting out RestartSec before starting again */
        SERVICE_FAILED,
        _SERVICE_STATE_MAX,
} ServiceState;

typedef enum ServiceRestart {
        SERVICE_RESTART_NO,
        SERVICE_RESTART_ON_FAILURE,
        _SERVICE_RESTART_MAX,
} ServiceRestart;

/* Why the service last stopped; drives Restart=on-failure and the job result. */
typedef enum ServiceResult {
        SERVICE_SUCCESS,
        SERVICE_FAILURE_RESOURCES,   /* fork/exec/cgroup setup failed */
        SERVICE_FAILURE_TIMEOUT,     /* TimeoutStartSec=/TimeoutStopSec= elapsed */
        SERVICE_FAILURE_EXIT_CODE,   /* exited non-zero */
        SERVICE_FAILURE_SIGNAL,      /* killed by a signal */
        SERVICE_FAILURE_START_LIMIT, /* B7: restarted too many times too fast, refusing */
        SERVICE_FAILURE_PROTOCOL,    /* Type=notify main process exited cleanly before READY=1 */
        _SERVICE_RESULT_MAX,
} ServiceResult;

typedef struct Service {
        Unit unit; /* must be first: a Service* is a Unit* */

        ServiceType type;
        ServiceState state;
        ServiceResult result;

        /* argv-style NULL-terminated vectors, owned */
        char **exec_start_pre; /* may be NULL */
        char **exec_start;

        /*
         * Environment=/EnvironmentFile=, parsed and stored only (E1); not yet
         * consumed at spawn time (E2). "NAME=value" strv and a strv of paths,
         * each optionally '-'-prefixed (missing file is not an error) -- the
         * prefix is kept in the stored string itself. Either may be NULL.
         */
        char **environment;
        char **environment_files;

        /*
         * User=/Group= as written (a name or a numeric id), owned, NULL when
         * unset. Resolved to ids in the PARENT at every spawn -- getpwnam()
         * and friends go through NSS and are not async-signal-safe, so only
         * the resulting integers ever cross fork() (service-exec.c). Group=
         * alone keeps uid 0; User= alone takes the account's primary group.
         */
        char *user;
        char *group;

        pid_t main_pid;    /* ExecStart= process, 0 when none; forking: the daemon left behind */
        pid_t control_pid; /* ExecStartPre= process, or forking's ExecStart= parent; 0 when none */

        /*
         * Type=forking's main-pid discovery. pid_file is PIDFile= as
         * written, absolute (a relative value was prefixed with /run/ at
         * parse), owned, NULL when unset. guess_main_pid is GuessMainPID=,
         * default yes: with no PIDFile=, the sole pid left in the cgroup once
         * the parent has exited is taken as the main process. main_pid_alien
         * marks a main_pid found either way rather than forked by this
         * process: its SIGCHLD still arrives (PID 1 inherits every orphan,
         * and a non-PID-1 manager makes itself a subreaper), but its exit
         * status is unknowable to anyone else, so a cgroup-empty event with
         * an alien main pid still set means "gone, status unknown" rather
         * than "SIGCHLD not yet processed" -- see service_cgroup_empty_event().
         */
        char *pid_file;
        bool guess_main_pid;
        bool main_pid_alien;

        /*
         * The last main-process exit, split rather than a packed waitpid()
         * status (B2): main_exit_code is siginfo_t.si_code (CLD_EXITED /
         * CLD_KILLED / CLD_DUMPED), main_exit_status is si_status. A packed
         * status cannot tell CLD_KILLED from CLD_DUMPED without WCOREDUMP,
         * and that distinction is load-bearing for pico_is_clean_exit() in
         * service.c: a core dump is never clean, for any signal, ever.
         */
        int main_exit_code;
        int main_exit_status;

        struct pico_cgroup *cgroup; /* owned, NULL until started */

        bool remain_after_exit; /* RemainAfterExit=: EXITED still counts as active */

        /*
         * Set by service_stop(): an explicit stop is the one thing Restart=
         * must never turn back into a start. Cleared again by service_start()
         * so a fresh explicit start is not permanently vetoed by an old stop.
         */
        bool forbid_restart;

        ServiceRestart restart;
        usec_t restart_usec;       /* RestartSec=; 0 means restart immediately, NOT never */
        usec_t timeout_start_usec; /* TimeoutStartSec=; USEC_INFINITY means never time out */
        usec_t timeout_stop_usec;  /* TimeoutStopSec=; USEC_INFINITY means never time out */

        /*
         * B7: start-rate limiting. v30 already had this (a quarrying
         * regression to have dropped it, not a deferred feature -- see
         * service.c); these four are deliberately not parseable unit-file
         * settings, only upstream's hardcoded defaults (10s / 5 starts,
         * still real upstream defaults today). start_limit_begin anchors a
         * fixed window at the first attempt in it; start_limit_num counts
         * attempts inside that window; a successful start does not reset
         * either, only window expiry does.
         */
        usec_t start_limit_interval;
        unsigned start_limit_burst;
        usec_t start_limit_begin;
        unsigned start_limit_num;

        /*
         * The one in-flight timeout or restart delay. Owned, and managed by
         * pico_timer_add(..., &s->timer_event): the timer queue clears this
         * slot itself when the event fires or is cancelled, so it is NULL
         * exactly when no event is pending. It must be cancelled before the
         * Service is freed -- service_done() does that. See timer.h.
         */
        PicoTimerEvent *timer_event;

        unsigned n_restarts; /* how many times Restart= has fired, for logging */

        /*
         * sd_notify() state (manager-notify.c). For Type=notify, READY=1
         * from the main pid is what moves EXEC_START to RUNNING
         * (service_notify_ready()); for every other type notify_ready is
         * informational only. All three reset on every fresh
         * service_do_start() so a restart never carries a stale value.
         */
        bool notify_ready;
        char *status_text; /* owned, STATUS= from sd_notify, bounded */
        int status_errno;

        /*
         * Type=exec's readiness channel: the read end of an O_CLOEXEC pipe
         * whose write end the child holds across execve(). The child writes
         * a 1 right before execve() and a 0 right after a failed one; a
         * successful execve() closes the write end instead, so EOF after a
         * 1 is the "execve() succeeded" signal and nothing else is. -1 and
         * NULL when no start is waiting on one; the source owns the fd.
         */
        int exec_fd;
        sd_event_source *exec_fd_source;
        bool exec_fd_hot; /* the 1 has been read, EOF now means success */
} Service;

/* downcast/upcast helpers, valid because Unit is the first member */
#define SERVICE(u) ((Service *) (u))
#define UNIT(s) (&(s)->unit)

/* --- service.c --- */
int service_start(Service *s); /* DEAD -> START_PRE/EXEC_START */
int service_stop(Service *s);  /* SIGTERM, then cgroup_v2_kill on timeout */

/*
 * B9/CVE-2021-4034-class load-time validation: refuse a unit whose
 * ExecStart=/ExecStartPre= would reach execve() with a NULL or empty argv[0]
 * (the PwnKit primitive -- no PAM/seccomp/namespaces stand between pico-init
 * and it) or a non-absolute path. Called by unit_parse_file() once a
 * [Service] fragment has finished parsing. 0 or -ENOEXEC.
 */
int service_verify(Service *s);

/*
 * SIGCHLD delivered for a pid belonging to this service.
 *
 * `code` is siginfo_t.si_code (CLD_EXITED / CLD_KILLED / CLD_DUMPED) and
 * `status` is si_status. The two are separate because waitpid()'s packed
 * status cannot distinguish CLD_KILLED from CLD_DUMPED without WCOREDUMP,
 * and that distinction is load-bearing: a signal death may count as a clean
 * exit for a long-running daemon, but a core dump never counts as clean for
 * anything. Reap with waitid() so both arrive intact.
 */
void service_sigchld_event(Service *s, pid_t pid, int code, int status);

/* cgroup.events reported populated=0 */
void service_cgroup_empty_event(Service *s);

/* READY=1 arrived from the main pid (manager-notify.c). Completes the start
 * of a Type=notify service still in EXEC_START; a no-op for every other
 * type and state. */
void service_notify_ready(Service *s);

const char *service_type_to_string(ServiceType t);
const char *service_state_to_string(ServiceState s);
const char *service_restart_to_string(ServiceRestart r);
const char *service_result_to_string(ServiceResult r);

/* --- service-exec.c --- */
/* fork/exec argv into s's cgroup with fds set up; child pid via ret_pid. 0 or -errno. */
int service_spawn(Service *s, char **argv, pid_t *ret_pid);
