/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Service units. service.c implements the state machine, service-exec.c the
 * fork/exec + fd/cgroup setup.
 *
 * Type=simple and Type=oneshot are supported. oneshot is not a luxury: nearly
 * every real boot-plumbing unit is one, and an init that cannot express "run
 * once, then stay exited" cannot boot an unmodified image. The two differ only
 * in when the start job completes -- simple counts as started the moment the
 * process is forked, oneshot not until it has exited successfully.
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

typedef enum ServiceType {
        SERVICE_TYPE_SIMPLE,  /* started once forked */
        SERVICE_TYPE_ONESHOT, /* started once it has exited successfully */
        _SERVICE_TYPE_MAX,
        _SERVICE_TYPE_INVALID = -1,
} ServiceType;

typedef enum ServiceState {
        SERVICE_DEAD,
        SERVICE_START_PRE,    /* ExecStartPre= running */
        SERVICE_EXEC_START,   /* ExecStart= forked; for oneshot, still running */
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
        SERVICE_FAILURE_RESOURCES, /* fork/exec/cgroup setup failed */
        SERVICE_FAILURE_TIMEOUT,   /* TimeoutStartSec=/TimeoutStopSec= elapsed */
        SERVICE_FAILURE_EXIT_CODE, /* exited non-zero */
        SERVICE_FAILURE_SIGNAL,    /* killed by a signal */
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

        pid_t main_pid;       /* ExecStart= process, 0 when none */
        pid_t control_pid;    /* ExecStartPre= process, 0 when none */
        int main_exit_status; /* waitpid status of the last main-process exit */

        struct pico_cgroup *cgroup; /* owned, NULL until started */

        bool remain_after_exit; /* RemainAfterExit=: EXITED still counts as active */

        ServiceRestart restart;
        usec_t restart_usec;       /* RestartSec= */
        usec_t timeout_start_usec; /* TimeoutStartSec= */
        usec_t timeout_stop_usec;  /* TimeoutStopSec= */

        /*
         * The one in-flight timeout or restart delay. Owned, and managed by
         * pico_timer_add(..., &s->timer_event): the timer queue clears this
         * slot itself when the event fires or is cancelled, so it is NULL
         * exactly when no event is pending. It must be cancelled before the
         * Service is freed -- service_done() does that. See timer.h.
         */
        PicoTimerEvent *timer_event;

        unsigned n_restarts; /* how many times Restart= has fired, for logging */
} Service;

/* downcast/upcast helpers, valid because Unit is the first member */
#define SERVICE(u) ((Service *) (u))
#define UNIT(s) (&(s)->unit)

/* --- service.c --- */
int service_start(Service *s); /* DEAD -> START_PRE/EXEC_START */
int service_stop(Service *s);  /* SIGTERM, then cgroup_v2_kill on timeout */

/* SIGCHLD delivered for a pid belonging to this service */
void service_sigchld_event(Service *s, pid_t pid, int status);

/* cgroup.events reported populated=0 */
void service_cgroup_empty_event(Service *s);

const char *service_type_to_string(ServiceType t);
const char *service_state_to_string(ServiceState s);
const char *service_restart_to_string(ServiceRestart r);
const char *service_result_to_string(ServiceResult r);

/* --- service-exec.c --- */
/* fork/exec argv into s's cgroup with fds set up; child pid via ret_pid. 0 or -errno. */
int service_spawn(Service *s, char **argv, pid_t *ret_pid);
