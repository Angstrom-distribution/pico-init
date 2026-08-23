/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Service units, Type=simple only. State machine per the plan:
 * DEAD -> START_PRE -> EXEC_START -> RUNNING -> EXITED/FAILED, with
 * Restart=/RestartSec= and start/stop timeouts. service.c implements the
 * state machine, service-exec.c the fork/exec + fd/env setup.
 */

#pragma once

#include <sys/types.h>

#include "cgroups-v2.h"
#include "unit.h"
#include "util.h"

typedef enum ServiceState {
        SERVICE_DEAD,
        SERVICE_START_PRE,  /* ExecStartPre= running */
        SERVICE_EXEC_START, /* ExecStart= forked, main pid not yet confirmed running */
        SERVICE_RUNNING,
        SERVICE_EXITED, /* main process gone, cgroup empty, clean exit */
        SERVICE_FAILED,
        _SERVICE_STATE_MAX,
} ServiceState;

typedef enum ServiceRestart {
        SERVICE_RESTART_NO,
        SERVICE_RESTART_ON_FAILURE,
        _SERVICE_RESTART_MAX,
} ServiceRestart;

typedef struct Service {
        Unit unit; /* must be first: a Service* is a Unit* */

        ServiceState state;

        /* argv-style NULL-terminated vectors, owned */
        char **exec_start_pre; /* may be NULL */
        char **exec_start;

        pid_t main_pid;       /* 0 when no main process */
        int main_exit_status; /* waitpid status of the last main-process exit */

        struct pico_cgroup *cgroup; /* owned, NULL until started */

        ServiceRestart restart;
        usec_t restart_usec;       /* RestartSec= */
        usec_t timeout_start_usec; /* TimeoutStartSec= */
        usec_t timeout_stop_usec;  /* TimeoutStopSec= */
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

const char *service_state_to_string(ServiceState s);
const char *service_restart_to_string(ServiceRestart r);

/* --- service-exec.c --- */
/* fork/exec argv into s's cgroup with fds/env set up; child pid via ret_pid. 0 or -errno. */
int service_spawn(Service *s, char **argv, pid_t *ret_pid);
