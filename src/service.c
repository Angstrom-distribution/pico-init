/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Service units. The vtable, the defaults and the string tables are real;
 * the state machine itself (service_start/service_stop and the SIGCHLD and
 * cgroup-empty hooks) lands in M3, quarried from systemd's service.c.
 */

#include <errno.h>
#include <stdlib.h>

#include "manager.h"
#include "service.h"
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

int service_start(Service *s) {
        (void) s;
        return -ENOSYS; /* TODO (M3): DEAD -> START_PRE/EXEC_START */
}

int service_stop(Service *s) {
        (void) s;
        return -ENOSYS; /* TODO (M3): SIGTERM, then cgroup_v2_kill on timeout */
}

void service_sigchld_event(Service *s, pid_t pid, int status) {
        (void) s;
        (void) pid;
        (void) status;
        /* TODO (M3) */
}

void service_cgroup_empty_event(Service *s) {
        (void) s;
        /* TODO (M3) */
}

static const char * const service_type_table[_SERVICE_TYPE_MAX] = {
        [SERVICE_TYPE_SIMPLE] = "simple",
        [SERVICE_TYPE_ONESHOT] = "oneshot",
};

const char *service_type_to_string(ServiceType t) {
        if (t < 0 || t >= _SERVICE_TYPE_MAX)
                return "invalid";

        return service_type_table[t];
}

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
        [SERVICE_FAILURE_SIGNAL] = "signal",
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

        /*
         * Cancel before freeing, never after. A pending event holds
         * &s->timer_event as its owner slot (see timer.h), so an event left
         * queued past this point would write into freed memory when it fires.
         */
        if (s->timer_event && u->manager && u->manager->timer)
                pico_timer_cancel(u->manager->timer, s->timer_event);
        s->timer_event = NULL;

        s->cgroup = cgroup_v2_free(s->cgroup);
}

static int service_start_thunk(Unit *u) {
        return service_start(SERVICE(u));
}

static int service_stop_thunk(Unit *u) {
        return service_stop(SERVICE(u));
}

static UnitActiveState service_active_state_thunk(Unit *u) {
        Service *s = SERVICE(u);

        switch (s->state) {
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
                 * its process is gone. */
                return s->remain_after_exit ? UNIT_ACTIVE : UNIT_INACTIVE;

        case SERVICE_STOP:
                return UNIT_DEACTIVATING;

        case SERVICE_FAILED:
                return UNIT_FAILED;

        default:
                return UNIT_INACTIVE;
        }
}

const UnitVTable service_vtable = {
        .object_size = sizeof(Service),
        .init = service_init,
        .done = service_done,
        .start = service_start_thunk,
        .stop = service_stop_thunk,
        .active_state = service_active_state_thunk,
};
