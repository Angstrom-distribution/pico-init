/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Target units. Deliberately thin: a target owns no process and no resources,
 * so starting one is just a state change plus the notification that completes
 * its job. Everything that makes a target useful -- pulling in the units it
 * Wants=, honouring the order they must run in -- is the job engine walking
 * edges, not anything this file does.
 *
 * This file is written fresh rather than quarried; systemd's target.c at the
 * quarry point is mostly cgroup-v1 and D-Bus plumbing pico-init does not have.
 */

#include <errno.h>

#include "target.h"
#include "unit.h"
#include "util.h"

static UnitActiveState target_active_state_of(TargetState s) {
        return s == TARGET_ACTIVE ? UNIT_ACTIVE : UNIT_INACTIVE;
}

static void target_set_state(Target *t, TargetState state) {
        UnitActiveState old_active;
        TargetState old;

        old = t->state;
        if (old == state)
                return;

        old_active = target_active_state_of(old);
        t->state = state;

        unit_notify(TARGET_UNIT(t), old_active, target_active_state_of(state));
}

int target_start(Target *t) {
        if (!t)
                return -EINVAL;

        if (t->state == TARGET_ACTIVE)
                return 0; /* idempotent */

        pico_log(PICO_LOG_DEBUG, "%s: reached", TARGET_UNIT(t)->id);
        target_set_state(t, TARGET_ACTIVE);

        return 0;
}

int target_stop(Target *t) {
        if (!t)
                return -EINVAL;

        if (t->state == TARGET_DEAD)
                return 0;

        target_set_state(t, TARGET_DEAD);

        return 0;
}

static const char * const target_state_table[_TARGET_STATE_MAX] = {
        [TARGET_DEAD] = "dead",
        [TARGET_ACTIVE] = "active",
};

const char *target_state_to_string(TargetState s) {
        if (s < 0 || s >= _TARGET_STATE_MAX)
                return "invalid";

        return target_state_table[s];
}

/* --- vtable thunks --- */

static void target_init(Unit *u) {
        TARGET(u)->state = TARGET_DEAD;
}

static int target_start_thunk(Unit *u) {
        return target_start(TARGET(u));
}

static int target_stop_thunk(Unit *u) {
        return target_stop(TARGET(u));
}

static UnitActiveState target_active_state_thunk(Unit *u) {
        return target_active_state_of(TARGET(u)->state);
}

/* No done() hook: a Target owns nothing beyond the Unit fields unit_free()
 * already handles. */
const UnitVTable target_vtable = {
        .object_size = sizeof(Target),
        .init = target_init,
        .done = NULL,
        .start = target_start_thunk,
        .stop = target_stop_thunk,
        .active_state = target_active_state_thunk,
};
