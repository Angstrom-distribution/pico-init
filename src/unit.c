/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Unit lifecycle, per-type dispatch and name validation. The concrete unit
 * types live in service.c and target.c; everything generic to "a unit" is
 * here, reached through the UnitVTable each type exports.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "job.h"
#include "unit.h"
#include "util.h"

const UnitVTable *unit_vtable_for(UnitType t) {
        switch (t) {
        case UNIT_SERVICE:
                return &service_vtable;
        case UNIT_TARGET:
                return &target_vtable;
        default:
                return NULL;
        }
}

int unit_new(Manager *m, UnitType type, const char *id, Unit **ret) {
        const UnitVTable *vtable;
        Unit *u;

        if (!ret)
                return -EINVAL;

        *ret = NULL;

        /* Validate before the name is ever used to build a path. */
        if (!unit_name_is_valid(id))
                return -EINVAL;

        vtable = unit_vtable_for(type);
        if (!vtable)
                return -EINVAL;

        /*
         * vtable->object_size, never sizeof(Unit): a Service is several times
         * larger than the base type it embeds, and allocating only the base
         * would corrupt the heap on the first write to a Service field.
         */
        u = calloc(1, vtable->object_size);
        if (!u)
                return -ENOMEM;

        u->manager = m;
        u->type = type;
        u->vtable = vtable;
        u->load_state = UNIT_STUB;

        u->id = pico_strdup(id);
        if (!u->id) {
                free(u);
                return -ENOMEM;
        }

        if (vtable->init)
                vtable->init(u);

        *ret = u;
        return 0;
}

Unit *unit_free(Unit *u) {
        size_t i;

        if (!u)
                return NULL;

        /*
         * Per-type teardown first. Only the concrete type knows what it owns
         * -- a Service holds two argv vectors, a cgroup and possibly a queued
         * timer event -- so without this hook every started service leaked all
         * of them. The base type cannot guess at any of it.
         */
        if (u->vtable && u->vtable->done)
                u->vtable->done(u);

        u->id = pico_mfree(u->id);
        u->description = pico_mfree(u->description);
        u->fragment_path = pico_mfree(u->fragment_path);

        for (i = 0; i < _UNIT_DEPENDENCY_MAX; i++) {
                /* the arrays are owned; the Unit* inside them are borrowed */
                u->dependencies[i] = pico_mfree(u->dependencies[i]);
                u->n_dependencies[i] = 0;
        }

        u->wanted_by = pico_strv_free(u->wanted_by);
        u->required_by = pico_strv_free(u->required_by);

        free(u);

        return NULL;
}

UnitActiveState unit_active_state(Unit *u) {
        if (!u || !u->vtable || !u->vtable->active_state)
                return UNIT_INACTIVE;

        return u->vtable->active_state(u);
}

int unit_start(Unit *u) {
        if (!u || !u->vtable || !u->vtable->start)
                return -ENOSYS;

        if (u->load_state != UNIT_LOADED) {
                pico_log(PICO_LOG_WARNING,
                         "%s: refusing to start, load state is %s",
                         u->id,
                         unit_load_state_to_string(u->load_state));
                return -ENOENT;
        }

        return u->vtable->start(u);
}

int unit_stop(Unit *u) {
        if (!u || !u->vtable || !u->vtable->stop)
                return -ENOSYS;

        return u->vtable->stop(u);
}

void unit_notify(Unit *u, UnitActiveState old_state, UnitActiveState new_state) {
        Job *j;

        if (!u || old_state == new_state)
                return;

        pico_log(PICO_LOG_DEBUG,
                 "%s: %s -> %s",
                 u->id,
                 unit_active_state_to_string(old_state),
                 unit_active_state_to_string(new_state));

        j = u->job;
        if (!j || j->state != JOB_RUNNING)
                return;

        /*
         * Job completion lives here rather than in each unit type, so a type
         * only has to describe its own state changes and never has to know
         * what a job is waiting for.
         */
        switch (j->type) {
        case JOB_START:
                if (new_state == UNIT_ACTIVE)
                        job_finish(j, JOB_DONE);
                else if (new_state == UNIT_FAILED)
                        job_finish(j, JOB_FAILED);
                break;

        case JOB_STOP:
                if (new_state == UNIT_INACTIVE)
                        job_finish(j, JOB_DONE);
                else if (new_state == UNIT_FAILED)
                        job_finish(j, JOB_FAILED);
                break;

        case JOB_RESTART:
                /*
                 * TODO (M2): a restart is a stop that turns into a start once
                 * the unit is down. Upstream does that conversion inside
                 * job_finish() and nowhere else -- doing it at dispatch time
                 * is what lost the ordering in systemd's dd17d38879, and
                 * returning early after the conversion is what left dependent
                 * jobs waiting forever in 57981b9812. Leave it to job.c.
                 */
                break;

        default:
                break;
        }
}

static const char * const unit_type_table[_UNIT_TYPE_MAX] = {
        [UNIT_SERVICE] = "service",
        [UNIT_TARGET] = "target",
};

const char *unit_type_to_string(UnitType t) {
        if (t < 0 || t >= _UNIT_TYPE_MAX)
                return "invalid";

        return unit_type_table[t];
}

static const char * const unit_load_state_table[_UNIT_LOAD_STATE_MAX] = {
        [UNIT_STUB] = "stub",
        [UNIT_LOADED] = "loaded",
        [UNIT_ERROR] = "error",
};

const char *unit_load_state_to_string(UnitLoadState s) {
        if (s < 0 || s >= _UNIT_LOAD_STATE_MAX)
                return "invalid";

        return unit_load_state_table[s];
}

static const char * const unit_active_state_table[_UNIT_ACTIVE_STATE_MAX] = {
        [UNIT_INACTIVE] = "inactive",         [UNIT_ACTIVATING] = "activating", [UNIT_ACTIVE] = "active",
        [UNIT_DEACTIVATING] = "deactivating", [UNIT_FAILED] = "failed",
};

const char *unit_active_state_to_string(UnitActiveState s) {
        if (s < 0 || s >= _UNIT_ACTIVE_STATE_MAX)
                return "invalid";

        return unit_active_state_table[s];
}

UnitType unit_type_from_name(const char *id) {
        const char *suffix;

        if (!id)
                return _UNIT_TYPE_INVALID;

        suffix = strrchr(id, '.');
        if (!suffix)
                return _UNIT_TYPE_INVALID;

        if (strcmp(suffix, ".service") == 0)
                return UNIT_SERVICE;

        if (strcmp(suffix, ".target") == 0)
                return UNIT_TARGET;

        return _UNIT_TYPE_INVALID;
}

/*
 * The character set systemd itself accepts in a unit name (its
 * VALID_CHARS_WITH_AT in src/basic/unit-name.c): alphanumerics plus
 * ':-_.\@'. Matching it exactly is what keeps the drop-in
 * unit-file-compatibility goal honest -- a stricter set would reject names
 * real images ship, a looser one would accept paths.
 */
#define UNIT_NAME_VALID_CHARS        \
        "0123456789"                 \
        "abcdefghijklmnopqrstuvwxyz" \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
        ":-_.\\@"

bool unit_name_is_valid(const char *name) {
        size_t len;

        if (!name)
                return false;

        len = strlen(name);
        if (len == 0 || len > UNIT_NAME_MAX)
                return false;

        /*
         * A leading dot covers "." and ".." in one test, and also rejects the
         * hidden names that would never be a real fragment anyway.
         */
        if (name[0] == '.')
                return false;

        /*
         * One strspn() rejects '/', every whitespace and every control
         * character at once. That is the whole point: a Requires= value
         * reaches this function before it is ever concatenated into a path, so
         * "../../tmp/evil.service" cannot escape the search directories.
         */
        if (strspn(name, UNIT_NAME_VALID_CHARS) != len)
                return false;

        /* and it has to name a type we can actually instantiate */
        if (unit_type_from_name(name) == _UNIT_TYPE_INVALID)
                return false;

        return true;
}
