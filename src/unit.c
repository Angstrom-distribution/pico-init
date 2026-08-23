/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M0 placeholder: allocation/free and the string tables are real, but
 * lifecycle transitions (unit_start/unit_stop dispatch, unit_active_state)
 * are stub bodies returning -ENOSYS or a fixed default. Real dispatch to
 * the concrete unit type lands once service.c grows a state machine.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "unit.h"
#include "util.h"

int unit_new(Manager *m, UnitType type, const char *id, Unit **ret) {
        (void) m;
        (void) type;
        (void) id;

        if (ret)
                *ret = NULL;

        return -ENOSYS;
}

Unit *unit_free(Unit *u) {
        size_t i;

        if (!u)
                return NULL;

        u->id = pico_mfree(u->id);
        u->description = pico_mfree(u->description);
        u->fragment_path = pico_mfree(u->fragment_path);

        for (i = 0; i < _UNIT_DEPENDENCY_MAX; i++)
                u->dependencies[i] = pico_mfree(u->dependencies[i]);

        free(u);

        return NULL;
}

UnitActiveState unit_active_state(Unit *u) {
        (void) u;
        return UNIT_INACTIVE;
}

int unit_start(Unit *u) {
        (void) u;
        return -ENOSYS;
}

int unit_stop(Unit *u) {
        (void) u;
        return -ENOSYS;
}

static const char * const unit_type_table[_UNIT_TYPE_MAX] = {
        [UNIT_SERVICE] = "service",
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

        return _UNIT_TYPE_INVALID;
}
