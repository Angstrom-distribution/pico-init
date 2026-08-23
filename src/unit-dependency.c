/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M0 placeholder: edge insertion (unit_add_dependency) and the DFS cycle
 * detector are stub bodies -- real graph management lands once unit_load()
 * actually produces loaded units to link together. detect_cycles defaults
 * to "no cycles" since M0 never builds a graph to walk.
 */

#include <errno.h>

#include "manager.h"
#include "unit.h"

int unit_add_dependency(Unit *u, UnitDependency d, Unit *other) {
        (void) u;
        (void) d;
        (void) other;
        return -ENOSYS;
}

int unit_dependency_detect_cycles(Manager *m) {
        (void) m;
        return 0;
}

static const char * const unit_dependency_table[_UNIT_DEPENDENCY_MAX] = {
        [UNIT_REQUIRES] = "Requires",
        [UNIT_WANTS] = "Wants",
        [UNIT_BEFORE] = "Before",
        [UNIT_AFTER] = "After",
};

const char *unit_dependency_to_string(UnitDependency d) {
        if (d < 0 || d >= _UNIT_DEPENDENCY_MAX)
                return "invalid";

        return unit_dependency_table[d];
}
