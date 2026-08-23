/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Base Unit type every unit kind embeds (as its first member), plus the
 * dependency graph. Implemented across unit.c (lifecycle/state),
 * unit-load.c (fragment lookup + load queue), unit-parse.c (INI parser),
 * unit-dependency.c (DAG build + cycle detection).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct Unit Unit;

/* forward declarations; full definitions in manager.h / job.h */
typedef struct Manager Manager;
typedef struct Job Job;

typedef enum UnitType {
        UNIT_SERVICE,
        _UNIT_TYPE_MAX,
        _UNIT_TYPE_INVALID = -1,
} UnitType;

typedef enum UnitLoadState {
        UNIT_STUB,   /* created, fragment not read yet */
        UNIT_LOADED, /* fragment parsed successfully */
        UNIT_ERROR,  /* fragment missing or malformed */
        _UNIT_LOAD_STATE_MAX,
} UnitLoadState;

typedef enum UnitActiveState {
        UNIT_INACTIVE,
        UNIT_ACTIVATING,
        UNIT_ACTIVE,
        UNIT_DEACTIVATING,
        UNIT_FAILED,
        _UNIT_ACTIVE_STATE_MAX,
} UnitActiveState;

/* Before/After are ordering, Requires/Wants are dependency -- distinct concepts */
typedef enum UnitDependency {
        UNIT_REQUIRES,
        UNIT_WANTS,
        UNIT_BEFORE,
        UNIT_AFTER,
        _UNIT_DEPENDENCY_MAX,
} UnitDependency;

struct Unit {
        Manager *manager;
        UnitType type;

        char *id;            /* "foo.service" */
        char *description;   /* [Unit] Description=, may be NULL */
        char *fragment_path; /* absolute path of the parsed file, NULL until found */
        UnitLoadState load_state;

        /* dependency graph: per-relation NULL-terminated arrays of borrowed Unit* */
        Unit **dependencies[_UNIT_DEPENDENCY_MAX];
        size_t n_dependencies[_UNIT_DEPENDENCY_MAX];

        Job *job; /* job currently applying to this unit, or NULL (borrowed) */

        /* intrusive load-queue link (see manager.h) */
        Unit *load_queue_next;
        bool in_load_queue;

        /* DFS generation marker for cycle detection, owned by unit-dependency.c */
        unsigned dep_generation;
};

/* --- unit.c --- */
int unit_new(Manager *m, UnitType type, const char *id, Unit **ret);
Unit *unit_free(Unit *u); /* returns NULL */

UnitActiveState unit_active_state(Unit *u);
int unit_start(Unit *u); /* dispatches to the concrete type, e.g. service_start */
int unit_stop(Unit *u);

const char *unit_type_to_string(UnitType t);
const char *unit_load_state_to_string(UnitLoadState s);
const char *unit_active_state_to_string(UnitActiveState s);
UnitType unit_type_from_name(const char *id); /* by suffix; _UNIT_TYPE_INVALID if unknown */

/* --- unit-load.c --- */
/* Find u->id's fragment in the search path, parse it, resolve to LOADED/ERROR. 0 or -errno. */
int unit_load(Unit *u);

/* --- unit-parse.c --- */
/* Parse one INI fragment (sections, escapes, line continuations) into u. 0 or -errno. */
int unit_parse_file(Unit *u, const char *path);

/* --- unit-dependency.c --- */
/* Record "u has dependency d on other" (also records the inverse where one exists). */
int unit_add_dependency(Unit *u, UnitDependency d, Unit *other);

/* Walk every loaded unit's ordering edges; -ELOOP if a cycle exists, else 0. */
int unit_dependency_detect_cycles(Manager *m);

const char *unit_dependency_to_string(UnitDependency d);
