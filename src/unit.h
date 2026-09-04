/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Base Unit type every unit kind embeds (as its first member), plus the
 * dependency graph. Implemented across unit.c (lifecycle/state/vtable
 * dispatch), unit-load.c (fragment lookup), unit-parse.c (INI parser),
 * unit-dependency.c (DAG build + cycle detection), unit-enable.c
 * (.wants/.requires directories and preset application).
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
        UNIT_TARGET,
        UNIT_SOCKET,
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

/*
 * The longest unit name accepted. systemd uses 256 including the NUL; this
 * matches, so a name valid there is valid here -- keeping the drop-in
 * unit-file-compatibility goal honest rather than inventing a smaller limit.
 */
#define UNIT_NAME_MAX 255

/*
 * Per-type behaviour. A concrete unit type (Service, Target) embeds Unit as
 * its first member and exports one of these; unit.c allocates object_size
 * bytes, calls init() once, and dispatches start/stop/active_state through it.
 *
 * done() exists because unit_free() cannot know what a concrete type owns: a
 * Service holds argv vectors, a cgroup and a pending timer event, and without
 * a per-type destructor every started service leaks all three. done() frees
 * only the type's own members -- unit_free() still frees the Unit fields and
 * the allocation itself.
 */
typedef struct UnitVTable {
        size_t object_size; /* sizeof(Service), sizeof(Target), ... */

        void (*init)(Unit *u); /* type defaults after calloc; may be NULL */
        void (*done)(Unit *u); /* free type-owned members; may be NULL */

        int (*start)(Unit *u);
        int (*stop)(Unit *u);
        UnitActiveState (*active_state)(Unit *u);
} UnitVTable;

extern const UnitVTable service_vtable; /* service.c */
extern const UnitVTable target_vtable;  /* target.c */
extern const UnitVTable socket_vtable;  /* socket.c */

const UnitVTable *unit_vtable_for(UnitType t); /* NULL for an invalid type */

struct Unit {
        Manager *manager;
        UnitType type;
        const UnitVTable *vtable;

        char *id;            /* "foo.service" */
        char *description;   /* [Unit] Description=, may be NULL */
        char *fragment_path; /* absolute path of the parsed file, NULL until found */
        UnitLoadState load_state;

        /* dependency graph: per-relation NULL-terminated arrays of borrowed Unit* */
        Unit **dependencies[_UNIT_DEPENDENCY_MAX];
        size_t n_dependencies[_UNIT_DEPENDENCY_MAX];

        /*
         * [Unit] Condition* checks, each an owned list of absolute paths that
         * must all pass. Only the two spellings this project's own units carry
         * are implemented; negation ('!') and triggering ('|') are not, and
         * unit-parse.c drops a value using either rather than mistaking it for
         * a literal path that can never exist.
         */
        char **condition_path_exists;       /* ConditionPathExists=, owned, may be NULL */
        char **condition_path_is_directory; /* ConditionPathIsDirectory=, owned, may be NULL */

        /* Result of the last unit_start() condition check. False means the
         * unit was deliberately left inactive, which is what job.c reads to
         * decide the unit gets no "Started ..." console line. */
        bool condition_result;

        /*
         * [Install] section, kept as raw names rather than resolved edges: at
         * parse time the named target may not be loaded yet, and whether these
         * are honoured at all depends on enablement (a .wants/ symlink or a
         * preset rule), which is only decided once every fragment has been
         * read. unit-enable.c turns them into real edges, or doesn't.
         */
        char **wanted_by;   /* [Install] WantedBy=, owned, may be NULL */
        char **required_by; /* [Install] RequiredBy=, owned, may be NULL */

        /* set once a .wants/.requires symlink or an applied preset enabled this
         * unit, so preset application can tell "no rule ran yet" from "already on" */
        bool enabled;

        Job *job; /* job currently applying to this unit, or NULL (borrowed) */

        /* intrusive load-queue link (see manager.h) */
        Unit *load_queue_next;
        bool in_load_queue;

        /* intrusive cgroup-empty-queue link (see manager.h). A verified
         * emptiness notification waits here until every signal in the same
         * epoll batch has been handled -- see the ordering comment at the top
         * of manager-loop.c for why that ordering is not optional. */
        Unit *cgroup_empty_queue_next;
        bool in_cgroup_empty_queue;

        /* DFS generation marker for cycle detection, owned by unit-dependency.c */
        unsigned dep_generation;
};

/* --- unit.c --- */
/* Allocate vtable->object_size bytes, set id/type/vtable, run vtable->init. 0 or -errno.
 * Does NOT add the unit to the manager's table -- manager_load_unit() does that. */
int unit_new(Manager *m, UnitType type, const char *id, Unit **ret);
Unit *unit_free(Unit *u); /* runs vtable->done, frees Unit fields, returns NULL */

UnitActiveState unit_active_state(Unit *u);
int unit_start(Unit *u); /* dispatches through vtable->start */
int unit_stop(Unit *u);  /* dispatches through vtable->stop */

/*
 * Called by a concrete unit type after its own state machine moved. Completes
 * or fails u->job when the unit reaches a state the in-flight job was waiting
 * for, so job bookkeeping lives in one place instead of in every unit type.
 */
void unit_notify(Unit *u, UnitActiveState old_state, UnitActiveState new_state);

const char *unit_type_to_string(UnitType t);
const char *unit_load_state_to_string(UnitLoadState s);
const char *unit_active_state_to_string(UnitActiveState s);
UnitType unit_type_from_name(const char *id); /* by suffix; _UNIT_TYPE_INVALID if unknown */

/*
 * Reject anything that must never become a filesystem path or a graph node.
 * Unit files are root-owned config, so this is not a privilege boundary -- but
 * "Requires=../../tmp/evil.service" resolving to a path outside the search
 * directories is still a bug, and one directory separator is all it takes.
 */
bool unit_name_is_valid(const char *name);

/* --- unit-load.c --- */
/* Find u->id's fragment in the manager's unit search path, parse it, resolve to
 * LOADED/ERROR. Idempotent once the unit has left UNIT_STUB. 0 or -errno. */
int unit_load(Unit *u);

/* --- unit-parse.c --- */
/* Parse one INI fragment (sections, escapes, line continuations) into u. 0 or -errno. */
int unit_parse_file(Unit *u, const char *path);

/* --- unit-dependency.c --- */
/* Record "u has dependency d on other", deduplicating. Also records the inverse
 * relation where one exists in this model (Before <-> After); Requires/Wants
 * have no inverse slot here, so nothing is recorded back for them. */
int unit_add_dependency(Unit *u, UnitDependency d, Unit *other);

/* As above, resolving `name` through the manager (loading it if needed). */
int unit_add_dependency_by_name(Unit *u, UnitDependency d, const char *name);

bool unit_has_dependency(Unit *u, UnitDependency d, Unit *other);

/* Walk every loaded unit's ordering edges; -ELOOP if a cycle exists, else 0. */
int unit_dependency_detect_cycles(Manager *m);

const char *unit_dependency_to_string(UnitDependency d);
