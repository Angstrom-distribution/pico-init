/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The dependency graph: edge insertion and ordering-cycle detection.
 *
 * Two relations that look alike are deliberately kept apart. Requires/Wants
 * say *whether* another unit must be pulled in; Before/After say *when* it
 * runs relative to this one. Only the ordering relation can form a deadlock,
 * so only that one is walked for cycles -- a Requires= loop is merely two
 * units that pull each other in, which is harmless and common.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "manager.h"
#include "unit.h"
#include "util.h"

/*
 * DFS colours. Kept as plain values reset at the start of every sweep rather
 * than the "generation counter" trick, which upstream used and which cost it a
 * real bug (systemd 4e7bd268ae): a stale generation left on a unit from an
 * earlier sweep reads as "already visited, loop-free", and the cycle goes
 * undetected. An O(n) reset over a table this small is not worth that risk.
 */
#define DEP_UNVISITED 0u
#define DEP_ON_STACK 1u
#define DEP_DONE 2u

static UnitDependency dependency_inverse(UnitDependency d) {
        switch (d) {
        case UNIT_BEFORE:
                return UNIT_AFTER;
        case UNIT_AFTER:
                return UNIT_BEFORE;
        case UNIT_CONFLICTS:
                return UNIT_CONFLICTED_BY;
        case UNIT_CONFLICTED_BY:
                return UNIT_CONFLICTS;
        default:
                /* Requires/Wants have no inverse slot in this model; the
                 * reverse relation (RequiredBy/WantedBy) is carried as raw
                 * [Install] names instead, resolved by unit-enable.c. */
                return _UNIT_DEPENDENCY_MAX;
        }
}

bool unit_has_dependency(Unit *u, UnitDependency d, Unit *other) {
        size_t i;

        if (!u || !other || d < 0 || d >= _UNIT_DEPENDENCY_MAX)
                return false;

        for (i = 0; i < u->n_dependencies[d]; i++)
                if (u->dependencies[d][i] == other)
                        return true;

        return false;
}

/* One direction only; the caller handles the inverse. */
static int unit_add_dependency_one(Unit *u, UnitDependency d, Unit *other) {
        Unit **deps;
        size_t n;

        if (unit_has_dependency(u, d, other))
                return 0; /* deduplicate: re-adding an edge is a no-op */

        n = u->n_dependencies[d];

        /* +2: the new entry plus the NULL terminator the array keeps */
        deps = realloc(u->dependencies[d], (n + 2) * sizeof(Unit *));
        if (!deps)
                return -ENOMEM;

        deps[n] = other;
        deps[n + 1] = NULL;

        u->dependencies[d] = deps;
        u->n_dependencies[d] = n + 1;

        return 0;
}

int unit_add_dependency(Unit *u, UnitDependency d, Unit *other) {
        UnitDependency inverse;
        int r;

        if (!u || !other || d < 0 || d >= _UNIT_DEPENDENCY_MAX)
                return -EINVAL;

        /* A unit ordered against itself is a one-node cycle; reject it here
         * rather than letting the detector find it later. */
        if (u == other)
                return -EINVAL;

        r = unit_add_dependency_one(u, d, other);
        if (r < 0)
                return r;

        /*
         * Insert the inverse directly instead of recursing back into this
         * function: a recursive call would try to invert again, and only the
         * dedup check would stop it. Being explicit costs nothing and removes
         * the question entirely.
         */
        inverse = dependency_inverse(d);
        if (inverse != _UNIT_DEPENDENCY_MAX) {
                r = unit_add_dependency_one(other, inverse, u);
                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_add_dependency_by_name(Unit *u, UnitDependency d, const char *name) {
        Unit *other = NULL;
        int r;

        if (!u || !u->manager || !name)
                return -EINVAL;

        if (!unit_name_is_valid(name))
                return -EINVAL;

        r = manager_load_unit(u->manager, name, &other);
        if (r < 0)
                return r;

        if (!other)
                return -ENOENT;

        return unit_add_dependency(u, d, other);
}

/* Remove every occurrence of `other` from one of u's arrays, keeping the
 * NULL terminator. */
static void unit_drop_dependency_one(Unit *u, UnitDependency d, Unit *other) {
        size_t i, n = 0;

        for (i = 0; i < u->n_dependencies[d]; i++)
                if (u->dependencies[d][i] != other)
                        u->dependencies[d][n++] = u->dependencies[d][i];

        if (u->dependencies[d])
                u->dependencies[d][n] = NULL;
        u->n_dependencies[d] = n;
}

int unit_dependency_unlink(Unit *u) {
        Manager *m;
        size_t i;
        int d;

        if (!u || !u->manager)
                return -EINVAL;

        m = u->manager;

        /* Requires=/Wants= have no inverse slot, so a peer holding one was
         * declared by a file that names u: dropping it would rewrite that
         * unit's graph behind its back. A peer's Conflicts= on u is the same
         * case -- the peer's own file named u. A peer's ConflictedBy= edge is
         * only u's own Conflicts= mirrored, so the drop loop below takes it. */
        for (i = 0; i < m->n_units; i++)
                if (m->units[i] != u &&
                    (unit_has_dependency(m->units[i], UNIT_REQUIRES, u) ||
                     unit_has_dependency(m->units[i], UNIT_WANTS, u) ||
                     unit_has_dependency(m->units[i], UNIT_CONFLICTS, u)))
                        return -EBUSY;

        for (i = 0; i < m->n_units; i++)
                if (m->units[i] != u)
                        for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++)
                                unit_drop_dependency_one(m->units[i], d, u);

        for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++) {
                u->dependencies[d] = pico_mfree(u->dependencies[d]);
                u->n_dependencies[d] = 0;
        }

        return 0;
}

void unit_stop_conflicting(Unit *u) {
        static const UnitDependency deps[] = { UNIT_CONFLICTS, UNIT_CONFLICTED_BY };
        size_t d, i;

        if (!u || !u->manager)
                return;

        for (d = 0; d < sizeof(deps) / sizeof(deps[0]); d++)
                for (i = 0; i < u->n_dependencies[deps[d]]; i++) {
                        Unit *other = u->dependencies[deps[d]][i];
                        UnitActiveState st = unit_active_state(other);
                        int r;

                        if (st != UNIT_ACTIVE && st != UNIT_ACTIVATING)
                                continue;

                        /*
                         * manager_add_job() only installs and queues; the
                         * stop runs later from the run queue, so this is
                         * safe from inside a unit's own state change. The
                         * stop is an explicit one, so it also sets the
                         * peer's forbid_restart: a ping-pong between two
                         * Restart=always units needs an outside trigger
                         * on every round.
                         */
                        r = manager_add_job(u->manager, JOB_STOP, other, NULL);
                        if (r < 0)
                                pico_log(PICO_LOG_DEBUG,
                                         "%s: could not stop conflicting %s: %s",
                                         u->id,
                                         other->id,
                                         strerror(-r));
                        else
                                pico_log(PICO_LOG_DEBUG, "%s: stopping conflicting %s", u->id, other->id);
                }
}

/* One frame of the explicit DFS stack. */
typedef struct DepFrame {
        Unit *u;
        size_t next; /* index of the next UNIT_AFTER edge to walk */
} DepFrame;

/*
 * Log the cycle we just closed, as unit ids in execution order. A bare -ELOOP
 * is undebuggable on a real board -- the whole value of detecting a cycle is
 * being told which units form it.
 */
static void log_cycle(const DepFrame *stack, size_t n_stack, const Unit *closing) {
        char buf[512];
        size_t off = 0;
        size_t start;
        size_t i;

        for (start = 0; start < n_stack; start++)
                if (stack[start].u == closing)
                        break;

        for (i = start; i < n_stack; i++) {
                int n = snprintf(buf + off, sizeof(buf) - off, "%s -> ", stack[i].u->id);

                if (n < 0 || (size_t) n >= sizeof(buf) - off) {
                        off = sizeof(buf) - 1;
                        break;
                }
                off += (size_t) n;
        }

        snprintf(buf + off, sizeof(buf) - off, "%s", closing->id);

        pico_log(PICO_LOG_ERR, "ordering cycle detected: %s", buf);
}

int unit_dependency_detect_cycles(Manager *m) {
        DepFrame *stack = NULL;
        size_t n_stack = 0;
        size_t n_alloc = 0;
        size_t i;
        int r = 0;

        if (!m)
                return -EINVAL;

        if (m->n_units == 0)
                return 0;

        for (i = 0; i < m->n_units; i++)
                m->units[i]->dep_generation = DEP_UNVISITED;

        /*
         * Iterative rather than recursive on purpose. Depth here is the length
         * of the longest ordering chain, which comes straight out of unit
         * files -- a malformed or merely large unit set must not be able to
         * blow PID1's stack.
         */
        stack = calloc(m->n_units + 1, sizeof(DepFrame));
        if (!stack)
                return -ENOMEM;

        n_alloc = m->n_units + 1;

        for (i = 0; i < m->n_units; i++) {
                Unit *root = m->units[i];

                if (root->dep_generation != DEP_UNVISITED)
                        continue;

                root->dep_generation = DEP_ON_STACK;
                stack[n_stack].u = root;
                stack[n_stack].next = 0;
                n_stack++;

                while (n_stack > 0) {
                        DepFrame *frame = &stack[n_stack - 1];
                        Unit *cur = frame->u;

                        if (frame->next < cur->n_dependencies[UNIT_AFTER]) {
                                Unit *next = cur->dependencies[UNIT_AFTER][frame->next];

                                frame->next++;

                                if (next->dep_generation == DEP_ON_STACK) {
                                        /* back edge: next is still open above us */
                                        log_cycle(stack, n_stack, next);
                                        r = -ELOOP;
                                        goto finish;
                                }

                                if (next->dep_generation == DEP_UNVISITED) {
                                        if (n_stack >= n_alloc) {
                                                /* cannot happen: at most one
                                                 * frame per unit is ever open */
                                                r = -ENOBUFS;
                                                goto finish;
                                        }

                                        next->dep_generation = DEP_ON_STACK;
                                        stack[n_stack].u = next;
                                        stack[n_stack].next = 0;
                                        n_stack++;
                                }

                                continue;
                        }

                        cur->dep_generation = DEP_DONE;
                        n_stack--;
                }
        }

finish:
        free(stack);
        return r;
}

static const char * const unit_dependency_table[_UNIT_DEPENDENCY_MAX] = {
        [UNIT_REQUIRES] = "Requires", [UNIT_WANTS] = "Wants",         [UNIT_BEFORE] = "Before",
        [UNIT_AFTER] = "After",       [UNIT_CONFLICTS] = "Conflicts", [UNIT_CONFLICTED_BY] = "ConflictedBy",
};

const char *unit_dependency_to_string(UnitDependency d) {
        if (d < 0 || d >= _UNIT_DEPENDENCY_MAX)
                return "invalid";

        return unit_dependency_table[d];
}
