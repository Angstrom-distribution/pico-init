/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The boot sequence. Kept in its own file because it is the one place that
 * says, in order, what booting actually means here -- and because M5's
 * integration work is exactly "make every step of this real".
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "manager-ctrl.h"
#include "manager-state.h"
#include "manager.h"
#include "unit-enable.h"
#include "unit.h"
#include "util.h"

/*
 * Give every target an After= on each unit it Wants= or Requires=.
 *
 * Without this a target is not a milestone at all: Wants= is a dependency, not
 * an ordering, so default.target would go active the instant it was started --
 * before a single thing it pulls in had run -- and "reached default.target"
 * would mean nothing. That is exactly what happened before this existed.
 *
 * This is pico-init's equivalent of upstream's DefaultDependencies=, narrowed
 * to the one rule that makes boot milestones work. An explicit Before= in a
 * unit file still wins, because unit_add_dependency() deduplicates and the
 * ordering graph is checked for cycles afterwards -- a unit that genuinely
 * must start after its own target simply says so and the cycle check reports
 * it rather than this silently forcing the other order.
 */
static void manager_add_target_default_ordering(Manager *m) {
        size_t i;

        for (i = 0; i < m->n_units; i++) {
                Unit *t = m->units[i];
                UnitDependency deps[2] = { UNIT_WANTS, UNIT_REQUIRES };
                size_t d;

                if (t->type != UNIT_TARGET || t->load_state != UNIT_LOADED)
                        continue;

                for (d = 0; d < 2; d++) {
                        size_t k;

                        for (k = 0; k < t->n_dependencies[deps[d]]; k++) {
                                Unit *pulled = t->dependencies[deps[d]][k];
                                int r;

                                /* Skip if the unit file already ordered these
                                 * two in either direction -- an explicit
                                 * statement outranks a default. */
                                if (unit_has_dependency(t, UNIT_AFTER, pulled) ||
                                    unit_has_dependency(t, UNIT_BEFORE, pulled))
                                        continue;

                                r = unit_add_dependency(t, UNIT_AFTER, pulled);
                                if (r < 0)
                                        pico_log(PICO_LOG_DEBUG,
                                                 "%s: could not order after %s: %s",
                                                 t->id,
                                                 pulled->id,
                                                 strerror(-r));
                        }
                }
        }
}

int manager_startup(Manager *m, const char *default_target) {
        Unit *target = NULL;
        size_t i;
        int r;

        if (!m)
                return -EINVAL;

        if (!default_target)
                default_target = PICO_DEFAULT_TARGET;

        /*
         * 0. Bring up the runtime state directory and the control socket
         * before anything can transition, so the very first unit_notify() of
         * the boot is already published rather than silently dropped.
         *
         * Neither is fatal: a read-only or absent /run costs picoctl its
         * verbs, and an image with no control socket is a supported
         * configuration. A boot that fails because its status reporting
         * failed would be strictly worse than one that boots quietly.
         */
        r = manager_state_setup(m);
        if (r < 0)
                pico_log(PICO_LOG_WARNING,
                         "state directory unavailable, picoctl reads will not work: %s",
                         strerror(-r));

        r = manager_ctrl_setup(m);
        if (r < 0)
                pico_log(PICO_LOG_WARNING,
                         "control socket unavailable, picoctl start/stop will not work: %s",
                         strerror(-r));

        /* 1. Every fragment in the search path becomes a graph node. */
        r = manager_load_units(m, NULL);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "loading units: %s", strerror(-r));

        /* 2. Drain whatever step 1's dependency resolution queued behind it. */
        r = manager_dispatch_load_queue(m);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "draining load queue: %s", strerror(-r));

        /*
         * 3. Enablement by symlink. Iterate by index and re-read m->n_units
         * every time: unit_add_wants_requires_dirs() resolves names through
         * manager_load_unit(), which can append to the table and realloc it,
         * so a cached pointer or a cached count would both be wrong.
         */
        for (i = 0; i < m->n_units; i++) {
                Unit *u = m->units[i];

                if (u->load_state != UNIT_LOADED)
                        continue;

                r = unit_add_wants_requires_dirs(u);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING, "%s: scanning .wants/.requires: %s", u->id, strerror(-r));
        }

        /* 4. Presets decide whatever the symlinks did not. */
        r = manager_apply_presets(m);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "applying presets: %s", strerror(-r));

        /* 5. Order every target after what it pulls in. */
        manager_add_target_default_ordering(m);

        /*
         * 6. Refuse to build a transaction over a graph that cannot be
         * ordered. This is fatal on purpose: a cycle means there is no boot
         * order at all, and starting units in an arbitrary one would be worse
         * than stopping and saying so. unit_dependency_detect_cycles() logs
         * the units involved.
         */
        r = unit_dependency_detect_cycles(m);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "ordering graph has a cycle, not starting the default target");
                return r;
        }

        /* 7. Root the boot transaction. */
        r = manager_load_unit(m, default_target, &target);
        if (r < 0 || !target) {
                pico_log(PICO_LOG_ERR, "cannot load %s: %s", default_target, strerror(r < 0 ? -r : ENOENT));
                return r < 0 ? r : -ENOENT;
        }

        if (target->load_state != UNIT_LOADED) {
                pico_log(PICO_LOG_ERR,
                         "%s did not load (%s), nothing to boot into",
                         default_target,
                         unit_load_state_to_string(target->load_state));
                return -ENOENT;
        }

        r = manager_add_job(m, JOB_START, target, NULL);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "queueing start job for %s: %s", default_target, strerror(-r));
                return r;
        }

        pico_log(PICO_LOG_INFO, "startup: %zu units loaded, %s queued", m->n_units, default_target);

        return 0;
}
