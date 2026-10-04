/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * SIGHUP's daemon-reload: re-read every loaded unit's fragment and replace
 * the directive values its in-memory Unit carries, without starting,
 * stopping or signalling anything -- the new values apply from the unit's
 * next start, exactly as `systemctl daemon-reload` leaves a running service.
 *
 * All or nothing per unit. The fragment is parsed into a scratch Unit of the
 * same type and id, never into the live one: unit_parse_file() writes each
 * directive as it goes, so a file that fails validation halfway through
 * would otherwise leave a live unit carrying half of the old configuration
 * and half of the new. Only once the scratch unit has parsed and verified
 * cleanly are its directive fields swapped into the live unit; the scratch
 * unit then takes the old values with it into unit_free().
 *
 * The scratch unit has no manager. That is what keeps the parse from
 * reaching into the rest of the table: config_parse_unit_deps() skips
 * dependency resolution without one, so no unit is loaded, and no Before=/
 * After= inverse edge is written onto a live neighbour pointing at memory
 * about to be freed. It is also what stops unit_free() from unlinking the
 * live unit's published state file, which is named after the same id.
 *
 * manager_reload() -- the real daemon-reload, whether reached via SIGHUP or
 * the picoctl daemon-reload ctrl verb (manager-ctrl.c) -- is more than the
 * per-unit swap above: a unit file dropped into the search path since boot
 * (or since the last reload) must become a known, loadable unit, and a
 * .wants/.requires symlink added or removed since then must take effect,
 * exactly as it would at the next boot. So it also, in order: (1) re-reads
 * every already-loaded unit's own fragment (unit_reload(), above); (2) runs
 * manager_load_units(m, NULL) again, the same whole-search-path fragment
 * scan manager_startup() runs once at boot, so a new fragment becomes a
 * graph node; (3) re-runs unit_add_wants_requires_dirs() for every loaded
 * unit, so a symlink that did not exist at boot (or at the previous reload)
 * is picked up -- safe to repeat: unit_add_dependency() dedupes, so re-
 * adding an edge that is already there is a no-op. None of this starts
 * anything: a newly known or newly enabled unit is not queued, matching
 * upstream daemon-reload exactly -- it only becomes startable, not started.
 *
 * Deliberately NOT re-run: manager_apply_presets(). Real `systemctl daemon-
 * reload` never touches presets either -- that is what `systemctl preset`
 * is for -- and this project's own manager_startup() only ever calls
 * manager_apply_presets() once, on m->first_boot (see unit-enable.h's own
 * comment on why that is a once-ever decision, not a per-boot one).
 * Re-running it from every reload would re-open a decision this project has
 * deliberately chosen to make exactly once; a unit discovered here with no
 * symlink pointing at it becomes known and loadable, same as at boot, but
 * stays undecided until something explicit (`picoctl enable`/`preset`)
 * decides it -- exactly the real systemd behavior for a reload.
 *
 * Not re-read, deliberately:
 *  - Requires=/Wants=/Before=/After= *declared in a changed unit's own
 *    fragment*. The graph stores an edge a unit declared and the inverse a
 *    neighbour's Before=/After= put there in the same slot, so dropping
 *    "this unit's own" edges cannot be done without also dropping edges
 *    other files still declare. Edges stay as loaded. (A .wants/.requires
 *    *symlink*, by contrast, is re-scanned every reload -- see above.)
 *  - Socket units. Their Listen*= lines are bound fds the paired service may
 *    hold right now; re-reading them means rebinding, which is not a reload.
 *  - A unit with a job or a control process in flight. Swapping a command
 *    list or Type= under a start or stop that is still walking the old one
 *    is how a reload restarts or kills something by accident; such a unit is
 *    skipped with a warning and picks the change up on the next reload.
 *  - Drop-in directories, which unit-load.c does not read yet either.
 *  - Load-state transitions on an already-loaded unit. A unit whose file is
 *    now gone, masked or invalid keeps its current configuration and gets a
 *    warning -- but a unit not loaded at all yet is exactly what step (2)
 *    above newly loads.
 */

#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "manager-state.h"
#include "manager.h"
#include "service.h"
#include "unit-enable.h"
#include "unit.h"
#include "util.h"

#define SWAP_FIELD(a, b)                   \
        do {                               \
                __typeof__(a) swap_ = (a); \
                (a) = (b);                 \
                (b) = swap_;               \
        } while (0)

/*
 * The directive-backed fields of the base Unit. Everything else on it is
 * identity (id, instance, aliases, fragment_path), graph, or runtime state
 * (condition_result, enabled, job, the queue links) and stays put.
 */
static void unit_swap_directives(Unit *u, Unit *fresh) {
        SWAP_FIELD(u->description, fresh->description);
        SWAP_FIELD(u->condition_path_exists, fresh->condition_path_exists);
        SWAP_FIELD(u->condition_path_exists_negated, fresh->condition_path_exists_negated);
        SWAP_FIELD(u->condition_path_is_directory, fresh->condition_path_is_directory);
        SWAP_FIELD(u->condition_path_is_directory_negated, fresh->condition_path_is_directory_negated);
        SWAP_FIELD(u->wanted_by, fresh->wanted_by);
        SWAP_FIELD(u->required_by, fresh->required_by);
        SWAP_FIELD(u->degraded_directives, fresh->degraded_directives);
        SWAP_FIELD(u->n_degraded_directives, fresh->n_degraded_directives);
}

/*
 * A Service's parsed [Service] values. Listed field by field rather than
 * "everything but the runtime state", so a field added to Service later is
 * left alone by reload until it is listed here -- a stale value until
 * reboot, never a runtime pid or timer reset to its default underneath a
 * running process. The *_idx cursors are runtime: they are only non-zero
 * while a control process walks the list, and such a unit is never swapped.
 */
static void service_swap_directives(Service *s, Service *fresh) {
        SWAP_FIELD(s->type, fresh->type);
        SWAP_FIELD(s->exec_start_pre, fresh->exec_start_pre);
        SWAP_FIELD(s->exec_start, fresh->exec_start);
        SWAP_FIELD(s->exec_start_pre_ignore, fresh->exec_start_pre_ignore);
        SWAP_FIELD(s->exec_start_ignore, fresh->exec_start_ignore);
        SWAP_FIELD(s->exec_stop, fresh->exec_stop);
        SWAP_FIELD(s->n_exec_stop, fresh->n_exec_stop);
        SWAP_FIELD(s->exec_condition, fresh->exec_condition);
        SWAP_FIELD(s->n_exec_condition, fresh->n_exec_condition);
        SWAP_FIELD(s->exec_stop_post, fresh->exec_stop_post);
        SWAP_FIELD(s->n_exec_stop_post, fresh->n_exec_stop_post);
        SWAP_FIELD(s->exec_reload, fresh->exec_reload);
        SWAP_FIELD(s->n_exec_reload, fresh->n_exec_reload);
        SWAP_FIELD(s->environment, fresh->environment);
        SWAP_FIELD(s->environment_files, fresh->environment_files);
        SWAP_FIELD(s->user, fresh->user);
        SWAP_FIELD(s->group, fresh->group);
        SWAP_FIELD(s->pid_file, fresh->pid_file);
        SWAP_FIELD(s->guess_main_pid, fresh->guess_main_pid);
        SWAP_FIELD(s->remain_after_exit, fresh->remain_after_exit);
        SWAP_FIELD(s->restart, fresh->restart);
        SWAP_FIELD(s->restart_usec, fresh->restart_usec);
        SWAP_FIELD(s->timeout_start_usec, fresh->timeout_start_usec);
        SWAP_FIELD(s->timeout_stop_usec, fresh->timeout_stop_usec);
}

/* Something is mid-flight on u that is still reading its current values. */
static bool unit_reload_busy(Unit *u) {
        if (u->job)
                return true;

        return u->type == UNIT_SERVICE && SERVICE(u)->control_pid > 0;
}

int unit_reload(Unit *u) {
        Unit *fresh = NULL;
        struct stat st;
        int r;

        if (!u)
                return -EINVAL;

        if (u->load_state != UNIT_LOADED || !u->fragment_path)
                return 0;

        if (u->type == UNIT_SOCKET) {
                pico_log(PICO_LOG_DEBUG, "%s: socket units are not re-read on reload", u->id);
                return 0;
        }

        if (unit_reload_busy(u)) {
                pico_log(PICO_LOG_WARNING, "%s: job or control process in flight, not reloaded", u->id);
                return -EBUSY;
        }

        /* The masked shapes unit_find_fragment() refuses at load: masking
         * is a load-state change, which reload does not make. */
        if (stat(u->fragment_path, &st) < 0) {
                r = -errno;
                pico_log(PICO_LOG_WARNING,
                         "%s: '%s': %s, keeping loaded configuration",
                         u->id,
                         u->fragment_path,
                         strerror(-r));
                return r;
        }

        if (!S_ISREG(st.st_mode) || st.st_size == 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s: '%s' is now masked or not a regular file, keeping loaded configuration",
                         u->id,
                         u->fragment_path);
                return -EBADF;
        }

        r = unit_new(NULL, u->type, u->id, &fresh);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "%s: reload: %s, keeping loaded configuration", u->id, strerror(-r));
                return r;
        }

        r = unit_parse_file(fresh, u->fragment_path);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s: failed to re-parse '%s': %s, keeping loaded configuration",
                         u->id,
                         u->fragment_path,
                         strerror(-r));
                unit_free(fresh);
                return r;
        }

        unit_swap_directives(u, fresh);
        if (u->type == UNIT_SERVICE)
                service_swap_directives(SERVICE(u), SERVICE(fresh));

        /* fresh now owns the old values; unit_free() frees them and, having
         * no manager, touches nothing outside itself. */
        unit_free(fresh);

        manager_state_notify_unit(u);
        pico_log(PICO_LOG_DEBUG, "%s: reloaded from '%s'", u->id, u->fragment_path);
        return 1;
}

int manager_reload(Manager *m) {
        size_t i;
        int n = 0;
        int r;

        if (!m)
                return -EINVAL;

        /*
         * Indexing rather than a saved count: unit_reload() never loads or
         * frees a unit, but reading m->n_units each time keeps that an
         * observed property of the loop rather than an assumption. `n`
         * counts only THIS step, by design -- it is the "how many unit
         * files actually changed" number the log line (and test-unit-
         * reload.c) reports; the discovery/rescan/preset steps below never
         * add to it, since nothing they do is a reload of an existing unit.
         */
        for (i = 0; i < m->n_units; i++)
                if (unit_reload(m->units[i]) > 0)
                        n++;

        /* Newly-added unit files become known (manager_startup()'s own
         * step 1, re-run). */
        r = manager_load_units(m, NULL);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "daemon-reload: loading new units: %s", strerror(-r));

        /* Every .wants/.requires symlink, old or new, re-scanned against
         * every currently-loaded unit (manager_startup()'s own step 3,
         * re-run) -- idempotent, so re-finding an edge that already exists
         * costs nothing. Indexed and re-reading m->n_units for the same
         * reason manager_startup() does: a scan can itself load a unit a
         * symlink names, appending to and reallocating m->units. */
        for (i = 0; i < m->n_units; i++) {
                Unit *u = m->units[i];

                if (u->load_state != UNIT_LOADED)
                        continue;

                r = unit_add_wants_requires_dirs(u);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING, "%s: scanning .wants/.requires: %s", u->id, strerror(-r));
        }

        /* Presets are deliberately NOT re-applied here -- see this file's
         * own header. A unit discovered above with no symlink naming it is
         * now known and loadable, same as at boot, but stays undecided
         * until something explicit (`picoctl enable`/`preset`) decides it. */

        pico_log(PICO_LOG_INFO,
                 "Reloaded %d unit%s; dependencies and socket units unchanged until reboot",
                 n,
                 n == 1 ? "" : "s");
        return n;
}
