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
#include <sys/stat.h>

#include "job.h"
#include "manager-state.h"
#include "specifier.h"
#include "unit-name.h"
#include "unit.h"
#include "util.h"

const UnitVTable *unit_vtable_for(UnitType t) {
        switch (t) {
        case UNIT_SERVICE:
                return &service_vtable;
        case UNIT_TARGET:
                return &target_vtable;
        case UNIT_SOCKET:
                return &socket_vtable;
        default:
                return NULL;
        }
}

int unit_new(Manager *m, UnitType type, const char *id, Unit **ret) {
        const UnitVTable *vtable;
        Unit *u;
        int r;

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

        /* Explicitly, not by relying on calloc: a unit with no conditions at
         * all must read as having passed them. */
        u->condition_result = true;

        u->id = pico_strdup(id);
        if (!u->id) {
                free(u);
                return -ENOMEM;
        }

        /* Derived from the owned u->id, not the caller's `id` -- and once,
         * here, rather than re-parsed by every specifier lookup and the
         * unit-load.c fallback that need it. */
        r = unit_name_to_instance(u->id, &u->instance);
        if (r < 0) {
                free(u->id);
                free(u);
                return r;
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
         * Cancel any job still applying to this unit, before anything else is
         * torn down.
         *
         * A job holds a borrowed j->unit and the unit points back at it as
         * u->job; freeing the unit without breaking that pair leaves the job
         * installed, still on the run queue, pointing at freed memory -- and
         * the next manager_dispatch_run_queue() runs it. job_free() already
         * refuses to leave the mirror image of this dangling (it uninstalls
         * first, clearing unit->job), and this is the other half of the same
         * invariant.
         *
         * Not reachable from today's two callers: manager_free() frees every
         * job before it frees any unit, and manager_load_unit()'s error path
         * runs on a unit that never had one. It becomes reachable the moment
         * a SIGHUP reload or unit garbage collection drops a live unit -- the
         * reload TODO in manager-loop.c -- so it is closed as a prerequisite
         * of that work rather than after it.
         *
         * JOB_CANCELED, non-recursive: this is job_install()'s own supersede
         * call, for the same reason. The unit is going away structurally, so
         * this is not a runtime failure of the unit and must not fail the
         * start jobs of everything that Requires= it; and recursion here would
         * re-enter a manager whose unit table is mid-edit. job_finish_full()
         * uninstalls, unlinks the run queue, resolves any deferred picoctl
         * reply with the real CANCELED result rather than leaving a client
         * hanging, and clears u->job on the way out.
         *
         * Before vtable->done(), not after: job_finish_full() republishes the
         * unit's state file, which dispatches through vtable->active_state()
         * -- reading a Service whose done() hook had already freed its members
         * would be the use-after-free this fix exists to prevent, one layer
         * further in.
         *
         * One constraint this hands to whoever writes the reload, worth
         * stating because this call is where it will first be noticed rather
         * than where it originates: job_finish_full() ends by walking this
         * unit's Before=/After= neighbours to re-queue whatever its completion
         * unblocked, and those are borrowed pointers into the manager's unit
         * table. So a unit must be freed while the units it has edges to are
         * still alive -- drop stale units one at a time from a table that is
         * otherwise intact, never bulk-free a set with edges among it. That is
         * already true of the dependency arrays themselves (any surviving unit
         * holding an edge to a freed one is dangling regardless of jobs);
         * manager_free() sidesteps it entirely by finishing every job before
         * it frees any unit.
         */
        if (u->job)
                job_finish_full(u->job, JOB_CANCELED, false);

        /*
         * Per-type teardown next. Only the concrete type knows what it owns
         * -- a Service holds two argv vectors, a cgroup and possibly a queued
         * timer event -- so without this hook every started service leaked all
         * of them. The base type cannot guess at any of it.
         */
        if (u->vtable && u->vtable->done)
                u->vtable->done(u);

        /* Before u->id is freed -- the published file is named after it, and
         * a state file must never outlive the unit it describes. */
        manager_state_forget_unit(u);

        u->id = pico_mfree(u->id);
        u->instance = pico_mfree(u->instance);
        u->description = pico_mfree(u->description);
        u->fragment_path = pico_mfree(u->fragment_path);

        for (i = 0; i < _UNIT_DEPENDENCY_MAX; i++) {
                /* the arrays are owned; the Unit* inside them are borrowed */
                u->dependencies[i] = pico_mfree(u->dependencies[i]);
                u->n_dependencies[i] = 0;
        }

        u->aliases = pico_strv_free(u->aliases);
        u->wanted_by = pico_strv_free(u->wanted_by);
        u->required_by = pico_strv_free(u->required_by);

        u->condition_path_exists = pico_strv_free(u->condition_path_exists);
        u->condition_path_exists_negated = pico_mfree(u->condition_path_exists_negated);
        u->condition_path_is_directory = pico_strv_free(u->condition_path_is_directory);
        u->condition_path_is_directory_negated = pico_mfree(u->condition_path_is_directory_negated);

        u->degraded_directives = pico_strv_free(u->degraded_directives);
        u->n_degraded_directives = 0;

        free(u);

        return NULL;
}

bool unit_has_name(const Unit *u, const char *name) {
        char **p;

        if (!u || !name)
                return false;

        if (u->id && strcmp(u->id, name) == 0)
                return true;

        for (p = u->aliases; p && *p; p++)
                if (strcmp(*p, name) == 0)
                        return true;

        return false;
}

int unit_add_alias(Unit *u, const char *name) {
        if (!u || !name || !*name)
                return -EINVAL;

        if (unit_has_name(u, name))
                return 0;

        return pico_strv_extend(&u->aliases, name);
}

int unit_add_degradation(Unit *u, const char *what) {
        char **p;
        int r;

        if (!u || !what || !*what)
                return -EINVAL;

        for (p = u->degraded_directives; p && *p; p++)
                if (strcmp(*p, what) == 0)
                        return 0;

        r = pico_strv_extend(&u->degraded_directives, what);
        if (r < 0)
                return r;

        u->n_degraded_directives++;
        return 0;
}

char *unit_degraded_directives_string(Unit *u) {
        size_t len = 0, off = 0;
        char **p;
        char *s;

        for (p = u ? u->degraded_directives : NULL; p && *p; p++)
                len += strlen(*p) + 1;

        s = malloc(len + 1);
        if (!s)
                return NULL;

        for (p = u ? u->degraded_directives : NULL; p && *p; p++) {
                size_t n = strlen(*p);

                if (off > 0)
                        s[off++] = ' ';
                memcpy(s + off, *p, n);
                off += n;
        }
        s[off] = '\0';

        return s;
}

UnitActiveState unit_active_state(Unit *u) {
        if (!u || !u->vtable || !u->vtable->active_state)
                return UNIT_INACTIVE;

        return u->vtable->active_state(u);
}

/*
 * All conditions must pass -- systemd's AND semantics for the non-triggering
 * ones. Evaluated at start time, not load time: the paths these name are
 * created by other units during the boot (/dev/ttyGS0 exists only once
 * usb-multi-gadget.service has run), so a load-time answer would be the wrong
 * one for exactly the case this exists to serve.
 *
 * Each entry's raw stat-based result is inverted when its parallel *_negated
 * flag is set, matching that one entry's leading '!' at parse time.
 */
static bool unit_condition_test(Unit *u) {
        char **p;
        size_t i;

        for (p = u->condition_path_exists, i = 0; p && *p; p++, i++) {
                struct stat st;
                bool met = stat(*p, &st) == 0;

                if (u->condition_path_exists_negated && u->condition_path_exists_negated[i])
                        met = !met;

                if (!met) {
                        pico_log(PICO_LOG_INFO, "%s: ConditionPathExists=%s not met, skipping", u->id, *p);
                        return false;
                }
        }

        for (p = u->condition_path_is_directory, i = 0; p && *p; p++, i++) {
                struct stat st;
                bool met = stat(*p, &st) == 0 && S_ISDIR(st.st_mode);

                if (u->condition_path_is_directory_negated && u->condition_path_is_directory_negated[i])
                        met = !met;

                if (!met) {
                        pico_log(PICO_LOG_INFO, "%s: ConditionPathIsDirectory=%s not met, skipping", u->id, *p);
                        return false;
                }
        }

        return true;
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

        /*
         * -EALREADY, not a failure and not 0: an unmet condition means the
         * unit was never meant to run here, so job_run() completes its job
         * successfully (systemd's own return for this case). Nothing is
         * exec'd, so Restart= never enters the picture either.
         */
        if (!unit_condition_test(u)) {
                u->condition_result = false;
                return -EALREADY;
        }

        u->condition_result = true;

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

        /*
         * Publish before the job bookkeeping below, not after: the early
         * return when no job is waiting is the common case (a Restart= cycle,
         * a service dying with nothing enqueued), and publishing after it
         * would silently skip exactly the transitions picoctl most needs to
         * report. See manager-state.h.
         */
        manager_state_notify_unit(u);

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
                /* A oneshot without RemainAfterExit= finishes by going
                 * straight back to INACTIVE and never reaches ACTIVE: that
                 * is a completed start too (v30 src/unit.c unit_notify()). */
                if (new_state == UNIT_ACTIVE || new_state == UNIT_INACTIVE)
                        job_finish(j, JOB_DONE);
                else if (new_state == UNIT_FAILED)
                        job_finish(j, JOB_FAILED);
                break;

        case JOB_STOP:
                /* Down is down: a unit that stops FAILED (SIGTERM ending a
                 * oneshot, a crash while in AUTO_RESTART) still completed
                 * the stop (v30 src/unit.c unit_notify()). */
                if (new_state == UNIT_INACTIVE || new_state == UNIT_FAILED)
                        job_finish(j, JOB_DONE);
                break;

        case JOB_RESTART:
                /*
                 * A restart is a stop that turns into a start once the unit is
                 * down, and job_finish_full() is where that conversion belongs
                 * -- doing it at dispatch time is what lost the ordering in
                 * systemd's dd17d38879, and returning early after it is what
                 * left dependent jobs waiting forever in 57981b9812.
                 *
                 * But job.c only ever sees the restart if something reports
                 * the unit reaching INACTIVE, and nothing did: this arm was a
                 * bare break, which made job_finish_full()'s conversion block
                 * unreachable, so a restart stopped a unit and never started
                 * it again. Reporting the stop half here is the whole of the
                 * missing link; the conversion itself stays in job.c.
                 * FAILED counts as down too, as for JOB_STOP above.
                 */
                if (new_state == UNIT_INACTIVE || new_state == UNIT_FAILED)
                        job_finish(j, JOB_DONE);
                break;

        default:
                break;
        }
}

static const char * const unit_type_table[_UNIT_TYPE_MAX] = {
        [UNIT_SERVICE] = "service",
        [UNIT_TARGET] = "target",
        [UNIT_SOCKET] = "socket",
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

        if (strcmp(suffix, ".socket") == 0)
                return UNIT_SOCKET;

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

        /*
         * '@' is already in UNIT_NAME_VALID_CHARS above, so only its
         * structural placement is left to check: an '@' before the last '.'
         * is a template/instance separator, and an empty prefix
         * ("@.service", "@bar.service") is not a name anyone could have
         * meant. Both spellings that DO have a prefix stay valid here --
         * "foo@.service" (a template) and "foo@bar.service" (an instance) --
         * see the header comment for why rejecting a template is not this
         * function's job.
         */
        {
                const char *e = strrchr(name, '.'); /* guaranteed by the type check below, but test anyway */
                const char *at;

                if (e) {
                        at = memchr(name, '@', (size_t) (e - name));
                        if (at == name)
                                return false;
                }
        }

        /* and it has to name a type we can actually instantiate */
        if (unit_type_from_name(name) == _UNIT_TYPE_INVALID)
                return false;

        return true;
}

/*
 * Specifier lookups, quarried from systemd's v30 unit.c (:1955-1994) down to
 * the five this project's two tables actually reference. %P (unescaped
 * prefix) is not carried: nothing here ever escapes a prefix, so it would
 * have no consumer. %f/%c/%r/%R/%t (cgroup/runtime-dir specifiers) are not
 * carried either -- no analog exists yet -- and reach a unit file as literal
 * pass-through, same as any other specifier neither table recognizes.
 *
 * File-static because only unit_name_printf()/unit_full_printf() below ever
 * build a table entry pointing at one; unit-parse.c calls only those two.
 */

static int specifier_prefix(char specifier, const void *data, const void *userdata, char **ret) {
        Unit *u = (Unit *) userdata;
        (void) specifier;
        (void) data;

        *ret = unit_name_to_prefix(u->id);
        return *ret ? 0 : -ENOMEM;
}

static int specifier_prefix_and_instance(char specifier, const void *data, const void *userdata, char **ret) {
        Unit *u = (Unit *) userdata;
        (void) specifier;
        (void) data;

        *ret = unit_name_to_prefix_and_instance(u->id);
        return *ret ? 0 : -ENOMEM;
}

/* %I: the instance, unescaped -- e.g. a device node instance "dev-ttyGS0"
 * becomes "dev/ttyGS0". "" for a non-instanced unit, matching v30 unit.c's
 * own specifier_instance_unescaped() (:1985-1993) rather than aborting the
 * way carrying its assert(u->meta.instance) forward would have. */
static int specifier_instance_unescaped(char specifier, const void *data, const void *userdata, char **ret) {
        Unit *u = (Unit *) userdata;
        (void) specifier;
        (void) data;

        if (!u->instance) {
                *ret = pico_strdup("");
                return *ret ? 0 : -ENOMEM;
        }

        *ret = unit_name_unescape(u->instance);
        return *ret ? 0 : -ENOMEM;
}

int unit_name_printf(Unit *u, const char *format, char **ret) {
        const PicoSpecifier table[] = {
                { 'n',         pico_specifier_string,       u->id },
                { 'N', specifier_prefix_and_instance,        NULL },
                { 'p',              specifier_prefix,        NULL },
                { 'i',         pico_specifier_string, u->instance },
                {   0,                          NULL,        NULL },
        };

        if (!u || !format || !ret)
                return -EINVAL;

        return pico_specifier_printf(format, table, u, ret);
}

int unit_full_printf(Unit *u, const char *format, char **ret) {
        const PicoSpecifier table[] = {
                { 'n',         pico_specifier_string,       u->id },
                { 'N', specifier_prefix_and_instance,        NULL },
                { 'p',              specifier_prefix,        NULL },
                { 'i',         pico_specifier_string, u->instance },
                { 'I',  specifier_instance_unescaped,        NULL },
                {   0,                          NULL,        NULL },
        };

        if (!u || !format || !ret)
                return -EINVAL;

        return pico_specifier_printf(format, table, u, ret);
}
