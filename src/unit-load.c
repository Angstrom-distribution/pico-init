/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Fragment lookup, quarried from systemd's ~2011-era unit_load_fragment()
 * in src/load-fragment.c (tag v30, commit 501c92c, copyright 2010
 * Lennart Poettering, GPL-2.0-or-later) down to its essential
 * shape: search a path for "<id>", hand a found file to the INI parser,
 * resolve to UNIT_LOADED, UNIT_ERROR or UNIT_MASKED. The 2011 original searched
 * several directories (/etc, /run, /usr/lib) with per-directory drop-in
 * merging; this searches the manager's own unit path, which defaults to two
 * entries: PICO_UNIT_DIR (admin overrides) then PICO_PACKAGED_UNIT_DIR (where
 * packages install units on a usrmerged system).
 *
 * The path lives on the Manager rather than in a file-static array so tests
 * can point unit loading at a temporary directory.
 *
 * Backported fix:
 *  - baa162cec "core: fix a use-after-free" -- the original freed its
 *    local `filename` before a log statement that still referenced the
 *    old value. unit_load() below logs using fragment_path's value before
 *    freeing it on the error path, not after.
 *
 * Template fallback: an instance with no fragment of its own (e.g.
 * "serial-getty@ttyUSB0.service", never shipped by any package) loads
 * through its template's file instead, quarried from v30's own template
 * fallback at load-fragment.c:2289-2300. u->fragment_path then records the
 * template's path, matching v30's own behaviour (load-fragment.c:2228-2230)
 * -- that is what picoctl status is meant to show. Not carried: v30's alias
 * retry (load-fragment.c:2302-2319) and its fragment_path-as-hint retry
 * (:2274-2287).
 *
 * Symlink aliases (default.target -> multi-user.target, the shape oe-core's
 * set_systemd_default_target and every Alias= enablement produce) are
 * resolved before a unit exists at all: manager_load_unit() asks
 * unit_resolve_alias() below and hands back the canonical unit, with the
 * alias recorded as one of its names. v30 instead merged two already-loaded
 * units (unit_merge()); resolving by name up front makes merging unnecessary,
 * because an alias never gets a Unit of its own to merge.
 */

#include "unit.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "manager.h"
#include "unit-name.h"
#include "util.h"

/*
 * Search every unit_path entry for "<dir>/<name>". 1 with *ret owned on a
 * hit, 0 on a clean miss or a mask, -ENOMEM. Split out of unit_load() so the
 * fallback below can run the exact same search twice, once for u->id and
 * once for its template -- the warning strings still name u->id as the
 * subject either time, since that is the unit actually being loaded
 * regardless of which filename was tried.
 *
 * The first candidate found, mask or not, is terminal (matches
 * unit_find_fragment()'s own "first hit in the path decides" rule): a mask
 * must shadow a lower-priority real fragment, not be skipped past. *ret_masked
 * is only ever set to true, never reset, so a second call reusing it (the
 * literal-then-template fallback in unit_load()) can't un-mask a unit.
 */
static int unit_find_fragment(Unit *u, const char *name, char **ret, bool *ret_masked) {
        char * const *dir;

        for (dir = u->manager->unit_path; *dir; dir++) {
                char candidate[PATH_MAX];
                struct stat st;
                int n;

                n = snprintf(candidate, sizeof(candidate), "%s/%s", *dir, name);
                if (n < 0 || (size_t) n >= sizeof(candidate)) {
                        pico_log(PICO_LOG_WARNING, "%s: search path entry '%s' too long, skipping", u->id, *dir);
                        continue;
                }

                if (stat(candidate, &st) < 0) {
                        if (errno != ENOENT)
                                pico_log(PICO_LOG_WARNING,
                                         "%s: stat('%s'): %s",
                                         u->id,
                                         candidate,
                                         strerror(errno));
                        continue;
                }

                /* v30 null_or_empty() (util.c): a symlink to a device node
                 * (conventionally /dev/null) or a zero-size regular file
                 * masks the unit -- refuse it here rather than falling
                 * through to a lower-priority real fragment. */
                if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode) || (S_ISREG(st.st_mode) && st.st_size == 0)) {
                        pico_log(PICO_LOG_INFO, "%s: '%s' masks the unit, refusing to load", u->id, candidate);
                        *ret_masked = true;
                        return 0;
                }

                if (!S_ISREG(st.st_mode)) {
                        pico_log(PICO_LOG_WARNING, "%s: '%s' is not a regular file, skipping", u->id, candidate);
                        continue;
                }

                *ret = pico_strdup(candidate);
                if (!*ret) /* 8ea913b2e-class check: this is the var just assigned */
                        return -ENOMEM;
                return 1;
        }

        return 0;
}

/*
 * One hop of alias resolution. The first entry named `name` anywhere in the
 * search path decides, the same precedence unit_find_fragment() uses: a
 * symlink there whose target's basename is a different, valid unit name of the
 * same type makes `name` an alias of that unit -- v30 collected the same names
 * while following the fragment's symlinks (load-fragment.c open_follow()).
 * Not an alias: a regular file, a symlink to a file of the same name, a mask
 * (-> /dev/null), anything instance- or template-shaped (the template
 * fallback in unit_load() owns those). 1 with *ret owned, 0, -ENOMEM.
 */
static int alias_one_hop(Manager *m, const char *name, char **ret) {
        char * const *dir;

        for (dir = m->unit_path; *dir; dir++) {
                char path[PATH_MAX], target[PATH_MAX];
                const char *base;
                struct stat st;
                ssize_t k;
                int n;

                n = snprintf(path, sizeof(path), "%s/%s", *dir, name);
                if (n < 0 || (size_t) n >= sizeof(path))
                        continue;

                if (lstat(path, &st) < 0)
                        continue;

                if (!S_ISLNK(st.st_mode))
                        return 0;

                k = readlink(path, target, sizeof(target) - 1);
                if (k <= 0)
                        return 0;
                target[k] = '\0';

                base = strrchr(target, '/');
                base = base ? base + 1 : target;

                if (strcmp(base, name) == 0 || !unit_name_is_valid(base) || strchr(base, '@') ||
                    unit_type_from_name(base) != unit_type_from_name(name))
                        return 0;

                *ret = pico_strdup(base);
                return *ret ? 1 : -ENOMEM;
        }

        return 0;
}

/* Bounded, so a symlink cycle degrades to "no alias" (and the literal load
 * then fails on ELOOP) instead of recursing forever. */
#define ALIAS_MAX_HOPS 8

int unit_resolve_alias(Manager *m, const char *name, char **ret) {
        char *cur = NULL;
        int hops, r;

        if (!m || !m->unit_path || !name || !ret)
                return -EINVAL;

        *ret = NULL;

        if (strchr(name, '@'))
                return 0;

        for (hops = 0; hops < ALIAS_MAX_HOPS; hops++) {
                char *next = NULL;

                r = alias_one_hop(m, cur ? cur : name, &next);
                if (r < 0) {
                        free(cur);
                        return r;
                }
                if (r == 0)
                        break;

                if (strcmp(next, name) == 0) { /* cycle back to the start */
                        free(next);
                        free(cur);
                        return 0;
                }

                free(cur);
                cur = next;
        }

        if (hops == ALIAS_MAX_HOPS) {
                pico_log(PICO_LOG_WARNING,
                         "%s: alias chain longer than %d links, treating as its own unit",
                         name,
                         ALIAS_MAX_HOPS);
                free(cur);
                return 0;
        }

        if (!cur)
                return 0;

        *ret = cur;
        return 1;
}

int unit_load(Unit *u) {
        char *fragment_path = NULL;
        bool masked = false;
        int r;

        if (!u)
                return -EINVAL;

        /* The search path lives on the manager, so a unit without one has
         * nowhere to look. */
        if (!u->manager || !u->manager->unit_path)
                return -EINVAL;

        if (u->load_state != UNIT_STUB)
                return 0; /* idempotent: already resolved by an earlier call */

        r = unit_find_fragment(u, u->id, &fragment_path, &masked);
        if (r < 0)
                return r;

        /*
         * Literal beats template, and it does so by searching the whole
         * path for the literal name before the template name is tried
         * anywhere -- not "try literal, then template, in each directory".
         * That ordering matters, not an implementation detail: it
         * is what lets serial-getty@ttyGS0.service in a higher-priority
         * directory win over serial-getty@.service in a lower-priority one,
         * and a per-directory "optimization" would invert it. See
         * test_literal_beats_template_across_dirs() in test-unit-load.c.
         */
        if (r == 0 && !masked && u->instance) {
                char *tmpl = unit_name_template(u->id);

                if (!tmpl)
                        return -ENOMEM;

                r = unit_find_fragment(u, tmpl, &fragment_path, &masked);
                free(tmpl);
                if (r < 0)
                        return r;
        }

        if (masked) {
                pico_log(PICO_LOG_DEBUG, "%s: masked, not loading", u->id);
                u->load_state = UNIT_MASKED;
                return 0;
        }

        if (r == 0) {
                pico_log(PICO_LOG_DEBUG, "%s: no unit file found in the search path", u->id);
                u->load_state = UNIT_ERROR;
                return -ENOENT;
        }

        r = unit_parse_file(u, fragment_path);
        if (r < 0) {
                /* baa162cec: log the path before freeing it, not after */
                pico_log(PICO_LOG_WARNING, "%s: failed to parse '%s': %s", u->id, fragment_path, strerror(-r));
                free(fragment_path);
                u->load_state = UNIT_ERROR;
                return r;
        }

        u->fragment_path = fragment_path; /* ownership transferred */
        u->load_state = UNIT_LOADED;
        return 0;
}
