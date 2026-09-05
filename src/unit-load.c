/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Fragment lookup, quarried from systemd's ~2011-era unit_load_fragment()
 * in src/load-fragment.c (tag v30, commit 501c92c, copyright 2010
 * Lennart Poettering, GPL-2.0-or-later) down to its essential
 * shape: search a path for "<id>", hand a found file to the INI parser,
 * resolve to UNIT_LOADED or UNIT_ERROR. The 2011 original searched
 * several directories (/etc, /run, /usr/lib) with per-directory drop-in
 * merging; this MVP searches the manager's own unit path, which defaults to
 * two entries -- PICO_UNIT_DIR (admin overrides) then PICO_PACKAGED_UNIT_DIR
 * (where packages actually install units, given angstrom-pico-init's usrmerge
 * decision -- see plans/29-pico-init.md "The decided scope").
 *
 * The path lives on the Manager rather than in a file-static array here
 * because it has to be redirectable: a test that cannot point unit loading at
 * a temporary directory can only be run as root against the host's real /etc,
 * which is no test at all. Adding a third directory (e.g. /run) stays a
 * one-line change to the default, not a rewrite.
 *
 * Backported fix:
 *  - baa162cec "core: fix a use-after-free" -- the original freed its
 *    local `filename` before a log statement that still referenced the
 *    old value. unit_load() below logs using fragment_path's value before
 *    freeing it on the error path, not after.
 *
 * G2 fallback: an instance with no fragment of its own (e.g.
 * "serial-getty@ttyUSB0.service", never shipped by any package) loads
 * through its template's file instead, quarried from v30's own template
 * fallback at load-fragment.c:2289-2300. u->fragment_path then records the
 * template's path, matching v30's own behaviour (load-fragment.c:2228-2230)
 * -- that is what picoctl status is meant to show. Not carried: v30's alias
 * retry (load-fragment.c:2302-2319) and its fragment_path-as-hint retry
 * (:2274-2287) -- pico has no Alias= and no linked-path hint.
 */

#include "unit.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "manager.h"
#include "unit-name.h"
#include "util.h"

/*
 * Search every unit_path entry for "<dir>/<name>". 1 with *ret owned on a
 * hit, 0 on a clean miss, -ENOMEM. Split out of unit_load() so the fallback
 * below can run the exact same search twice, once for u->id and once for
 * its template -- the warning strings still name u->id as the subject
 * either time, since that is the unit actually being loaded regardless of
 * which filename was tried.
 */
static int unit_find_fragment(Unit *u, const char *name, char **ret) {
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

int unit_load(Unit *u) {
        char *fragment_path = NULL;
        int r;

        if (!u)
                return -EINVAL;

        /* The search path lives on the manager, so a unit without one has
         * nowhere to look. */
        if (!u->manager || !u->manager->unit_path)
                return -EINVAL;

        if (u->load_state != UNIT_STUB)
                return 0; /* idempotent: already resolved by an earlier call */

        r = unit_find_fragment(u, u->id, &fragment_path);
        if (r < 0)
                return r;

        /*
         * Literal beats template, and it does so by searching the whole
         * path for the literal name before the template name is tried
         * anywhere -- not "try literal, then template, in each directory".
         * That ordering is load-bearing, not an implementation detail: it
         * is what lets serial-getty@ttyGS0.service in a higher-priority
         * directory win over serial-getty@.service in a lower-priority one
         * (G3(b)'s override), and it is exactly what a per-directory
         * "optimization" would silently invert. See
         * test_literal_beats_template_across_dirs() in test-unit-load.c.
         */
        if (r == 0 && u->instance) {
                char *tmpl = unit_name_template(u->id);

                if (!tmpl)
                        return -ENOMEM;

                r = unit_find_fragment(u, tmpl, &fragment_path);
                free(tmpl);
                if (r < 0)
                        return r;
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
