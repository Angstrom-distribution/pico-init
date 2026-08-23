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
 * merging; this MVP searches two -- PICO_UNIT_DIR (admin overrides) then
 * PICO_PACKAGED_UNIT_DIR (where packages actually install units, given
 * angstrom-pico-init's usrmerge decision -- see plans/29-pico-init.md
 * "The decided scope") -- keeping the loop-over-an-array shape so a third
 * directory (e.g. /run) is still a one-line change, not a rewrite.
 *
 * Backported fix:
 *  - baa162cec "core: fix a use-after-free" -- the original freed its
 *    local `filename` before a log statement that still referenced the
 *    old value. unit_load() below logs using fragment_path's value before
 *    freeing it on the error path, not after.
 */

#include "unit.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "manager.h"
#include "util.h"

static const char * const unit_search_path[] = {
        PICO_UNIT_DIR,
        PICO_PACKAGED_UNIT_DIR,
        NULL,
};

int unit_load(Unit *u) {
        const char * const *dir;
        char *fragment_path = NULL;
        int r;

        if (!u)
                return -EINVAL;

        if (u->load_state != UNIT_STUB)
                return 0; /* idempotent: already resolved by an earlier call */

        for (dir = unit_search_path; *dir; dir++) {
                char candidate[PATH_MAX];
                struct stat st;
                int n;

                n = snprintf(candidate, sizeof(candidate), "%s/%s", *dir, u->id);
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

                fragment_path = pico_strdup(candidate);
                if (!fragment_path) /* 8ea913b2e-class check: this is the var just assigned */
                        return -ENOMEM;
                break;
        }

        if (!fragment_path) {
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
