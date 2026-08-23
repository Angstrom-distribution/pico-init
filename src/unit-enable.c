/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Enablement: .wants/.requires symlink directories and preset application.
 * See unit-enable.h for why both are read at boot rather than at install time.
 *
 * M2 placeholder. Every function below is a no-op returning success, so
 * manager_startup() runs its full sequence today with enablement simply
 * deciding nothing -- which is the honest behaviour for "not implemented yet",
 * and lets the boot path be exercised before this file is real.
 */

#include <errno.h>

#include "manager.h"
#include "unit-enable.h"
#include "unit.h"
#include "util.h"

int unit_add_wants_requires_dirs(Unit *u) {
        if (!u || !u->manager)
                return -EINVAL;

        /*
         * TODO (M2): for each dir in u->manager->unit_path, scan
         * <dir>/<u->id>.wants/ and <dir>/<u->id>.requires/. Every entry names
         * a unit that <u> should pull in: add UNIT_WANTS / UNIT_REQUIRES from
         * u to it via unit_add_dependency_by_name(), and set that unit's
         * ->enabled so preset application knows not to second-guess it.
         *
         * Validate each entry name with unit_name_is_valid() before use -- the
         * entries are symlink names and become paths.
         */
        return 0;
}

int unit_install_enablement(Unit *u) {
        if (!u)
                return -EINVAL;

        /*
         * TODO (M2): for each name in u->wanted_by, add UNIT_WANTS from that
         * unit to u; likewise u->required_by with UNIT_REQUIRES. Note the
         * direction: "WantedBy=multi-user.target" means the *target* wants
         * *u*, so the edge runs from the named unit to u, not the other way.
         * Then set u->enabled.
         */
        return 0;
}

int manager_preset_query(Manager *m, const char *unit_name) {
        if (!m || !unit_name)
                return -EINVAL;

        /*
         * TODO (M2): read every *.preset file across m->preset_path and answer
         * for unit_name. The real rules, from systemd.preset(5):
         *   - files are sorted by filename lexicographically across ALL
         *     directories at once, not per-directory; the lexicographically
         *     earliest filename wins for a given unit
         *   - within one file, the first matching line wins
         *   - directives are "enable <glob>" and "disable <glob>", with shell
         *     style wildcards; blank lines and #/; comments are ignored
         *   - a same-named file in an earlier directory shadows a later one
         *     (/etc > /run > /usr/lib)
         */
        return -ENOENT; /* no rule matched */
}

int manager_apply_presets(Manager *m) {
        if (!m)
                return -EINVAL;

        /*
         * TODO (M2): for each loaded unit that no .wants/.requires symlink
         * already enabled (u->enabled false) and that has [Install] data, ask
         * manager_preset_query() and call unit_install_enablement() when the
         * answer is enable.
         *
         * Note the default deliberately: -ENOENT ("no rule matched") means
         * ENABLE, not disable. That is upstream's behaviour -- `systemctl
         * preset` enables a unit no rule speaks for -- and it is what OE
         * images already get from systemd-preset at rootfs time, so matching
         * it is what the drop-in-compatibility goal requires. An image that
         * wants the opposite ships a catch-all "disable *" rule, which is also
         * exactly how it would do it under real systemd.
         */
        return 0;
}
