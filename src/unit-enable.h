/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Enablement: deciding which units a target actually pulls in.
 *
 * Upstream splits this across install time and boot time -- `systemctl enable`
 * writes a .wants/ symlink, `systemctl preset` consults the preset files to
 * decide which units get one, and PID 1 only ever reads the resulting symlinks.
 * pico-init reads both, at boot, because on an image-built read-only rootfs
 * nothing ever runs `systemctl preset`: the preset file ships in the image and
 * would otherwise have no reader at all.
 *
 * The two sources are not equal. A .wants/ or .requires/ symlink is an explicit
 * decision already made and is authoritative. A preset rule is only a default,
 * so it applies to a unit no symlink already spoke for -- which is why Unit
 * carries an `enabled` flag rather than this being one merged pass.
 */

#pragma once

#include "unit.h"

typedef struct Manager Manager;

/*
 * Add the Wants=/Requires= edges implied by every <dir>/<u->id>.wants/ and
 * <dir>/<u->id>.requires/ directory across the manager's unit search path.
 * Marks each named unit enabled. 0 or -errno.
 *
 * Called on the *target* (the directory is named after the unit doing the
 * wanting), which is the direction the symlink layout actually encodes.
 */
int unit_add_wants_requires_dirs(Unit *u);

/*
 * Honour u's own [Install] WantedBy=/RequiredBy= now: for each name listed,
 * add a Wants/Requires edge from that unit to u, loading it if needed, and
 * mark u enabled. 0 or -errno.
 */
int unit_install_enablement(Unit *u);

/*
 * Look up `unit_name` in the preset files along the manager's preset search
 * path. Returns 1 to enable, 0 to disable, -ENOENT when no rule matched, or
 * -errno on a read error.
 */
int manager_preset_query(Manager *m, const char *unit_name);

/*
 * Apply presets to every loaded unit that no symlink already enabled, calling
 * unit_install_enablement() for each one a preset says to enable. Number
 * enabled, or -errno.
 */
int manager_apply_presets(Manager *m);
