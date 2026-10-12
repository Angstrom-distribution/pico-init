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
 * path. Returns 1 to enable, 0 to disable, -ENOENT when no rule matched,
 * -ECANCELED when an "ignore" rule matched (leave the unit as it is), or
 * -errno on a read error.
 */
int manager_preset_query(Manager *m, const char *unit_name);

/*
 * Apply presets to every loaded unit that no symlink already enabled, calling
 * unit_install_enablement() for each one a preset says to enable -- and, for
 * each of those, persisting the decision as a real .wants/.requires symlink
 * under the manager's own unit directory (unit_path[0]), the same way
 * `systemctl preset` would. A unit a preset left disabled gets no symlink
 * and no edge, which is exactly what "disabled" means on disk: nothing
 * written at all.
 *
 * This is what makes calling this function indistinguishable, on disk, from
 * a real `systemctl preset-all`. manager_startup() calls it at most once per
 * machine's life (first boot only), so a unit whose symlink was later removed
 * (e.g. `picoctl disable`) stays disabled.
 *
 * Number enabled, or -errno. A failure persisting one unit's symlink is
 * logged and does not undo that unit's in-memory enablement or stop the loop
 * over the rest -- the in-memory decision for this boot is still correct
 * even when the write that would make it survive a reboot failed.
 */
int manager_apply_presets(Manager *m);

/*
 * Create (or repair) one <etcdir>/<target><suffix>/<unit_id> symlink
 * pointing at `link_target`, idempotently -- install.c's create_symlink(),
 * shared with picoctl's own enable verb (src/picoctl.c
 * create_enable_symlink()) so a symlink persisted here at boot and one
 * `picoctl enable` writes by hand can never disagree about what "enabled"
 * looks like on disk.
 *
 * `etcdir` is the directory .wants/.requires live under (manager.h's
 * PICO_UNIT_DIR in production, a --root-prefixed or fixture equivalent
 * otherwise) -- never derived internally, so a caller with its own idea of
 * --root (picoctl) and one with none (boot time) can share this one
 * implementation.
 *
 * Returns 1 if a symlink was created or replaced, 0 if the correct symlink
 * already existed, or -errno. Never logs or prints -- each caller decides
 * how, or whether, to report what it did.
 */
int unit_enable_create_symlink(
                const char *etcdir,
                const char *target,
                const char *suffix,
                const char *unit_id,
                const char *link_target);
