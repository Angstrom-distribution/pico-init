/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * PID 1's own first-boot detection and /etc/machine-id fill-in -- the
 * pico-init equivalent of upstream's src/core/machine-id-setup.c (the
 * first-boot/credential plumbing in src/core/main.c) and
 * src/shared/machine-id-setup.c's machine_id_setup(), narrowed to the one
 * case that matters here: a fresh image boots with /etc/machine-id missing,
 * empty, or literally "uninitialized", and nothing has run before PID 1 to
 * fill it in (no systemd-firstboot, no systemd-machine-id-setup).
 *
 * Not carried from upstream (all in acquire_machine_id()): the
 * D-Bus-machine-id, system-credential, container_uuid and SMBIOS/DMI
 * acquisition chain, since these images have none of those sources. Also
 * not carried: machine_id_commit() (the transient-file ->
 * real-file promotion a switch-root/soft-reboot does) and the
 * /run/machine-id-survives-soft-reboot reuse path -- pico-init has no
 * switch-root handoff, so a boot either gets a real writable /etc from the
 * start or stays on the transient fallback for its entire life.
 *
 * One difference from upstream: upstream refuses to boot at all when
 * /etc/machine-id is BOTH missing and /etc/ is read-only ("System cannot
 * boot", src/shared/machine-id-setup.c). pico-init logs a warning and continues with the
 * id only cached in this process, matching every other optional-subsystem
 * failure in main.c -- a board that cannot persist a machine id anywhere
 * is still more useful booted than frozen over it.
 */

#pragma once

#include <stdbool.h>

#include "sd-id128.h"

/*
 * Fills in /etc/machine-id if it is missing, empty, or literally
 * "uninitialized" (first boot); otherwise reads the existing id as-is.
 *
 * `root` is an optional path prefix (NULL or "" for the real root),
 * exactly the testability convention manager.h's own search-path setters
 * use -- never a production argument. On a read-only /etc, falls back to
 * a tmpfs-backed bind mount of /run/machine-id over /etc/machine-id,
 * matching upstream's own transient-file mechanism; first boot is still
 * reported true in that case; see machine-id-setup.h's deviation note
 * above for the one case this fallback cannot cover.
 *
 * *ret_id (if non-NULL) is set to the resulting id, and *ret_first_boot
 * (if non-NULL) to whether this call generated a new one. 0 on success --
 * including every fallback path, which only ever costs persistence, never
 * the call itself -- or -errno when getrandom() itself failed, the one
 * genuinely fatal case.
 */
int machine_id_setup(const char *root, sd_id128_t *ret_id, bool *ret_first_boot);

/*
 * The id the most recent machine_id_setup() call established, for a caller
 * (netd's persistent-MAC hashing) that wants it without reopening and
 * re-parsing /etc/machine-id itself. All-zero (sd_id128_is_null() true)
 * before machine_id_setup() has run. Equivalent to sd_id128_get_machine()
 * minus the file I/O: the two can never disagree, since machine_id_setup()
 * is always what put a readable id at /etc/machine-id in the first place.
 */
sd_id128_t machine_id_setup_get(void);
