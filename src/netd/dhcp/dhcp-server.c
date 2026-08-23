/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * QUARRY PLACEHOLDER -- src/libsystemd-network/sd-dhcp-server.c (1,207 lines).
 *
 * The DHCPv4 server: socket setup, lease pool derived from Address= the
 * way upstream does it, and the receive path.
 *
 * Much closer to a real port than the client: 11.3% event-coupled, one io
 * event source, synchronous request -> reply handlers. Carries a real
 * 2013 Intel copyright line.
 *
 * Dropped: lease-file persistence (the sd-json dependency, see
 * dhcp-lease.c) and DHCP relay.
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. Nothing has been lifted
 * yet; this file exists so meson, REUSE and the include graph are settled
 * before N3 starts, and so no later milestone has to edit
 * meson.build while another one is also editing it.
 *
 * When the lift happens, this comment is replaced by the real one, in exactly
 * the style src/unit-parse.c's header demonstrates: the history review from
 * 4925d9f07f forward on main, and one recorded keep-or-backport call per
 * upstream fix, each with its commit hash. That record is the deliverable,
 * not a formality -- it is the only thing that makes a lifted file
 * maintainable afterwards.
 */

#include "dhcp-server-internal.h"
